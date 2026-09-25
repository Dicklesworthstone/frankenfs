//! Write-through image I/O with restart-safe external repair coverage.
//!
//! This device owns both image and archive inode locks. Before the first source
//! write, it durably invalidates the archive header. `sync` verifies the intended
//! source bytes and atomically publishes fresh protection before returning.
//! An interrupted/failed write epoch is therefore unavailable for offline repair,
//! never mistaken for the previous protection point. No filesystem blocks are
//! reserved, relocated, or repurposed.
//!
//! Open requires the image to match its existing protection point. A mismatch
//! at open may be a legitimate write by another program, so it is NEVER silently
//! rolled back. Use offline restore to a separate image for explicit recovery.
//! All image access while this device is open must go through this device;
//! advisory locks cannot exclude kernel mounts or non-cooperating writers.

use super::{
    Archive, DIGEST_BYTES, GROUP_PREFIX_BYTES, HEADER_BYTES, Header, MemoryGroup, ProtectionInfo,
    checkpoint, corrupt, digest_parts, hash_image, load_source, parent_path, source_digest,
    symbol_digest,
};
use crate::codec::{decode_group_with_owned_repair_symbols, encode_group};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, ByteOffset, GroupNumber};
use parking_lot::{Mutex, MutexGuard};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;

const PENDING_MAGIC: &[u8; 8] = b"FFSRQPD2";

enum Phase {
    Clean,
    Dirty,
    Poisoned,
}

struct State {
    archive: Archive,
    phase: Phase,
    /// Digests of intended complete blocks, including partial-write preservation.
    /// Unchanged blocks retain the checksums in the previous archive.
    changed: BTreeMap<u64, [u8; 32]>,
    /// One hash per source-digest table, attested against the admitted image.
    /// This prevents a valid table from another snapshot from authorizing a
    /// rollback merely because its own local checksum is internally consistent.
    tables: Vec<[u8; 32]>,
    /// A single group's metadata cache bounds the read-side working set.
    cached_hashes: Option<(u32, Vec<[u8; 32]>)>,
}

/// A fixed-size, writable compatibility image protected by an external sidecar.
///
/// `write_all_at` has ordinary write-through semantics, not a durability ACK.
/// A successful `sync` acknowledges both source durability AND fresh repair
/// coverage. An error after writing may leave changed source bytes; neither an
/// error nor dropping this device implicitly rolls those bytes back or commits
/// their protection. A pending archive requires explicit offline reconciliation.
///
/// Reads verify complete source blocks. When no writes are outstanding, detected
/// corruption within the available redundancy is reconstructed and verified
/// before read data is returned. During a dirty epoch, reads still verify but
/// never decode against the old parity. Recovery from complete group loss remains
/// available through the offline restore API.
///
/// This initial implementation scans the image at each dirty sync, and re-encodes
/// only changed groups or groups with damaged parity. It favors correctness over
/// low fsync latency; it is not the default filesystem mount path. Working memory
/// includes one digest per admitted group, one per changed block, and bounded
/// group buffers; the read-side metadata cache holds only one group at a time.
pub struct SidecarImageDevice {
    image: File,
    sidecar_path: PathBuf,
    image_bytes: u64,
    state: Mutex<State>,
}

impl std::fmt::Debug for SidecarImageDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarImageDevice")
            .field("image_bytes", &self.image_bytes)
            .field("sidecar_path", &self.sidecar_path)
            .finish_non_exhaustive()
    }
}

impl SidecarImageDevice {
    /// Open an exclusively owned image and its matching, existing sidecar.
    /// Neither file is changed on admission failure. The archive path is
    /// canonicalized once; future syncs replace that archive with a new snapshot.
    pub fn open(cx: &Cx, image_path: &Path, sidecar_path: &Path) -> Result<Self> {
        checkpoint(cx)?;
        let image = File::options().read(true).write(true).open(image_path)?;
        let image_meta = image.metadata()?;
        if !image_meta.is_file() {
            return Err(corrupt("live repair requires a regular image file"));
        }
        image.try_lock().map_err(io::Error::from)?;
        let sidecar_path = sidecar_path.canonicalize()?;
        let file = File::options().read(true).write(true).open(&sidecar_path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || (metadata.dev(), metadata.ino()) == (image_meta.dev(), image_meta.ino())
        {
            return Err(corrupt(
                "image and repair archive must be distinct regular files",
            ));
        }
        file.try_lock().map_err(io::Error::from)?;
        let mut raw = [0; HEADER_BYTES];
        file.read_exact_at(&mut raw, 0)?;
        if &raw[..8] == PENDING_MAGIC {
            return Err(corrupt(
                "repair archive has an unfinished write epoch; reconcile offline",
            ));
        }
        let header = Header::decode(&raw)?;
        if metadata.len() != header.expected_len()? || image_meta.len() != header.image_bytes {
            return Err(corrupt("live repair image or archive length mismatch"));
        }
        if hash_image(cx, &image, header.image_bytes)? != header.snapshot_digest {
            return Err(corrupt(
                "image differs from its protection point; refusing implicit rollback",
            ));
        }
        let archive = Archive { file, header };
        let mut tables = Vec::new();
        // A whole-image digest does not bind independently checksummed group
        // records. Establish that binding against the admitted source before
        // allowing any read repair, and remember it across subsequent reads.
        for group in 0..archive.header.groups {
            let record = archive.read_group(cx, group)?;
            if record.invalid_symbols != 0 {
                return Err(corrupt("live repair admission requires intact parity"));
            }
            let (source, _) = load_source(cx, &image, &archive.header, group, false)?;
            for (index, bytes) in source.blocks.iter().enumerate() {
                if source_digest(&archive.header, source.first + index as u64, bytes)
                    != record.hashes[index]
                {
                    return Err(corrupt(
                        "source digest table differs from the admitted image",
                    ));
                }
            }
            tables.push(Self::table_digest(&archive.header, group, &record.hashes)?);
        }
        if image.metadata()?.len() != archive.header.image_bytes
            || hash_image(cx, &image, archive.header.image_bytes)? != archive.header.snapshot_digest
        {
            return Err(corrupt("image changed during live repair admission"));
        }
        checkpoint(cx)?;
        Ok(Self {
            image,
            sidecar_path,
            image_bytes: archive.header.image_bytes,
            state: Mutex::new(State {
                archive,
                phase: Phase::Clean,
                changed: BTreeMap::new(),
                tables,
                cached_hashes: None,
            }),
        })
    }

    fn lock(&self, cx: &Cx) -> Result<MutexGuard<'_, State>> {
        loop {
            checkpoint(cx)?;
            if let Some(state) = self.state.try_lock_for(Duration::from_millis(10)) {
                checkpoint(cx)?;
                if matches!(state.phase, Phase::Poisoned) {
                    return Err(corrupt(
                        "live repair device is poisoned after an I/O failure",
                    ));
                }
                return Ok(state);
            }
        }
    }

    fn range_end(&self, offset: ByteOffset, length: usize) -> Result<u64> {
        offset
            .0
            .checked_add(length as u64)
            .filter(|&end| end <= self.image_bytes)
            .ok_or_else(|| corrupt("live repair I/O exceeds fixed image geometry"))
    }

    fn check_image_len(&self) -> Result<()> {
        if self.image.metadata()?.len() != self.image_bytes {
            return Err(corrupt("image length changed while live repair owned it"));
        }
        Ok(())
    }

    fn table_digest(header: &Header, group: u32, hashes: &[[u8; 32]]) -> Result<[u8; 32]> {
        let (_, count) = header.group_geometry(group)?;
        if hashes.len() != count as usize {
            return Err(corrupt(
                "source digest table has the wrong number of blocks",
            ));
        }
        let mut metadata = header.prefix(group)?.to_vec();
        for hash in hashes {
            metadata.extend_from_slice(hash);
        }
        Ok(digest_parts(
            b"ffs-sidecar-group-v2",
            &[&header.seed, &metadata],
        ))
    }

    fn check_table(state: &State, group: u32, hashes: &[[u8; 32]]) -> Result<()> {
        let actual = Self::table_digest(&state.archive.header, group, hashes)?;
        if state.tables.get(group as usize) != Some(&actual) {
            return Err(corrupt(
                "repair source table changed from the admitted generation",
            ));
        }
        Ok(())
    }

    fn expected_hash(cx: &Cx, state: &mut State, block: u64) -> Result<[u8; 32]> {
        if let Some(hash) = state.changed.get(&block) {
            return Ok(*hash);
        }
        let header = &state.archive.header;
        let group = (block / u64::from(header.options.group_blocks)) as u32;
        if state.cached_hashes.as_ref().map(|(index, _)| *index) != Some(group) {
            let (_, count) = header.group_geometry(group)?;
            let mut metadata = vec![0; GROUP_PREFIX_BYTES + count as usize * DIGEST_BYTES];
            let offset = header.group_offset(group)?;
            state.archive.file.read_exact_at(&mut metadata, offset)?;
            let mut digest = [0; DIGEST_BYTES];
            state
                .archive
                .file
                .read_exact_at(&mut digest, offset + metadata.len() as u64)?;
            checkpoint(cx)?;
            if metadata[..GROUP_PREFIX_BYTES] != header.prefix(group)?
                || digest != digest_parts(b"ffs-sidecar-group-v2", &[&header.seed, &metadata])
                || state.tables.get(group as usize) != Some(&digest)
            {
                return Err(corrupt("live repair source digest metadata is corrupt"));
            }
            state.cached_hashes = Some((
                group,
                metadata[GROUP_PREFIX_BYTES..]
                    .as_chunks::<DIGEST_BYTES>()
                    .0
                    .to_vec(),
            ));
        }
        let relative = (block % u64::from(header.options.group_blocks)) as usize;
        state
            .cached_hashes
            .as_ref()
            .and_then(|(_, hashes)| hashes.get(relative))
            .copied()
            .ok_or_else(|| corrupt("live repair source digest is missing"))
    }

    fn read_source_block(&self, header: &Header, block: u64) -> Result<Vec<u8>> {
        let mut bytes = vec![0; header.options.block_size as usize];
        self.image.read_exact_at(
            &mut bytes[..header.real_block_len(block)],
            block * u64::from(header.options.block_size),
        )?;
        Ok(bytes)
    }

    fn media_error(error: &FfsError) -> bool {
        matches!(error, FfsError::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof
            || (cfg!(target_os = "linux") && error.raw_os_error() == Some(5)))
    }

    fn verified_block(&self, cx: &Cx, state: &mut State, block: u64) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        let expected = Self::expected_hash(cx, state, block)?;
        match self.read_source_block(&state.archive.header, block) {
            Ok(bytes) if source_digest(&state.archive.header, block, &bytes) == expected => {
                Ok(bytes)
            }
            Err(error) if !Self::media_error(&error) => Err(error),
            _ if matches!(state.phase, Phase::Dirty) => Err(corrupt(
                "source corruption during a dirty epoch; old parity is not current",
            )),
            _ => {
                let group = (block / u64::from(state.archive.header.options.group_blocks)) as u32;
                self.repair_group(cx, state, group)?;
                let bytes = self.read_source_block(&state.archive.header, block)?;
                if source_digest(&state.archive.header, block, &bytes) != expected {
                    return Err(corrupt(
                        "live repair readback did not match the expected source",
                    ));
                }
                Ok(bytes)
            }
        }
    }

    fn repair_group(&self, cx: &Cx, state: &State, group: u32) -> Result<usize> {
        let header = &state.archive.header;
        let record = state.archive.read_group(cx, group)?;
        Self::check_table(state, group, &record.hashes)?;
        let (first, count) = header.group_geometry(group)?;
        let mut blocks = Vec::with_capacity(count as usize);
        let mut before = Vec::with_capacity(count as usize);
        let mut damaged = Vec::new();
        for index in 0..count {
            checkpoint(cx)?;
            let block = first + u64::from(index);
            match self.read_source_block(header, block) {
                Ok(bytes) => {
                    if source_digest(header, block, &bytes) != record.hashes[index as usize] {
                        damaged.push(index);
                    }
                    before.push(Some(bytes.clone()));
                    blocks.push(bytes);
                }
                Err(error) if Self::media_error(&error) => {
                    before.push(None);
                    blocks.push(vec![0; header.options.block_size as usize]);
                    damaged.push(index);
                }
                Err(error) => return Err(error),
            }
        }
        if damaged.is_empty() {
            return Ok(0);
        }
        let source = MemoryGroup {
            first,
            block_size: header.options.block_size,
            blocks,
        };
        let decoded = decode_group_with_owned_repair_symbols(
            cx,
            &source,
            &header.seed,
            GroupNumber(group),
            BlockNumber(first),
            count,
            &damaged,
            record.symbols,
        )?;
        checkpoint(cx)?;
        let mut seen = BTreeSet::new();
        if !decoded.complete || decoded.recovered.len() != damaged.len() {
            return Err(corrupt(
                "live repair could not reconstruct every damaged block",
            ));
        }
        // Validate EVERY result and compare EVERY target before the first write.
        for recovered in &decoded.recovered {
            let index = recovered
                .block
                .0
                .checked_sub(first)
                .filter(|&index| index < u64::from(count))
                .ok_or_else(|| corrupt("live decoder returned a foreign target"))?
                as usize;
            if !seen.insert(index)
                || damaged.binary_search(&(index as u32)).is_err()
                || recovered.data.len() != header.options.block_size as usize
                || source_digest(header, recovered.block.0, &recovered.data) != record.hashes[index]
            {
                return Err(corrupt("live decoder output failed source verification"));
            }
            match (
                &before[index],
                self.read_source_block(header, recovered.block.0),
            ) {
                (Some(expected), Ok(current)) if *expected == current => {}
                (None, Err(error)) if Self::media_error(&error) => {}
                (_, Err(error)) => return Err(error),
                _ => return Err(corrupt("live repair target changed before writeback")),
            }
        }
        for recovered in &decoded.recovered {
            checkpoint(cx)?;
            self.image.write_all_at(
                &recovered.data[..header.real_block_len(recovered.block.0)],
                recovered.block.0 * u64::from(header.options.block_size),
            )?;
        }
        self.image.sync_all()?;
        for recovered in &decoded.recovered {
            checkpoint(cx)?;
            if self.read_source_block(header, recovered.block.0)? != recovered.data {
                return Err(corrupt("live repair failed post-write readback"));
            }
        }
        Ok(damaged.len())
    }

    fn fence(cx: &Cx, state: &mut State) -> Result<()> {
        if matches!(state.phase, Phase::Dirty) {
            return Ok(());
        }
        checkpoint(cx)?;
        let mut pending = state.archive.header.encode();
        pending[..8].copy_from_slice(PENDING_MAGIC);
        // A partial failure must prevent further source writes on this handle.
        state.phase = Phase::Poisoned;
        state.archive.file.write_all_at(&pending, 0)?;
        state.archive.file.sync_all()?;
        state.phase = Phase::Dirty;
        checkpoint(cx)
    }

    fn write_group(
        cx: &Cx,
        staged: &mut NamedTempFile,
        header: &Header,
        group: u32,
        source: &MemoryGroup,
    ) -> Result<()> {
        let mut metadata = header.prefix(group)?.to_vec();
        for (relative, bytes) in source.blocks.iter().enumerate() {
            metadata.extend_from_slice(&source_digest(
                header,
                source.first + relative as u64,
                bytes,
            ));
        }
        let encoded = encode_group(
            cx,
            source,
            &header.seed,
            GroupNumber(group),
            BlockNumber(source.first),
            source.blocks.len() as u32,
            header.options.repair_symbols,
        )?;
        if encoded.repair_symbols.len() != header.options.repair_symbols as usize {
            return Err(corrupt("live encoder returned incomplete protection"));
        }
        let digest = digest_parts(b"ffs-sidecar-group-v2", &[&header.seed, &metadata]);
        staged.write_all(&metadata)?;
        staged.write_all(&digest)?;
        for symbol in encoded.repair_symbols {
            checkpoint(cx)?;
            staged.write_all(&symbol.esi.to_le_bytes())?;
            staged.write_all(&symbol.data)?;
            staged.write_all(&symbol_digest(
                header,
                group,
                &digest,
                symbol.esi,
                &symbol.data,
            ))?;
        }
        Ok(())
    }

    fn refresh(&self, cx: &Cx, state: &mut State) -> Result<()> {
        self.check_image_len()?;
        self.image.sync_all()?;
        let mut header = state.archive.header.clone();
        let mut staged = NamedTempFile::new_in(parent_path(&self.sidecar_path))?;
        // Lock the new inode BEFORE making it visible at the archive name.
        staged.as_file().try_lock().map_err(io::Error::from)?;
        staged.write_all(&[0; HEADER_BYTES])?;
        let mut snapshot = blake3::Hasher::new();
        let mut tables = Vec::new();
        for group in 0..header.groups {
            checkpoint(cx)?;
            let record = state.archive.read_group(cx, group)?;
            Self::check_table(state, group, &record.hashes)?;
            let (source, _) = load_source(cx, &self.image, &header, group, false)?;
            let mut hashes = Vec::with_capacity(source.blocks.len());
            for (relative, bytes) in source.blocks.iter().enumerate() {
                let block = source.first + relative as u64;
                let expected = state
                    .changed
                    .get(&block)
                    .unwrap_or(&record.hashes[relative]);
                let actual = source_digest(&header, block, bytes);
                if actual != *expected {
                    return Err(corrupt(
                        "source changed outside the write epoch; refusing to bless corruption",
                    ));
                }
                hashes.push(actual);
                snapshot.update(&bytes[..header.real_block_len(block)]);
            }
            tables.push(Self::table_digest(&header, group, &hashes)?);
            let changed = state
                .changed
                .range(source.first..source.first + source.blocks.len() as u64)
                .next()
                .is_some();
            if changed || record.invalid_symbols != 0 {
                Self::write_group(cx, &mut staged, &header, group, &source)?;
            } else {
                // Validated source/parity records can be copied without re-encoding.
                let start = header.group_offset(group)?;
                let end = if group + 1 < header.groups {
                    header.group_offset(group + 1)?
                } else {
                    header.expected_len()?
                };
                let mut raw = vec![0; (end - start) as usize];
                state.archive.file.read_exact_at(&mut raw, start)?;
                staged.write_all(&raw)?;
            }
        }
        header.snapshot_digest = *snapshot.finalize().as_bytes();
        self.check_image_len()?;
        if hash_image(cx, &self.image, self.image_bytes)? != header.snapshot_digest
            || staged.as_file().metadata()?.len() != header.expected_len()?
        {
            return Err(corrupt("live snapshot changed during refresh"));
        }
        staged.as_file().write_all_at(&header.encode(), 0)?;
        staged.as_file().sync_all()?;
        let mut stored_header = [0; HEADER_BYTES];
        staged.as_file().read_exact_at(&mut stored_header, 0)?;
        if Header::decode(&stored_header)?.encode() != header.encode() {
            return Err(corrupt("staged live protection header failed readback"));
        }
        // Read the staged archive back through the ordinary format validator.
        let validation = Archive {
            file: staged.as_file().try_clone()?,
            header: header.clone(),
        };
        for group in 0..header.groups {
            let record = validation.read_group(cx, group)?;
            if record.invalid_symbols != 0
                || tables.get(group as usize)
                    != Some(&Self::table_digest(&header, group, &record.hashes)?)
            {
                return Err(corrupt("staged live parity failed readback verification"));
            }
        }
        drop(validation);
        checkpoint(cx)?;
        let old = state.archive.file.metadata()?;
        let named = std::fs::metadata(&self.sidecar_path)?;
        if (old.dev(), old.ino()) != (named.dev(), named.ino()) {
            return Err(corrupt(
                "repair archive path was replaced by another writer",
            ));
        }
        let parent = File::open(parent_path(&self.sidecar_path))?;
        let file = staged
            .persist(&self.sidecar_path)
            .map_err(|error| FfsError::Io(error.error))?;
        // Rename is committed. Finish the directory barrier despite cancellation.
        state.phase = Phase::Poisoned;
        state.archive = Archive { file, header };
        parent.sync_all()?;
        state.changed.clear();
        state.tables = tables;
        state.cached_hashes = None;
        state.phase = Phase::Clean;
        Ok(())
    }

    /// Scrub and repair all groups at a clean durability boundary.
    /// A pending write epoch is never repaired using its preceding parity.
    pub fn scrub(&self, cx: &Cx) -> Result<u64> {
        let state = self.lock(cx)?;
        if !matches!(state.phase, Phase::Clean) {
            return Err(corrupt("sync outstanding writes before a repair scrub"));
        }
        self.check_image_len()?;
        let mut repaired = 0;
        for group in 0..state.archive.header.groups {
            repaired += self.repair_group(cx, &state, group)? as u64;
        }
        checkpoint(cx)?;
        Ok(repaired)
    }

    /// Last committed protection point. An outstanding epoch is reported as an
    /// error instead of presenting the preceding generation as current coverage.
    pub fn protection(&self, cx: &Cx) -> Result<ProtectionInfo> {
        let state = self.lock(cx)?;
        if !matches!(state.phase, Phase::Clean) {
            return Err(corrupt("repair coverage is pending until sync completes"));
        }
        state.archive.header.info()
    }
}

impl ByteDevice for SidecarImageDevice {
    fn len_bytes(&self) -> u64 {
        self.image_bytes
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let end = self.range_end(offset, buf.len())?;
        if buf.is_empty() {
            return Ok(());
        }
        let mut state = self.lock(cx)?;
        self.check_image_len()?;
        let size = u64::from(state.archive.header.options.block_size);
        let mut result = vec![0; buf.len()];
        for block in offset.0 / size..end.div_ceil(size) {
            let bytes = self.verified_block(cx, &mut state, block)?;
            let start = offset.0.max(block * size);
            let stop = end.min((block + 1) * size);
            result[(start - offset.0) as usize..(stop - offset.0) as usize].copy_from_slice(
                &bytes[(start - block * size) as usize..(stop - block * size) as usize],
            );
        }
        checkpoint(cx)?;
        buf.copy_from_slice(&result);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        let end = self.range_end(offset, buf.len())?;
        if buf.is_empty() {
            return Ok(());
        }
        let mut state = self.lock(cx)?;
        self.check_image_len()?;
        let size = u64::from(state.archive.header.options.block_size);
        let mut intended = Vec::new();
        for block in offset.0 / size..end.div_ceil(size) {
            // A partial write must not preserve corrupt bytes outside its range.
            let mut bytes = self.verified_block(cx, &mut state, block)?;
            let start = offset.0.max(block * size);
            let stop = end.min((block + 1) * size);
            bytes[(start - block * size) as usize..(stop - block * size) as usize]
                .copy_from_slice(&buf[(start - offset.0) as usize..(stop - offset.0) as usize]);
            intended.push((block, source_digest(&state.archive.header, block, &bytes)));
        }
        Self::fence(cx, &mut state)?;
        if let Err(error) = self.image.write_all_at(buf, offset.0) {
            state.phase = Phase::Poisoned;
            return Err(error.into());
        }
        state.changed.extend(intended);
        // Even a late cancellation retains the intended hashes for an explicit
        // subsequent sync; dropping still leaves a durably pending archive.
        checkpoint(cx)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        let mut state = self.lock(cx)?;
        if matches!(state.phase, Phase::Clean) {
            self.check_image_len()?;
            self.image.sync_all()?;
            return checkpoint(cx);
        }
        self.refresh(cx, &mut state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar::{SidecarOptions, protect, verify};
    use crate::sidecar_restore::restore;

    struct Fixture {
        _dir: tempfile::TempDir,
        image: PathBuf,
        sidecar: PathBuf,
        original: Vec<u8>,
        /// See `crate::sidecar::TEST_CHILD_PROCESS_GATE`.
        _flocks: Option<std::sync::RwLockReadGuard<'static, ()>>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::build(Some(crate::sidecar::test_flock_holder()))
        }

        /// For a test already holding the gate exclusively.
        fn build(flocks: Option<std::sync::RwLockReadGuard<'static, ()>>) -> Self {
            let dir = tempfile::tempdir().expect("directory");
            let image = dir.path().join("source.img");
            let sidecar = dir.path().join("source.ffs-rq");
            let original: Vec<u8> = (0_usize..16 * 512 + 37)
                .map(|i| ((i * 31 + i / 512) % 251) as u8)
                .collect();
            std::fs::write(&image, &original).expect("source");
            protect(
                &Cx::for_testing(),
                &image,
                &sidecar,
                SidecarOptions {
                    block_size: 512,
                    group_blocks: 8,
                    repair_symbols: 4,
                },
            )
            .expect("initial protection");
            Self {
                _dir: dir,
                image,
                sidecar,
                original,
                _flocks: flocks,
            }
        }

        fn open(&self) -> SidecarImageDevice {
            SidecarImageDevice::open(&Cx::for_testing(), &self.image, &self.sidecar)
                .expect("matching device")
        }

        fn damage(&self, offset: u64, bytes: &[u8]) {
            File::options()
                .write(true)
                .open(&self.image)
                .expect("fault handle")
                .write_all_at(bytes, offset)
                .expect("injected damage");
        }
    }

    #[test]
    fn synced_overwrites_reopen_and_restore_the_new_acknowledged_bytes() {
        let fixture = Fixture::new();
        let cx = Cx::for_testing();
        let mut expected = fixture.original.clone();
        let device = fixture.open();
        device
            .write_all_at(&cx, ByteOffset(500), &[0x93; 90])
            .expect("cross-block write");
        expected[500..590].fill(0x93);
        device
            .write_all_at(&cx, ByteOffset(16 * 512 + 9), &[0x72; 28])
            .expect("partial tail");
        expected[16 * 512 + 9..].fill(0x72);
        assert!(device.protection(&cx).is_err());
        let mut read = [0; 90];
        device
            .read_exact_at(&cx, ByteOffset(500), &mut read)
            .expect("read own write");
        assert_eq!(read, [0x93; 90]);
        device.sync(&cx).expect("source and fresh parity ACK");
        assert_eq!(
            device.protection(&cx).expect("fresh").snapshot_blake3,
            blake3::hash(&expected).to_hex().to_string()
        );
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("latest archive")
                .is_healthy()
        );
        drop(fixture.open());
        fixture.damage(513, &[0xff; 90]);
        let output = fixture.image.with_extension("restored");
        restore(&cx, &fixture.image, &fixture.sidecar, &output).expect("recover latest ACK");
        assert_eq!(std::fs::read(output).expect("restored"), expected);
    }

    #[test]
    fn dropping_unsynced_writes_cannot_resurrect_previous_parity() {
        let fixture = Fixture::new();
        let cx = Cx::for_testing();
        let device = fixture.open();
        device
            .write_all_at(&cx, ByteOffset(20), &[0x91; 20])
            .expect("write");
        drop(device);
        assert!(Archive::open(&cx, &fixture.sidecar).is_err());
        let error = SidecarImageDevice::open(&cx, &fixture.image, &fixture.sidecar)
            .expect_err("pending epoch");
        assert!(error.to_string().contains("unfinished"));
        assert_eq!(
            &std::fs::read(&fixture.image).expect("source")[20..40],
            &[0x91; 20]
        );
        let output = fixture.image.with_extension("not-created");
        assert!(restore(&cx, &fixture.image, &fixture.sidecar, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn process_exit_before_sync_leaves_coverage_pending() {
        const IMAGE: &str = "FFS_LIVE_REPAIR_CRASH_IMAGE";
        const ARCHIVE: &str = "FFS_LIVE_REPAIR_CRASH_ARCHIVE";
        const CUT: &str = "FFS_LIVE_REPAIR_CRASH_CUT";
        if let (Some(image), Some(archive)) = (std::env::var_os(IMAGE), std::env::var_os(ARCHIVE)) {
            let cx = Cx::for_testing();
            let device = SidecarImageDevice::open(&cx, Path::new(&image), Path::new(&archive))
                .expect("child open");
            let cut = std::env::var(CUT).expect("crash cut");
            if cut == "fence" {
                let mut state = device.lock(&cx).expect("state");
                SidecarImageDevice::fence(&cx, &mut state)
                    .expect("durable fence before source write");
            } else {
                device
                    .write_all_at(&cx, ByteOffset(512), &[0x6d; 512])
                    .expect("child write");
                if cut == "sync" {
                    device
                        .sync(&cx)
                        .expect("durable source and fresh protection");
                }
            }
            // No device drop, unmount, destructor or sync may repair this epoch.
            std::process::exit(0);
        }
        // Exclusive while children exist: they inherit sibling tests' flocked
        // descriptors until exec (crate::sidecar::TEST_CHILD_PROCESS_GATE).
        let _no_flock_holders = crate::sidecar::TEST_CHILD_PROCESS_GATE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for cut in ["fence", "write", "sync"] {
            let fixture = Fixture::build(None);
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "sidecar::live::tests::process_exit_before_sync_leaves_coverage_pending",
                ])
                .env(IMAGE, &fixture.image)
                .env(ARCHIVE, &fixture.sidecar)
                .env(CUT, cut)
                .status()
                .expect("child execution");
            assert!(status.success(), "cut={cut}");
            let mut expected = fixture.original.clone();
            if cut != "fence" {
                expected[512..1024].fill(0x6d);
            }
            assert_eq!(std::fs::read(&fixture.image).expect("source"), expected);
            let cx = Cx::for_testing();
            if cut == "sync" {
                assert!(
                    verify(&cx, &fixture.image, &fixture.sidecar)
                        .expect("committed")
                        .is_healthy()
                );
                fixture.damage(512, &[0xff; 512]);
                let output = fixture.image.with_extension("after-crash-restored");
                restore(&cx, &fixture.image, &fixture.sidecar, &output).expect("latest epoch");
                assert_eq!(std::fs::read(output).expect("restored"), expected);
            } else {
                assert!(Archive::open(&cx, &fixture.sidecar).is_err(), "cut={cut}");
            }
        }
    }

    #[test]
    fn invalid_ranges_and_prewrite_cancellation_preserve_both_files() {
        let fixture = Fixture::new();
        let archive = std::fs::read(&fixture.sidecar).expect("archive");
        let device = fixture.open();
        let cx = Cx::for_testing();
        assert!(
            device
                .write_all_at(&cx, ByteOffset(u64::MAX), &[1])
                .is_err()
        );
        assert!(
            device
                .write_all_at(&cx, ByteOffset(device.len_bytes() - 1), &[1; 2])
                .is_err()
        );
        cx.set_cancel_requested(true);
        assert!(matches!(
            device.write_all_at(&cx, ByteOffset(0), &[1]),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(
            std::fs::read(&fixture.image).expect("source"),
            fixture.original
        );
        assert_eq!(std::fs::read(&fixture.sidecar).expect("archive"), archive);
    }

    #[test]
    fn cancelled_sync_retains_intended_hashes_for_explicit_retry() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x41; 100])
            .expect("write");
        cx.set_cancel_requested(true);
        assert!(matches!(device.sync(&cx), Err(FfsError::Cancelled)));
        device
            .sync(&Cx::for_testing())
            .expect("retry explicit sync");
        drop(device);
        assert!(
            verify(&Cx::for_testing(), &fixture.image, &fixture.sidecar)
                .expect("new protection")
                .is_healthy()
        );
    }

    #[test]
    fn refresh_never_blesses_unobserved_corruption_as_new_source_data() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x41; 100])
            .expect("write");
        fixture.damage(7 * 512, &[0x66; 512]);
        assert!(
            device
                .sync(&cx)
                .expect_err("unknown corruption")
                .to_string()
                .contains("bless")
        );
        assert!(device.protection(&cx).is_err());
        drop(device);
        assert!(Archive::open(&cx, &fixture.sidecar).is_err());
        assert_eq!(
            &std::fs::read(&fixture.image).expect("source")[..100],
            &[0x41; 100]
        );
    }

    #[test]
    fn clean_reads_repair_checksum_corruption_before_returning_data() {
        let fixture = Fixture::new();
        let device = fixture.open();
        fixture.damage(512, &[0xab; 512]);
        fixture.damage(5 * 512, &[0xcd; 512]);
        let mut bytes = [0; 200];
        device
            .read_exact_at(&Cx::for_testing(), ByteOffset(520), &mut bytes)
            .expect("self-healed read");
        assert_eq!(&bytes, &fixture.original[520..720]);
        assert_eq!(
            std::fs::read(&fixture.image).expect("both targets repaired"),
            fixture.original
        );
    }

    #[test]
    fn dirty_reads_never_roll_back_a_new_write_using_old_parity() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(512), &[0xaa; 512])
            .expect("new write");
        fixture.damage(512, &[0xbb; 512]);
        let mut buffer = [0x99; 10];
        let error = device
            .read_exact_at(&cx, ByteOffset(512), &mut buffer)
            .expect_err("stale parity");
        assert!(error.to_string().contains("old parity"));
        assert_eq!(buffer, [0x99; 10]);
        assert_eq!(
            &std::fs::read(&fixture.image).expect("not rolled back")[512..1024],
            &[0xbb; 512]
        );
    }

    #[test]
    fn exhausted_redundancy_preserves_source_and_read_destination() {
        let fixture = Fixture::new();
        let device = fixture.open();
        fixture.damage(0, &[0xfe; 5 * 512]);
        let before = std::fs::read(&fixture.image).expect("damaged image");
        let mut buffer = [0x99; 10];
        assert!(
            device
                .read_exact_at(&Cx::for_testing(), ByteOffset(10), &mut buffer)
                .is_err()
        );
        assert_eq!(buffer, [0x99; 10]);
        assert_eq!(std::fs::read(&fixture.image).expect("unchanged"), before);
    }

    #[test]
    fn lifetime_locks_cover_image_aliases_and_replaced_archive_inode() {
        let fixture = Fixture::new();
        let alias = fixture.image.with_extension("alias");
        std::fs::hard_link(&fixture.image, &alias).expect("image hard link");
        let cx = Cx::for_testing();
        let device = fixture.open();
        assert!(SidecarImageDevice::open(&cx, &alias, &fixture.sidecar).is_err());
        device
            .write_all_at(&cx, ByteOffset(0), &[7; 5])
            .expect("write");
        device.sync(&cx).expect("publish replacement inode");
        let other = File::options()
            .read(true)
            .write(true)
            .open(&fixture.sidecar)
            .expect("new inode");
        assert!(other.try_lock().is_err());
        drop(device);
        other.try_lock().expect("released only at device drop");
    }

    #[test]
    fn admission_never_implicitly_rolls_back_external_writes() {
        let fixture = Fixture::new();
        let archive = std::fs::read(&fixture.sidecar).expect("archive");
        fixture.damage(0, &[0x55; 5]);
        let before = std::fs::read(&fixture.image).expect("externally changed");
        assert!(
            SidecarImageDevice::open(&Cx::for_testing(), &fixture.image, &fixture.sidecar).is_err()
        );
        assert_eq!(
            std::fs::read(&fixture.image).expect("not rolled back"),
            before
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("not changed"),
            archive
        );
    }

    fn alternate_generation(fixture: &Fixture) -> (PathBuf, Vec<u8>, u64) {
        let cx = Cx::for_testing();
        // This block is beyond the seed prefix, so the snapshots intentionally
        // have the same seed and geometry. Each transplanted record is valid
        // locally, yet represents a different source generation.
        fixture.damage(10 * 512, &[0x83; 512]);
        let alternate = fixture.sidecar.with_extension("alternate");
        protect(
            &cx,
            &fixture.image,
            &alternate,
            SidecarOptions {
                block_size: 512,
                group_blocks: 8,
                repair_symbols: 4,
            },
        )
        .expect("alternate protection");
        let archive = Archive::open(&cx, &alternate).expect("alternate archive");
        let offset = archive.header.group_offset(1).expect("group offset");
        let end = archive.header.group_offset(2).expect("next group");
        let mut record = vec![0; (end - offset) as usize];
        archive
            .file
            .read_exact_at(&mut record, offset)
            .expect("valid alternate record");
        drop(archive);
        (alternate, record, offset)
    }

    #[test]
    fn admission_binds_group_tables_to_the_whole_image_not_only_local_checksums() {
        let fixture = Fixture::new();
        let (alternate, _, offset) = alternate_generation(&fixture);
        let original = Archive::open(&Cx::for_testing(), &fixture.sidecar).expect("old archive");
        let end = original.header.group_offset(2).expect("next group");
        let mut old_record = vec![0; (end - offset) as usize];
        original
            .file
            .read_exact_at(&mut old_record, offset)
            .expect("old record");
        drop(original);
        File::options()
            .write(true)
            .open(&alternate)
            .expect("archive fault handle")
            .write_all_at(&old_record, offset)
            .expect("transplant old group");
        let before = std::fs::read(&fixture.image).expect("current source");
        let error = SidecarImageDevice::open(&Cx::for_testing(), &fixture.image, &alternate)
            .expect_err("valid header and group checksums do not establish one snapshot");
        assert!(error.to_string().contains("source digest table"));
        assert_eq!(
            std::fs::read(&fixture.image).expect("not rolled back"),
            before
        );
    }

    #[test]
    fn a_transplanted_valid_group_cannot_change_the_admitted_read_generation() {
        let fixture = Fixture::new();
        let (_, alternate_record, offset) = alternate_generation(&fixture);
        std::fs::write(&fixture.image, &fixture.original).expect("restore original source");
        let device = fixture.open();
        // Model storage returning an internally valid record from a different
        // epoch, bypassing the advisory lock only for fault injection.
        File::options()
            .write(true)
            .open(&fixture.sidecar)
            .expect("archive fault handle")
            .write_all_at(&alternate_record, offset)
            .expect("transplant valid group");
        let mut output = [0x99; 64];
        assert!(
            device
                .read_exact_at(&Cx::for_testing(), ByteOffset(10 * 512), &mut output)
                .is_err()
        );
        assert_eq!(output, [0x99; 64]);
        assert_eq!(
            std::fs::read(&fixture.image).expect("unchanged source"),
            fixture.original
        );
    }

    #[test]
    fn repeated_sync_epochs_replace_the_source_table_anchors() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut expected = fixture.original.clone();
        for value in [0x27, 0x58, 0x83] {
            device
                .write_all_at(&cx, ByteOffset(10 * 512), &[value; 512])
                .expect("next write");
            expected[10 * 512..11 * 512].fill(value);
            device.sync(&cx).expect("next source and parity ACK");
            assert_eq!(
                device.protection(&cx).expect("protection").snapshot_blake3,
                blake3::hash(&expected).to_hex().to_string()
            );
        }
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("latest")
                .is_healthy()
        );
        drop(fixture.open());
    }

    #[test]
    fn cancelled_caller_does_not_wait_for_another_operation_lock() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let _held = device.state.lock();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        assert!(matches!(device.sync(&cx), Err(FfsError::Cancelled)));
    }
}
