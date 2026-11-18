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
    Archive, DIGEST_BYTES, GROUP_PREFIX_BYTES, HEADER_BYTES, Header, MemberProtectionBinding,
    MemberRole, MemberSliceGeometry, MemoryGroup, NativeCommitBinding, ProtectedViewIdentity,
    ProtectionInfo, ProvenanceAuth, SET_MANIFEST_PREFIX_BYTES, SET_PENDING_MAGIC, SidecarOptions,
    SidecarReport, StorageSetManifest, StorageSetTopology, TrustPolicy, checkpoint, corrupt,
    digest_parts, hash_image, load_source, parent_path, por_key_id, protect, publish_new,
    source_digest, symbol_digest, tables_root_digest, verify,
};
use crate::codec::{decode_group_with_owned_repair_symbols, encode_group};
use crate::decision::{
    AutomaticRepairVerdict, MandatoryRepairPreconditions, RepairLossCalibration,
    evaluate_automatic_repair_gate,
};
use crate::evidence::{
    EvidenceLedger, EvidenceRecord, ProtectedCommitAckDetail, ProtectedRepairGateDetail,
};
use crate::por::PorKey;
use crate::sidecar_restore::decode_missing_group;
use asupersync::Cx;
use ffs_block::{ByteDevice, VolumeDevice};
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, ByteOffset, GroupNumber};
use parking_lot::{Mutex, MutexGuard};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

const PENDING_MAGIC: &[u8; 8] = b"FFSRQPD2";

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Shared append-only JSONL evidence ledger handle for live/protected repair.
pub type SharedEvidenceLedger = Arc<Mutex<EvidenceLedger<Box<dyn Write + Send>>>>;
pub(crate) type FenceHook = Arc<dyn Fn(&Cx) -> Result<()> + Send + Sync>;

/// Open an append-only JSONL [`SharedEvidenceLedger`] at `path`.
pub fn open_shared_evidence_ledger(path: &Path) -> Result<SharedEvidenceLedger> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let boxed: Box<dyn Write + Send> = Box::new(file);
    Ok(Arc::new(Mutex::new(EvidenceLedger::new(boxed))))
}

/// Compute a 32-byte BLAKE3 digest over `bytes`.
#[must_use]
pub fn blake3_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[derive(Clone, Copy)]
pub(crate) struct ArchiveDigests {
    pub(crate) header_blake3: [u8; 32],
    pub(crate) snapshot_digest: [u8; 32],
    pub(crate) tables_root: [u8; 32],
}

/// Separate native-commit vs protected-parity durability acknowledgment status (`bd-tqrnc`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtectionAckStatus {
    pub epoch_generation: u64,
    pub native_durable: bool,
    pub protected_durable: bool,
    pub authenticated_provenance: bool,
    pub fenced_at_ns: Option<u64>,
    pub native_durable_at_ns: Option<u64>,
    pub protected_durable_at_ns: Option<u64>,
    /// Elapsed nanoseconds during which native state was mutated or committed without sealed parity.
    pub unprotected_interval_ns: u64,
    pub native_token_summary: Option<String>,
    pub post_commit_error: Option<String>,
}

/// Options controlling live sidecar open, two-stage repair authorization, provenance, and audit logging.
#[derive(Clone)]
pub struct SidecarLiveOptions {
    pub read_only: bool,
    pub allow_automatic_repair: bool,
    pub member_index: u32,
    pub set_id_hex: Option<String>,
    pub initial_generation: u64,
    pub authenticated_provenance: bool,
    pub require_trusted_root: bool,
    pub calibration: Option<RepairLossCalibration>,
    pub evidence_ledger: Option<SharedEvidenceLedger>,
    pub(crate) external_fence_hook: Option<FenceHook>,
}

impl std::fmt::Debug for SidecarLiveOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarLiveOptions")
            .field("read_only", &self.read_only)
            .field("allow_automatic_repair", &self.allow_automatic_repair)
            .field("member_index", &self.member_index)
            .field("initial_generation", &self.initial_generation)
            .field("authenticated_provenance", &self.authenticated_provenance)
            .field("require_trusted_root", &self.require_trusted_root)
            .field("has_calibration", &self.calibration.is_some())
            .field("has_evidence_ledger", &self.evidence_ledger.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for SidecarLiveOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            allow_automatic_repair: true,
            member_index: 0,
            set_id_hex: None,
            initial_generation: 1,
            authenticated_provenance: false,
            require_trusted_root: false,
            calibration: Some(RepairLossCalibration::default_operator_exclusive()),
            evidence_ledger: None,
            external_fence_hook: None,
        }
    }
}

enum Phase {
    Clean,
    Dirty,
    Poisoned,
}

struct State {
    archive: Archive,
    phase: Phase,
    /// Allocation identity changes on every successful archive publication.
    /// Cursors keep only this token alive, never an image/archive descriptor.
    protection_epoch: Arc<()>,
    /// Digests of intended complete blocks, including partial-write preservation.
    /// Unchanged blocks retain the checksums in the previous archive.
    changed: BTreeMap<u64, [u8; 32]>,
    /// One hash per source-digest table, attested against the admitted image.
    /// This prevents a valid table from another snapshot from authorizing a
    /// rollback merely because its own local checksum is internally consistent.
    tables: Vec<[u8; 32]>,
    /// A single group's metadata cache bounds the read-side working set.
    cached_hashes: Option<(u32, Vec<[u8; 32]>)>,
    /// Nesting depth of active multi-barrier native commits (`defer_seal_depth > 0`
    /// flushes physical `self.image` on `sync()` without prematurely sealing parity).
    defer_seal_depth: u32,
    /// Tracks whether any source write escaped during the current deferred commit.
    writes_during_defer: bool,
    epoch_generation: u64,
    native_durable: bool,
    fenced_at_ns: Option<u64>,
    native_durable_at_ns: Option<u64>,
    protected_durable_at_ns: Option<u64>,
    last_unprotected_interval_ns: u64,
    native_token_summary: Option<String>,
    post_commit_error: Option<String>,
}

struct GroupRepair {
    recovered_blocks: u64,
    invalid_symbols: u64,
    /// Verified reconstruction for a strictly read-only device. Never retained
    /// beyond this read, written back, or used as a new protection generation.
    in_memory: BTreeMap<u64, Vec<u8>>,
}

/// Progress for an opportunistic, group-at-a-time protection scrub.
///
/// Create with `Default`. A cursor resumes only on the same device and archive
/// publication; any intervening successful refresh restarts it at group zero,
/// even when the new snapshot has identical bytes. It retains no file locks.
#[derive(Debug, Default)]
pub struct ProtectionScrubCursor {
    epoch: Option<Arc<()>>,
    next_group: u32,
    rebuild_archive: bool,
    report: ProtectionScrubReport,
}

/// Observations from successfully completed group steps in one protection epoch.
/// This is not a point-in-time filesystem snapshot or a lifetime repair counter.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionScrubReport {
    /// Groups whose source tables, source bytes and repair symbols were checked.
    pub groups_verified: u32,
    /// Real source bytes checked; virtual padding in a short tail is excluded.
    pub source_bytes_verified: u64,
    /// Source blocks recovered by successful group steps in this pass.
    /// Repairs from an interrupted/restarted pass or the final refresh are excluded.
    pub source_blocks_recovered: u64,
    /// Invalid repair symbols observed during those group steps.
    pub invalid_repair_symbols: u64,
    /// A replacement archive was verified, published and directory-synced.
    pub archive_rebuilt: bool,
}

/// One non-waiting admission attempt for a protection scrub step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionScrubStep {
    /// Another operation holds the device serializer. No I/O or progress change.
    Busy,
    /// Caller writes await an explicit sync. No I/O or progress change.
    PendingWrites,
    /// One group completed. The serializer is released before returning.
    GroupVerified { group: u32 },
    /// The entire pass completed, including any required archive replacement.
    /// The cursor is reset and can be reused for the next pass.
    Complete(ProtectionScrubReport),
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
/// before read data is returned, including complete group loss when the surviving
/// parity equations have sufficient rank. During a dirty epoch, recovery remains
/// available for groups whose intended source digests still match the admitted
/// protection point. A changed digest anywhere in a group forbids using that
/// group's old parity, even to recover an unchanged block. Opening a mismatched image
/// still requires explicit offline reconciliation rather than implicit rollback.
///
/// Partial writes verify the bytes they preserve. Complete replacement of a
/// block's real bytes does not need the discarded contents to be recoverable;
/// the caller's replacement is tracked as a new write, never as a parity repair.
///
/// This initial implementation scans the image at each dirty sync, and re-encodes
/// only changed groups or groups with damaged parity. It favors correctness over
/// low fsync latency; it is not the default filesystem mount path. Working memory
/// includes one digest per admitted group, one per changed block, and bounded
/// group buffers; the read-side metadata cache holds only one group at a time.
///
/// [`Self::open_read_only`] instead opens both files without write capability.
/// Reads can reconstruct the admitted generation in memory, but never write
/// repairs, invalidate protection, rebuild archives, or synchronize backing
/// files. A pre-existing image/snapshot mismatch remains an admission error.
pub struct SidecarImageDevice {
    image: File,
    sidecar_path: PathBuf,
    image_bytes: u64,
    protection_groups: u32,
    read_only: bool,
    options: SidecarLiveOptions,
    state: Mutex<State>,
}

impl std::fmt::Debug for SidecarImageDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarImageDevice")
            .field("image_bytes", &self.image_bytes)
            .field("sidecar_path", &self.sidecar_path)
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

impl SidecarImageDevice {
    /// Open an exclusively owned image and its matching, existing sidecar.
    /// Neither file is changed on admission failure. The archive path is
    /// canonicalized once; future syncs replace that archive with a new snapshot.
    pub fn open(cx: &Cx, image_path: &Path, sidecar_path: &Path) -> Result<Self> {
        Self::open_with_options(cx, image_path, sidecar_path, SidecarLiveOptions::default())
    }

    /// Open an immutable image and its existing protection without write access.
    /// Shared inode locks permit other cooperating read-only owners and exclude
    /// cooperating writers. Offline ownership is still the caller's obligation.
    /// Admission uses the same whole-image and source-table generation checks
    /// as the writable device; this is not implicit recovery of a stale image.
    /// Later recoverable corruption is reconstructed only in memory. Neither
    /// file needs write permission, and no scratch archive is created.
    pub fn open_read_only(cx: &Cx, image_path: &Path, sidecar_path: &Path) -> Result<Self> {
        Self::open_with_options(
            cx,
            image_path,
            sidecar_path,
            SidecarLiveOptions {
                read_only: true,
                allow_automatic_repair: false,
                ..SidecarLiveOptions::default()
            },
        )
    }

    /// Open with explicit two-stage calibration, provenance, and audit-ledger options.
    pub fn open_with_options(
        cx: &Cx,
        image_path: &Path,
        sidecar_path: &Path,
        options: SidecarLiveOptions,
    ) -> Result<Self> {
        let read_only = options.read_only;
        checkpoint(cx)?;
        if options.require_trusted_root && !options.authenticated_provenance {
            return Err(corrupt(
                "trusted-root provenance required; standalone unkeyed sidecar is not authenticated",
            ));
        }
        let image = File::options()
            .read(true)
            .write(!read_only)
            .open(image_path)?;
        let image_meta = image.metadata()?;
        if !image_meta.is_file() {
            return Err(corrupt("live repair requires a regular image file"));
        }
        if read_only {
            image.try_lock_shared().map_err(io::Error::from)?;
        } else {
            image.try_lock().map_err(io::Error::from)?;
        }
        let sidecar_path = sidecar_path.canonicalize()?;
        let file = File::options()
            .read(true)
            .write(!read_only)
            .open(&sidecar_path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || (metadata.dev(), metadata.ino()) == (image_meta.dev(), image_meta.ino())
        {
            return Err(corrupt(
                "image and repair archive must be distinct regular files",
            ));
        }
        if read_only {
            file.try_lock_shared().map_err(io::Error::from)?;
        } else {
            file.try_lock().map_err(io::Error::from)?;
        }
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
        let initial_gen = options.initial_generation.max(1);
        let init_ts = now_unix_ns();
        Ok(Self {
            image,
            sidecar_path,
            image_bytes: archive.header.image_bytes,
            protection_groups: archive.header.groups,
            read_only,
            options,
            state: Mutex::new(State {
                archive,
                phase: Phase::Clean,
                protection_epoch: Arc::new(()),
                changed: BTreeMap::new(),
                tables,
                cached_hashes: None,
                defer_seal_depth: 0,
                writes_during_defer: false,
                epoch_generation: initial_gen,
                native_durable: true,
                fenced_at_ns: None,
                native_durable_at_ns: Some(init_ts),
                protected_durable_at_ns: Some(init_ts),
                last_unprotected_interval_ns: 0,
                native_token_summary: None,
                post_commit_error: None,
            }),
        })
    }

    fn require_writeback(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        if self.read_only {
            return Err(FfsError::ReadOnly);
        }
        Ok(())
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
            _ => {
                let group = (block / u64::from(state.archive.header.options.group_blocks)) as u32;
                let mut outcome = self.repair_group(cx, state, group)?;
                let bytes = match outcome.in_memory.remove(&block) {
                    Some(bytes) => bytes,
                    None => self.read_source_block(&state.archive.header, block)?,
                };
                if source_digest(&state.archive.header, block, &bytes) != expected {
                    return Err(corrupt(
                        "live repair readback did not match the expected source",
                    ));
                }
                Ok(bytes)
            }
        }
    }

    fn repair_group(&self, cx: &Cx, state: &State, group: u32) -> Result<GroupRepair> {
        let header = &state.archive.header;
        let record = state.archive.read_group(cx, group)?;
        Self::check_table(state, group, &record.hashes)?;
        let (first, count) = header.group_geometry(group)?;
        // Parity covers the entire group, not only the requested block. Check
        // every intended digest before decoding or touching any repair target.
        // Writes in other groups cannot invalidate these equations. Rewriting
        // a block back to its admitted bytes also makes its old parity current.
        // Keep this check in the shared repair entry point so no caller can
        // accidentally restore a changed peer while repairing an unchanged one.
        if state
            .changed
            .range(first..first + u64::from(count))
            .any(|(&block, expected)| record.hashes[(block - first) as usize] != *expected)
        {
            let mut pre = MandatoryRepairPreconditions::all_passed();
            pre.native_generation_fresh = false;
            pre.group_peer_digests_unchanged = false;
            let _ = self.record_repair_gate_verdict(state, group, 1, pre);
            return Err(corrupt(
                "source corruption during a dirty epoch; old parity is not current for this group; \
                 refusing to bless corruption",
            ));
        }
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
            return Ok(GroupRepair {
                recovered_blocks: 0,
                invalid_symbols: record.invalid_symbols,
                in_memory: BTreeMap::new(),
            });
        }
        let source = MemoryGroup {
            first,
            block_size: header.options.block_size,
            blocks,
        };
        let recovered_blocks = if damaged.len() == count as usize {
            // The archived digest table is already bound to this admitted
            // generation. Complete group loss, including a one-block tail,
            // can therefore use parity alone without trusting damaged source.
            decode_missing_group(cx, header, group, &source, record.symbols)?
        } else {
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
            if !decoded.complete {
                return Err(corrupt(
                    "live repair could not reconstruct every damaged block",
                ));
            }
            decoded.recovered
        };
        checkpoint(cx)?;
        let mut seen = BTreeSet::new();
        if recovered_blocks.len() != damaged.len() {
            return Err(corrupt(
                "live repair could not reconstruct every damaged block",
            ));
        }
        // Validate EVERY result and compare EVERY target before the first write.
        for recovered in &recovered_blocks {
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
        if self.read_only {
            checkpoint(cx)?;
            return Ok(GroupRepair {
                recovered_blocks: damaged.len() as u64,
                invalid_symbols: record.invalid_symbols,
                in_memory: recovered_blocks
                    .into_iter()
                    .map(|recovered| (recovered.block.0, recovered.data))
                    .collect(),
            });
        }
        let preconditions = MandatoryRepairPreconditions {
            exclusive_ownership: !self.read_only && self.options.allow_automatic_repair,
            storage_set_identity_match: true,
            native_generation_fresh: true,
            group_peer_digests_unchanged: true,
            symbol_and_decoded_digests_valid: true,
            trusted_root_authenticated: !self.options.require_trusted_root
                || self.options.authenticated_provenance,
            target_prewrite_unchanged: true,
        };
        let verdict =
            self.record_repair_gate_verdict(state, group, damaged.len() as u32, preconditions)?;
        if let AutomaticRepairVerdict::Refuse { reason, .. } = verdict {
            return Err(corrupt(&format!(
                "automatic repair writeback refused by gate: {reason:?}"
            )));
        }
        for recovered in &recovered_blocks {
            checkpoint(cx)?;
            self.image.write_all_at(
                &recovered.data[..header.real_block_len(recovered.block.0)],
                recovered.block.0 * u64::from(header.options.block_size),
            )?;
        }
        self.image.sync_all()?;
        for recovered in &recovered_blocks {
            checkpoint(cx)?;
            if self.read_source_block(header, recovered.block.0)? != recovered.data {
                return Err(corrupt("live repair failed post-write readback"));
            }
        }
        Ok(GroupRepair {
            recovered_blocks: damaged.len() as u64,
            invalid_symbols: record.invalid_symbols,
            in_memory: BTreeMap::new(),
        })
    }

    fn set_id_label(&self, state: &State) -> String {
        self.options.set_id_hex.clone().unwrap_or_else(|| {
            blake3::Hash::from_bytes(state.archive.header.snapshot_digest)
                .to_hex()
                .to_string()
        })
    }

    fn record_repair_gate_verdict(
        &self,
        state: &State,
        group: u32,
        damaged_blocks: u32,
        preconditions: MandatoryRepairPreconditions,
    ) -> Result<AutomaticRepairVerdict> {
        let verdict =
            evaluate_automatic_repair_gate(&preconditions, self.options.calibration.as_ref());
        if let Some(ledger_arc) = &self.options.evidence_ledger {
            let detail = match &verdict {
                AutomaticRepairVerdict::Authorize {
                    expected_repair_loss,
                    refusal_loss,
                    calibration,
                } => ProtectedRepairGateDetail {
                    set_id_hex: self.set_id_label(state),
                    member_index: self.options.member_index,
                    generation: state.epoch_generation,
                    authenticated_provenance: self.options.authenticated_provenance,
                    damaged_blocks,
                    authorized: true,
                    expected_repair_loss: Some(*expected_repair_loss),
                    refusal_loss: Some(*refusal_loss),
                    calibration_provenance: Some(calibration.provenance.clone()),
                    refusal_reason: None,
                },
                AutomaticRepairVerdict::Refuse {
                    reason,
                    expected_repair_loss,
                    refusal_loss,
                    calibration_provenance,
                } => ProtectedRepairGateDetail {
                    set_id_hex: self.set_id_label(state),
                    member_index: self.options.member_index,
                    generation: state.epoch_generation,
                    authenticated_provenance: self.options.authenticated_provenance,
                    damaged_blocks,
                    authorized: false,
                    expected_repair_loss: *expected_repair_loss,
                    refusal_loss: *refusal_loss,
                    calibration_provenance: calibration_provenance.clone(),
                    refusal_reason: Some(format!("{reason:?}")),
                },
            };
            let record = EvidenceRecord::protected_repair_gate(group, detail);
            ledger_arc.lock().append(&record)?;
        }
        Ok(verdict)
    }

    fn emit_commit_ack_evidence(&self, state: &State) {
        if let Some(ledger_arc) = &self.options.evidence_ledger {
            let detail = ProtectedCommitAckDetail {
                set_id_hex: self.set_id_label(state),
                generation: state.epoch_generation,
                native_durable: state.native_durable,
                protected_durable: matches!(state.phase, Phase::Clean),
                unprotected_interval_ns: Self::current_unprotected_interval_ns(state),
                native_token_summary: state.native_token_summary.clone(),
                post_commit_error: state.post_commit_error.clone(),
            };
            let _ = ledger_arc
                .lock()
                .append(&EvidenceRecord::protected_commit_ack(detail));
        }
    }

    fn current_unprotected_interval_ns(state: &State) -> u64 {
        if matches!(state.phase, Phase::Clean) {
            state.last_unprotected_interval_ns
        } else if let Some(fenced_at) = state.fenced_at_ns {
            now_unix_ns().saturating_sub(fenced_at)
        } else {
            state.last_unprotected_interval_ns
        }
    }

    fn fence(&self, cx: &Cx, state: &mut State) -> Result<()> {
        if let Some(hook) = &self.options.external_fence_hook {
            hook(cx)?;
        }
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
        state.fenced_at_ns = Some(now_unix_ns());
        state.native_durable = false;
        state.native_durable_at_ns = None;
        state.protected_durable_at_ns = None;
        state.post_commit_error = None;
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

    /// Read one refresh group against the caller's intended generation. Only
    /// checksum failures and media errors can request recovery; cancellation,
    /// authorization failures and metadata errors never become erasures.
    fn load_refresh_group(
        &self,
        cx: &Cx,
        state: &State,
        group: u32,
        admitted: &[[u8; 32]],
    ) -> Result<(MemoryGroup, Vec<[u8; 32]>)> {
        let header = &state.archive.header;
        let load = || {
            checkpoint(cx)?;
            let (source, _) = match load_source(cx, &self.image, header, group, false) {
                Ok(source) => source,
                Err(error) if Self::media_error(&error) => return Ok(None),
                Err(error) => return Err(error),
            };
            let mut hashes = Vec::with_capacity(source.blocks.len());
            for (relative, bytes) in source.blocks.iter().enumerate() {
                checkpoint(cx)?;
                let block = source.first + relative as u64;
                let expected = state.changed.get(&block).unwrap_or(&admitted[relative]);
                let actual = source_digest(header, block, bytes);
                if actual != *expected {
                    return Ok(None);
                }
                hashes.push(actual);
            }
            Ok(Some((source, hashes)))
        };
        if let Some(verified) = load()? {
            return Ok(verified);
        }
        // This common entry point freshly checks the attested source table AND
        // every intended digest in the group before decoding. A changed peer
        // forbids old parity, even when the damaged target itself is unchanged.
        // Reconstructed bytes are synced and read back without publishing or
        // clearing this epoch. Never retry indefinitely on an unstable source.
        self.repair_group(cx, state, group)?;
        load()?.ok_or_else(|| {
            corrupt("source changed outside the write epoch; refusing to bless corruption")
        })
    }

    fn refresh(&self, cx: &Cx, state: &mut State) -> Result<()> {
        // Guard the common publication seam as well as public entry points:
        // a future maintenance caller must not give read-only I/O write power.
        self.require_writeback(cx)?;
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
            let (source, hashes) = self.load_refresh_group(cx, state, group, &record.hashes)?;
            for (relative, bytes) in source.blocks.iter().enumerate() {
                checkpoint(cx)?;
                let block = source.first + relative as u64;
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
        let sealed_ts = now_unix_ns();
        if let Some(fenced_at) = state.fenced_at_ns {
            state.last_unprotected_interval_ns = sealed_ts.saturating_sub(fenced_at);
        }
        state.fenced_at_ns = None;
        state.native_durable = true;
        if state.native_durable_at_ns.is_none() {
            state.native_durable_at_ns = Some(sealed_ts);
        }
        state.protected_durable_at_ns = Some(sealed_ts);
        state.post_commit_error = None;
        state.epoch_generation = state.epoch_generation.saturating_add(1);
        state.changed.clear();
        state.tables = tables;
        state.cached_hashes = None;
        state.protection_epoch = Arc::new(());
        state.phase = Phase::Clean;
        self.emit_commit_ack_evidence(state);
        Ok(())
    }

    /// Scrub source data and restore damaged protection at a clean boundary.
    /// Returns the number of recovered source blocks, not regenerated symbols.
    /// Damaged parity and header bytes are replaced atomically only after all
    /// source groups verify against the admitted generation. A pending write
    /// epoch is never repaired using its preceding parity.
    pub fn scrub(&self, cx: &Cx) -> Result<u64> {
        self.require_writeback(cx)?;
        let mut state = self.lock(cx)?;
        if !matches!(state.phase, Phase::Clean) {
            return Err(corrupt("sync outstanding writes before a repair scrub"));
        }
        self.check_image_len()?;
        let mut stored_header = [0; HEADER_BYTES];
        state.archive.file.read_exact_at(&mut stored_header, 0)?;
        let mut rebuild_archive = stored_header != state.archive.header.encode();
        let mut repaired = 0;
        for group in 0..state.archive.header.groups {
            let outcome = self.repair_group(cx, &state, group)?;
            repaired += outcome.recovered_blocks;
            rebuild_archive |= outcome.invalid_symbols != 0;
        }
        if rebuild_archive {
            // No source generation changes here: refresh rechecks all expected
            // digests, verifies the staged archive, and retains inode exclusion
            // across rename and its directory durability barrier.
            self.refresh(cx, &mut state)?;
        }
        checkpoint(cx)?;
        Ok(repaired)
    }

    /// Check one source/parity group without waiting for foreground ownership.
    ///
    /// Busy and dirty devices defer without changing bytes or cursor progress.
    /// Poisoning, I/O errors, corruption and cancellation remain errors. Clean
    /// admission, epoch comparison and the entire step share the source-write
    /// serializer, so a writer cannot race a separate cleanliness check.
    ///
    /// After all groups verify, a separate final step replenishes damaged parity
    /// or header bytes through the existing verified atomic replacement path.
    /// That exceptional step rescans the entire image under the serializer and
    /// can block foreground I/O; only ordinary scan steps are group-bounded.
    /// No step calls `sync` to finish a caller's outstanding write epoch.
    ///
    /// Source repairs from successful earlier steps may remain after a later
    /// failure. Each step revalidates the admitted source table before repair;
    /// the cursor is scheduling state, never authority to skip verification.
    pub fn scrub_step(
        &self,
        cx: &Cx,
        cursor: &mut ProtectionScrubCursor,
    ) -> Result<ProtectionScrubStep> {
        self.require_writeback(cx)?;
        let Some(mut state) = self.state.try_lock() else {
            checkpoint(cx)?;
            return Ok(ProtectionScrubStep::Busy);
        };
        checkpoint(cx)?;
        match state.phase {
            Phase::Dirty => return Ok(ProtectionScrubStep::PendingWrites),
            Phase::Poisoned => {
                return Err(corrupt(
                    "live repair device is poisoned after an I/O failure",
                ));
            }
            Phase::Clean => {}
        }
        self.check_image_len()?;
        if !cursor
            .epoch
            .as_ref()
            .is_some_and(|epoch| Arc::ptr_eq(epoch, &state.protection_epoch))
        {
            *cursor = ProtectionScrubCursor {
                epoch: Some(Arc::clone(&state.protection_epoch)),
                ..ProtectionScrubCursor::default()
            };
        }
        let header = &state.archive.header;
        if cursor.next_group < header.groups {
            let group = cursor.next_group;
            let (first, count) = header.group_geometry(group)?;
            let first_byte = first
                .checked_mul(u64::from(header.options.block_size))
                .ok_or_else(|| corrupt("protection scrub source offset overflow"))?;
            let bytes = self
                .image_bytes
                .checked_sub(first_byte)
                .ok_or_else(|| corrupt("protection scrub group exceeds image"))?
                .min(u64::from(count) * u64::from(header.options.block_size));
            let outcome = self.repair_group(cx, &state, group)?;
            checkpoint(cx)?;
            cursor.rebuild_archive |= outcome.invalid_symbols != 0;
            cursor.report.groups_verified += 1;
            cursor.report.source_bytes_verified += bytes;
            cursor.report.source_blocks_recovered += outcome.recovered_blocks;
            cursor.report.invalid_repair_symbols += outcome.invalid_symbols;
            cursor.next_group += 1;
            return Ok(ProtectionScrubStep::GroupVerified { group });
        }
        // Re-read the header at completion, including damage that occurred
        // after the final group. Never restore a pending header: Phase::Dirty
        // was excluded while holding the very lock that protects the fence.
        let mut stored_header = [0; HEADER_BYTES];
        state.archive.file.read_exact_at(&mut stored_header, 0)?;
        if cursor.rebuild_archive || stored_header != state.archive.header.encode() {
            self.refresh(cx, &mut state)?;
            cursor.report.archive_rebuilt = true;
        }
        checkpoint(cx)?;
        let report = cursor.report;
        *cursor = ProtectionScrubCursor::default();
        Ok(ProtectionScrubStep::Complete(report))
    }

    /// Number of protection groups in this fixed-size admitted image.
    ///
    /// This immutable geometry is available even during a pending write epoch,
    /// without waiting for the device serializer. It bounds maintenance work;
    /// it does not attest to the freshness or validity of any repair symbol.
    #[must_use]
    pub const fn protection_group_count(&self) -> u32 {
        self.protection_groups
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

    /// Explicitly durably invalidate coverage (`PENDING_MAGIC` + `sync_all()`) before
    /// an in-memory MVCC/CoW mutation makes new filesystem state visible.
    pub fn fence_before_mutation(&self, cx: &Cx) -> Result<()> {
        self.require_writeback(cx)?;
        let mut state = self.lock(cx)?;
        self.check_image_len()?;
        self.fence(cx, &mut state)
    }

    /// Record a committed native format token (`native_durable = true`) while
    /// external parity may still be awaiting its seal barrier.
    pub fn record_native_commit(&self, token: &NativeCommitBinding) {
        let mut state = self.state.lock();
        state.native_durable = true;
        let now = now_unix_ns();
        state.native_durable_at_ns = Some(now);
        if let Some(fenced_at) = state.fenced_at_ns {
            state.last_unprotected_interval_ns = now.saturating_sub(fenced_at);
        }
        state.native_token_summary = Some(token.summary());
        if !matches!(state.phase, Phase::Clean) {
            self.emit_commit_ack_evidence(&state);
        }
    }

    /// Inspect separate `native_durable` vs `protected_durable` status, unprotected
    /// interval, and any post-commit seal/cancellation error (`bd-tqrnc`).
    #[must_use]
    pub fn ack_status(&self) -> ProtectionAckStatus {
        let state = self.state.lock();
        let protected_durable = matches!(state.phase, Phase::Clean);
        ProtectionAckStatus {
            epoch_generation: state.epoch_generation,
            native_durable: state.native_durable,
            protected_durable,
            authenticated_provenance: self.options.authenticated_provenance,
            fenced_at_ns: state.fenced_at_ns,
            native_durable_at_ns: state.native_durable_at_ns,
            protected_durable_at_ns: state.protected_durable_at_ns,
            unprotected_interval_ns: Self::current_unprotected_interval_ns(&state),
            native_token_summary: state.native_token_summary.clone(),
            post_commit_error: state.post_commit_error.clone(),
        }
    }

    pub(crate) fn clean_binding_digests(
        &self,
        cx: &Cx,
    ) -> Result<(MemberSliceGeometry, ArchiveDigests)> {
        let state = self.lock(cx)?;
        if !matches!(state.phase, Phase::Clean) {
            return Err(corrupt(
                "cannot extract sealed member binding during an unsealed write epoch",
            ));
        }
        let encoded_hdr = state.archive.header.encode();
        let header_blake3 = *blake3::hash(&encoded_hdr).as_bytes();
        let snapshot_digest = state.archive.header.snapshot_digest;
        let tables_root = tables_root_digest(&state.tables);
        let geo = MemberSliceGeometry {
            backing_bytes: self.image_bytes,
            offset: 0,
            length: self.image_bytes,
            block_size: state.archive.header.options.block_size,
            group_blocks: state.archive.header.options.group_blocks,
            repair_symbols: state.archive.header.options.repair_symbols,
            groups: state.archive.header.groups,
        };
        Ok((
            geo,
            ArchiveDigests {
                header_blake3,
                snapshot_digest,
                tables_root,
            },
        ))
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
        self.require_writeback(cx)?;
        let end = self.range_end(offset, buf.len())?;
        if buf.is_empty() {
            return Ok(());
        }
        let mut state = self.lock(cx)?;
        self.check_image_len()?;
        let size = u64::from(state.archive.header.options.block_size);
        let mut intended = Vec::new();
        for block in offset.0 / size..end.div_ceil(size) {
            checkpoint(cx)?;
            let block_start = block * size;
            let real_len = state.archive.header.real_block_len(block);
            let start = offset.0.max(block_start);
            let stop = end.min(block_start + real_len as u64);
            let mut bytes = if start == block_start && stop - start == real_len as u64 {
                // Every real byte comes from the caller. Do not require old
                // data that will be discarded to be readable or recoverable.
                // A short final block still hashes with zero virtual padding.
                vec![0; size as usize]
            } else {
                // A partial write must not preserve corrupt bytes outside its range.
                self.verified_block(cx, &mut state, block)?
            };
            bytes[(start - block_start) as usize..(stop - block_start) as usize]
                .copy_from_slice(&buf[(start - offset.0) as usize..(stop - offset.0) as usize]);
            intended.push((block, source_digest(&state.archive.header, block, &bytes)));
        }
        self.fence(cx, &mut state)?;
        if let Err(error) = self.image.write_all_at(buf, offset.0) {
            state.phase = Phase::Poisoned;
            return Err(error.into());
        }
        if state.defer_seal_depth > 0 {
            state.writes_during_defer = true;
        }
        state.native_durable = false;
        state.changed.extend(intended);
        // Even a late cancellation retains the intended hashes for an explicit
        // subsequent sync; dropping still leaves a durably pending archive.
        checkpoint(cx)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        let mut state = self.lock(cx)?;
        if self.read_only {
            if !matches!(state.phase, Phase::Clean) {
                return Err(corrupt(
                    "read-only protection has an unexpected write epoch",
                ));
            }
            self.check_image_len()?;
            return checkpoint(cx);
        }
        if state.defer_seal_depth > 0 {
            // Intermediate barrier inside a multi-sync native transaction:
            // flush physical backing storage ONLY, keeping `PENDING_MAGIC` on disk
            // so intermediate dirty format states are never sealed into parity!
            self.check_image_len()?;
            self.image.sync_all()?;
            return checkpoint(cx);
        }
        if matches!(state.phase, Phase::Clean) {
            self.check_image_len()?;
            self.image.sync_all()?;
            return checkpoint(cx);
        }
        let result = self.refresh(cx, &mut state);
        if let Err(ref err) = result {
            let now = now_unix_ns();
            if let Some(fenced_at) = state.fenced_at_ns {
                state.last_unprotected_interval_ns = now.saturating_sub(fenced_at);
            }
            state.post_commit_error = Some(err.to_string());
            self.emit_commit_ack_evidence(&state);
        }
        result
    }

    fn begin_durability_commit(&self, cx: &Cx) -> Result<()> {
        self.require_writeback(cx)?;
        let mut state = self.lock(cx)?;
        if state.defer_seal_depth == 0 {
            state.writes_during_defer = false;
        }
        state.defer_seal_depth = state
            .defer_seal_depth
            .checked_add(1)
            .ok_or_else(|| corrupt("sidecar durability commit nesting overflow"))?;
        Ok(())
    }

    fn complete_durability_commit(&self) {
        let mut state = self.state.lock();
        state.defer_seal_depth = state.defer_seal_depth.saturating_sub(1);
        if state.defer_seal_depth == 0 {
            state.writes_during_defer = false;
            if matches!(state.phase, Phase::Dirty) {
                let now = now_unix_ns();
                state.native_durable = true;
                state.native_durable_at_ns = Some(now);
                if let Some(fenced_at) = state.fenced_at_ns {
                    state.last_unprotected_interval_ns = now.saturating_sub(fenced_at);
                }
                self.emit_commit_ack_evidence(&state);
            }
        }
    }

    fn abort_durability_commit(&self) {
        let mut state = self.state.lock();
        state.defer_seal_depth = state.defer_seal_depth.saturating_sub(1);
        if state.defer_seal_depth == 0 && state.writes_during_defer {
            // Physical source writes escaped before the native transaction
            // committed; poison the live handle so uncommitted bytes can NEVER
            // be sealed into a sidecar generation!
            state.writes_during_defer = false;
            state.native_durable = false;
            state.phase = Phase::Poisoned;
        }
    }
}

// ── Whole-Storage-Set Coordinator (`ProtectedStorageSet`, `bd-tqrnc`) ────────

/// Specification of one required member (`Data`, `Log`, or `Special`) when
/// creating or admitting a protected storage set.
#[derive(Debug, Clone)]
pub struct StorageSetMemberSpec {
    pub role: MemberRole,
    pub image_path: PathBuf,
    pub sidecar_path: PathBuf,
    pub native_member_id: [u8; 16],
    pub offset: u64,
    pub length: Option<u64>,
}

/// Request to create fresh per-member sidecars (when not already present) and
/// seal a whole-storage-set [`StorageSetManifest`] (`FFSRQSM3`).
#[derive(Debug, Clone)]
pub struct StorageSetProtectRequest {
    pub manifest_path: PathBuf,
    pub filesystem: String,
    pub topology: StorageSetTopology,
    pub view: ProtectedViewIdentity,
    pub native_binding: NativeCommitBinding,
    pub members: Vec<StorageSetMemberSpec>,
    pub options: SidecarOptions,
    pub signing_key: Option<PorKey>,
}

/// Verification report across an entire [`StorageSetManifest`] and its members.
#[derive(Debug, Clone)]
pub struct StorageSetVerifyReport {
    pub manifest: StorageSetManifest,
    pub member_reports: Vec<SidecarReport>,
    pub matches_all_members: bool,
}

impl StorageSetVerifyReport {
    /// True iff the manifest, every member snapshot, and every repair symbol match.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.matches_all_members && self.member_reports.iter().all(SidecarReport::is_healthy)
    }
}

fn archive_file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|os| os.to_str())
        .map(str::to_owned)
        .ok_or_else(|| corrupt("sidecar path must have a valid UTF-8 filename"))
}

fn read_archive_binding_digests(cx: &Cx, sidecar_path: &Path) -> Result<(Header, ArchiveDigests)> {
    let archive = Archive::open(cx, sidecar_path)?;
    let encoded_hdr = archive.header.encode();
    let header_blake3 = *blake3::hash(&encoded_hdr).as_bytes();
    let snapshot_digest = archive.header.snapshot_digest;
    let mut tables = Vec::with_capacity(archive.header.groups as usize);
    for group in 0..archive.header.groups {
        let record = archive.read_group(cx, group)?;
        if record.invalid_symbols != 0 {
            return Err(corrupt(
                "member sidecar has invalid repair symbols; cannot bind storage set",
            ));
        }
        tables.push(SidecarImageDevice::table_digest(
            &archive.header,
            group,
            &record.hashes,
        )?);
    }
    let tables_root = tables_root_digest(&tables);
    Ok((
        archive.header,
        ArchiveDigests {
            header_blake3,
            snapshot_digest,
            tables_root,
        },
    ))
}

fn resolve_slice_length(backing_bytes: u64, offset: u64, length: Option<u64>) -> Result<u64> {
    if offset >= backing_bytes {
        return Err(corrupt(
            "member slice offset reaches or exceeds backing file",
        ));
    }
    let resolved = length.unwrap_or_else(|| backing_bytes.saturating_sub(offset));
    if resolved == 0
        || offset
            .checked_add(resolved)
            .is_none_or(|end| end > backing_bytes)
    {
        return Err(corrupt(
            "member slice length is zero or exceeds backing file bounds",
        ));
    }
    Ok(resolved)
}

/// Protect every offline member of a storage set and atomically publish a
/// [`StorageSetManifest`] (`FFSRQSM3`) binding all members and `native_binding`.
pub fn protect_storage_set(
    cx: &Cx,
    request: &StorageSetProtectRequest,
) -> Result<StorageSetManifest> {
    checkpoint(cx)?;
    if request.members.is_empty() {
        return Err(corrupt("storage set requires at least one member"));
    }
    if request.manifest_path.exists() {
        return Err(corrupt(
            "refusing to overwrite an existing storage-set manifest",
        ));
    }
    request.options.validate()?;

    let mut seen_sidecars = BTreeSet::new();
    let mut member_bindings = Vec::with_capacity(request.members.len());
    let mut id_hasher = blake3::Hasher::new();
    id_hasher.update(b"ffs-storage-set-id-v3");
    id_hasher.update(request.filesystem.as_bytes());
    id_hasher.update(request.native_binding.summary().as_bytes());

    for (idx, spec) in request.members.iter().enumerate() {
        checkpoint(cx)?;
        let img_meta = std::fs::metadata(&spec.image_path)?;
        if !img_meta.is_file() {
            return Err(corrupt("storage-set member image must be a regular file"));
        }
        let backing_bytes = img_meta.len();
        let slice_len = resolve_slice_length(backing_bytes, spec.offset, spec.length)?;
        let archive_filename = archive_file_name(&spec.sidecar_path)?;
        if !seen_sidecars.insert(spec.sidecar_path.clone()) {
            return Err(corrupt(
                "duplicate sidecar archive path across storage-set members",
            ));
        }
        if spec.sidecar_path.exists() {
            let report = verify(cx, &spec.image_path, &spec.sidecar_path)?;
            if !report.is_healthy() {
                return Err(corrupt(
                    "existing member sidecar does not cleanly match member image",
                ));
            }
        } else {
            protect(cx, &spec.image_path, &spec.sidecar_path, request.options)?;
        }
        let (hdr, digests) = read_archive_binding_digests(cx, &spec.sidecar_path)?;
        if hdr.image_bytes != backing_bytes {
            return Err(corrupt("member sidecar disagrees with member backing size"));
        }
        id_hasher.update(&digests.header_blake3);
        id_hasher.update(&spec.native_member_id);
        let member_index =
            u32::try_from(idx).map_err(|_| corrupt("storage-set member index overflow"))?;
        member_bindings.push(MemberProtectionBinding {
            member_index,
            role: spec.role,
            native_member_id: spec.native_member_id,
            geometry: MemberSliceGeometry {
                backing_bytes,
                offset: spec.offset,
                length: slice_len,
                block_size: hdr.options.block_size,
                group_blocks: hdr.options.group_blocks,
                repair_symbols: hdr.options.repair_symbols,
                groups: hdr.groups,
            },
            archive_filename,
            header_blake3: digests.header_blake3,
            snapshot_digest: digests.snapshot_digest,
            tables_root: digests.tables_root,
        });
    }

    let id_digest = id_hasher.finalize();
    let mut set_id = [0_u8; 16];
    set_id.copy_from_slice(&id_digest.as_bytes()[..16]);

    let provenance =
        request
            .signing_key
            .as_ref()
            .map_or(ProvenanceAuth::UnauthenticatedChecksum, |key| {
                ProvenanceAuth::AuthenticatedTrustedRoot {
                    key_id: por_key_id(key),
                    mac_hex: String::new(),
                }
            });

    let manifest = StorageSetManifest {
        set_id,
        generation: 1,
        filesystem: request.filesystem.clone(),
        topology: request.topology.clone(),
        view: request.view.clone(),
        native_binding: request.native_binding.clone(),
        members: member_bindings,
        provenance,
    };
    let encoded = manifest.encode(request.signing_key.as_ref())?;
    let verify_policy = request
        .signing_key
        .map_or(TrustPolicy::AllowUnauthenticated, |key| {
            TrustPolicy::RequireTrustedRoot { key }
        });
    let decoded = StorageSetManifest::decode(&encoded, verify_policy)?;
    let mut staged = NamedTempFile::new_in(parent_path(&request.manifest_path))?;
    staged.write_all(&encoded)?;
    publish_new(cx, staged, &request.manifest_path)?;
    Ok(decoded)
}

/// Verify an offline [`StorageSetManifest`] (`FFSRQSM3`) and every member's
/// sidecar archive against `trust_policy`.
pub fn verify_storage_set(
    cx: &Cx,
    manifest_path: &Path,
    members: &[(PathBuf, PathBuf)],
    trust_policy: TrustPolicy,
) -> Result<StorageSetVerifyReport> {
    checkpoint(cx)?;
    let raw = std::fs::read(manifest_path)?;
    let manifest = StorageSetManifest::decode(&raw, trust_policy)?;
    if members.len() != manifest.members.len() {
        return Err(corrupt(
            "supplied member count disagrees with storage-set manifest",
        ));
    }
    let mut reports = Vec::with_capacity(members.len());
    let mut matches_all = true;
    for ((image_path, sidecar_path), expected) in members.iter().zip(&manifest.members) {
        checkpoint(cx)?;
        let actual_name = archive_file_name(sidecar_path)?;
        if actual_name != expected.archive_filename {
            return Err(corrupt(
                "member sidecar filename disagrees with storage-set manifest binding",
            ));
        }
        let report = verify(cx, image_path, sidecar_path)?;
        let (_, digests) = read_archive_binding_digests(cx, sidecar_path)?;
        if report.current_image_bytes != expected.geometry.backing_bytes
            || digests.header_blake3 != expected.header_blake3
            || digests.snapshot_digest != expected.snapshot_digest
            || digests.tables_root != expected.tables_root
        {
            return Err(corrupt(
                "member sidecar generation or tables digest disagrees with storage-set manifest",
            ));
        }
        matches_all &= report.is_healthy();
        reports.push(report);
    }
    Ok(StorageSetVerifyReport {
        manifest,
        member_reports: reports,
        matches_all_members: matches_all,
    })
}

/// Admission options when opening a live [`ProtectedStorageSet`].
#[derive(Clone)]
pub struct StorageSetOpenOptions {
    pub read_only: bool,
    pub allow_automatic_repair: bool,
    pub trust_policy: TrustPolicy,
    pub signing_key: Option<PorKey>,
    pub calibration: Option<RepairLossCalibration>,
    pub evidence_ledger: Option<SharedEvidenceLedger>,
}

impl std::fmt::Debug for StorageSetOpenOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageSetOpenOptions")
            .field("read_only", &self.read_only)
            .field("allow_automatic_repair", &self.allow_automatic_repair)
            .field("has_signing_key", &self.signing_key.is_some())
            .field("has_calibration", &self.calibration.is_some())
            .field("has_evidence_ledger", &self.evidence_ledger.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for StorageSetOpenOptions {
    fn default() -> Self {
        Self {
            read_only: false,
            allow_automatic_repair: true,
            trust_policy: TrustPolicy::AllowUnauthenticated,
            signing_key: None,
            calibration: Some(RepairLossCalibration::default_operator_exclusive()),
            evidence_ledger: None,
        }
    }
}

/// Write-gating wrapper around one [`ProtectedStorageSet`] member, optionally
/// bounded to `[offset, offset + length)` via [`VolumeDevice`].
type BindingExtractor = Arc<dyn Fn(&Cx) -> Result<NativeCommitBinding> + Send + Sync>;

struct MemberAccessDevice {
    inner: Arc<SidecarImageDevice>,
    writable: bool,
    auto_seal: Option<(Arc<ProtectedStorageSet>, BindingExtractor)>,
}

impl std::fmt::Debug for MemberAccessDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberAccessDevice")
            .field("inner", &self.inner)
            .field("writable", &self.writable)
            .field("has_auto_seal", &self.auto_seal.is_some())
            .finish_non_exhaustive()
    }
}

impl ByteDevice for MemberAccessDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        self.inner.read_exact_at(cx, offset, buf)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        self.inner.write_all_at(cx, offset, buf)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)?;
        if self.writable
            && let Some((set, extractor)) = &self.auto_seal
            && set.all_members_clean_and_manifest_fenced()
        {
            let binding = extractor(cx)?;
            set.seal_manifest_when_members_clean(cx, binding)?;
        }
        Ok(())
    }

    fn begin_durability_commit(&self, cx: &Cx) -> Result<()> {
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        self.inner.begin_durability_commit(cx)
    }

    fn complete_durability_commit(&self) {
        self.inner.complete_durability_commit();
    }

    fn abort_durability_commit(&self) {
        self.inner.abort_durability_commit();
    }
}

/// Handle to one admitted member inside a [`ProtectedStorageSet`].
#[derive(Debug, Clone)]
pub struct ProtectedMemberHandle {
    pub member_index: u32,
    pub role: MemberRole,
    pub native_member_id: [u8; 16],
    pub archive_filename: String,
    pub offset: u64,
    pub length: u64,
    pub device: Arc<SidecarImageDevice>,
}

impl ProtectedMemberHandle {
    /// Construct a [`ByteDevice`] bounded to `[offset, offset + length)` with
    /// caller-write authority gated by `writable`.
    pub fn open_bounded_device(&self, writable: bool) -> Result<Box<dyn ByteDevice>> {
        self.open_bounded_device_internal(writable, None)
    }

    fn open_bounded_device_internal(
        &self,
        writable: bool,
        auto_seal: Option<(Arc<ProtectedStorageSet>, BindingExtractor)>,
    ) -> Result<Box<dyn ByteDevice>> {
        let base = MemberAccessDevice {
            inner: Arc::clone(&self.device),
            writable,
            auto_seal,
        };
        if self.offset == 0 && self.length == self.device.len_bytes() {
            Ok(Box::new(base))
        } else {
            let sliced = VolumeDevice::from_range(base, self.offset, Some(self.length), !writable)?;
            Ok(Box::new(sliced))
        }
    }
}

struct ManifestFenceSlot {
    manifest_path: PathBuf,
    file: File,
    manifest: StorageSetManifest,
    fenced: bool,
    fenced_at_ns: Option<u64>,
    poisoned: bool,
    post_commit_error: Option<String>,
    signing_key: Option<PorKey>,
}

impl ManifestFenceSlot {
    fn fence(&mut self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        if self.poisoned {
            return Err(corrupt(
                "storage-set manifest coordinator is poisoned after an I/O failure",
            ));
        }
        if self.fenced {
            return Ok(());
        }
        let mut raw_prefix = [0_u8; SET_MANIFEST_PREFIX_BYTES];
        if let Err(err) = self.file.read_exact_at(&mut raw_prefix, 0) {
            self.poisoned = true;
            return Err(err.into());
        }
        raw_prefix[..8].copy_from_slice(SET_PENDING_MAGIC);
        if let Err(err) = self
            .file
            .write_all_at(&raw_prefix, 0)
            .and_then(|()| self.file.sync_all())
        {
            self.poisoned = true;
            return Err(err.into());
        }
        self.fenced = true;
        self.fenced_at_ns = Some(now_unix_ns());
        Ok(())
    }
}

/// Live coordinator owning all required [`SidecarImageDevice`] members and
/// optional [`StorageSetManifest`] (`FFSRQSM3` / `FFSRQPM3`).
pub struct ProtectedStorageSet {
    members: Vec<ProtectedMemberHandle>,
    manifest_slot: Option<Arc<Mutex<ManifestFenceSlot>>>,
    authenticated_provenance: bool,
}

impl std::fmt::Debug for ProtectedStorageSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedStorageSet")
            .field("member_count", &self.members.len())
            .field("has_manifest", &self.manifest_slot.is_some())
            .field("authenticated_provenance", &self.authenticated_provenance)
            .finish_non_exhaustive()
    }
}

impl ProtectedStorageSet {
    /// Admit a single-member standalone sidecar (with optional bounded `[offset, length)` slice).
    pub fn open_standalone(
        cx: &Cx,
        image_path: &Path,
        sidecar_path: &Path,
        offset: u64,
        length: Option<u64>,
        options: &StorageSetOpenOptions,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let require_trusted_root =
            matches!(options.trust_policy, TrustPolicy::RequireTrustedRoot { .. });
        if require_trusted_root {
            return Err(corrupt(
                "trusted-root provenance requires a signed storage-set manifest (--manifest + --trust-key-file); unkeyed standalone sidecar checksums are not authenticated",
            ));
        }
        let live_opts = SidecarLiveOptions {
            read_only: options.read_only,
            allow_automatic_repair: options.allow_automatic_repair,
            member_index: 0,
            set_id_hex: None,
            initial_generation: 1,
            authenticated_provenance: false,
            require_trusted_root: false,
            calibration: options.calibration.clone(),
            evidence_ledger: options.evidence_ledger.clone(),
            external_fence_hook: None,
        };
        let device = Arc::new(SidecarImageDevice::open_with_options(
            cx,
            image_path,
            sidecar_path,
            live_opts,
        )?);
        let slice_len = resolve_slice_length(device.len_bytes(), offset, length)?;
        let archive_filename = archive_file_name(sidecar_path)?;
        Ok(Self {
            members: vec![ProtectedMemberHandle {
                member_index: 0,
                role: MemberRole::Data,
                native_member_id: [0_u8; 16],
                archive_filename,
                offset,
                length: slice_len,
                device,
            }],
            manifest_slot: None,
            authenticated_provenance: false,
        })
    }

    /// Admit a multi-member (or manifest-bound single-member) storage set against
    /// its [`StorageSetManifest`] (`FFSRQSM3`) and `options.trust_policy`.
    pub fn open_manifest(
        cx: &Cx,
        manifest_path: &Path,
        member_paths: &[(PathBuf, PathBuf)],
        options: &StorageSetOpenOptions,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let manifest_path = manifest_path.canonicalize()?;
        let manifest_file = File::options()
            .read(true)
            .write(!options.read_only)
            .open(&manifest_path)?;
        let manifest_meta = manifest_file.metadata()?;
        if !manifest_meta.is_file() {
            return Err(corrupt("storage-set manifest must be a regular file"));
        }
        if options.read_only {
            manifest_file.try_lock_shared().map_err(io::Error::from)?;
        } else {
            manifest_file.try_lock().map_err(io::Error::from)?;
        }
        let raw_manifest = std::fs::read(&manifest_path)?;
        let manifest = StorageSetManifest::decode(&raw_manifest, options.trust_policy)?;
        if member_paths.len() != manifest.members.len() {
            return Err(corrupt(
                "supplied member count disagrees with storage-set manifest",
            ));
        }
        let authenticated = manifest.is_authenticated();
        let require_trusted_root =
            matches!(options.trust_policy, TrustPolicy::RequireTrustedRoot { .. });
        let signing_key = match (options.signing_key, options.trust_policy) {
            (Some(k), _) => Some(k),
            (None, TrustPolicy::RequireTrustedRoot { key }) => Some(key),
            (None, TrustPolicy::AllowUnauthenticated) => None,
        };
        if !options.read_only && authenticated && signing_key.is_none() {
            return Err(corrupt(
                "writable authenticated storage set requires its signing key (--trust-key-file) to seal future generations",
            ));
        }

        let set_id_hex = manifest.set_id_hex();
        let initial_gen = manifest.generation;
        let expected_members = manifest.members.clone();
        let slot = Arc::new(Mutex::new(ManifestFenceSlot {
            manifest_path,
            file: manifest_file,
            manifest,
            fenced: false,
            fenced_at_ns: None,
            poisoned: false,
            post_commit_error: None,
            signing_key,
        }));

        let mut handles = Vec::with_capacity(member_paths.len());
        let mut seen_inodes = BTreeSet::new();
        seen_inodes.insert((manifest_meta.dev(), manifest_meta.ino()));

        for (idx, ((image_path, sidecar_path), expected)) in
            member_paths.iter().zip(&expected_members).enumerate()
        {
            checkpoint(cx)?;
            let actual_name = archive_file_name(sidecar_path)?;
            if actual_name != expected.archive_filename {
                return Err(corrupt(
                    "member sidecar filename disagrees with storage-set manifest binding",
                ));
            }
            let img_meta = std::fs::metadata(image_path)?;
            let rq_meta = std::fs::metadata(sidecar_path)?;
            if !seen_inodes.insert((img_meta.dev(), img_meta.ino()))
                || !seen_inodes.insert((rq_meta.dev(), rq_meta.ino()))
            {
                return Err(corrupt(
                    "duplicate image, sidecar, or manifest inode across storage set",
                ));
            }
            let hook_slot = Arc::clone(&slot);
            let fence_hook: Option<FenceHook> = if options.read_only {
                None
            } else {
                Some(Arc::new(move |hook_cx: &Cx| {
                    hook_slot.lock().fence(hook_cx)
                }))
            };
            let live_opts = SidecarLiveOptions {
                read_only: options.read_only,
                allow_automatic_repair: options.allow_automatic_repair,
                member_index: u32::try_from(idx).map_err(|_| corrupt("member index overflow"))?,
                set_id_hex: Some(set_id_hex.clone()),
                initial_generation: initial_gen,
                authenticated_provenance: authenticated,
                require_trusted_root,
                calibration: options.calibration.clone(),
                evidence_ledger: options.evidence_ledger.clone(),
                external_fence_hook: fence_hook,
            };
            let device = Arc::new(SidecarImageDevice::open_with_options(
                cx,
                image_path,
                sidecar_path,
                live_opts,
            )?);
            let (geo, digests) = device.clean_binding_digests(cx)?;
            if geo.backing_bytes != expected.geometry.backing_bytes
                || geo.block_size != expected.geometry.block_size
                || geo.group_blocks != expected.geometry.group_blocks
                || geo.repair_symbols != expected.geometry.repair_symbols
                || geo.groups != expected.geometry.groups
                || digests.header_blake3 != expected.header_blake3
                || digests.snapshot_digest != expected.snapshot_digest
                || digests.tables_root != expected.tables_root
            {
                return Err(corrupt(
                    "member sidecar archive disagrees with storage-set manifest generation or geometry",
                ));
            }
            let _ = resolve_slice_length(
                geo.backing_bytes,
                expected.geometry.offset,
                Some(expected.geometry.length),
            )?;
            handles.push(ProtectedMemberHandle {
                member_index: expected.member_index,
                role: expected.role,
                native_member_id: expected.native_member_id,
                archive_filename: actual_name,
                offset: expected.geometry.offset,
                length: expected.geometry.length,
                device,
            });
        }

        Ok(Self {
            members: handles,
            manifest_slot: Some(slot),
            authenticated_provenance: authenticated,
        })
    }

    /// Admitted member handles in manifest order (`0..N`).
    #[must_use]
    pub fn members(&self) -> &[ProtectedMemberHandle] {
        &self.members
    }

    /// Primary member (`index 0`) device handle.
    #[must_use]
    pub fn primary_device(&self) -> &Arc<SidecarImageDevice> {
        &self.members[0].device
    }

    /// Snapshot of the current [`StorageSetManifest`], if manifest-backed.
    #[must_use]
    pub fn manifest(&self) -> Option<StorageSetManifest> {
        self.manifest_slot
            .as_ref()
            .map(|slot| slot.lock().manifest.clone())
    }

    /// Whether provenance is cryptographically authenticated via a trusted root key.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.authenticated_provenance
    }

    /// Total RaptorQ protection groups across all admitted members.
    #[must_use]
    pub fn protection_group_count(&self) -> u32 {
        self.members.iter().fold(0_u32, |acc, m| {
            acc.saturating_add(m.device.protection_group_count())
        })
    }

    /// Durably fence the storage-set manifest (`FFSRQPM3`) and primary member
    /// (`FFSRQPD2`) BEFORE an in-memory MVCC/CoW mutation publishes new state.
    pub fn fence_before_mutation(&self, cx: &Cx) -> Result<()> {
        if let Some(slot) = &self.manifest_slot {
            slot.lock().fence(cx)?;
        }
        for member in &self.members {
            member.device.fence_before_mutation(cx)?;
        }
        Ok(())
    }

    /// Record a committed native format token (`native_durable = true`) across
    /// all members before or during parity sealing.
    pub fn record_native_commit(&self, binding: &NativeCommitBinding) {
        for member in &self.members {
            member.device.record_native_commit(binding);
        }
    }

    /// Construct a bounded [`ByteDevice`] for `member_index` that automatically
    /// seals the [`StorageSetManifest`] once all members reach `Phase::Clean`.
    pub fn open_member_device_with_auto_seal(
        self: &Arc<Self>,
        member_index: usize,
        writable: bool,
        extractor: BindingExtractor,
    ) -> Result<Box<dyn ByteDevice>> {
        let handle = self
            .members
            .get(member_index)
            .ok_or_else(|| corrupt("storage-set member index out of bounds"))?;
        let auto_seal = if writable && self.manifest_slot.is_some() {
            Some((Arc::clone(self), extractor))
        } else {
            None
        };
        handle.open_bounded_device_internal(writable, auto_seal)
    }

    fn all_members_clean_and_manifest_fenced(&self) -> bool {
        let Some(slot) = &self.manifest_slot else {
            return false;
        };
        if !slot.lock().fenced {
            return false;
        }
        self.members
            .iter()
            .all(|m| m.device.ack_status().protected_durable)
    }

    fn seal_manifest_when_members_clean(
        &self,
        cx: &Cx,
        native_binding: NativeCommitBinding,
    ) -> Result<()> {
        self.record_native_commit(&native_binding);
        self.seal_manifest_inner(cx, native_binding)
    }

    /// Seal every member archive FIRST, then atomically publish the updated
    /// [`StorageSetManifest`] (`FFSRQSM3`, `generation + 1`) LAST with directory sync.
    pub fn seal_committed(&self, cx: &Cx, native_binding: NativeCommitBinding) -> Result<()> {
        self.record_native_commit(&native_binding);
        for member in &self.members {
            if let Err(err) = member.device.sync(cx) {
                if let Some(slot) = &self.manifest_slot {
                    slot.lock().post_commit_error = Some(err.to_string());
                }
                return Err(err);
            }
        }
        self.seal_manifest_inner(cx, native_binding)
    }

    fn seal_manifest_inner(&self, cx: &Cx, native_binding: NativeCommitBinding) -> Result<()> {
        let Some(slot_arc) = &self.manifest_slot else {
            return Ok(());
        };
        let mut slot = slot_arc.lock();
        if slot.poisoned {
            return Err(corrupt(
                "storage-set manifest coordinator is poisoned after an I/O failure",
            ));
        }
        let mut bindings = Vec::with_capacity(self.members.len());
        let mut any_digest_changed = false;
        for (member, prev) in self.members.iter().zip(&slot.manifest.members) {
            let (mut geo, digests) = member.device.clean_binding_digests(cx)?;
            geo.offset = member.offset;
            geo.length = member.length;
            if digests.header_blake3 != prev.header_blake3
                || digests.snapshot_digest != prev.snapshot_digest
                || digests.tables_root != prev.tables_root
            {
                any_digest_changed = true;
            }
            bindings.push(MemberProtectionBinding {
                member_index: member.member_index,
                role: member.role,
                native_member_id: member.native_member_id,
                geometry: geo,
                archive_filename: member.archive_filename.clone(),
                header_blake3: digests.header_blake3,
                snapshot_digest: digests.snapshot_digest,
                tables_root: digests.tables_root,
            });
        }
        let binding_changed = native_binding != slot.manifest.native_binding;
        if !slot.fenced && !any_digest_changed && !binding_changed {
            return checkpoint(cx);
        }
        let next_gen = slot
            .manifest
            .generation
            .checked_add(1)
            .ok_or_else(|| corrupt("storage-set manifest generation overflow"))?;
        let mut next_manifest = slot.manifest.clone();
        next_manifest.generation = next_gen;
        next_manifest.native_binding = native_binding;
        next_manifest.members = bindings;

        let publish_res = (|| -> Result<()> {
            checkpoint(cx)?;
            let encoded = next_manifest.encode(slot.signing_key.as_ref())?;
            let verify_policy = slot
                .signing_key
                .map_or(TrustPolicy::AllowUnauthenticated, |key| {
                    TrustPolicy::RequireTrustedRoot { key }
                });
            let verified_manifest = StorageSetManifest::decode(&encoded, verify_policy)?;
            let mut staged = NamedTempFile::new_in(parent_path(&slot.manifest_path))?;
            staged.as_file().try_lock().map_err(io::Error::from)?;
            staged.write_all(&encoded)?;
            staged.as_file().sync_all()?;
            checkpoint(cx)?;
            let old_meta = slot.file.metadata()?;
            let named_meta = std::fs::metadata(&slot.manifest_path)?;
            if (old_meta.dev(), old_meta.ino()) != (named_meta.dev(), named_meta.ino()) {
                return Err(corrupt(
                    "storage-set manifest path was replaced by another writer",
                ));
            }
            let parent = File::open(parent_path(&slot.manifest_path))?;
            let new_file = staged
                .persist(&slot.manifest_path)
                .map_err(|err| FfsError::Io(err.error))?;
            slot.poisoned = true;
            slot.file = new_file;
            parent.sync_all()?;
            slot.manifest = verified_manifest;
            slot.fenced = false;
            slot.fenced_at_ns = None;
            slot.post_commit_error = None;
            slot.poisoned = false;
            Ok(())
        })();
        if let Err(ref err) = publish_res {
            slot.post_commit_error = Some(err.to_string());
        }
        publish_res
    }

    /// Aggregate separate `native_durable` vs `protected_durable` status across
    /// all members and the whole-set manifest (`bd-tqrnc`).
    #[must_use]
    pub fn ack_status(&self) -> ProtectionAckStatus {
        let mut base = self.members[0].device.ack_status();
        for member in &self.members[1..] {
            let status = member.device.ack_status();
            base.native_durable &= status.native_durable;
            base.protected_durable &= status.protected_durable;
            base.unprotected_interval_ns = base
                .unprotected_interval_ns
                .max(status.unprotected_interval_ns);
            if base.post_commit_error.is_none() {
                base.post_commit_error = status.post_commit_error;
            }
        }
        if let Some(slot_arc) = &self.manifest_slot {
            let slot = slot_arc.lock();
            base.epoch_generation = slot.manifest.generation;
            if slot.fenced || slot.poisoned {
                base.protected_durable = false;
                if let Some(fenced_at) = slot.fenced_at_ns {
                    let live_ns = now_unix_ns().saturating_sub(fenced_at);
                    base.unprotected_interval_ns = base.unprotected_interval_ns.max(live_ns);
                }
            }
            if base.post_commit_error.is_none() {
                base.post_commit_error.clone_from(&slot.post_commit_error);
            }
        }
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar_restore::restore;

    mod read_only;

    fn finish_incremental_scrub(
        device: &SidecarImageDevice,
        cursor: &mut ProtectionScrubCursor,
    ) -> ProtectionScrubReport {
        let groups = device.state.lock().archive.header.groups;
        for _ in 0..=groups {
            match device
                .scrub_step(&Cx::for_testing(), cursor)
                .expect("scrub step")
            {
                ProtectionScrubStep::GroupVerified { .. } => {}
                ProtectionScrubStep::Complete(report) => return report,
                other => panic!("unexpected deferral: {other:?}"),
            }
        }
        panic!("a quiescent scrub must finish in groups + 1 steps");
    }

    #[test]
    fn incremental_scrub_is_group_bounded_and_healthy_passes_do_not_republish() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        let cx = Cx::for_testing();
        let mut cursor = ProtectionScrubCursor::default();
        for _ in 0..2 {
            for group in 0..3 {
                assert_eq!(
                    device.scrub_step(&cx, &mut cursor).unwrap(),
                    ProtectionScrubStep::GroupVerified { group }
                );
                assert!(device.state.try_lock().is_some(), "step retained its lock");
            }
            assert_eq!(
                device.scrub_step(&cx, &mut cursor).unwrap(),
                ProtectionScrubStep::Complete(ProtectionScrubReport {
                    groups_verified: 3,
                    source_bytes_verified: 16 * 512 + 37,
                    ..ProtectionScrubReport::default()
                })
            );
            assert!(cursor.epoch.is_none());
            assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
        }
    }

    #[test]
    fn incremental_scrub_replenishes_lost_parity_and_recovers_a_short_tail() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let saved = device.protection(&cx).unwrap();
        for symbol in 0..4 {
            fixture.damage_parity(&device, 0, symbol);
        }
        fixture.damage_parity(&device, 2, 0);
        fixture.damage(16 * 512, &[0xfe; 37]);
        let mut cursor = ProtectionScrubCursor::default();
        assert_eq!(
            device.scrub_step(&cx, &mut cursor).unwrap(),
            ProtectionScrubStep::GroupVerified { group: 0 }
        );
        assert_eq!(
            &std::fs::read(&fixture.image).unwrap()[16 * 512..],
            &[0xfe; 37],
            "a step must not visit later groups"
        );
        let report = finish_incremental_scrub(&device, &mut cursor);
        assert_eq!(report.groups_verified, 3);
        assert_eq!(report.source_bytes_verified, 16 * 512 + 37);
        assert_eq!(report.source_blocks_recovered, 1);
        assert_eq!(report.invalid_repair_symbols, 5);
        assert!(report.archive_rebuilt);
        assert_eq!(device.protection(&cx).unwrap(), saved);
        assert_eq!(std::fs::read(&fixture.image).unwrap(), fixture.original);
        let named = File::options()
            .read(true)
            .write(true)
            .open(&fixture.sidecar)
            .unwrap();
        assert!(
            named.try_lock().is_err(),
            "replacement inode must remain owned"
        );
        drop(named);
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .unwrap()
                .is_healthy()
        );
        // Recovery after reopening proves new symbols are usable, not merely
        // an optimistic report from the preceding maintenance cursor.
        let reopened = fixture.open();
        fixture.damage(0, &[0xfe; 512]);
        let mut bytes = [0; 512];
        reopened
            .read_exact_at(&cx, ByteOffset(0), &mut bytes)
            .unwrap();
        assert_eq!(bytes.as_slice(), &fixture.original[..512]);
    }

    #[test]
    fn incremental_scrub_busy_admission_does_not_wait_or_advance() {
        let fixture = Fixture::new();
        let device = Arc::new(fixture.open());
        let cx = Cx::for_testing();
        let mut cursor = ProtectionScrubCursor::default();
        device.scrub_step(&cx, &mut cursor).unwrap();
        let before = cursor.report;
        let held = device.state.lock();
        let worker_device = Arc::clone(&device);
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = worker_device.scrub_step(&cx, &mut cursor);
            send.send(result).unwrap();
            cursor
        });
        let result = receive.recv_timeout(Duration::from_secs(2));
        // Release before asserting/joining even if a broken implementation waits.
        drop(held);
        let cursor = worker.join().unwrap();
        assert_eq!(
            result.expect("maintenance must not wait").unwrap(),
            ProtectionScrubStep::Busy
        );
        assert_eq!(cursor.next_group, 1);
        assert_eq!(cursor.report, before);
        assert_eq!(std::fs::read(&fixture.image).unwrap(), fixture.original);
    }

    #[test]
    fn incremental_scrub_defers_a_pending_finalization_and_restarts_after_sync() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        fixture.damage_parity(&device, 0, 0);
        let mut cursor = ProtectionScrubCursor::default();
        for _ in 0..3 {
            device.scrub_step(&cx, &mut cursor).unwrap();
        }
        let before = cursor.report;
        device
            .write_all_at(&cx, ByteOffset(0), &[0x51; 512])
            .unwrap();
        let source = std::fs::read(&fixture.image).unwrap();
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        assert_eq!(&archive[..8], PENDING_MAGIC);
        assert_eq!(
            device.scrub_step(&cx, &mut cursor).unwrap(),
            ProtectionScrubStep::PendingWrites
        );
        assert_eq!(cursor.next_group, 3);
        assert_eq!(cursor.report, before);
        assert_eq!(std::fs::read(&fixture.image).unwrap(), source);
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
        assert!(device.protection(&cx).is_err());
        device.sync(&cx).unwrap();
        assert_eq!(
            device.scrub_step(&cx, &mut cursor).unwrap(),
            ProtectionScrubStep::GroupVerified { group: 0 }
        );
        let report = finish_incremental_scrub(&device, &mut cursor);
        assert_eq!(
            report.invalid_repair_symbols, 0,
            "do not carry old observations"
        );
        assert!(
            !report.archive_rebuilt,
            "the explicit sync already rebuilt it"
        );
        assert_eq!(std::fs::read(&fixture.image).unwrap(), source);
    }

    #[test]
    fn incremental_scrub_restarts_even_after_an_identical_byte_publication() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut cursor = ProtectionScrubCursor::default();
        device.scrub_step(&cx, &mut cursor).unwrap();
        let old_epoch = Arc::clone(cursor.epoch.as_ref().unwrap());
        let old_header = device.state.lock().archive.header.encode();
        device
            .write_all_at(&cx, ByteOffset(0), &fixture.original[..512])
            .unwrap();
        device.sync(&cx).unwrap();
        assert_eq!(device.state.lock().archive.header.encode(), old_header);
        assert_eq!(
            device.scrub_step(&cx, &mut cursor).unwrap(),
            ProtectionScrubStep::GroupVerified { group: 0 }
        );
        assert!(!Arc::ptr_eq(cursor.epoch.as_ref().unwrap(), &old_epoch));
    }

    #[test]
    fn incremental_scrub_cursor_neither_keeps_file_locks_nor_crosses_device_opens() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut cursor = ProtectionScrubCursor::default();
        device.scrub_step(&cx, &mut cursor).unwrap();
        drop(device);
        let reopened = fixture.open();
        assert_eq!(
            reopened.scrub_step(&cx, &mut cursor).unwrap(),
            ProtectionScrubStep::GroupVerified { group: 0 }
        );
    }

    #[test]
    fn incremental_scrub_cancelled_finalization_preserves_the_archive_for_retry() {
        let fixture = Fixture::new();
        let device = fixture.open();
        fixture.damage_parity(&device, 0, 0);
        let cx = Cx::for_testing();
        let mut cursor = ProtectionScrubCursor::default();
        for _ in 0..3 {
            device.scrub_step(&cx, &mut cursor).unwrap();
        }
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        let before = cursor.report;
        cx.set_cancel_requested(true);
        assert!(matches!(
            device.scrub_step(&cx, &mut cursor),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
        assert_eq!(cursor.report, before);
        assert_eq!(cursor.next_group, 3);
        assert!(finish_incremental_scrub(&device, &mut cursor).archive_rebuilt);
    }

    #[test]
    fn incremental_scrub_refuses_transplanted_source_tables() {
        let fixture = Fixture::new();
        let (_, record, offset) = alternate_generation(&fixture);
        std::fs::write(&fixture.image, &fixture.original).unwrap();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut cursor = ProtectionScrubCursor::default();
        device.scrub_step(&cx, &mut cursor).unwrap();
        File::options()
            .write(true)
            .open(&fixture.sidecar)
            .unwrap()
            .write_all_at(&record, offset)
            .unwrap();
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        let error = device.scrub_step(&cx, &mut cursor).unwrap_err();
        assert!(error.to_string().contains("admitted generation"));
        assert_eq!(cursor.next_group, 1);
        assert_eq!(std::fs::read(&fixture.image).unwrap(), fixture.original);
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
    }

    #[test]
    fn incremental_scrub_cannot_rebuild_from_an_unrecoverable_later_group() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        fixture.damage_parity(&device, 0, 0);
        for symbol in 0..4 {
            fixture.damage_parity(&device, 2, symbol);
        }
        fixture.damage(16 * 512, &[0xfe; 37]);
        let source = std::fs::read(&fixture.image).unwrap();
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        let mut cursor = ProtectionScrubCursor::default();
        for _ in 0..2 {
            device.scrub_step(&cx, &mut cursor).unwrap();
        }
        assert!(device.scrub_step(&cx, &mut cursor).is_err());
        assert_eq!(cursor.next_group, 2);
        assert!(cursor.rebuild_archive);
        assert_eq!(std::fs::read(&fixture.image).unwrap(), source);
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
    }

    #[test]
    fn incremental_scrub_publication_failure_is_not_completion() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        fixture.damage_parity(&device, 0, 0);
        let mut cursor = ProtectionScrubCursor::default();
        for _ in 0..3 {
            device.scrub_step(&cx, &mut cursor).unwrap();
        }
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        let retained = fixture.sidecar.with_extension("retained");
        std::fs::rename(&fixture.sidecar, &retained).unwrap();
        std::fs::create_dir(&fixture.sidecar).unwrap();
        assert!(device.scrub_step(&cx, &mut cursor).is_err());
        assert_eq!(cursor.next_group, 3);
        assert!(!cursor.report.archive_rebuilt);
        assert_eq!(std::fs::read(&retained).unwrap(), archive);
        assert_eq!(std::fs::read(&fixture.image).unwrap(), fixture.original);
    }

    #[test]
    fn incremental_scrub_rechecks_header_damage_after_the_last_group() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut cursor = ProtectionScrubCursor::default();
        for _ in 0..3 {
            device.scrub_step(&cx, &mut cursor).unwrap();
        }
        File::options()
            .write(true)
            .open(&fixture.sidecar)
            .unwrap()
            .write_all_at(b"BADHDR!!", 0)
            .unwrap();
        let report = finish_incremental_scrub(&device, &mut cursor);
        assert!(report.archive_rebuilt);
        assert_eq!(report.invalid_repair_symbols, 0);
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .unwrap()
                .is_healthy()
        );
    }

    #[test]
    fn incremental_scrub_poisoning_and_io_errors_are_not_deferrals() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut cursor = ProtectionScrubCursor::default();
        device.state.lock().phase = Phase::Poisoned;
        assert!(
            device
                .scrub_step(&cx, &mut cursor)
                .unwrap_err()
                .to_string()
                .contains("poisoned")
        );
        assert!(cursor.epoch.is_none());
        device.state.lock().phase = Phase::Clean; // test-only injected state
        device
            .state
            .lock()
            .archive
            .file
            .set_len(HEADER_BYTES as u64)
            .unwrap();
        assert!(matches!(
            device.scrub_step(&cx, &mut cursor),
            Err(FfsError::Io(_))
        ));
        assert_eq!(cursor.next_group, 0);
    }

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

        fn damage_parity(&self, device: &SidecarImageDevice, group: u32, symbol: u32) {
            let state = device.state.lock();
            let header = &state.archive.header;
            assert!(symbol < header.options.repair_symbols);
            let (_, count) = header.group_geometry(group).expect("group");
            let stride = 4 + u64::from(header.options.block_size) + DIGEST_BYTES as u64;
            let offset = header.group_offset(group).expect("offset")
                + GROUP_PREFIX_BYTES as u64
                + u64::from(count) * DIGEST_BYTES as u64
                + DIGEST_BYTES as u64
                + u64::from(symbol) * stride
                + 4;
            let file = File::options()
                .read(true)
                .write(true)
                .open(&self.sidecar)
                .expect("archive fault handle");
            let mut byte = [0];
            file.read_exact_at(&mut byte, offset).expect("read parity");
            byte[0] ^= 1;
            file.write_all_at(&byte, offset).expect("damage parity");
        }
    }

    #[test]
    fn dirty_sync_repairs_unmodified_groups_and_protects_the_new_epoch() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut expected = fixture.original.clone();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x41; 100])
            .expect("new bytes in the first group");
        expected[..100].fill(0x41);
        fixture.damage(9 * 512, &[0xfe; 512]);
        fixture.damage(16 * 512, &[0xfe; 37]);
        fixture.damage_parity(&device, 2, 0);
        assert!(device.protection(&cx).is_err());
        device
            .sync(&cx)
            .expect("recover both untouched groups without a preparatory read");
        assert_eq!(std::fs::read(&fixture.image).expect("source"), expected);
        assert_eq!(
            device
                .protection(&cx)
                .expect("fresh coverage")
                .snapshot_blake3,
            blake3::hash(&expected).to_hex().to_string()
        );
        drop(device);
        let report = verify(&cx, &fixture.image, &fixture.sidecar).expect("archive");
        assert!(report.is_healthy());
        assert_eq!(report.invalid_repair_symbols, 0);
        drop(fixture.open());
        // The replacement archive must protect the new write, not merely the
        // recovered groups from the preceding snapshot.
        fixture.damage(0, &[0xfe; 512]);
        let restored = fixture.image.with_extension("sync-recovery-restored");
        restore(&cx, &fixture.image, &fixture.sidecar, &restored).expect("restore new epoch");
        assert_eq!(std::fs::read(restored).expect("restored"), expected);
    }

    #[test]
    fn dirty_sync_refuses_changed_targets_and_peers_without_rollback() {
        for damaged_block in [0, 1] {
            let fixture = Fixture::new();
            let device = fixture.open();
            let cx = Cx::for_testing();
            device
                .write_all_at(&cx, ByteOffset(0), &[0x41; 512])
                .expect("changed first block");
            fixture.damage(damaged_block * 512, &[0xfe; 512]);
            let source = std::fs::read(&fixture.image).expect("damaged source");
            let archive = std::fs::read(&fixture.sidecar).expect("pending archive");
            let intended = device.state.lock().changed.clone();
            let error = device.sync(&cx).expect_err("stale parity");
            assert!(error.to_string().contains("old parity"));
            assert!(error.to_string().contains("bless"));
            assert_eq!(std::fs::read(&fixture.image).expect("no rollback"), source);
            assert_eq!(
                std::fs::read(&fixture.sidecar).expect("no publication"),
                archive
            );
            assert_eq!(&archive[..8], PENDING_MAGIC);
            assert_eq!(device.state.lock().changed, intended);
            assert!(matches!(device.state.lock().phase, Phase::Dirty));
            assert!(device.protection(&cx).is_err());
            drop(device);
            assert!(Archive::open(&cx, &fixture.sidecar).is_err());
        }
    }

    #[test]
    fn dirty_sync_exhausted_parity_keeps_intended_writes_retryable() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut expected = fixture.original.clone();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x41; 100])
            .expect("first-group write");
        expected[..100].fill(0x41);
        fixture.damage(8 * 512, &[0xfe; 512]);
        for symbol in 0..4 {
            fixture.damage_parity(&device, 1, symbol);
        }
        let source = std::fs::read(&fixture.image).expect("damaged source");
        let archive = std::fs::read(&fixture.sidecar).expect("pending archive");
        let intended = device.state.lock().changed.clone();
        assert!(device.sync(&cx).is_err());
        assert_eq!(
            std::fs::read(&fixture.image).expect("unchanged source"),
            source
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("no publication"),
            archive
        );
        assert_eq!(device.state.lock().changed, intended);
        assert!(matches!(device.state.lock().phase, Phase::Dirty));
        assert!(device.protection(&cx).is_err());
        // An explicit complete replacement supplies known bytes; retry need not
        // decode discarded data or lose the earlier intended first-group write.
        device
            .write_all_at(
                &cx,
                ByteOffset(8 * 512),
                &fixture.original[8 * 512..9 * 512],
            )
            .expect("replace unrecoverable source explicitly");
        device.sync(&cx).expect("retry and replenish lost parity");
        assert_eq!(std::fs::read(&fixture.image).expect("source"), expected);
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("fresh protection")
                .is_healthy()
        );
        drop(fixture.open());
    }

    #[test]
    fn dirty_sync_cancellation_preserves_repair_targets_for_retry() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut expected = fixture.original.clone();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x41; 100])
            .expect("write");
        expected[..100].fill(0x41);
        fixture.damage(8 * 512, &[0xfe; 512]);
        let source = std::fs::read(&fixture.image).expect("damaged source");
        let archive = std::fs::read(&fixture.sidecar).expect("pending archive");
        cx.set_cancel_requested(true);
        assert!(matches!(device.sync(&cx), Err(FfsError::Cancelled)));
        assert_eq!(std::fs::read(&fixture.image).expect("no repair"), source);
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("no publication"),
            archive
        );
        device
            .sync(&Cx::for_testing())
            .expect("explicit retry recovers the unaffected group");
        assert_eq!(std::fs::read(&fixture.image).expect("source"), expected);
        drop(device);
        assert!(
            verify(&Cx::for_testing(), &fixture.image, &fixture.sidecar)
                .expect("fresh protection")
                .is_healthy()
        );
    }

    #[test]
    fn dirty_sync_repairs_groups_rewritten_to_the_admitted_generation() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x41; 512])
            .expect("change block");
        device
            .write_all_at(&cx, ByteOffset(0), &fixture.original[..512])
            .expect("restore its admitted bytes explicitly");
        assert!(device.state.lock().changed.contains_key(&0));
        fixture.damage(512, &[0xfe; 512]);
        device
            .sync(&cx)
            .expect("recorded writes alone do not make old parity stale");
        assert_eq!(
            std::fs::read(&fixture.image).expect("source"),
            fixture.original
        );
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("unchanged generation protected")
                .is_healthy()
        );
    }

    #[test]
    fn dirty_sync_does_not_repair_a_truncated_image_by_extending_it() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x41; 100])
            .expect("write");
        let shortened = device.len_bytes() - 1;
        File::options()
            .write(true)
            .open(&fixture.image)
            .expect("fault handle")
            .set_len(shortened)
            .expect("external truncation");
        let source = std::fs::read(&fixture.image).expect("truncated source");
        let archive = std::fs::read(&fixture.sidecar).expect("pending archive");
        let error = device.sync(&cx).expect_err("geometry mismatch");
        assert!(error.to_string().contains("length"));
        assert_eq!(
            std::fs::metadata(&fixture.image).expect("length").len(),
            shortened
        );
        assert_eq!(std::fs::read(&fixture.image).expect("no extension"), source);
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("no publication"),
            archive
        );
        assert!(device.protection(&cx).is_err());
    }

    #[test]
    fn dirty_sync_rejects_transplanted_tables_even_after_cached_reads() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut bytes = [0; 512];
        device
            .read_exact_at(&cx, ByteOffset(8 * 512), &mut bytes)
            .expect("cache the admitted group's hashes");
        device
            .write_all_at(&cx, ByteOffset(0), &[0x41; 512])
            .expect("write without evicting the cached group");
        fixture.damage(8 * 512, &[0xfe; 512]);
        {
            let state = device.state.lock();
            assert_eq!(
                state.cached_hashes.as_ref().map(|(group, _)| *group),
                Some(1)
            );
            let header = &state.archive.header;
            let offset = header.group_offset(1).expect("group offset");
            let (_, count) = header.group_geometry(1).expect("group geometry");
            let mut metadata = vec![0; GROUP_PREFIX_BYTES + count as usize * DIGEST_BYTES];
            state
                .archive
                .file
                .read_exact_at(&mut metadata, offset)
                .expect("metadata");
            let forged = source_digest(header, 8, &[0xfe; 512]);
            metadata[GROUP_PREFIX_BYTES..GROUP_PREFIX_BYTES + DIGEST_BYTES]
                .copy_from_slice(&forged);
            let digest = digest_parts(b"ffs-sidecar-group-v2", &[&header.seed, &metadata]);
            state
                .archive
                .file
                .write_all_at(&metadata, offset)
                .expect("forged table");
            state
                .archive
                .file
                .write_all_at(&digest, offset + metadata.len() as u64)
                .expect("locally valid table digest");
        }
        let source = std::fs::read(&fixture.image).expect("damaged source");
        let archive = std::fs::read(&fixture.sidecar).expect("transplanted archive");
        let error = device.sync(&cx).expect_err("unattested table");
        assert!(error.to_string().contains("admitted generation"));
        assert_eq!(std::fs::read(&fixture.image).expect("no rollback"), source);
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("no publication"),
            archive
        );
        assert!(device.protection(&cx).is_err());
    }

    #[test]
    fn dirty_sync_does_not_publish_repairs_before_a_later_group_failure() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut expected = fixture.original.clone();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x41; 100])
            .expect("write");
        expected[..100].fill(0x41);
        fixture.damage(8 * 512, &[0xfe; 512]);
        fixture.damage(16 * 512, &[0xfe; 37]);
        for symbol in 0..4 {
            fixture.damage_parity(&device, 2, symbol);
        }
        let archive = std::fs::read(&fixture.sidecar).expect("pending archive");
        let intended = device.state.lock().changed.clone();
        assert!(device.sync(&cx).is_err());
        let source = std::fs::read(&fixture.image).expect("partly repaired source");
        assert_eq!(&source[..16 * 512], &expected[..16 * 512]);
        assert_eq!(&source[16 * 512..], &[0xfe; 37]);
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("no publication"),
            archive
        );
        assert_eq!(&archive[..8], PENDING_MAGIC);
        assert_eq!(device.state.lock().changed, intended);
        assert!(device.protection(&cx).is_err());
        device
            .write_all_at(&cx, ByteOffset(16 * 512), &fixture.original[16 * 512..])
            .expect("explicit replacement of the unrecoverable tail");
        device.sync(&cx).expect("retry the entire publication");
        assert_eq!(std::fs::read(&fixture.image).expect("source"), expected);
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("all groups freshly protected")
                .is_healthy()
        );
        drop(fixture.open());
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
    fn dirty_read_repairs_another_group_without_publishing_pending_writes() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        // The final block of group zero must not invalidate group one's parity.
        device
            .write_all_at(&cx, ByteOffset(7 * 512), &[0x27; 512])
            .expect("write at group boundary");
        let mut expected = fixture.original.clone();
        expected[7 * 512..8 * 512].fill(0x27);
        let pending = std::fs::read(&fixture.sidecar).expect("pending archive");
        assert_eq!(&pending[..8], PENDING_MAGIC);
        fixture.damage(8 * 512, &[0xfe; 512]);
        let mut bytes = [0; 512];
        device
            .read_exact_at(&cx, ByteOffset(8 * 512), &mut bytes)
            .expect("unmodified group remains recoverable");
        assert_eq!(bytes.as_slice(), &expected[8 * 512..9 * 512]);
        assert_eq!(
            std::fs::read(&fixture.image).expect("repaired source"),
            expected
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("still pending"),
            pending
        );
        assert!(device.protection(&cx).is_err());
        assert!(Archive::open(&cx, &fixture.sidecar).is_err());
        device
            .sync(&cx)
            .expect("commit the actual intended generation");
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("fresh coverage")
                .is_healthy()
        );
        drop(fixture.open());
        fixture.damage(7 * 512, &[0xfe; 512]);
        let output = fixture.image.with_extension("dirty-read-restored");
        restore(&cx, &fixture.image, &fixture.sidecar, &output)
            .expect("new parity protects the pending write, not its predecessor");
        assert_eq!(
            std::fs::read(output).expect("restored new generation"),
            expected
        );
    }

    #[test]
    fn dirty_read_repairs_a_short_tail_without_extending_the_image() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x27; 512])
            .expect("pending write elsewhere");
        fixture.damage(16 * 512, &[0xfe; 37]);
        let pending = std::fs::read(&fixture.sidecar).expect("pending archive");
        let mut bytes = [0; 37];
        device
            .read_exact_at(&cx, ByteOffset(16 * 512), &mut bytes)
            .expect("recover complete tail group from parity");
        assert_eq!(bytes.as_slice(), &fixture.original[16 * 512..]);
        let mut expected = fixture.original.clone();
        expected[..512].fill(0x27);
        assert_eq!(
            std::fs::read(&fixture.image).expect("fixed-size source"),
            expected
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("still pending"),
            pending
        );
        assert!(device.protection(&cx).is_err());
        device.sync(&cx).expect("publish padded-tail protection");
    }

    #[test]
    fn dirty_partial_write_repairs_preserved_bytes_in_another_group() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x27; 512])
            .expect("first dirty group");
        fixture.damage(8 * 512, &[0xfe; 512]);
        let pending = std::fs::read(&fixture.sidecar).expect("pending archive");
        device
            .write_all_at(&cx, ByteOffset(8 * 512 + 13), &[0x58; 20])
            .expect("recover preserved bytes before editing the second group");
        let mut expected = fixture.original.clone();
        expected[..512].fill(0x27);
        expected[8 * 512 + 13..8 * 512 + 33].fill(0x58);
        assert_eq!(
            std::fs::read(&fixture.image).expect("intended source"),
            expected
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("still pending"),
            pending
        );
        let mut bytes = [0; 512];
        device
            .read_exact_at(&cx, ByteOffset(8 * 512), &mut bytes)
            .expect("read newly intended block");
        assert_eq!(bytes.as_slice(), &expected[8 * 512..9 * 512]);
        device.sync(&cx).expect("protect both changed groups");
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("updated parity")
                .is_healthy()
        );
    }

    #[test]
    fn dirty_repair_rejects_a_changed_peer_before_touching_any_source() {
        for damaged in [0, 512] {
            let fixture = Fixture::new();
            let device = fixture.open();
            let cx = Cx::for_testing();
            device
                .write_all_at(&cx, ByteOffset(0), &[0x27; 512])
                .expect("changed first block");
            fixture.damage(damaged, &[0xfe; 512]);
            let source = std::fs::read(&fixture.image).expect("damaged source");
            let pending = std::fs::read(&fixture.sidecar).expect("pending archive");
            // Exercise the common entry point directly: checking only a read's
            // target would wrongly allow recovery when its peer was written.
            {
                let state = device.lock(&cx).expect("state");
                assert!(device.repair_group(&cx, &state, 0).is_err());
            }
            let mut bytes = [0xa5; 512];
            let error = device
                .read_exact_at(&cx, ByteOffset(damaged), &mut bytes)
                .expect_err("old parity cannot restore this group");
            assert!(error.to_string().contains("old parity"));
            assert_eq!(bytes, [0xa5; 512]);
            assert_eq!(std::fs::read(&fixture.image).expect("no rollback"), source);
            assert_eq!(
                std::fs::read(&fixture.sidecar).expect("no publication"),
                pending
            );
        }
    }

    #[test]
    fn dirty_repair_accepts_a_group_rewritten_to_its_admitted_generation() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x27; 512])
            .expect("temporary new bytes");
        device
            .write_all_at(&cx, ByteOffset(0), &fixture.original[..512])
            .expect("explicitly restore the original intended bytes");
        let pending = std::fs::read(&fixture.sidecar).expect("still a dirty epoch");
        fixture.damage(512, &[0xfe; 512]);
        let mut bytes = [0; 512];
        device
            .read_exact_at(&cx, ByteOffset(512), &mut bytes)
            .expect("all intended digests again agree with the saved parity");
        assert_eq!(bytes.as_slice(), &fixture.original[512..1024]);
        assert_eq!(
            std::fs::read(&fixture.image).expect("restored source"),
            fixture.original
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("no early commit"),
            pending
        );
        assert!(device.protection(&cx).is_err());
        device.sync(&cx).expect("finish the epoch explicitly");
    }

    #[test]
    fn dirty_read_with_insufficient_parity_preserves_the_entire_output() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x27; 512])
            .expect("pending write in the other group");
        fixture.damage(8 * 512, &[0xfe; 8 * 512]);
        let source = std::fs::read(&fixture.image).expect("unrecoverable group");
        let pending = std::fs::read(&fixture.sidecar).expect("pending archive");
        // A valid prefix is read before the unrecoverable group. Neither that
        // prefix nor a partially reconstructed suffix may reach the caller.
        let mut bytes = [0xa5; 1024];
        assert!(
            device
                .read_exact_at(&cx, ByteOffset(7 * 512), &mut bytes)
                .is_err()
        );
        assert_eq!(bytes, [0xa5; 1024]);
        assert_eq!(
            std::fs::read(&fixture.image).expect("no partial repair"),
            source
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("no publication"),
            pending
        );
        assert!(device.protection(&cx).is_err());
    }

    #[test]
    fn dirty_read_rejects_a_transplanted_table_even_with_cached_source_hashes() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x27; 512])
            .expect("pending write elsewhere");
        let mut bytes = [0; 512];
        device
            .read_exact_at(&cx, ByteOffset(8 * 512), &mut bytes)
            .expect("cache the admitted table");
        fixture.damage(8 * 512, &[0xfe; 512]);
        {
            let state = device.lock(&cx).expect("state");
            let header = &state.archive.header;
            let (_, count) = header.group_geometry(1).expect("second group");
            let offset = header.group_offset(1).expect("group offset");
            let mut metadata = vec![0; GROUP_PREFIX_BYTES + count as usize * DIGEST_BYTES];
            state
                .archive
                .file
                .read_exact_at(&mut metadata, offset)
                .expect("group metadata");
            let forged = source_digest(header, 8, &[0xfe; 512]);
            metadata[GROUP_PREFIX_BYTES..GROUP_PREFIX_BYTES + DIGEST_BYTES]
                .copy_from_slice(&forged);
            let digest = digest_parts(b"ffs-sidecar-group-v2", &[&header.seed, &metadata]);
            state
                .archive
                .file
                .write_all_at(&metadata, offset)
                .expect("inject another internally consistent table");
            state
                .archive
                .file
                .write_all_at(&digest, offset + metadata.len() as u64)
                .expect("matching local table checksum");
        }
        let source = std::fs::read(&fixture.image).expect("damaged source");
        let archive = std::fs::read(&fixture.sidecar).expect("transplanted archive");
        bytes.fill(0xa5);
        let error = device
            .read_exact_at(&cx, ByteOffset(8 * 512), &mut bytes)
            .expect_err("a locally valid table is not an admitted generation");
        assert!(error.to_string().contains("admitted generation"));
        assert_eq!(bytes, [0xa5; 512]);
        assert_eq!(
            std::fs::read(&fixture.image).expect("unchanged source"),
            source
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("no publication"),
            archive
        );
    }

    #[test]
    fn complete_group_overwrite_does_not_require_recovering_discarded_bytes() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut expected = fixture.original.clone();
        // Eight damaged sources exceed this group's four-symbol repair budget.
        fixture.damage(0, &[0xfe; 8 * 512]);
        device
            .write_all_at(&cx, ByteOffset(0), &[0x27; 8 * 512])
            .expect("explicit replacement needs none of the discarded bytes");
        expected[..8 * 512].fill(0x27);
        assert!(device.protection(&cx).is_err());
        device
            .sync(&cx)
            .expect("commit replacement and fresh parity");
        assert_eq!(std::fs::read(&fixture.image).expect("new source"), expected);
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("new protection")
                .is_healthy()
        );
        drop(fixture.open());
        fixture.damage(512, &[0xfe; 512]);
        let output = fixture.image.with_extension("replacement-restored");
        restore(&cx, &fixture.image, &fixture.sidecar, &output).expect("recover new generation");
        assert_eq!(
            std::fs::read(output).expect("restored replacement"),
            expected
        );
    }

    #[test]
    fn complete_overwrite_replaces_a_damaged_dirty_epoch_block() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x27; 512])
            .expect("first write");
        fixture.damage(0, &[0xfe; 512]);
        device
            .write_all_at(&cx, ByteOffset(0), &[0x58; 512])
            .expect("replace without using stale parity");
        let mut expected = fixture.original.clone();
        expected[..512].fill(0x58);
        device.sync(&cx).expect("commit latest intended bytes");
        assert_eq!(std::fs::read(&fixture.image).expect("source"), expected);
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("latest protection")
                .is_healthy()
        );
    }

    #[test]
    fn complete_short_tail_overwrite_needs_no_parity_and_keeps_zero_padding() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        for symbol in 0..4 {
            fixture.damage_parity(&device, 2, symbol);
        }
        fixture.damage(16 * 512, &[0xfe; 37]);
        device
            .write_all_at(&cx, ByteOffset(16 * 512), &[0x58; 37])
            .expect("replace every real byte of the partial final block");
        let mut expected = fixture.original.clone();
        expected[16 * 512..].fill(0x58);
        device
            .sync(&cx)
            .expect("regenerate padded source protection");
        assert_eq!(
            std::fs::read(&fixture.image).expect("fixed-size image"),
            expected
        );
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("padded digest and parity")
                .is_healthy()
        );
        drop(fixture.open());
    }

    #[test]
    fn mixed_write_does_not_publish_full_blocks_before_a_bad_partial_suffix() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        // The full-block prefix is replaceable, but the one-byte suffix must
        // preserve source bytes from an entirely unrecoverable second group.
        fixture.damage(8 * 512, &[0xfe; 8 * 512]);
        let source = std::fs::read(&fixture.image).expect("damaged source");
        let archive = std::fs::read(&fixture.sidecar).expect("saved archive");
        assert!(
            device
                .write_all_at(&cx, ByteOffset(0), &[0x58; 8 * 512 + 1])
                .is_err()
        );
        assert_eq!(
            std::fs::read(&fixture.image).expect("no prefix written"),
            source
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("no new epoch"),
            archive
        );
    }

    #[test]
    fn partial_overwrite_still_refuses_corrupt_dirty_epoch_bytes() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x27; 512])
            .expect("start dirty epoch");
        fixture.damage(512, &[0xfe; 512]);
        let source = std::fs::read(&fixture.image).expect("damaged source");
        let archive = std::fs::read(&fixture.sidecar).expect("pending archive");
        let error = device
            .write_all_at(&cx, ByteOffset(515), &[0x58; 20])
            .expect_err("partial write must not preserve unknown bytes");
        assert!(error.to_string().contains("old parity"));
        assert_eq!(std::fs::read(&fixture.image).expect("source"), source);
        assert_eq!(std::fs::read(&fixture.sidecar).expect("archive"), archive);
        assert!(device.protection(&cx).is_err());
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
                device
                    .fence(&cx, &mut state)
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
    fn clean_reads_repair_a_completely_erased_partial_tail_group() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let archive = std::fs::read(&fixture.sidecar).expect("saved parity");
        fixture.damage(16 * 512, &[0xfe; 37]);
        let mut bytes = [0x99; 23];
        device
            .read_exact_at(&cx, ByteOffset(16 * 512 + 7), &mut bytes)
            .expect("parity-only recovery of the sole tail block");
        assert_eq!(&bytes, &fixture.original[16 * 512 + 7..16 * 512 + 30]);
        assert_eq!(
            std::fs::read(&fixture.image).expect("repaired image"),
            fixture.original
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("unchanged parity"),
            archive
        );
        drop(device);
        drop(fixture.open());
    }

    #[test]
    fn clean_scrub_reconstructs_a_completely_erased_multiblock_tail_group() {
        let mut fixture = Fixture::new();
        fixture.original.resize(19 * 512 + 37, 0x46);
        std::fs::write(&fixture.image, &fixture.original).expect("longer source");
        let sidecar = fixture.sidecar.with_extension("six-parity");
        let cx = Cx::for_testing();
        protect(
            &cx,
            &fixture.image,
            &sidecar,
            SidecarOptions {
                block_size: 512,
                group_blocks: 8,
                repair_symbols: 6,
            },
        )
        .expect("six equations protect the four-block tail");
        let device = SidecarImageDevice::open(&cx, &fixture.image, &sidecar).expect("admit");
        fixture.damage(16 * 512, &[0xfe; 3 * 512 + 37]);
        assert_eq!(device.scrub(&cx).expect("recover all four sources"), 4);
        assert_eq!(
            std::fs::read(&fixture.image).expect("repaired image"),
            fixture.original
        );
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &sidecar)
                .expect("verify")
                .is_healthy()
        );
    }

    #[test]
    fn partial_write_recovers_a_completely_erased_tail_before_preserving_its_bytes() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let mut expected = fixture.original.clone();
        fixture.damage(16 * 512, &[0xfe; 37]);
        device
            .write_all_at(&cx, ByteOffset(16 * 512 + 9), &[0x27; 11])
            .expect("repair the bytes outside the partial write first");
        expected[16 * 512 + 9..16 * 512 + 20].fill(0x27);
        device
            .sync(&cx)
            .expect("acknowledge repaired source and new parity");
        assert_eq!(std::fs::read(&fixture.image).expect("new image"), expected);
        drop(device);
        drop(fixture.open());
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("verify")
                .is_healthy()
        );
    }

    #[test]
    fn complete_group_loss_beyond_parity_budget_preserves_source_and_destination() {
        let fixture = Fixture::new();
        let device = fixture.open();
        fixture.damage(0, &[0xfe; 8 * 512]);
        let before = std::fs::read(&fixture.image).expect("damaged source");
        let archive = std::fs::read(&fixture.sidecar).expect("saved parity");
        let mut output = [0x99; 64];
        assert!(matches!(
            device.read_exact_at(&Cx::for_testing(), ByteOffset(7), &mut output),
            Err(FfsError::RepairFailed(_))
        ));
        assert_eq!(output, [0x99; 64]);
        assert_eq!(
            std::fs::read(&fixture.image).expect("unchanged source"),
            before
        );
        assert_eq!(
            std::fs::read(&fixture.sidecar).expect("unchanged parity"),
            archive
        );
    }

    #[test]
    fn clean_scrub_rebuilds_all_lost_parity_without_changing_the_snapshot() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let saved = device.protection(&cx).expect("saved protection");
        for symbol in 0..4 {
            fixture.damage_parity(&device, 0, symbol);
        }
        assert_eq!(device.scrub(&cx).expect("rebuild parity"), 0);
        assert_eq!(device.protection(&cx).expect("same snapshot"), saved);
        assert_eq!(
            std::fs::read(&fixture.image).expect("unchanged source"),
            fixture.original
        );
        let named = File::options()
            .read(true)
            .write(true)
            .open(&fixture.sidecar)
            .expect("published archive");
        assert!(named.try_lock().is_err());
        drop(device);
        drop(named);
        let report = verify(&cx, &fixture.image, &fixture.sidecar).expect("reopen");
        assert_eq!(report.invalid_repair_symbols, 0);
        assert!(report.is_healthy());
        drop(fixture.open());
    }

    #[test]
    fn clean_scrub_repairs_source_and_replenishes_damaged_parity_together() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        fixture.damage_parity(&device, 2, 0);
        fixture.damage(16 * 512, &[0xfe; 37]);
        assert_eq!(device.scrub(&cx).expect("repair source and parity"), 1);
        assert_eq!(
            std::fs::read(&fixture.image).expect("restored source"),
            fixture.original
        );
        drop(device);
        let report = verify(&cx, &fixture.image, &fixture.sidecar).expect("reopen");
        assert_eq!(report.invalid_repair_symbols, 0);
        assert!(report.is_healthy());
    }

    #[test]
    fn clean_scrub_restores_a_corrupted_header_from_the_admitted_generation() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        let saved = device.protection(&cx).expect("saved protection");
        File::options()
            .write(true)
            .open(&fixture.sidecar)
            .expect("archive fault handle")
            .write_all_at(b"BADHDR!!", 0)
            .expect("damage header");
        assert_eq!(device.scrub(&cx).expect("rebuild header"), 0);
        assert_eq!(device.protection(&cx).expect("same snapshot"), saved);
        drop(device);
        assert!(
            verify(&cx, &fixture.image, &fixture.sidecar)
                .expect("reopen repaired header")
                .is_healthy()
        );
        drop(fixture.open());
    }

    #[test]
    fn scrub_does_not_rebuild_parity_from_unrecoverable_source() {
        let fixture = Fixture::new();
        let device = fixture.open();
        fixture.damage_parity(&device, 0, 0);
        fixture.damage(0, &[0xfe; 8 * 512]);
        let source = std::fs::read(&fixture.image).expect("damaged source");
        let archive = std::fs::read(&fixture.sidecar).expect("damaged archive");
        assert!(device.scrub(&Cx::for_testing()).is_err());
        assert_eq!(std::fs::read(&fixture.image).expect("source"), source);
        assert_eq!(std::fs::read(&fixture.sidecar).expect("archive"), archive);
    }

    #[test]
    fn cancelled_parity_scrub_preserves_evidence_and_can_be_retried() {
        let fixture = Fixture::new();
        let device = fixture.open();
        fixture.damage_parity(&device, 0, 0);
        let archive = std::fs::read(&fixture.sidecar).expect("damaged archive");
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        assert!(matches!(device.scrub(&cx), Err(FfsError::Cancelled)));
        assert_eq!(std::fs::read(&fixture.sidecar).expect("archive"), archive);
        assert_eq!(
            std::fs::read(&fixture.image).expect("source"),
            fixture.original
        );
        assert_eq!(device.scrub(&Cx::for_testing()).expect("retry"), 0);
        drop(device);
        assert!(
            verify(&Cx::for_testing(), &fixture.image, &fixture.sidecar)
                .expect("fresh protection")
                .is_healthy()
        );
    }

    #[test]
    fn dirty_scrub_cannot_republish_the_preceding_generation() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();
        device
            .write_all_at(&cx, ByteOffset(0), &[0x27; 512])
            .expect("new source write");
        fixture.damage_parity(&device, 1, 0);
        let source = std::fs::read(&fixture.image).expect("new source");
        let archive = std::fs::read(&fixture.sidecar).expect("pending archive");
        assert!(device.scrub(&cx).is_err());
        assert!(device.protection(&cx).is_err());
        assert_eq!(std::fs::read(&fixture.image).expect("source"), source);
        assert_eq!(std::fs::read(&fixture.sidecar).expect("archive"), archive);
        drop(device);
        assert!(Archive::open(&cx, &fixture.sidecar).is_err());
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

    fn zfs_mirror_binding(txg: u64, generation: u64, seed: u8) -> NativeCommitBinding {
        NativeCommitBinding::Zfs {
            pool_guid: 0x5A46_535F_5445_5354,
            top_guid: 0x7777_8888_9999_AAAA,
            member_guids: vec![0x1001_0000_0000_0001, 0x1002_0000_0000_0002],
            guid_sum: 0x5A46_535F_5445_5354_u64
                .wrapping_add(0x7777_8888_9999_AAAA)
                .wrapping_add(0x1001_0000_0000_0001)
                .wrapping_add(0x1002_0000_0000_0002),
            version: 5000,
            ashift: 9,
            asize: 16 * 512,
            label_txg: 20,
            committed_txg: txg,
            published_slot: u32::try_from(txg % 128).unwrap(),
            root_bp_blake3: [seed; 32],
            generation,
            operation_digest: [seed.wrapping_add(1); 32],
        }
    }

    fn copy_storage_set_cut(
        manifest: &Path,
        members: &[(PathBuf, PathBuf)],
    ) -> (tempfile::TempDir, PathBuf, Vec<(PathBuf, PathBuf)>) {
        let cut_dir = tempfile::tempdir().expect("cut dir");
        let cut_manifest = cut_dir.path().join("set.ffsrqset");
        std::fs::copy(manifest, &cut_manifest).expect("copy manifest");
        let mut cut_members = Vec::with_capacity(members.len());
        for (idx, (img, rq)) in members.iter().enumerate() {
            let dst_img = cut_dir.path().join(format!("m{idx}.img"));
            let rq_name = rq.file_name().unwrap();
            let dst_rq = cut_dir.path().join(rq_name);
            std::fs::copy(img, &dst_img).expect("copy img");
            std::fs::copy(rq, &dst_rq).expect("copy rq");
            cut_members.push((dst_img, dst_rq));
        }
        (cut_dir, cut_manifest, cut_members)
    }

    #[test]
    fn bd_tqrnc_storage_set_persistence_prefix_multi_device_cuts_and_ack_ledger() {
        let _flock_holder = crate::sidecar::test_flock_holder();
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let m0_img = dir.path().join("m0.img");
        let m0_rq = dir.path().join("m0.ffsrq");
        let m1_img = dir.path().join("m1.img");
        let m1_rq = dir.path().join("m1.ffsrq");
        let manifest_path = dir.path().join("pool.ffsrqset");
        let ledger_path = dir.path().join("evidence.jsonl");

        let g1_m0: Vec<u8> = (0_u32..(16 * 512))
            .map(|i| u8::try_from((i * 7 + 3) % 251).unwrap())
            .collect();
        let g1_m1: Vec<u8> = (0_u32..(16 * 512))
            .map(|i| u8::try_from((i * 11 + 5) % 251).unwrap())
            .collect();
        std::fs::write(&m0_img, &g1_m0).unwrap();
        std::fs::write(&m1_img, &g1_m1).unwrap();

        let key: PorKey = [0x42; 32];
        let mut id0 = [0_u8; 16];
        id0[..8].copy_from_slice(&0x1001_0000_0000_0001_u64.to_le_bytes());
        let mut id1 = [0_u8; 16];
        id1[..8].copy_from_slice(&0x1002_0000_0000_0002_u64.to_le_bytes());

        let g1_binding = zfs_mirror_binding(20, 0, 0x11);
        let manifest = protect_storage_set(
            &cx,
            &StorageSetProtectRequest {
                manifest_path: manifest_path.clone(),
                filesystem: "zfs".to_owned(),
                topology: StorageSetTopology::ZfsMirror { width: 2 },
                view: ProtectedViewIdentity {
                    partition_selector: None,
                    zfs_dataset: vec!["data".to_owned()],
                    btrfs_subvolume_id: None,
                },
                native_binding: g1_binding,
                members: vec![
                    StorageSetMemberSpec {
                        role: MemberRole::Data,
                        image_path: m0_img.clone(),
                        sidecar_path: m0_rq.clone(),
                        native_member_id: id0,
                        offset: 0,
                        length: None,
                    },
                    StorageSetMemberSpec {
                        role: MemberRole::Data,
                        image_path: m1_img.clone(),
                        sidecar_path: m1_rq.clone(),
                        native_member_id: id1,
                        offset: 0,
                        length: None,
                    },
                ],
                options: SidecarOptions {
                    block_size: 512,
                    group_blocks: 8,
                    repair_symbols: 4,
                },
                signing_key: Some(key),
            },
        )
        .expect("protect 2-member ZFS mirror set");
        assert_eq!(manifest.generation, 1);
        assert!(manifest.is_authenticated());

        let member_paths = vec![(m0_img.clone(), m0_rq.clone()), (m1_img.clone(), m1_rq)];

        // Cut 0: verified G_1 set admits cleanly under RequireTrustedRoot and rejects wrong PorKey.
        let verified_g1 = verify_storage_set(
            &cx,
            &manifest_path,
            &member_paths,
            TrustPolicy::RequireTrustedRoot { key },
        )
        .expect("verify G_1");
        assert!(verified_g1.is_healthy());
        assert!(
            verify_storage_set(
                &cx,
                &manifest_path,
                &member_paths,
                TrustPolicy::RequireTrustedRoot { key: [0x99; 32] },
            )
            .is_err(),
            "wrong PorKey must refuse manifest verification"
        );

        let ledger = open_shared_evidence_ledger(&ledger_path).expect("open ledger");
        let open_opts = StorageSetOpenOptions {
            read_only: false,
            allow_automatic_repair: true,
            trust_policy: TrustPolicy::RequireTrustedRoot { key },
            signing_key: Some(key),
            calibration: Some(RepairLossCalibration::default_operator_exclusive()),
            evidence_ledger: Some(Arc::clone(&ledger)),
        };
        let set =
            ProtectedStorageSet::open_manifest(&cx, &manifest_path, &member_paths, &open_opts)
                .expect("admit live storage set");
        assert!(set.is_authenticated());
        let ack0 = set.ack_status();
        assert!(ack0.native_durable);
        assert!(ack0.protected_durable);
        assert_eq!(ack0.epoch_generation, 1);
        assert!(ack0.post_commit_error.is_none());

        let dev0 = set.members()[0].open_bounded_device(true).unwrap();
        let dev1 = set.members()[1].open_bounded_device(true).unwrap();

        // Cut 1: Multi-barrier durability deferral + member 0 write + intermediate barrier.
        // Neither member archive nor manifest may prematurely seal!
        dev0.begin_durability_commit(&cx).unwrap();
        dev1.begin_durability_commit(&cx).unwrap();
        dev0.write_all_at(&cx, ByteOffset(2 * 512), &[0xA5; 512])
            .unwrap();
        dev0.sync(&cx).expect("intermediate child-block barrier");

        assert_eq!(
            &std::fs::read(&manifest_path).unwrap()[..8],
            SET_PENDING_MAGIC
        );
        assert_eq!(&std::fs::read(&m0_rq).unwrap()[..8], PENDING_MAGIC);
        let ack1 = set.ack_status();
        assert!(!ack1.native_durable);
        assert!(!ack1.protected_durable);

        {
            let (_cut_dir, cut_manifest, cut_members) =
                copy_storage_set_cut(&manifest_path, &member_paths);
            let cut_before_m0 = std::fs::read(&cut_members[0].0).unwrap();
            assert!(
                ProtectedStorageSet::open_manifest(
                    &cx,
                    &cut_manifest,
                    &cut_members,
                    &StorageSetOpenOptions {
                        evidence_ledger: None,
                        ..open_opts.clone()
                    },
                )
                .is_err(),
                "Cut 1 (in-flight uncommitted epoch) must refuse live admission"
            );
            assert_eq!(
                std::fs::read(&cut_members[0].0).unwrap(),
                cut_before_m0,
                "refusal at Cut 1 must never roll back or mutate member bytes"
            );
        }

        // Cut 2: Both members complete native commit (`native_durable = true`),
        // BEFORE parity refresh (`protected_durable = false`).
        dev1.write_all_at(&cx, ByteOffset(2 * 512), &[0xB6; 512])
            .unwrap();
        dev1.sync(&cx).expect("member 1 intermediate barrier");
        dev0.complete_durability_commit();
        dev1.complete_durability_commit();
        let g2_binding = zfs_mirror_binding(21, 1, 0x22);
        set.record_native_commit(&g2_binding);

        let ack2 = set.ack_status();
        assert!(
            ack2.native_durable && !ack2.protected_durable,
            "Cut 2 must report native_durable=true and protected_durable=false separately: {ack2:?}"
        );

        // Cut 3: Torn 1-of-2 member seal (member 0 sealed, member 1 still dirty, manifest fenced).
        set.members()[0]
            .device
            .sync(&cx)
            .expect("seal member 0 only");
        assert!(set.members()[0].device.ack_status().protected_durable);
        assert!(!set.members()[1].device.ack_status().protected_durable);
        assert!(!set.ack_status().protected_durable);
        {
            let (_cut_dir, cut_manifest, cut_members) =
                copy_storage_set_cut(&manifest_path, &member_paths);
            assert!(
                verify_storage_set(
                    &cx,
                    &cut_manifest,
                    &cut_members,
                    TrustPolicy::RequireTrustedRoot { key },
                )
                .is_err(),
                "Cut 3 (torn 1-of-2 member seal with pending manifest) must fail verification"
            );
            assert!(
                ProtectedStorageSet::open_manifest(
                    &cx,
                    &cut_manifest,
                    &cut_members,
                    &StorageSetOpenOptions {
                        evidence_ledger: None,
                        ..open_opts.clone()
                    },
                )
                .is_err(),
                "Cut 3 must refuse live storage-set admission"
            );
        }

        // Cut 4: Complete whole-set seal (`G_2`) and verify authenticated manifest + self-healing!
        set.seal_committed(&cx, g2_binding.clone())
            .expect("seal whole storage set G_2");
        let ack4 = set.ack_status();
        assert!(ack4.native_durable);
        assert!(ack4.protected_durable);
        assert_eq!(ack4.epoch_generation, 2);
        assert!(ack4.post_commit_error.is_none());
        assert_eq!(set.manifest().unwrap().native_binding, g2_binding);

        let mut expected_m0 = g1_m0;
        expected_m0[2 * 512..3 * 512].fill(0xA5);
        let mut expected_m1 = g1_m1;
        expected_m1[2 * 512..3 * 512].fill(0xB6);
        drop(dev0);
        drop(dev1);
        drop(set);

        let verified_g2 = verify_storage_set(
            &cx,
            &manifest_path,
            &member_paths,
            TrustPolicy::RequireTrustedRoot { key },
        )
        .expect("verify G_2");
        assert!(verified_g2.is_healthy());
        assert_eq!(verified_g2.manifest.generation, 2);
        assert_eq!(verified_g2.manifest.native_binding, g2_binding);

        // Reopen G_2, inject 2-block media corruption in BOTH members, and prove read self-healing
        // restores G_2 (never rolling back to G_1) and logs ProtectedRepairGate decisions!
        let reopened =
            ProtectedStorageSet::open_manifest(&cx, &manifest_path, &member_paths, &open_opts)
                .expect("reopen G_2");
        File::options()
            .write(true)
            .open(&m0_img)
            .unwrap()
            .write_all_at(&[0xEE; 1024], 2 * 512)
            .unwrap();
        File::options()
            .write(true)
            .open(&m1_img)
            .unwrap()
            .write_all_at(&[0xDD; 1024], 2 * 512)
            .unwrap();

        let r_dev0 = reopened.members()[0].open_bounded_device(false).unwrap();
        let r_dev1 = reopened.members()[1].open_bounded_device(false).unwrap();
        let mut buf0 = vec![0_u8; 16 * 512];
        let mut buf1 = vec![0_u8; 16 * 512];
        r_dev0.read_exact_at(&cx, ByteOffset(0), &mut buf0).unwrap();
        r_dev1.read_exact_at(&cx, ByteOffset(0), &mut buf1).unwrap();
        assert_eq!(buf0, expected_m0);
        assert_eq!(buf1, expected_m1);
        assert_eq!(std::fs::read(&m0_img).unwrap(), expected_m0);
        assert_eq!(std::fs::read(&m1_img).unwrap(), expected_m1);
        drop(r_dev0);
        drop(r_dev1);
        drop(reopened);

        let records = crate::evidence::parse_evidence_ledger(&std::fs::read(&ledger_path).unwrap());
        assert!(
            records.iter().any(|r| {
                r.protected_commit_ack
                    .as_ref()
                    .is_some_and(|ack| ack.native_durable && !ack.protected_durable)
            }),
            "ledger must record unprotected native-durable interval"
        );
        assert!(
            records.iter().any(|r| {
                r.protected_commit_ack
                    .as_ref()
                    .is_some_and(|ack| ack.native_durable && ack.protected_durable)
            }),
            "ledger must record sealed protected-durable acknowledgment"
        );
        assert!(
            records.iter().any(|r| {
                r.protected_repair_gate.as_ref().is_some_and(|gate| {
                    gate.authorized
                        && gate.authenticated_provenance
                        && gate.expected_repair_loss.unwrap_or(f64::INFINITY)
                            < gate.refusal_loss.unwrap_or(0.0)
                })
            }),
            "ledger must record authorized two-stage expected-loss repair gate"
        );
    }

    #[test]
    fn bd_tqrnc_expected_loss_gate_and_provenance_refusal_controls() {
        let _flock_holder = crate::sidecar::test_flock_holder();
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let img = dir.path().join("single.img");
        let rq = dir.path().join("single.ffsrq");
        let ledger_path = dir.path().join("refusal.jsonl");
        let orig: Vec<u8> = (0_u32..(16 * 512))
            .map(|i| u8::try_from((i * 13 + 7) % 251).unwrap())
            .collect();
        std::fs::write(&img, &orig).unwrap();
        protect(
            &cx,
            &img,
            &rq,
            SidecarOptions {
                block_size: 512,
                group_blocks: 8,
                repair_symbols: 4,
            },
        )
        .unwrap();

        // 1. Standalone unkeyed sidecar MUST refuse RequireTrustedRoot.
        let key: PorKey = [0x55; 32];
        let unauth_err = ProtectedStorageSet::open_standalone(
            &cx,
            &img,
            &rq,
            0,
            None,
            &StorageSetOpenOptions {
                trust_policy: TrustPolicy::RequireTrustedRoot { key },
                ..StorageSetOpenOptions::default()
            },
        )
        .expect_err("unkeyed standalone checksums are not authenticated provenance");
        assert!(unauth_err.to_string().contains("trusted-root provenance"));

        // 2. Missing calibration (`None`) MUST refuse automatic repair writeback and log ProtectedRepairGate(authorized=false).
        let ledger = open_shared_evidence_ledger(&ledger_path).unwrap();
        {
            let set_no_cal = ProtectedStorageSet::open_standalone(
                &cx,
                &img,
                &rq,
                0,
                None,
                &StorageSetOpenOptions {
                    calibration: None,
                    evidence_ledger: Some(Arc::clone(&ledger)),
                    ..StorageSetOpenOptions::default()
                },
            )
            .unwrap();
            File::options()
                .write(true)
                .open(&img)
                .unwrap()
                .write_all_at(&[0xEE; 512], 0)
                .unwrap();
            let corrupted_snapshot = std::fs::read(&img).unwrap();
            let mut buf = [0_u8; 512];
            let err = set_no_cal
                .primary_device()
                .read_exact_at(&cx, ByteOffset(0), &mut buf)
                .expect_err("missing calibration must refuse automatic repair");
            assert!(
                err.to_string().contains("MissingCalibration"),
                "unexpected error: {err}"
            );
            assert_eq!(
                std::fs::read(&img).unwrap(),
                corrupted_snapshot,
                "missing calibration refusal must not write to backing image"
            );
        }
        std::fs::write(&img, &orig).unwrap();

        // 3. Unfavorable calibration ((1 - q)*L_wrong + C_repair > L_refusal) MUST refuse writeback.
        {
            let unfavorable = RepairLossCalibration {
                c_repair: 10.0,
                l_wrong: 10_000.0,
                l_refusal: 100.0,
                q_correct: 0.5,
                provenance: "adversarial-high-wrong-loss".to_owned(),
            };
            let set_unfav = ProtectedStorageSet::open_standalone(
                &cx,
                &img,
                &rq,
                0,
                None,
                &StorageSetOpenOptions {
                    calibration: Some(unfavorable),
                    evidence_ledger: Some(Arc::clone(&ledger)),
                    ..StorageSetOpenOptions::default()
                },
            )
            .unwrap();
            File::options()
                .write(true)
                .open(&img)
                .unwrap()
                .write_all_at(&[0xCC; 512], 512)
                .unwrap();
            let corrupted_snapshot = std::fs::read(&img).unwrap();
            let mut buf = [0_u8; 512];
            let err = set_unfav
                .primary_device()
                .read_exact_at(&cx, ByteOffset(512), &mut buf)
                .expect_err("unfavorable expected loss must refuse automatic repair");
            assert!(
                err.to_string().contains("ExpectedLossNotLowerThanRefusal"),
                "unexpected error: {err}"
            );
            assert_eq!(std::fs::read(&img).unwrap(), corrupted_snapshot);
        }
        std::fs::write(&img, &orig).unwrap();

        let records = crate::evidence::parse_evidence_ledger(&std::fs::read(&ledger_path).unwrap());
        let refusals = records
            .iter()
            .filter(|r| {
                r.protected_repair_gate
                    .as_ref()
                    .is_some_and(|g| !g.authorized)
            })
            .count();
        assert!(
            refusals >= 2,
            "expected >= 2 logged repair-gate refusals, got {refusals}"
        );

        // 4. Unsigned manifest refused under RequireTrustedRoot; stale G_1 member archive and swapped
        // member archives refused after G_2 legitimate write without rolling back!
        let m1_img = dir.path().join("m1.img");
        let m1_rq = dir.path().join("m1.ffsrq");
        std::fs::write(&m1_img, &orig).unwrap();
        let unsigned_manifest = dir.path().join("unsigned.ffsrqset");
        protect_storage_set(
            &cx,
            &StorageSetProtectRequest {
                manifest_path: unsigned_manifest.clone(),
                filesystem: "zfs".to_owned(),
                topology: StorageSetTopology::ZfsMirror { width: 2 },
                view: ProtectedViewIdentity::default(),
                native_binding: zfs_mirror_binding(20, 0, 0x31),
                members: vec![
                    StorageSetMemberSpec {
                        role: MemberRole::Data,
                        image_path: img.clone(),
                        sidecar_path: rq.clone(),
                        native_member_id: [1; 16],
                        offset: 0,
                        length: None,
                    },
                    StorageSetMemberSpec {
                        role: MemberRole::Data,
                        image_path: m1_img.clone(),
                        sidecar_path: m1_rq.clone(),
                        native_member_id: [2; 16],
                        offset: 0,
                        length: None,
                    },
                ],
                options: SidecarOptions {
                    block_size: 512,
                    group_blocks: 8,
                    repair_symbols: 4,
                },
                signing_key: None,
            },
        )
        .unwrap();
        let members = vec![(img.clone(), rq.clone()), (m1_img.clone(), m1_rq.clone())];
        assert!(
            verify_storage_set(
                &cx,
                &unsigned_manifest,
                &members,
                TrustPolicy::RequireTrustedRoot { key },
            )
            .is_err(),
            "unsigned manifest must fail RequireTrustedRoot"
        );

        let g1_rq0_saved = std::fs::read(&rq).unwrap();
        {
            let set = ProtectedStorageSet::open_manifest(
                &cx,
                &unsigned_manifest,
                &members,
                &StorageSetOpenOptions::default(),
            )
            .unwrap();
            let d0 = set.members()[0].open_bounded_device(true).unwrap();
            d0.write_all_at(&cx, ByteOffset(0), &[0x77; 512]).unwrap();
            set.seal_committed(&cx, zfs_mirror_binding(21, 1, 0x32))
                .unwrap();
        }
        let g2_img0 = std::fs::read(&img).unwrap();

        // Swapped member sidecars refused!
        let swapped = vec![(img.clone(), m1_rq), (m1_img, rq.clone())];
        assert!(
            ProtectedStorageSet::open_manifest(
                &cx,
                &unsigned_manifest,
                &swapped,
                &StorageSetOpenOptions::default(),
            )
            .is_err(),
            "swapped member archives must be refused"
        );

        // Transplant checksum-valid stale G_1 archive onto member 0 after G_2 seal -> refused, never rolled back!
        std::fs::write(&rq, &g1_rq0_saved).unwrap();
        assert!(
            verify_storage_set(
                &cx,
                &unsigned_manifest,
                &members,
                TrustPolicy::AllowUnauthenticated,
            )
            .is_err(),
            "stale G_1 member archive must fail G_2 manifest verification"
        );
        assert!(
            ProtectedStorageSet::open_manifest(
                &cx,
                &unsigned_manifest,
                &members,
                &StorageSetOpenOptions::default(),
            )
            .is_err(),
            "stale G_1 member archive must fail live admission"
        );
        assert_eq!(
            std::fs::read(&img).unwrap(),
            g2_img0,
            "stale G_1 archive must never roll member 0 back to G_1"
        );
    }

    #[test]
    fn bd_tqrnc_abort_durability_commit_after_escaped_write_poisons_and_refuses_seal() {
        let fixture = Fixture::new();
        let device = fixture.open();
        let cx = Cx::for_testing();

        device.begin_durability_commit(&cx).unwrap();
        device
            .write_all_at(&cx, ByteOffset(512), &[0xAB; 512])
            .unwrap();
        device.abort_durability_commit();

        let err = device.sync(&cx).expect_err(
            "aborted multi-barrier commit with escaped writes must poison and refuse seal",
        );
        assert!(err.to_string().contains("poisoned"));
        let status = device.ack_status();
        assert!(!status.native_durable);
        assert!(!status.protected_durable);
        drop(device);

        // Pending archive header (`FFSRQPD2`) guarantees reopen also refuses uncommitted state!
        assert!(SidecarImageDevice::open(&cx, &fixture.image, &fixture.sidecar).is_err());
    }
}
