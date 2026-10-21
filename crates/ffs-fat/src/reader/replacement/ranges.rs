//! Bounded streaming sources for native range writes and truncation.
//!
//! Old payload, patch bytes and zero extension are composed on demand, never in
//! a file-sized Vec. Native range updates retain allocation and initialize only
//! newly exposed bytes; explicit offline replacement keeps its separate COW
//! protocol. In-place range updates are ordered, not crash-atomic overwrites.

mod native;

use super::super::{FatVolume, FileChain};
use super::{
    EXPECT_END, HASH_BYTES, Replacement, allocate, change_fat, checkpoint, hash_device,
    modified_timestamp, set_dirty, set_hints, validate_boot_state, write_volume,
};
use anyhow::{Context, Result, anyhow, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatGeometry, FatKind};
use ffs_types::ByteOffset;

struct FileSource<'a> {
    volume: &'a FatVolume,
    chain: FileChain,
}

impl ByteDevice for FileSource<'_> {
    fn len_bytes(&self) -> u64 {
        u64::from(self.chain.size)
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        checked_end(offset.0, bytes.len(), self.len_bytes())?;
        let mut at = offset.0;
        // FatVolume::read has a per-request limit, not a file-size limit.
        // Honor it even when a source consumer supplies a large destination.
        for target in bytes.chunks_mut(HASH_BYTES) {
            let read = self.volume.read(cx, &self.chain, at, target.len())?;
            if read.len() != target.len() {
                return Err(FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short read from retained FAT source chain",
                )));
            }
            target.copy_from_slice(&read);
            at += target.len() as u64;
        }
        checkpoint(cx)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)
    }
}

fn checked_end(offset: u64, length: usize, limit: u64) -> ffs_error::Result<u64> {
    offset
        .checked_add(length as u64)
        .filter(|end| *end <= limit)
        .ok_or_else(|| FfsError::Format("edited FAT source range exceeds its length".into()))
}

/// Read-only projection of an old byte source, resized and optionally patched.
/// Empty patches implement truncation/zero extension without materialization.
struct EditSource<'a> {
    original: &'a dyn ByteDevice,
    size: u64,
    patch_offset: u64,
    patch_end: u64,
    patch: &'a [u8],
}

impl<'a> EditSource<'a> {
    fn new(
        original: &'a dyn ByteDevice,
        size: u64,
        patch_offset: u64,
        patch: &'a [u8],
    ) -> ffs_error::Result<Self> {
        let patch_end = checked_end(patch_offset, patch.len(), size)?;
        Ok(Self {
            original,
            size,
            patch_offset,
            patch_end,
            patch,
        })
    }
}

impl ByteDevice for EditSource<'_> {
    fn len_bytes(&self) -> u64 {
        self.size
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let end = checked_end(offset.0, bytes.len(), self.size)?;
        bytes.fill(0);
        let old_end = end.min(self.original.len_bytes());
        let prefix_end = old_end.min(self.patch_offset);
        if offset.0 < prefix_end {
            self.original.read_exact_at(
                cx,
                offset,
                &mut bytes[..(prefix_end - offset.0) as usize],
            )?;
        }
        let suffix_start = offset.0.max(self.patch_end);
        if suffix_start < old_end {
            self.original.read_exact_at(
                cx,
                ByteOffset(suffix_start),
                &mut bytes[(suffix_start - offset.0) as usize..(old_end - offset.0) as usize],
            )?;
        }
        let patch_start = offset.0.max(self.patch_offset);
        let patch_end = end.min(self.patch_end);
        if patch_start < patch_end {
            bytes[(patch_start - offset.0) as usize..(patch_end - offset.0) as usize]
                .copy_from_slice(
                    &self.patch[(patch_start - self.patch_offset) as usize
                        ..(patch_end - self.patch_offset) as usize],
                );
        }
        checkpoint(cx)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)
    }
}

/// Revalidate the retained handle before any write. The structural checker
/// intentionally permits dirty bits while checking an in-flight mutation and
/// cannot substitute for boot geometry, reserved-state and FSInfo admission.
fn validate_edit_state(cx: &Cx, volume: &FatVolume) -> Result<()> {
    checkpoint(cx)?;
    let mut boot = [0; 512];
    volume.read_exact(cx, 0, &mut boot)?;
    let geometry = FatGeometry::parse(&boot, volume.geometry.volume_bytes())
        .map_err(|error| anyhow!("invalid FAT boot geometry before file edit: {error}"))?;
    if geometry != volume.geometry {
        bail!("FAT boot geometry changed since the volume was opened");
    }
    // Check FAT[0] against the media descriptor as well as all selected FAT[1]
    // clean/error bits and the backup boot geometry, not merely allocation links.
    volume.validate_admission(cx, &boot)?;
    validate_boot_state(cx, volume)?;
    if let Some(number) = volume.geometry.fs_info_sector() {
        let offset = u64::from(number) * u64::from(volume.geometry.sector_bytes());
        let mut info = [0; 512];
        volume.read_exact(cx, offset, &mut info)?;
        if info[..4] != 0x4161_5252_u32.to_le_bytes()
            || info[484..488] != 0x6141_7272_u32.to_le_bytes()
            || info[508..512] != 0xAA55_0000_u32.to_le_bytes()
        {
            bail!("invalid FSInfo signatures before file edit; image left unchanged");
        }
        // Free counts and next-free hints are advisory; only the signatures
        // required by set_hints are admission requirements.
    }
    Ok(())
}

/// Retain the existing prefix rather than requiring disjoint free space to
/// shrink. Publish and verify the shorter directory record before cutting the
/// chain; sync the cut before freeing its tail. Interruption may leave excess
/// allocation, but no successfully published length refers to freed storage.
fn shrink_in_volume(cx: &Cx, volume: &FatVolume, path: &str, size: u32, now: u64) -> Result<()> {
    checkpoint(cx)?;
    let (date, time) = modified_timestamp(now)?;
    validate_edit_state(cx, volume)?;
    let entry = volume.resolve(cx, path)?.ok_or(FfsError::IsDirectory)?;
    if entry.native.is_directory() {
        return Err(FfsError::IsDirectory.into());
    }
    if entry.native.attributes & 1 != 0 {
        return Err(FfsError::PermissionDenied.into());
    }
    if entry.native.attributes & 0xC8 != 0 || size >= entry.native.size {
        bail!("invalid native shrink target or size");
    }
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!("shrinking requires a complete clean allocation/namespace check");
    }
    let source = FileSource {
        volume,
        chain: volume.file_chain(cx, &entry)?,
    };
    let keep = u64::from(size).div_ceil(u64::from(volume.geometry.cluster_bytes())) as usize;
    if keep > source.chain.clusters.len() {
        bail!("retained length exceeds validated FAT chain");
    }
    let mut clusters = Vec::new();
    clusters
        .try_reserve_exact(keep)
        .context("allocating retained shrink chain")?;
    clusters.extend_from_slice(&source.chain.clusters[..keep]);
    let mut release = Vec::new();
    release
        .try_reserve_exact(source.chain.clusters.len() - keep)
        .context("allocating bounded shrink release map")?;
    for index in keep..source.chain.clusters.len() {
        release.push((
            source.chain.clusters[index],
            source
                .chain
                .clusters
                .get(index + 1)
                .copied()
                .unwrap_or(EXPECT_END),
        ));
    }
    release.sort_unstable_by_key(|&(cluster, _)| cluster);
    let cut = if keep > 0 && keep < source.chain.clusters.len() {
        Some((source.chain.clusters[keep - 1], source.chain.clusters[keep]))
    } else {
        None
    };
    let digest = hash_device(cx, &EditSource::new(&source, u64::from(size), 0, &[])?)?;
    let mut original = [0; 32];
    volume.read_exact(cx, entry.offset, &mut original)?;
    let mut updated = original;
    let first = clusters.first().copied().unwrap_or(0);
    if volume.geometry.kind() == FatKind::Fat32 {
        let high = u16::from_le_bytes([original[20], original[21]]) & 0xF000;
        updated[20..22].copy_from_slice(&(high | (first >> 16) as u16).to_le_bytes());
    }
    // FAT16 bytes 20..22 may contain an OS/2 EA index; do not clear them.
    updated[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    updated[28..32].copy_from_slice(&size.to_le_bytes());
    updated[22..24].copy_from_slice(&time.to_le_bytes());
    updated[24..26].copy_from_slice(&date.to_le_bytes());
    updated[11] |= 0x20;
    let plan = Replacement {
        path: path.to_owned(),
        entry_offset: entry.offset,
        old_size: entry.native.size,
        size,
        original,
        updated,
        free_after: before.free_clusters + release.len() as u64,
        clusters,
        release,
        digest,
        files: before.files,
        directories: before.directories,
        creation: None,
    };
    let sector_bytes = u64::from(volume.geometry.sector_bytes());
    let start = entry.offset / sector_bytes * sector_bytes;
    let within = (entry.offset - start) as usize;
    let mut sector = allocate(sector_bytes as usize)?;
    let mut readback = allocate(sector_bytes as usize)?;
    volume.read_exact(cx, start, &mut sector)?;
    if sector[within..within + 32] != original {
        bail!("shrink target changed before dirty publication");
    }
    // A shorter little-endian length is not necessarily safe to write in one
    // sector update: 0x00010000 -> 0x0000FFFF can tear into 0x0001FFFF.
    // Publish their bitwise intersection first whenever the final size sets a
    // previously clear bit. Both transitions then change bits in one direction,
    // so a mixture of their old/new size bytes cannot exceed the relevant EOF.
    // Unlike unconditionally hiding EOF, this keeps any common prefix visible.
    // Truncate-to-zero must also persist zero EOF with the OLD head before
    // clearing either half of a FAT32 head (or the FAT16 low word).
    let guard_size = entry.native.size & size;
    let needs_guard = guard_size != size || first != entry.native.first_cluster;
    let mut guarded = original;
    if needs_guard {
        guarded[28..32].copy_from_slice(&guard_size.to_le_bytes());
    }
    let mut phase = "publishing dirty state";
    let result = (|| -> Result<()> {
        set_dirty(cx, volume, true)?;
        set_hints(cx, volume, u32::MAX)?;
        volume.device.sync(cx)?;
        if needs_guard {
            phase = "publishing a bounded EOF before the shorter directory entry";
            volume.read_exact(cx, start, &mut sector)?;
            if sector[within..within + 32] != original {
                bail!("shrink target changed before guarded length publication");
            }
            sector[within..within + 32].copy_from_slice(&guarded);
            write_volume(cx, volume, start, &sector)?;
            volume.device.sync(cx)?;
            volume.read_exact(cx, start, &mut readback)?;
            if readback != sector {
                bail!(
                    "guarded shrink sector failed readback; no chain cut or reclamation attempted"
                );
            }
        }
        phase = "publishing the shorter directory entry";
        volume.read_exact(cx, start, &mut sector)?;
        if sector[within..within + 32] != guarded {
            bail!("shrink target changed before final length publication");
        }
        sector[within..within + 32].copy_from_slice(&updated);
        write_volume(cx, volume, start, &sector)?;
        volume.device.sync(cx)?;
        volume.read_exact(cx, start, &mut readback)?;
        if readback != sector {
            bail!("shorter directory sector failed readback; allocation retained");
        }
        phase = "detaching the truncated tail";
        if let Some((cluster, successor)) = cut {
            let end = match volume.geometry.kind() {
                FatKind::Fat16 => 0xFFFF,
                FatKind::Fat32 => 0x0FFF_FFFF,
            };
            change_fat(cx, volume, &std::iter::once((cluster, successor, end)))?;
            volume.device.sync(cx)?;
            // A successful sync alone cannot detect a dropped or misdirected
            // write. Verify the cut in every selected mirror before reuse.
            let width = volume.geometry.kind().entry_bytes() as usize;
            for copy in volume.copies() {
                let offset = volume
                    .geometry
                    .entry_offset(copy, cluster)
                    .map_err(|error| anyhow!("{error}"))?;
                let mut bytes = [0; 4];
                volume.read_exact(cx, offset, &mut bytes[..width])?;
                if u32::from_le_bytes(bytes) & end != end {
                    bail!("truncated chain cut failed readback in FAT copy {copy}");
                }
            }
        }
        phase = "verifying the detached file";
        plan.verify_payload(cx, volume)?;
        phase = "releasing detached allocation";
        change_fat(
            cx,
            volume,
            &plan
                .release
                .iter()
                .map(|&(cluster, expected)| (cluster, expected, 0)),
        )?;
        set_hints(cx, volume, plan.free_after as u32)?;
        volume.device.sync(cx)?;
        phase = "verifying retained payload and allocation";
        plan.verify_payload(cx, volume)?;
        let after = volume.check(cx)?;
        let expected_counts = (plan.free_after, before.files, before.directories);
        let actual_counts = (after.free_clusters, after.files, after.directories);
        if !after.clean
            || !after.complete
            || !after.namespace_complete
            || actual_counts != expected_counts
        {
            bail!(
                "shrink verification failed: {}",
                serde_json::to_string(&after)?
            );
        }
        phase = "synchronizing final clean state";
        set_dirty(cx, volume, false)?;
        volume.device.sync(cx)?;
        Ok(())
    })();
    result.with_context(|| format!(
        "FAT shrink failed while {phase}; image retained and may be dirty or partially changed; no rollback or atomicity is claimed"
    ))
}

pub fn write_range_in_volume(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    offset: u64,
    data: &[u8],
    now: u64,
) -> Result<usize> {
    checkpoint(cx)?;
    let entry = volume
        .resolve(cx, path)?
        .ok_or_else(|| anyhow!("cannot write to the root directory"))?;
    if entry.native.is_directory() {
        return Err(FfsError::IsDirectory.into());
    }
    if entry.native.attributes & 1 != 0 {
        return Err(FfsError::PermissionDenied.into());
    }
    // A zero-byte write must not extend a file, rewrite timestamps, allocate
    // clusters or enter the dirty-state protocol, even beyond the current EOF.
    if data.is_empty() {
        return Ok(0);
    }
    let end = offset
        .checked_add(data.len() as u64)
        .context("write offset overflow")?;
    let end_u32 = u32::try_from(end).context("FAT regular file write exceeds 4 GiB - 1")?;
    validate_edit_state(cx, volume)?;
    let original = FileSource {
        volume,
        chain: volume.file_chain(cx, &entry)?,
    };
    let source = EditSource::new(
        &original,
        u64::from(entry.native.size.max(end_u32)),
        offset,
        data,
    )?;
    native::apply(cx, volume, path, &entry, &original.chain, &source, now)?;
    Ok(data.len())
}

pub fn truncate_in_volume(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    size: u64,
    now: u64,
) -> Result<()> {
    checkpoint(cx)?;
    let entry = volume
        .resolve(cx, path)?
        .ok_or_else(|| anyhow!("cannot truncate the root directory"))?;
    if entry.native.is_directory() {
        return Err(FfsError::IsDirectory.into());
    }
    if entry.native.attributes & 1 != 0 {
        return Err(FfsError::PermissionDenied.into());
    }
    let size_u32 = u32::try_from(size).context("FAT regular file truncate exceeds 4 GiB - 1")?;
    if size_u32 == entry.native.size {
        return Ok(());
    }
    if size_u32 < entry.native.size {
        return shrink_in_volume(cx, volume, path, size_u32, now);
    }
    validate_edit_state(cx, volume)?;
    let original = FileSource {
        volume,
        chain: volume.file_chain(cx, &entry)?,
    };
    let source = EditSource::new(&original, size, 0, &[])?;
    native::apply(cx, volume, path, &entry, &original.chain, &source, now)
}

companion_bin_tests! {
#[cfg(test)]
mod tests {
    use super::super::{SliceSource, creation, hash_device, open_volume};
    use super::*;

    mod shrink_publication;

    #[test]
    fn edited_source_matches_materialized_oracle_at_every_window() {
        let cx = Cx::for_testing();
        let original = b"abcdefghijklmnopqrstuvwxyz";
        let device = SliceSource(original);
        for (size, offset, patch) in [
            (26, 8, b"PATCH".as_slice()),
            (26, 0, b"FIRST".as_slice()),
            (36, 32, b"LAST".as_slice()),
            (26, 0, b"".as_slice()),
            (11, 0, b"".as_slice()),
            (40, 0, b"".as_slice()),
            (0, 0, b"".as_slice()),
        ] {
            let source = EditSource::new(&device, size as u64, offset as u64, patch).unwrap();
            let mut expected = original.to_vec();
            expected.resize(size, 0);
            expected[offset..offset + patch.len()].copy_from_slice(patch);
            for start in 0..=size {
                for end in start..=size {
                    let mut actual = vec![0xA5; end - start];
                    source
                        .read_exact_at(&cx, ByteOffset(start as u64), &mut actual)
                        .unwrap();
                    assert_eq!(actual, expected[start..end]);
                }
            }
        }
    }

    #[test]
    fn edited_source_rejects_overflow_out_of_bounds_and_cancellation() {
        let cx = Cx::for_testing();
        let device = SliceSource(b"old");
        assert!(EditSource::new(&device, u64::MAX, u64::MAX, b"x").is_err());
        assert!(EditSource::new(&device, 3, 3, b"x").is_err());
        let source = EditSource::new(&device, 8, 5, b"new").unwrap();
        let mut bytes = [0xA5; 2];
        assert!(source.read_exact_at(&cx, ByteOffset(7), &mut bytes).is_err());
        assert_eq!(bytes, [0xA5; 2]);
        assert!(
            source
                .read_exact_at(&cx, ByteOffset(u64::MAX), &mut bytes)
                .is_err()
        );
        assert!(matches!(
            source.write_all_at(&cx, ByteOffset(0), b"x"),
            Err(FfsError::ReadOnly)
        ));
        cx.set_cancel_requested(true);
        assert!(matches!(
            source.read_exact_at(&cx, ByteOffset(0), &mut bytes),
            Err(FfsError::Cancelled)
        ));
    }

    struct PatternSource(u64);

    impl ByteDevice for PatternSource {
        fn len_bytes(&self) -> u64 {
            self.0
        }

        fn read_exact_at(
            &self,
            cx: &Cx,
            offset: ByteOffset,
            bytes: &mut [u8],
        ) -> ffs_error::Result<()> {
            checkpoint(cx)?;
            checked_end(offset.0, bytes.len(), self.0)?;
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = ((offset.0 + index as u64) % 251) as u8;
            }
            Ok(())
        }

        fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
            Err(FfsError::ReadOnly)
        }

        fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
            checkpoint(cx)
        }
    }

    fn edit_fixture(kind: &str) -> (tempfile::TempDir, FatVolume) {
        use clap::Parser as _;

        let cx = Cx::for_testing();
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("edit.fat");
        let cli = crate::Cli::try_parse_from([
            "ffs-fat", "format", image.to_str().unwrap(), "--kind", kind,
            "--size-mib", if kind == "fat16" { "4" } else { "64" },
        ]).unwrap();
        let crate::Command::Format { options } = cli.command else {
            panic!("expected formatter options");
        };
        crate::formatter::create(&cx, &options).unwrap();
        let args = crate::reader::ImageArgs {
            image, offset: 0, length: None,
            oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii,
            sidecar: None,
        };
        let volume = open_volume(&cx, &args, true).unwrap();
        let source = PatternSource(u64::from(volume.geometry.cluster_bytes()) * 3 + 97);
        let plan = creation::prepare(&cx, &volume, "/target.bin", &source, 1_700_000_000).unwrap();
        plan.execute(&cx, &volume, &source, || Ok(())).unwrap();
        (directory, volume)
    }

    #[test]
    fn fat16_full_volume_shrink_retains_prefix_and_reclaims_tail() {
        let (_directory, volume) = edit_fixture("fat16");
        let cx = Cx::for_testing();
        const NOW: u64 = 1_700_000_000;
        let cluster_bytes = u64::from(volume.geometry.cluster_bytes());
        let entry = volume.resolve(&cx, "/target.bin").unwrap().unwrap();
        let old_chain = volume.file_chain(&cx, &entry).unwrap().clusters;
        let filler = PatternSource(volume.free_clusters(&cx).unwrap() * cluster_bytes);
        let plan = creation::prepare(&cx, &volume, "/filler.bin", &filler, NOW).unwrap();
        plan.execute(&cx, &volume, &filler, || Ok(())).unwrap();
        assert_eq!(volume.free_clusters(&cx).unwrap(), 0);

        for (size, kept) in [(cluster_bytes + 17, 2), (cluster_bytes + 1, 2), (0, 0)] {
            truncate_in_volume(&cx, &volume, "/target.bin", size, NOW).unwrap();
            let entry = volume.resolve(&cx, "/target.bin").unwrap().unwrap();
            let chain = volume.file_chain(&cx, &entry).unwrap();
            assert_eq!(u64::from(entry.native.size), size);
            assert_eq!(chain.clusters, old_chain[..kept]);
            assert_eq!(volume.free_clusters(&cx).unwrap(), (old_chain.len() - kept) as u64);
            let bytes = volume.read(&cx, &chain, 0, size as usize).unwrap();
            let mut expected = vec![0; size as usize];
            PatternSource(size).read_exact_at(&cx, ByteOffset(0), &mut expected).unwrap();
            assert_eq!(bytes, expected);
            validate_edit_state(&cx, &volume).unwrap();
            let check = volume.check(&cx).unwrap();
            assert!(check.clean && check.complete && check.namespace_complete);
            assert_eq!(check.files, 2);
        }
        let entry = volume.resolve(&cx, "/filler.bin").unwrap().unwrap();
        let source = FileSource { volume: &volume, chain: volume.file_chain(&cx, &entry).unwrap() };
        assert_eq!(hash_device(&cx, &source).unwrap(), hash_device(&cx, &filler).unwrap());
    }

    #[test]
    fn shrink_keeps_exact_prefix_on_both_fat_widths() {
        for kind in ["fat16", "fat32"] {
            let (_directory, volume) = edit_fixture(kind);
            let cx = Cx::for_testing();
            let entry = volume.resolve(&cx, "/target.bin").unwrap().unwrap();
            let old = volume.file_chain(&cx, &entry).unwrap();
            let size = u64::from(volume.geometry.cluster_bytes());
            truncate_in_volume(&cx, &volume, "/target.bin", size, 1_700_000_002).unwrap();
            let entry = volume.resolve(&cx, "/target.bin").unwrap().unwrap();
            let chain = volume.file_chain(&cx, &entry).unwrap();
            assert_eq!(chain.clusters, old.clusters[..1]);
            let mut expected = vec![0; size as usize];
            PatternSource(size).read_exact_at(&cx, ByteOffset(0), &mut expected).unwrap();
            assert_eq!(volume.read(&cx, &chain, 0, size as usize).unwrap(), expected);
            let check = volume.check(&cx).unwrap();
            assert!(check.clean && check.complete && check.namespace_complete);
            validate_edit_state(&cx, &volume).unwrap();
        }
    }

    #[test]
    fn dirty_reserved_state_rejects_edits_without_changing_image() {
        for operation in ["shrink", "grow", "write"] {
            let (_directory, volume) = edit_fixture("fat16");
            let cx = Cx::for_testing();
            let copy = volume.copies().last().unwrap();
            let offset = volume.geometry.entry_offset(copy, 2).unwrap() - 2;
            write_volume(&cx, &volume, offset, &0x7FFF_u16.to_le_bytes()).unwrap();
            let before = hash_device(&cx, volume.device.as_ref()).unwrap();
            let result = match operation {
                "shrink" => truncate_in_volume(&cx, &volume, "/target.bin", 17, 1_700_000_000),
                "grow" => truncate_in_volume(&cx, &volume, "/target.bin", 65536, 1_700_000_000),
                _ => write_range_in_volume(&cx, &volume, "/target.bin", 0, b"x", 1_700_000_000).map(|_| ()),
            };
            assert!(result.is_err());
            assert_eq!(hash_device(&cx, volume.device.as_ref()).unwrap(), before);
        }
    }

    fn assert_refused_edits_preserve_image(cx: &Cx, volume: &FatVolume) {
        let before = hash_device(cx, volume.device.as_ref()).unwrap();
        assert!(truncate_in_volume(cx, volume, "/target.bin", 17, 1_700_000_000).is_err());
        assert!(truncate_in_volume(cx, volume, "/target.bin", 65536, 1_700_000_000).is_err());
        assert!(write_range_in_volume(cx, volume, "/target.bin", 0, b"x", 1_700_000_000).is_err());
        assert_eq!(hash_device(cx, volume.device.as_ref()).unwrap(), before);
    }

    #[test]
    fn retained_fat16_handle_revalidates_media_and_all_reserved_entries() {
        for corrupt_media in [false, true] {
            let (_directory, volume) = edit_fixture("fat16");
            let cx = Cx::for_testing();
            if corrupt_media {
                // A valid but different media byte must agree with FAT[0].
                let mut original = [0];
                volume.read_exact(&cx, 21, &mut original).unwrap();
                let media = if original[0] == 0xF0 { 0xF8 } else { 0xF0 };
                write_volume(&cx, &volume, 21, &[media]).unwrap();
            } else {
                let copy = volume.copies().last().unwrap();
                let offset = volume.geometry.entry_offset(copy, 2).unwrap() - 4;
                write_volume(&cx, &volume, offset, &0_u16.to_le_bytes()).unwrap();
            }
            assert_refused_edits_preserve_image(&cx, &volume);
        }
    }

    #[test]
    fn retained_fat16_handle_refuses_changed_but_parseable_boot_geometry() {
        let (_directory, volume) = edit_fixture("fat16");
        let cx = Cx::for_testing();
        let mut boot = [0; 512];
        volume.read_exact(&cx, 0, &mut boot).unwrap();
        let reserved = u16::from_le_bytes([boot[14], boot[15]]);
        boot[14..16].copy_from_slice(&(reserved + 1).to_le_bytes());
        let changed = FatGeometry::parse(&boot, volume.geometry.volume_bytes()).unwrap();
        assert_ne!(changed, volume.geometry);
        write_volume(&cx, &volume, 0, &boot).unwrap();
        assert_refused_edits_preserve_image(&cx, &volume);
    }

    #[test]
    fn malformed_fsinfo_is_refused_before_dirty_publication() {
        let (_directory, volume) = edit_fixture("fat32");
        let cx = Cx::for_testing();
        let sector = volume.geometry.fs_info_sector().unwrap();
        let offset = u64::from(sector) * u64::from(volume.geometry.sector_bytes());
        write_volume(&cx, &volume, offset, &[0; 4]).unwrap();
        assert_refused_edits_preserve_image(&cx, &volume);
    }

    #[test]
    fn fat32_large_range_write_shrink_and_growth_stream_past_read_limit() {
        use clap::Parser as _;

        let cx = Cx::for_testing();
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("large.fat");
        let cli = crate::Cli::try_parse_from([
            "ffs-fat",
            "format",
            image.to_str().unwrap(),
            "--kind",
            "fat32",
            "--size-mib",
            "64",
        ])
        .unwrap();
        let crate::Command::Format { options } = cli.command else {
            panic!("expected formatter options");
        };
        crate::formatter::create(&cx, &options).unwrap();
        let args = crate::reader::ImageArgs {
            image,
            offset: 0,
            length: None,
            oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii,
            sidecar: None,
        };
        let volume = open_volume(&cx, &args, true).unwrap();
        const NOW: u64 = 1_700_000_000;
        const READ_LIMIT: u64 = 16 * 1024 * 1024;
        let size = READ_LIMIT + 8193;
        let original = PatternSource(size);
        let plan = creation::prepare(&cx, &volume, "/large.bin", &original, NOW).unwrap();
        plan.execute(&cx, &volume, &original, || Ok(())).unwrap();

        assert_eq!(
            write_range_in_volume(&cx, &volume, "/large.bin", READ_LIMIT + 37, b"edited", NOW)
                .unwrap(),
            6
        );
        let entry = volume.resolve(&cx, "/large.bin").unwrap().unwrap();
        let chain = volume.file_chain(&cx, &entry).unwrap();
        assert_eq!(u64::from(entry.native.size), size);
        let mut expected = vec![0; 128];
        original
            .read_exact_at(&cx, ByteOffset(READ_LIMIT), &mut expected)
            .unwrap();
        expected[37..43].copy_from_slice(b"edited");
        assert_eq!(volume.read(&cx, &chain, READ_LIMIT, 128).unwrap(), expected);
        let mut tail = [0; 73];
        original
            .read_exact_at(&cx, ByteOffset(size - 73), &mut tail)
            .unwrap();
        assert_eq!(volume.read(&cx, &chain, size - 73, 73).unwrap(), tail);

        let shorter = size - 4096;
        truncate_in_volume(&cx, &volume, "/large.bin", shorter, NOW).unwrap();
        let entry = volume.resolve(&cx, "/large.bin").unwrap().unwrap();
        assert_eq!(u64::from(entry.native.size), shorter);
        let longer = size + 4096;
        truncate_in_volume(&cx, &volume, "/large.bin", longer, NOW).unwrap();
        let entry = volume.resolve(&cx, "/large.bin").unwrap().unwrap();
        let chain = volume.file_chain(&cx, &entry).unwrap();
        assert_eq!(u64::from(entry.native.size), longer);
        assert_eq!(volume.read(&cx, &chain, READ_LIMIT, 128).unwrap(), expected);
        assert_eq!(volume.read(&cx, &chain, shorter, 8192).unwrap(), vec![0; 8192]);

        let before = hash_device(&cx, volume.device.as_ref()).unwrap();
        assert_eq!(
            write_range_in_volume(&cx, &volume, "/large.bin", longer + 65536, &[], NOW)
                .unwrap(),
            0
        );
        assert_eq!(
            write_range_in_volume(&cx, &volume, "/large.bin", u64::MAX, &[], NOW).unwrap(),
            0
        );
        assert_eq!(hash_device(&cx, volume.device.as_ref()).unwrap(), before);
        let check = volume.check(&cx).unwrap();
        assert!(check.clean && check.complete && check.namespace_complete);
    }
}
}
