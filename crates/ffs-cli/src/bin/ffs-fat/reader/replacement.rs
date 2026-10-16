//! Ordered native replacement or create-only publication on an offline FAT image.
//!
//! New contents use disjoint, initialized clusters. Data and new FAT links are
//! synchronized before the directory entry, and that entry is synchronized
//! before old allocation is freed. This is not an atomic transaction: failures
//! after dirty publication require native checking/recovery on a separate copy.
//! Native state and high-bit rules: Linux v6.19 fs/fat/{inode,fatent}.c and
//! dosfstools v4.2 src/{fat,boot}.c. No native implementation code is reused.

mod creation;
mod metadata;
mod ranges;
pub use creation::{
    MkdirArgs, RenameArgs, RmdirArgs, UnlinkArgs, mkdir_in_volume, rename_in_volume,
    rmdir_in_volume, run_mkdir, run_rename, run_rmdir, run_unlink, unlink_in_volume,
};
pub use metadata::set_attr_in_volume;
pub use ranges::{truncate_in_volume, write_range_in_volume};

use super::{FatTable, FatVolume, ImageArgs, MAX_CHAIN_CLUSTERS, allocate, checkpoint, corrupt};
use anyhow::{Context, Result, anyhow, bail};
use asupersync::{Cx, types::CancelKind};
use clap::Args;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatEntry, FatGeometry, FatKind};
use ffs_types::ByteOffset;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const HASH_BYTES: usize = 64 * 1024;
const EXPECT_END: u32 = u32::MAX;

#[derive(Debug, Args)]
pub struct ReplaceArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// Native regular-file path inside the selected volume.
    path: String,
    /// Immutable regular source file; never opened for writing.
    #[arg(long)]
    source: PathBuf,
    /// Create a new short- or long-name file; refuse any existing name or alias.
    #[arg(long)]
    create: bool,
    /// Confirm exclusive ownership: no mounted or unrelated image writers.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Validate source, namespace, allocation and capacity without writing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

struct ImageFile {
    file: Arc<File>,
    length: u64,
    writable: bool,
}

impl ByteDevice for ImageFile {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        self.range(offset.0, bytes.len())?;
        self.file.read_exact_at(bytes, offset.0)?;
        checkpoint(cx)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        if self.file.metadata()?.len() != self.length {
            return Err(corrupt(offset.0, "image length changed during replacement"));
        }
        self.range(offset.0, bytes.len())?;
        self.file.write_all_at(bytes, offset.0)?;
        checkpoint(cx)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        self.file.sync_all()?;
        checkpoint(cx)
    }
}

impl ImageFile {
    fn range(&self, offset: u64, count: usize) -> ffs_error::Result<()> {
        if offset
            .checked_add(count as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(corrupt(
                offset,
                "replacement device range exceeds the retained file",
            ));
        }
        Ok(())
    }
}

fn open_regular(path: &Path, writable: bool) -> Result<(Arc<File>, Stamp)> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        bail!(
            "replacement requires regular files, not symlinks or devices: {}",
            path.display()
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let after = file.metadata()?;
    if !after.is_file() || Stamp::of(&before) != Stamp::of(&after) {
        bail!("file identity changed while opening {}", path.display());
    }
    if writable {
        file.try_lock()
            .map_err(|error| anyhow!("cannot exclusively lock image: {error}"))?;
    } else {
        file.try_lock_shared()
            .map_err(|error| anyhow!("cannot shared-lock input: {error}"))?;
    }
    Ok((Arc::new(file), Stamp::of(&after)))
}

fn stable(file: &File, path: &Path, stamp: Stamp) -> Result<()> {
    let named = fs::symlink_metadata(path)?;
    if !named.is_file() || Stamp::of(&named) != stamp || Stamp::of(&file.metadata()?) != stamp {
        bail!(
            "replacement input changed after preflight: {}",
            path.display()
        );
    }
    Ok(())
}

fn hash_device(cx: &Cx, source: &dyn ByteDevice) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = allocate(HASH_BYTES)?;
    let mut at = 0_u64;
    while at < source.len_bytes() {
        checkpoint(cx)?;
        let count = (source.len_bytes() - at).min(HASH_BYTES as u64) as usize;
        source.read_exact_at(cx, ByteOffset(at), &mut buffer[..count])?;
        digest.update(&buffer[..count]);
        at += count as u64;
    }
    checkpoint(cx)?;
    Ok(digest.finalize().into())
}

/// FAT has no timezone field. Match the reader's explicit UTC wall-clock
/// projection, retaining its two-second modification-time precision.
fn modified_timestamp(seconds: u64) -> Result<(u16, u16)> {
    let mut days = seconds / 86_400;
    let mut year = 1970_u64;
    while year <= 2107 {
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let count = if leap { 366 } else { 365 };
        if days < count {
            break;
        }
        days -= count;
        year += 1;
    }
    if !(1980..=2107).contains(&year) {
        bail!("modification time lies outside FAT's 1980..2107 calendar");
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1_u64;
    for count in months {
        if days < count {
            break;
        }
        days -= count;
        month += 1;
    }
    let daytime = seconds % 86_400;
    let date = ((year - 1980) << 9) | (month << 5) | (days + 1);
    let time = ((daytime / 3600) << 11) | (((daytime % 3600) / 60) << 5) | ((daytime % 60) / 2);
    Ok((date as u16, time as u16))
}

/// Shared admission for retained writable handles. The structural checker also
/// runs inside dirty mutations, so allocation consistency alone cannot prove
/// that the boot mapping and every selected FAT are safe to start another write.
fn validate_boot_state(cx: &Cx, volume: &FatVolume) -> Result<()> {
    checkpoint(cx)?;
    let mut primary = [0; 512];
    volume.read_exact(cx, 0, &mut primary)?;
    let geometry = FatGeometry::parse(&primary, volume.geometry.volume_bytes())
        .map_err(|error| anyhow!("invalid FAT geometry before mutation: {error}"))?;
    if geometry != volume.geometry {
        bail!("FAT geometry changed since the volume was opened");
    }
    // Validate media/FAT[0], every selected FAT[1] clean/error state, and the
    // backup geometry. Inactive FATs and reserved high bits retain their policy.
    volume.validate_admission(cx, &primary)?;
    let state_at = if volume.geometry.kind() == FatKind::Fat16 {
        37
    } else {
        65
    };
    for number in std::iter::once(0_u16).chain(volume.geometry.backup_boot_sector()) {
        let offset = u64::from(number) * u64::from(volume.geometry.sector_bytes());
        let mut boot = [0; 512];
        volume.read_exact(cx, offset, &mut boot)?;
        if boot[state_at] != 0 {
            bail!(
                "mutation requires clean primary and backup boot state without surface-test requests or unknown flags"
            );
        }
    }
    if let Some(number) = volume.geometry.fs_info_sector() {
        let offset = u64::from(number) * u64::from(volume.geometry.sector_bytes());
        let mut info = [0; 512];
        volume.read_exact(cx, offset, &mut info)?;
        if info[..4] != 0x4161_5252_u32.to_le_bytes()
            || info[484..488] != 0x6141_7272_u32.to_le_bytes()
            || info[508..512] != 0xAA55_0000_u32.to_le_bytes()
        {
            bail!("invalid FSInfo signatures before mutation; image left unchanged");
        }
        // Counts and next-free values remain advisory; validate only the
        // signatures the hint writer needs, before any dirty marker is written.
    }
    checkpoint(cx)?;
    Ok(())
}

fn reserve_clusters(cx: &Cx, volume: &FatVolume, needed: usize, free: u64) -> Result<Vec<u32>> {
    if needed > MAX_CHAIN_CLUSTERS || needed as u64 > free {
        bail!(
            "insufficient disjoint free allocation for replacement; old clusters are not reused before publication"
        );
    }
    let mut clusters = Vec::new();
    clusters
        .try_reserve_exact(needed)
        .context("allocating bounded replacement chain")?;
    let mut table = FatTable::new(volume);
    for cluster in 2..=volume.geometry.cluster_count() + 1 {
        if clusters.len() == needed {
            break;
        }
        checkpoint(cx)?;
        if table.entry(cx, cluster)? == FatEntry::Free {
            volume.cluster_offset(cluster)?;
            clusters.push(cluster);
        }
    }
    if clusters.len() != needed {
        bail!("free allocation changed during replacement preflight");
    }
    Ok(clusters)
}

struct Replacement {
    path: String,
    entry_offset: u64,
    old_size: u32,
    size: u32,
    original: [u8; 32],
    updated: [u8; 32],
    clusters: Vec<u32>,
    /// Sorted cluster -> expected old successor; EXPECT_END denotes any native EOC.
    release: Vec<(u32, u32)>,
    digest: [u8; 32],
    free_after: u64,
    files: u64,
    directories: u64,
    creation: Option<creation::Namespace>,
}

impl Replacement {
    fn prepare(
        cx: &Cx,
        volume: &FatVolume,
        path: &str,
        source: &dyn ByteDevice,
        now: u64,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let size =
            u32::try_from(source.len_bytes()).context("FAT file size exceeds 2^32 - 1 bytes")?;
        let (date, time) = modified_timestamp(now)?;
        validate_boot_state(cx, volume)?;
        let entry = volume.resolve(cx, path)?.ok_or(FfsError::IsDirectory)?;
        if entry.native.is_directory() {
            return Err(FfsError::IsDirectory.into());
        }
        if entry.native.attributes & 1 != 0 {
            bail!("native read-only attribute forbids replacement");
        }
        if entry.native.attributes & 0xC8 != 0 {
            bail!("unsupported native attributes on replacement target");
        }
        let before = volume.check(cx)?;
        if !before.clean || !before.complete || !before.namespace_complete {
            bail!(
                "replacement requires a complete clean allocation/namespace check: {}",
                serde_json::to_string(&before)?
            );
        }
        let old = volume.file_chain(cx, &entry)?;
        let needed = u64::from(size).div_ceil(u64::from(volume.geometry.cluster_bytes())) as usize;
        let clusters = reserve_clusters(cx, volume, needed, before.free_clusters)?;
        let mut release = Vec::new();
        release
            .try_reserve_exact(old.clusters.len())
            .context("allocating bounded release map")?;
        for (index, cluster) in old.clusters.iter().copied().enumerate() {
            release.push((
                cluster,
                old.clusters.get(index + 1).copied().unwrap_or(EXPECT_END),
            ));
        }
        release.sort_unstable_by_key(|&(cluster, _)| cluster);
        let mut original = [0; 32];
        volume.read_exact(cx, entry.offset, &mut original)?;
        let mut updated = original;
        let first = clusters.first().copied().unwrap_or(0);
        if volume.geometry.kind() == FatKind::Fat32 {
            // The upper four directory-cluster bits are reserved, just like
            // the upper FAT-entry bits. FAT16's field may hold an OS/2 EA index.
            let high = u16::from_le_bytes([original[20], original[21]]) & 0xF000;
            updated[20..22].copy_from_slice(&(high | (first >> 16) as u16).to_le_bytes());
        }
        updated[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        updated[28..32].copy_from_slice(&size.to_le_bytes());
        updated[22..24].copy_from_slice(&time.to_le_bytes());
        updated[24..26].copy_from_slice(&date.to_le_bytes());
        updated[11] |= 0x20;
        let digest = hash_device(cx, source)?;
        checkpoint(cx)?;
        Ok(Self {
            path: path.to_owned(),
            entry_offset: entry.offset,
            old_size: old.size,
            size,
            original,
            updated,
            free_after: before.free_clusters + release.len() as u64 - needed as u64,
            clusters,
            release,
            digest,
            files: before.files,
            directories: before.directories,
            creation: None,
        })
    }

    fn report(&self, volume: &FatVolume, dry_run: bool) -> serde_json::Value {
        let mut source_sha256 = String::with_capacity(self.digest.len() * 2);
        for byte in self.digest {
            write!(&mut source_sha256, "{byte:02x}").expect("format SHA-256 into String");
        }
        let mut report = serde_json::json!({
            "operation": "replace_existing_file", "dry_run": dry_run,
            "format": format!("{:?}", volume.geometry.kind()),
            "volume_offset": volume.base, "volume_bytes": volume.geometry.volume_bytes(),
            "oem_code_page": volume.oem_code_page.label(), "path": self.path,
            "entry_offset": self.entry_offset, "previous_bytes": self.old_size, "new_bytes": self.size,
            "new_clusters": self.clusters.len(), "released_clusters": self.release.len(),
            "free_clusters_after": self.free_after,
            "source_sha256": source_sha256,
            "contract": "offline ordered replacement; interrupted mutation may require native recovery; not atomic"
        });
        if let Some(namespace) = &self.creation {
            report["operation"] = "create_new_file".into();
            report["created_new_file"] = (!dry_run).into();
            report["name_profile"] = "portable_utf16_lfn_ascii_alias".into();
            report["new_directory_clusters"] = namespace.directory_clusters().into();
            report["contract"] = "offline ordered creation; interrupted mutation may require native recovery; not atomic".into();
        }
        report
    }

    fn execute(
        &self,
        cx: &Cx,
        volume: &FatVolume,
        source: &dyn ByteDevice,
        source_stable: impl Fn() -> Result<()>,
    ) -> Result<serde_json::Value> {
        checkpoint(cx)?;
        let mut current = [0; 32];
        volume.read_exact(cx, self.entry_offset, &mut current)?;
        let initial = self.creation.as_ref().map_or(self.original, |namespace| {
            namespace.initial_entry(self.original)
        });
        if current != initial || source.len_bytes() != u64::from(self.size) {
            bail!("replacement target or source changed before dirty publication");
        }
        if let Some(namespace) = &self.creation {
            namespace.validate(cx, volume)?;
        }
        source_stable()?;
        let mut phase = "publishing dirty state";
        let result = (|| -> Result<serde_json::Value> {
            set_dirty(cx, volume, true)?;
            set_hints(cx, volume, u32::MAX)?;
            volume.device.sync(cx)?;
            phase = "initializing disjoint data";
            let mut buffer = allocate(volume.geometry.cluster_bytes() as usize)?;
            let mut copied = Sha256::new();
            let mut at = 0_u64;
            for cluster in &self.clusters {
                checkpoint(cx)?;
                buffer.fill(0);
                let count = (u64::from(self.size) - at).min(buffer.len() as u64) as usize;
                source.read_exact_at(cx, ByteOffset(at), &mut buffer[..count])?;
                copied.update(&buffer[..count]);
                write_volume(cx, volume, volume.cluster_offset(*cluster)?, &buffer)?;
                at += count as u64;
            }
            let copied: [u8; 32] = copied.finalize().into();
            if at != u64::from(self.size)
                || copied != self.digest
                || hash_device(cx, source)? != self.digest
            {
                bail!("source bytes changed while staging replacement");
            }
            source_stable()?;
            volume.device.sync(cx)?;
            phase = "publishing new allocation";
            let end = match volume.geometry.kind() {
                FatKind::Fat16 => 0xFFFF,
                FatKind::Fat32 => 0x0FFF_FFFF,
            };
            change_fat(
                cx,
                volume,
                &self
                    .clusters
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(index, cluster)| {
                        (
                            cluster,
                            0,
                            self.clusters.get(index + 1).copied().unwrap_or(end),
                        )
                    }),
            )?;
            volume.device.sync(cx)?;
            if let Some(namespace) = &self.creation {
                phase = "initializing and publishing directory storage";
                namespace.stage(cx, volume)?;
            }
            phase = "publishing the replacement directory entry";
            let sector_bytes = u64::from(volume.geometry.sector_bytes());
            let start = self.entry_offset / sector_bytes * sector_bytes;
            let within = (self.entry_offset - start) as usize;
            let mut sector = allocate(sector_bytes as usize)?;
            volume.read_exact(cx, start, &mut sector)?;
            if sector[within..within + 32] != self.original {
                bail!("directory entry changed before replacement publication");
            }
            sector[within..within + 32].copy_from_slice(&self.updated);
            write_volume(cx, volume, start, &sector)?;
            volume.device.sync(cx)?;
            phase = "verifying published file contents";
            self.verify_payload(cx, volume)?;
            phase = "releasing old allocation";
            change_fat(
                cx,
                volume,
                &self
                    .release
                    .iter()
                    .map(|&(cluster, expected)| (cluster, expected, 0)),
            )?;
            set_hints(cx, volume, self.free_after as u32)?;
            volume.device.sync(cx)?;
            phase = "checking completed allocation and namespace";
            let verification = volume.check(cx)?;
            if !verification.clean || !verification.complete || !verification.namespace_complete {
                bail!(
                    "replacement verification failed: {}",
                    serde_json::to_string(&verification)?
                );
            }
            if verification.free_clusters != self.free_after {
                bail!(
                    "replacement verification failed: {}",
                    serde_json::to_string(&verification)?
                );
            }
            if verification.files != self.files || verification.directories != self.directories {
                bail!(
                    "replacement verification failed: {}",
                    serde_json::to_string(&verification)?
                );
            }
            phase = "synchronizing final clean state";
            set_dirty(cx, volume, false)?;
            volume.device.sync(cx)?;
            let mut report = self.report(volume, false);
            report["durability"] = "all_data_metadata_and_clean_state_synced".into();
            report["payload_verification"] = "sha256_via_native_reader".into();
            report["verification"] = serde_json::to_value(verification)?;
            Ok(report)
        })();
        result.with_context(|| format!("FAT file update failed while {phase}; image retained and may be dirty or partially changed; no rollback or atomicity is claimed"))
    }

    fn verify_payload(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        let mut record = [0; 32];
        volume.read_exact(cx, self.entry_offset, &mut record)?;
        if record != self.updated {
            bail!("replacement directory metadata differs from the prepared publication");
        }
        let entry = volume
            .resolve(cx, &self.path)?
            .ok_or(FfsError::IsDirectory)?;
        if entry.offset != self.entry_offset || entry.native.size != self.size {
            bail!("replacement readback resolved a different file identity or length");
        }
        if self.creation.is_some()
            && (entry.name()? != self.path.rsplit('/').next().unwrap_or("")
                || entry.native.short_name.as_slice() != &self.updated[..11]
                || entry.native.case_flags != self.updated[12])
        {
            bail!("created file readback changed its native name, short alias or case flags");
        }
        let chain = volume.file_chain(cx, &entry)?;
        if chain.clusters != self.clusters {
            bail!("replacement readback did not retain the prepared allocation");
        }
        let mut digest = Sha256::new();
        let mut at = 0_u64;
        while at < u64::from(self.size) {
            let bytes = volume.read(cx, &chain, at, HASH_BYTES)?;
            digest.update(&bytes);
            at += bytes.len() as u64;
        }
        let actual: [u8; 32] = digest.finalize().into();
        if actual != self.digest {
            bail!("replacement payload hash differs from the immutable source");
        }
        checkpoint(cx)?;
        Ok(())
    }
}

fn write_volume(cx: &Cx, volume: &FatVolume, offset: u64, bytes: &[u8]) -> Result<()> {
    checkpoint(cx)?;
    if offset
        .checked_add(bytes.len() as u64)
        .is_none_or(|end| end > volume.geometry.volume_bytes())
    {
        bail!("replacement write exceeds the explicitly selected volume");
    }
    let physical = volume
        .base
        .checked_add(offset)
        .context("replacement physical offset overflow")?;
    volume
        .device
        .write_all_at(cx, ByteOffset(physical), bytes)?;
    checkpoint(cx)?;
    Ok(())
}

fn set_hints(cx: &Cx, volume: &FatVolume, free: u32) -> Result<()> {
    let Some(number) = volume.geometry.fs_info_sector() else {
        return Ok(());
    };
    let offset = u64::from(number) * u64::from(volume.geometry.sector_bytes());
    let mut sector = allocate(volume.geometry.sector_bytes() as usize)?;
    volume.read_exact(cx, offset, &mut sector)?;
    if sector[..4] != 0x4161_5252_u32.to_le_bytes()
        || sector[484..488] != 0x6141_7272_u32.to_le_bytes()
        || sector[508..512] != 0xAA55_0000_u32.to_le_bytes()
    {
        bail!("FSInfo signatures changed after replacement admission");
    }
    sector[488..492].copy_from_slice(&free.to_le_bytes());
    sector[492..496].copy_from_slice(&u32::MAX.to_le_bytes());
    write_volume(cx, volume, offset, &sector)
}

fn set_dirty(cx: &Cx, volume: &FatVolume, dirty: bool) -> Result<()> {
    if dirty {
        // Prepared plans can outlive preflight. Check the complete retained
        // mapping and ALL selected reserved records before the first write,
        // not after dirtying a boot sector or an earlier FAT copy.
        validate_boot_state(cx, volume)?;
    }
    let geometry = &volume.geometry;
    let width = geometry.kind().entry_bytes() as usize;
    let (state_at, clean_mask, value_mask) = match geometry.kind() {
        FatKind::Fat16 => (37, 0x8000, 0xFFFF),
        FatKind::Fat32 => (65, 0x0800_0000, 0x0FFF_FFFF),
    };
    // Linux's native BPB state and FAT[1]'s native clean bit both remain dirty
    // until every data, directory, allocation and hint barrier has succeeded.
    for number in std::iter::once(0_u16).chain(geometry.backup_boot_sector()) {
        let offset = u64::from(number) * u64::from(geometry.sector_bytes());
        let mut bytes = allocate(geometry.sector_bytes() as usize)?;
        volume.read_exact(cx, offset, &mut bytes)?;
        if bytes[state_at] & 3 != u8::from(!dirty) {
            bail!("native boot state changed during replacement");
        }
        if dirty {
            bytes[state_at] |= 1;
        } else {
            bytes[state_at] &= !1;
        }
        write_volume(cx, volume, offset, &bytes)?;
    }
    for copy in volume.copies() {
        let offset = geometry
            .entry_offset(copy, 2)
            .map_err(|error| anyhow!("{error}"))?
            - 2 * width as u64;
        let mut bytes = allocate(geometry.sector_bytes() as usize)?;
        volume.read_exact(cx, offset, &mut bytes)?;
        let raw = if width == 2 {
            u32::from(u16::from_le_bytes([bytes[2], bytes[3]]))
        } else {
            u32::from_le_bytes(bytes[4..8].try_into().expect("four-byte FAT entry"))
        };
        let expected = if dirty {
            value_mask
        } else {
            value_mask & !clean_mask
        };
        if raw & value_mask != expected {
            bail!("FAT reserved state changed during replacement");
        }
        let updated = if dirty {
            raw & !clean_mask
        } else {
            raw | clean_mask
        };
        bytes[width..2 * width].copy_from_slice(&updated.to_le_bytes()[..width]);
        write_volume(cx, volume, offset, &bytes)?;
    }
    Ok(())
}

/// Coalesce sorted native entry changes into sectors while preserving all
/// untouched bytes, each FAT32 high nibble, and any unselected inactive FAT.
fn change_fat(
    cx: &Cx,
    volume: &FatVolume,
    changes: &(impl Iterator<Item = (u32, u32, u32)> + Clone),
) -> Result<()> {
    let geometry = &volume.geometry;
    let width = geometry.kind().entry_bytes() as usize;
    let sector_bytes = u64::from(geometry.sector_bytes());
    let mask = if width == 2 { 0xFFFF } else { 0x0FFF_FFFF };
    for copy in volume.copies() {
        let mut position = None;
        let mut sector = allocate(sector_bytes as usize)?;
        for (cluster, expected, value) in changes.clone() {
            checkpoint(cx)?;
            let offset = geometry
                .entry_offset(copy, cluster)
                .map_err(|error| anyhow!("{error}"))?;
            let start = offset / sector_bytes * sector_bytes;
            if position != Some(start) {
                if let Some(previous) = position {
                    write_volume(cx, volume, previous, &sector)?;
                }
                volume.read_exact(cx, start, &mut sector)?;
                position = Some(start);
            }
            let at = (offset - start) as usize;
            let raw = if width == 2 {
                u32::from(u16::from_le_bytes([sector[at], sector[at + 1]]))
            } else {
                u32::from_le_bytes(sector[at..at + 4].try_into().expect("four-byte FAT entry"))
            };
            if if expected == EXPECT_END {
                geometry.kind().decode_entry(raw & mask) != FatEntry::End
            } else {
                raw & mask != expected
            } {
                bail!("FAT allocation changed at cluster {cluster} in copy {copy}");
            }
            let updated = (raw & !mask) | value;
            sector[at..at + width].copy_from_slice(&updated.to_le_bytes()[..width]);
        }
        if let Some(position) = position {
            write_volume(cx, volume, position, &sector)?;
        }
    }
    Ok(())
}

pub fn run(cx: &Cx, args: &ReplaceArgs) -> Result<serde_json::Value> {
    let signal = cx.clone();
    ctrlc::set_handler(move || {
        signal.cancel_with(
            CancelKind::User,
            Some("FAT file update interrupted by Ctrl+C"),
        );
    })
    .context("installing FAT file-update cancellation handler; no mutation started")?;
    replace(cx, args)
}

fn replace(cx: &Cx, args: &ReplaceArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if !args.offline_image {
        bail!(
            "--offline-image is required; advisory locks do not exclude kernel or unrelated writers"
        );
    }
    let (source, source_stamp) = open_regular(&args.source, false)?;
    let source_device = ImageFile {
        file: source.clone(),
        length: source_stamp.length,
        writable: false,
    };
    let (volume, image_check) = if args.image.sidecar.is_some() {
        let img_meta = fs::symlink_metadata(&args.image.image)?;
        if (img_meta.dev(), img_meta.ino()) == (source_stamp.device, source_stamp.inode) {
            bail!("source must not alias the backing image");
        }
        (open_volume(cx, &args.image, !args.dry_run)?, None)
    } else {
        let (image, image_stamp) = open_regular(&args.image.image, !args.dry_run)?;
        if (image_stamp.device, image_stamp.inode) == (source_stamp.device, source_stamp.inode) {
            bail!("source must not alias the backing image");
        }
        let volume = FatVolume::from_device(
            cx,
            Box::new(ImageFile {
                file: image.clone(),
                length: image_stamp.length,
                writable: !args.dry_run,
            }),
            args.image.offset,
            args.image
                .length
                .unwrap_or_else(|| image_stamp.length.saturating_sub(args.image.offset)),
        )?
        .with_oem_code_page(args.image.oem_code_page);
        (volume, Some((image, image_stamp)))
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock predates the Unix epoch")?
        .as_secs();
    let plan = if args.create {
        creation::prepare(cx, &volume, &args.path, &source_device, now)?
    } else {
        Replacement::prepare(cx, &volume, &args.path, &source_device, now)?
    };
    if let Some((ref image, image_stamp)) = image_check {
        stable(image, &args.image.image, image_stamp)?;
    }
    stable(&source, &args.source, source_stamp)?;
    checkpoint(cx)?;
    if args.dry_run {
        return Ok(plan.report(&volume, true));
    }
    let mut report = plan.execute(cx, &volume, &source_device, || {
        stable(&source, &args.source, source_stamp)
    })?;
    if args.image.sidecar.is_some() {
        report["sidecar_refreshed"] = true.into();
    }
    Ok(report)
}

struct SidecarDevice {
    inner: ffs_repair::sidecar::live::SidecarImageDevice,
    writable: bool,
}

impl ByteDevice for SidecarDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        self.inner.read_exact_at(cx, offset, bytes)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        self.inner.write_all_at(cx, offset, bytes)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        self.inner.sync(cx)
    }
}

struct SliceSource<'a>(&'a [u8]);

impl ByteDevice for SliceSource<'_> {
    fn len_bytes(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bytes: &mut [u8],
    ) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let start =
            usize::try_from(offset.0).map_err(|_| corrupt(offset.0, "source offset overflow"))?;
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| corrupt(offset.0, "source length overflow"))?;
        let slice = self
            .0
            .get(start..end)
            .ok_or_else(|| corrupt(offset.0, "source read exceeds slice"))?;
        bytes.copy_from_slice(slice);
        checkpoint(cx)
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)
    }
}

pub fn open_volume(cx: &Cx, args: &ImageArgs, writable: bool) -> Result<FatVolume> {
    if let Some(sidecar) = &args.sidecar {
        // Blocking caller writes in SidecarDevice alone does not prevent the
        // underlying protected reader from repairing the image during a read.
        // Strict read-only operations and dry runs must remove that authority
        // at the owning device, before native admission performs its first read.
        let inner = if writable {
            ffs_repair::sidecar::live::SidecarImageDevice::open(cx, &args.image, sidecar)
        } else {
            ffs_repair::sidecar::live::SidecarImageDevice::open_read_only(cx, &args.image, sidecar)
        }
        .with_context(|| format!("admitting FAT image and sidecar {}", sidecar.display()))?;
        let len = inner.len_bytes();
        return Ok(FatVolume::from_device(
            cx,
            Box::new(SidecarDevice { inner, writable }),
            args.offset,
            args.length
                .unwrap_or_else(|| len.saturating_sub(args.offset)),
        )?
        .with_oem_code_page(args.oem_code_page));
    }
    let (image, image_stamp) = open_regular(&args.image, writable)?;
    Ok(FatVolume::from_device(
        cx,
        Box::new(ImageFile {
            file: image,
            length: image_stamp.length,
            writable,
        }),
        args.offset,
        args.length
            .unwrap_or_else(|| image_stamp.length.saturating_sub(args.offset)),
    )?
    .with_oem_code_page(args.oem_code_page))
}

pub fn sync_volume(cx: &Cx, volume: &FatVolume) -> Result<()> {
    volume.device.sync(cx)?;
    Ok(())
}

pub fn create_in_volume(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    data: &[u8],
    now: u64,
    read_only: bool,
) -> Result<serde_json::Value> {
    let source = SliceSource(data);
    let mut plan = creation::prepare(cx, volume, path, &source, now)?;
    // Publish permissions with the initial directory record, not as a second
    // mutation after a writable file has already been committed and verified.
    if read_only {
        plan.updated[11] |= 1;
    }
    plan.execute(cx, volume, &source, || Ok(()))
}

pub fn replace_in_volume(
    cx: &Cx,
    volume: &FatVolume,
    path: &str,
    data: &[u8],
    now: u64,
) -> Result<serde_json::Value> {
    let source = SliceSource(data);
    let plan = Replacement::prepare(cx, volume, path, &source, now)?;
    plan.execute(cx, volume, &source, || Ok(()))
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
    #[cfg(test)]
    mod read_only_tests;
    #[cfg(test)]
    mod admission_tests;
}
