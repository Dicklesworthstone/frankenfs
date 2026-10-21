//! Non-destructive offline resize into a fresh, standalone native volume image.
//!
//! Keep the dialect and cluster size. By default, preserve every native cluster
//! number and shrink only a provably free tail. Explicit --relocate constructs
//! a checked read-only view moving live tail clusters into free retained slots.
//! The source is strictly read-only, without sidecar read-repair or in-place I/O.
//! Build and check a private read-only candidate before creating output. Keep
//! the output primary boot sector absent until full byte readback and the native
//! checker have succeeded. Interrupted output is retained, never auto-deleted.

mod relocation;

use super::reader::{FatVolume, ImageArgs, MAX_CHAIN_CLUSTERS, checkpoint};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::Args;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_ondisk::fat::{FatEntry, FatGeometry, FatKind, FatOemCodePage};
use ffs_types::ByteOffset;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const TRANSFER: usize = 64 * 1024;

#[derive(Debug, Args)]
pub struct ResizeArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// New standalone volume image. Existing files, symlinks and devices are refused.
    #[arg(long)]
    output: PathBuf,
    /// Exact output length in MiB. Dialect and cluster size are retained.
    #[arg(long)]
    size_mib: u64,
    /// Move live tail clusters into free retained slots when shrinking.
    /// Only the new output is changed; bad tail clusters are still refused.
    #[arg(long)]
    relocate: bool,
    /// Confirm the source stays offline and immutable for the complete operation.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Check source, geometry, shrink safety and planned namespace; create nothing.
    #[arg(long)]
    dry_run: bool,
}

fn invalid(detail: impl Into<String>) -> FfsError {
    FfsError::Format(detail.into())
}

fn buffer(length: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .context("allocating bounded resize scratch")?;
    bytes.resize(length, 0);
    Ok(bytes)
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
    fn of(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            length: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

fn source_unchanged(file: &File, path: &Path, stamp: Stamp) -> Result<()> {
    let named = fs::symlink_metadata(path)?;
    if !named.is_file()
        || named.file_type().is_symlink()
        || Stamp::of(&named) != stamp
        || Stamp::of(&file.metadata()?) != stamp
    {
        bail!("resize source changed; no consistent copy can be acknowledged");
    }
    Ok(())
}

/// Read-only selected-volume capability, also used by constructed-image tests.
#[derive(Clone)]
struct Slice {
    inner: Arc<dyn ByteDevice>,
    base: u64,
    length: u64,
}

impl ByteDevice for Slice {
    fn len_bytes(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if at
            .0
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(invalid("resize read exceeds selected volume"));
        }
        let physical = self
            .base
            .checked_add(at.0)
            .ok_or_else(|| invalid("resize offset overflow"))?;
        self.inner.read_exact_at(cx, ByteOffset(physical), bytes)?;
        checkpoint(cx)
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, _: &Cx) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
}

struct FileDevice {
    file: Arc<File>,
    length: u64,
    writable: bool,
}

impl FileDevice {
    fn range(&self, at: u64, length: usize) -> ffs_error::Result<()> {
        if at
            .checked_add(length as u64)
            .is_none_or(|end| end > self.length)
            || self.file.metadata()?.len() != self.length
        {
            return Err(invalid("resize backing length or access range changed"));
        }
        Ok(())
    }
}

impl ByteDevice for FileDevice {
    fn len_bytes(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        self.range(at.0, bytes.len())?;
        self.file.read_exact_at(bytes, at.0)?;
        checkpoint(cx)
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        self.range(at.0, bytes.len())?;
        self.file.write_all_at(bytes, at.0)?;
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

/// Counts that resizing is never allowed to change. Free space changes only by
/// the difference in admitted data-cluster count, not by dropping preallocation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ownership {
    files: u64,
    directories: u64,
    allocated: u64,
    referenced: u64,
    preallocated: u64,
    bad: u64,
}

fn checked(cx: &Cx, volume: &FatVolume) -> Result<(Ownership, u64)> {
    let report = volume.check(cx)?;
    if !report.clean
        || !report.complete
        || !report.namespace_complete
        || report.omitted_issues != 0
        || report.lost_clusters != Some(0)
    {
        bail!(
            "resize requires complete clean ownership: {}",
            serde_json::to_string(&report)?
        );
    }
    Ok((
        Ownership {
            files: report.files,
            directories: report.directories,
            allocated: report.allocated_clusters,
            referenced: report.referenced_clusters,
            preallocated: report.preallocated_clusters,
            bad: report.bad_clusters,
        },
        report.free_clusters,
    ))
}

fn fat_start(geometry: &FatGeometry, copy: u8) -> Result<u64> {
    Ok(geometry
        .entry_offset(copy, 2)
        .map_err(|e| invalid(e.to_string()))?
        - 2 * u64::from(geometry.kind().entry_bytes()))
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("checked native word"))
}

fn fat_sectors(boot: &[u8], kind: FatKind) -> u64 {
    match kind {
        FatKind::Fat16 => u64::from(u16::from_le_bytes([boot[22], boot[23]])),
        FatKind::Fat32 => u64::from(word(boot, 36)),
    }
}

/// Find the smallest FAT that can address the resulting data area. The
/// predicate is monotone; a bounded binary search avoids fixed-point cycling
/// when a FAT-sector increment removes exactly one data cluster.
fn layout(boot: &[u8], old: &FatGeometry, length: u64) -> Result<(Vec<u8>, FatGeometry)> {
    let sector = u64::from(old.sector_bytes());
    if length == 0 || !length.is_multiple_of(sector) || length / sector > u64::from(u32::MAX) {
        bail!("resize length must fit the native sector count and logical-sector alignment");
    }
    let total = length / sector;
    let reserved = u64::from(u16::from_le_bytes([boot[14], boot[15]]));
    let roots = old.fixed_root().map_or(0, |(_, bytes)| bytes / sector);
    let copies = u64::from(old.fat_count());
    let cluster_sectors = u64::from(old.cluster_bytes()) / sector;
    let width = u64::from(old.kind().entry_bytes());
    let available = total
        .checked_sub(reserved + roots)
        .context("resize target has no data area")?;
    let mut low = 1;
    let mut high = available / copies;
    if high == 0 {
        bail!("resize target has no FAT capacity");
    }
    while low < high {
        let mid = low + (high - low) / 2;
        let count = (available - copies * mid) / cluster_sectors;
        if mid * sector / width >= count + 2 {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    let fat = if length == old.volume_bytes() {
        fat_sectors(boot, old.kind())
    } else {
        low
    };
    let mut updated = boot.to_vec();
    updated[19..21].fill(0);
    updated[32..36].copy_from_slice(&(total as u32).to_le_bytes());
    // Output is a standalone volume, never a new partition-table image.
    updated[28..32].fill(0);
    match old.kind() {
        FatKind::Fat16 => {
            let fat = u16::try_from(fat).context("FAT16 table exceeds native field width")?;
            updated[22..24].copy_from_slice(&fat.to_le_bytes());
            if total <= u64::from(u16::MAX) {
                updated[19..21].copy_from_slice(&(total as u16).to_le_bytes());
                updated[32..36].fill(0);
            }
        }
        FatKind::Fat32 => updated[36..40].copy_from_slice(&(fat as u32).to_le_bytes()),
    }
    let new = FatGeometry::parse(&updated, length).map_err(|e| invalid(e.to_string()))?;
    if new.kind() != old.kind()
        || new.cluster_bytes() != old.cluster_bytes()
        || new.cluster_count() as usize > MAX_CHAIN_CLUSTERS
        || (new.kind() == FatKind::Fat16 && new.cluster_count() < 4087)
    {
        bail!("resize would change dialect or exceed the admitted cluster profile");
    }
    new.cluster_offset(new.cluster_count() + 1)
        .map_err(|e| invalid(e.to_string()))?;
    Ok((updated, new))
}

struct Plan {
    source: Slice,
    old: FatGeometry,
    new: FatGeometry,
    old_fat_bytes: u64,
    new_fat_bytes: u64,
    fat_start: u64,
    old_data: u64,
    new_data: u64,
    /// One bounded byte per ORIGINAL cluster: 0 free, 1 live, 2 bad.
    allocation: Vec<u8>,
    patches: BTreeMap<u64, Vec<u8>>,
    ownership: Ownership,
    free: u64,
    page: FatOemCodePage,
}

impl Plan {
    fn prepare(cx: &Cx, source: Slice, length: u64, page: FatOemCodePage) -> Result<Arc<Self>> {
        checkpoint(cx)?;
        let volume = FatVolume::from_device(cx, Box::new(source.clone()), 0, source.length)?
            .with_oem_code_page(page);
        let (ownership, old_free) = checked(cx, &volume)?;
        let old = volume.geometry;
        let sector = u64::from(old.sector_bytes());
        let mut boot = buffer(sector as usize)?;
        source.read_exact_at(cx, ByteOffset(0), &mut boot)?;
        let (updated, new) = layout(&boot, &old, length)?;
        let start = fat_start(&old, 0)?;
        let old_fat_bytes = fat_sectors(&boot, old.kind()) * sector;
        let new_fat_bytes = fat_sectors(&updated, old.kind()) * sector;
        let mut allocation = buffer(old.cluster_count() as usize)?;
        let selected = if old.mirrored() { 0 } else { old.active_fat() };
        let width = old.kind().entry_bytes() as usize;
        let mut table = buffer(TRANSFER)?;
        let mut index = 0_usize;
        let mut used = 0_u64;
        while index < allocation.len() {
            checkpoint(cx)?;
            let entries = (allocation.len() - index).min(TRANSFER / width);
            let at = fat_start(&old, selected)? + (index as u64 + 2) * width as u64;
            source.read_exact_at(cx, ByteOffset(at), &mut table[..entries * width])?;
            for local in 0..entries {
                let at = local * width;
                let raw = if width == 2 {
                    u32::from(u16::from_le_bytes([table[at], table[at + 1]]))
                } else {
                    word(&table, at)
                };
                let state = match old.kind().decode_entry(raw) {
                    FatEntry::Free => 0,
                    FatEntry::Next(_) | FatEntry::End => 1,
                    FatEntry::Bad => 2,
                    FatEntry::Reserved => {
                        bail!("reserved allocation changed during resize preflight")
                    }
                };
                if state != 0 && index + local >= new.cluster_count() as usize {
                    bail!(
                        "shrink would remove allocated or bad cluster {}; compaction is not performed",
                        index + local + 2
                    );
                }
                allocation[index + local] = state;
                used += u64::from(state != 0);
            }
            index += entries;
        }
        if used != ownership.allocated + ownership.bad
            || old_free + used != u64::from(old.cluster_count())
        {
            bail!("allocation changed during resize preflight");
        }
        let free = u64::from(new.cluster_count())
            .checked_sub(used)
            .context("resize capacity underflow")?;
        let state_at = if old.kind() == FatKind::Fat16 { 37 } else { 65 };
        let mut patches = BTreeMap::new();
        for number in std::iter::once(0_u16).chain(old.backup_boot_sector()) {
            let offset = u64::from(number) * sector;
            let mut bytes = buffer(sector as usize)?;
            source.read_exact_at(cx, ByteOffset(offset), &mut bytes)?;
            if bytes[state_at] != 0 {
                bail!("resize refuses dirty, surface-test or unknown boot state");
            }
            let (rewritten, geometry) = layout(&bytes, &old, length)?;
            if geometry != new {
                bail!("resize boot copies disagree");
            }
            patches.insert(offset, rewritten);
        }
        if let Some(info) = old.fs_info_sector() {
            let mut numbers = vec![info];
            if let Some(backup) = old.backup_boot_sector()
                && let Some(number) = backup.checked_add(info)
                && u64::from(number) * sector < start
                && number != info
                && Some(number) != old.backup_boot_sector()
            {
                numbers.push(number);
            }
            for (index, number) in numbers.into_iter().enumerate() {
                let offset = u64::from(number) * sector;
                if patches.contains_key(&offset) {
                    bail!("FSInfo overlaps a boot record");
                }
                let mut bytes = buffer(sector as usize)?;
                source.read_exact_at(cx, ByteOffset(offset), &mut bytes)?;
                if word(&bytes, 0) != 0x4161_5252
                    || word(&bytes, 484) != 0x6141_7272
                    || word(&bytes, 508) != 0xAA55_0000
                {
                    if index == 0 {
                        bail!("invalid primary FSInfo");
                    }
                    continue; // An unspecified reserved sector is not repair authority.
                }
                bytes[488..492].copy_from_slice(&(free as u32).to_le_bytes());
                bytes[492..496].copy_from_slice(&u32::MAX.to_le_bytes());
                patches.insert(offset, bytes);
            }
        }
        let old_data = old.cluster_offset(2).map_err(|e| invalid(e.to_string()))?;
        let new_data = new.cluster_offset(2).map_err(|e| invalid(e.to_string()))?;
        let plan = Arc::new(Self {
            source,
            old,
            new,
            old_fat_bytes,
            new_fat_bytes,
            fat_start: start,
            old_data,
            new_data,
            allocation,
            patches,
            ownership,
            free,
            page,
        });
        let device: Arc<dyn ByteDevice> = plan.clone();
        plan.verify(cx, device)?;
        Ok(plan)
    }

    fn verify(&self, cx: &Cx, device: Arc<dyn ByteDevice>) -> Result<()> {
        let volume = FatVolume::from_device(
            cx,
            Box::new(Slice {
                inner: device,
                base: 0,
                length: self.new.volume_bytes(),
            }),
            0,
            self.new.volume_bytes(),
        )?
        .with_oem_code_page(self.page);
        let (ownership, free) = checked(cx, &volume)?;
        if volume.geometry != self.new || ownership != self.ownership || free != self.free {
            bail!("resized image changed reachable ownership or allocation accounting");
        }
        Ok(())
    }

    /// Source range for one output segment, or None for sanitized free storage.
    /// No per-file path conversion: all native names/metadata remain raw bytes.
    fn mapping(&self, at: u64, maximum: u64) -> (Option<u64>, usize) {
        let count;
        let source;
        let tables_end = self.fat_start + self.new_fat_bytes * u64::from(self.new.fat_count());
        if at < self.fat_start {
            source = Some(at);
            count = maximum.min(self.fat_start - at);
        } else if at < tables_end {
            let relative = at - self.fat_start;
            let copy = relative / self.new_fat_bytes;
            let within = relative % self.new_fat_bytes;
            let retained = (u64::from(self.old.cluster_count().min(self.new.cluster_count())) + 2)
                * u64::from(self.old.kind().entry_bytes());
            if within < retained {
                source = Some(self.fat_start + copy * self.old_fat_bytes + within);
                count = maximum.min(retained - within);
            } else {
                source = None;
                count = maximum.min(self.new_fat_bytes - within);
            }
        } else if at < self.new_data {
            source = Some(self.old_data - (self.new_data - at));
            count = maximum.min(self.new_data - at);
        } else {
            let cluster = u64::from(self.new.cluster_bytes());
            let relative = at - self.new_data;
            let mut index = relative / cluster;
            let copy = self.allocation.get(index as usize) == Some(&1);
            source = copy.then_some(self.old_data + relative);
            let mut run = maximum.min(cluster - relative % cluster);
            while run < maximum {
                index += 1;
                if (self.allocation.get(index as usize) == Some(&1)) != copy {
                    break;
                }
                run += (maximum - run).min(cluster);
            }
            count = run;
        }
        (source, count as usize)
    }

    fn report(&self, dry_run: bool) -> serde_json::Value {
        serde_json::json!({
            "operation": "resize_to_new_image", "dry_run": dry_run,
            "format": format!("{:?}", self.new.kind()),
            "source_volume_bytes": self.old.volume_bytes(),
            "output_volume_bytes": self.new.volume_bytes(),
            "source_data_clusters": self.old.cluster_count(),
            "output_data_clusters": self.new.cluster_count(),
            "free_clusters_after": self.free, "cluster_bytes": self.new.cluster_bytes(),
            "files": self.ownership.files, "directories": self.ownership.directories,
            "cluster_numbers_preserved": true, "source_modified": false,
            "protection_transferred": false, "bootability_verified": false,
            "contract": "fresh standalone image; no in-place resize, compaction, dialect conversion, partition-table edit or sidecar transfer"
        })
    }
}

impl ByteDevice for Plan {
    fn len_bytes(&self) -> u64 {
        self.new.volume_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let end =
            at.0.checked_add(bytes.len() as u64)
                .filter(|end| *end <= self.len_bytes())
                .ok_or_else(|| invalid("resize view range overflow"))?;
        let mut done = 0;
        while done < bytes.len() {
            checkpoint(cx)?;
            let position = at.0 + done as u64;
            let (source, count) = self.mapping(position, (bytes.len() - done).min(TRANSFER) as u64);
            if let Some(source) = source {
                self.source.read_exact_at(
                    cx,
                    ByteOffset(source),
                    &mut bytes[done..done + count],
                )?;
            } else {
                bytes[done..done + count].fill(0);
            }
            done += count;
        }
        for (&offset, patch) in &self.patches {
            let left = at.0.max(offset);
            let right = end.min(offset + patch.len() as u64);
            if left < right {
                bytes[(left - at.0) as usize..(right - at.0) as usize]
                    .copy_from_slice(&patch[(left - offset) as usize..(right - offset) as usize]);
            }
        }
        checkpoint(cx)
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, _: &Cx) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
}

/// Only the private candidate checker sees the withheld, already prepared boot
/// sector. Every other byte comes from actual output readback. This capability
/// never escapes as a mounted filesystem or grants write/recovery admission.
struct Candidate {
    output: Arc<dyn ByteDevice>,
    primary: Vec<u8>,
}

impl ByteDevice for Candidate {
    fn len_bytes(&self) -> u64 {
        self.output.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        if at
            .0
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.len_bytes())
        {
            return Err(invalid("candidate read outside output"));
        }
        let prefix = (self.primary.len() as u64)
            .saturating_sub(at.0)
            .min(bytes.len() as u64) as usize;
        if prefix != 0 {
            bytes[..prefix].copy_from_slice(&self.primary[at.0 as usize..at.0 as usize + prefix]);
        }
        if prefix < bytes.len() {
            self.output.read_exact_at(
                cx,
                ByteOffset(at.0 + prefix as u64),
                &mut bytes[prefix..],
            )?;
        }
        checkpoint(cx)
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, _: &Cx) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
}

fn publish(
    cx: &Cx,
    plan: &Plan,
    output: Arc<dyn ByteDevice>,
    stable: impl Fn() -> Result<()>,
) -> Result<String> {
    checkpoint(cx)?;
    if output.len_bytes() != plan.len_bytes() {
        bail!("resize output length changed");
    }
    let primary = plan
        .patches
        .get(&0)
        .context("resize primary boot record absent")?
        .clone();
    let mut bytes = buffer(TRANSFER)?;
    output.read_exact_at(cx, ByteOffset(0), &mut bytes[..primary.len()])?;
    if bytes[..primary.len()].iter().any(|byte| *byte != 0) {
        bail!("resize publication requires a fresh zero-initialized output");
    }
    let mut expected = Sha256::new();
    expected.update(&primary);
    let mut at = primary.len() as u64;
    while at < plan.len_bytes() {
        let count = (plan.len_bytes() - at).min(TRANSFER as u64) as usize;
        plan.read_exact_at(cx, ByteOffset(at), &mut bytes[..count])?;
        expected.update(&bytes[..count]);
        output.write_all_at(cx, ByteOffset(at), &bytes[..count])?;
        at += count as u64;
    }
    output.sync(cx)?;
    stable()?;
    let expected: [u8; 32] = expected.finalize().into();
    let mut actual = Sha256::new();
    actual.update(&primary);
    at = primary.len() as u64;
    while at < plan.len_bytes() {
        let count = (plan.len_bytes() - at).min(TRANSFER as u64) as usize;
        output.read_exact_at(cx, ByteOffset(at), &mut bytes[..count])?;
        actual.update(&bytes[..count]);
        at += count as u64;
    }
    let actual: [u8; 32] = actual.finalize().into();
    if actual != expected {
        bail!("resize output SHA-256 readback differs from prepared bytes");
    }
    plan.verify(
        cx,
        Arc::new(Candidate {
            output: Arc::clone(&output),
            primary: primary.clone(),
        }),
    )?;
    output.read_exact_at(cx, ByteOffset(0), &mut bytes[..primary.len()])?;
    if bytes[..primary.len()].iter().any(|byte| *byte != 0) {
        bail!("withheld primary boot sector changed before publication");
    }
    stable()?;
    checkpoint(cx)?;
    output.write_all_at(cx, ByteOffset(0), &primary)?;
    output.sync(cx)?;
    output.read_exact_at(cx, ByteOffset(0), &mut bytes[..primary.len()])?;
    if bytes[..primary.len()] != primary {
        bail!("resize primary boot publication failed readback");
    }
    Ok(expected.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn run(cx: &Cx, args: &ResizeArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if !args.offline_image {
        bail!("--offline-image is required");
    }
    if args.image.sidecar.is_some() {
        bail!(
            "resize does not attach, repair or transfer sidecars; use native input without --sidecar"
        );
    }
    let length = args
        .size_mib
        .checked_mul(1024 * 1024)
        .filter(|length| *length != 0)
        .context("resize length overflow or zero size")?;
    let named = fs::symlink_metadata(&args.image.image)?;
    if !named.is_file() || named.file_type().is_symlink() {
        bail!("resize source must be a regular non-symlink image");
    }
    let input = Arc::new(
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&args.image.image)?,
    );
    input
        .try_lock_shared()
        .map_err(|e| anyhow::anyhow!("cannot lock resize source: {e}"))?;
    let stamp = Stamp::of(&named);
    source_unchanged(&input, &args.image.image, stamp)?;
    let selected = args
        .image
        .length
        .unwrap_or_else(|| stamp.length.saturating_sub(args.image.offset));
    if args
        .image
        .offset
        .checked_add(selected)
        .is_none_or(|end| end > stamp.length)
    {
        bail!("resize selected volume exceeds source");
    }
    let source = Slice {
        inner: Arc::new(FileDevice {
            file: Arc::clone(&input),
            length: stamp.length,
            writable: false,
        }),
        base: args.image.offset,
        length: selected,
    };
    let (source, relocated) = if args.relocate {
        relocation::prepare(cx, source, length, args.image.oem_code_page)?
    } else {
        (source, 0)
    };
    let plan = Plan::prepare(cx, source, length, args.image.oem_code_page)?;
    source_unchanged(&input, &args.image.image, stamp)?;
    let leaf = args
        .output
        .file_name()
        .context("resize output needs a filename")?;
    let parent_path = args
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .context("resolve existing resize output directory")?;
    let parent = File::open(&parent_path)?;
    let parent_id = (parent.metadata()?.dev(), parent.metadata()?.ino());
    let path = parent_path.join(leaf);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(_) => bail!("resize output already exists; it will never be overwritten"),
    }
    let mut report = plan.report(args.dry_run);
    report["relocation_requested"] = args.relocate.into();
    report["relocated_clusters"] = relocated.into();
    report["cluster_numbers_preserved"] = (relocated == 0).into();
    if args.relocate {
        report["contract"] = "fresh standalone image with verified live-tail relocation; no in-place resize, dialect conversion, partition-table edit or sidecar transfer".into();
    }
    report["output"] = path.to_string_lossy().into_owned().into();
    report["source_volume_offset"] = args.image.offset.into();
    checkpoint(cx)?;
    if args.dry_run {
        return Ok(report);
    }
    source_unchanged(&input, &args.image.image, stamp)?;
    let output = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?,
    );
    let result = (|| -> Result<()> {
        output
            .try_lock()
            .map_err(|e| anyhow::anyhow!("cannot lock new resize output: {e}"))?;
        output.set_len(length)?;
        let identity = (output.metadata()?.dev(), output.metadata()?.ino());
        let stable = || -> Result<()> {
            source_unchanged(&input, &args.image.image, stamp)?;
            let named = fs::symlink_metadata(&path)?;
            let directory = fs::metadata(&parent_path)?;
            if !named.is_file()
                || named.file_type().is_symlink()
                || (named.dev(), named.ino()) != identity
                || named.len() != length
                || (directory.dev(), directory.ino()) != parent_id
            {
                bail!("resize output or parent identity changed");
            }
            Ok(())
        };
        stable()?;
        let device: Arc<dyn ByteDevice> = Arc::new(FileDevice {
            file: Arc::clone(&output),
            length,
            writable: true,
        });
        let digest = publish(cx, &plan, device, stable)?;
        // Publish the host namespace durably before reporting success. A late
        // error can leave a complete image: never describe it as rolled back.
        parent.sync_all()?;
        report["sha256"] = digest.into();
        report["durability"] = "verified_image_and_parent_directory_synced".into();
        Ok(())
    })();
    result.with_context(|| format!(
        "resize failed; source was not written; output {} is retained and may be incomplete or already complete; no rollback claimed", path.display()
    ))?;
    Ok(report)
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
