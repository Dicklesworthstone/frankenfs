//! Ordered creation of one native FAT directory on an offline image.
//!
//! The new directory cluster, including native dot entries, is initialized and
//! synchronized before its FAT allocation or parent namespace entry is published.
//! Parent long-name and growth ordering is shared with file creation.

mod exchange;
mod rename_in_place;
mod spelling;

use super::super::super::ImageArgs;
use super::super::{
    ImageFile, change_fat, checkpoint, open_regular, reserve_clusters, set_dirty, set_hints,
    stable, validate_boot_state, write_volume,
};
use super::{
    Extension, Namespace, Slot, deleted_slot, directory_offsets, parent, patch_slot, read_slot,
    reserve_slots,
};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::Args;
use ffs_error::FfsError;
use ffs_ondisk::fat::FatKind;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Args)]
pub struct MkdirArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// New native directory path. Every parent must already exist.
    path: String,
    /// Confirm exclusive ownership: no mounted or unrelated image writers.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Validate namespace, allocation and capacity without writing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct UnlinkArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// Existing native regular-file path inside the selected volume.
    path: String,
    /// Confirm exclusive ownership: no mounted or unrelated image writers.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Validate namespace and allocation without writing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RmdirArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// Existing empty native directory path inside the selected volume.
    path: String,
    /// Confirm exclusive ownership: no mounted or unrelated image writers.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Validate namespace and emptiness without writing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RenameArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// Existing source native path inside the selected volume.
    from: String,
    /// Destination native path inside the selected volume.
    to: String,
    /// Refuse any existing destination, including another spelling or alias.
    #[arg(long)]
    no_replace: bool,
    /// Swap two existing objects without temporary names or allocation.
    /// Serialized operation; native multi-sector FAT updates are not crash-atomic.
    #[arg(long, conflicts_with = "no_replace")]
    exchange: bool,
    /// Confirm exclusive ownership: no mounted or unrelated image writers.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Validate namespace and allocation without writing.
    #[arg(long)]
    dry_run: bool,
}

pub(super) struct DirectoryCreation {
    pub(super) path: String,
    pub(super) namespace: Namespace,
    pub(super) directory_cluster: u32,
    pub(super) parent_cluster: u32,
    updated: [u8; 32],
    free_after: u64,
    files: u64,
    directories: u64,
}

fn directory_entry(name: &[u8; 11], flags: u8, cluster: u32, date: u16, time: u16) -> [u8; 32] {
    let mut entry = [0; 32];
    entry[..11].copy_from_slice(name);
    entry[11] = 0x10;
    entry[12] = flags;
    entry[14..16].copy_from_slice(&time.to_le_bytes());
    entry[16..18].copy_from_slice(&date.to_le_bytes());
    entry[18..20].copy_from_slice(&date.to_le_bytes());
    entry[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    entry[22..24].copy_from_slice(&time.to_le_bytes());
    entry[24..26].copy_from_slice(&date.to_le_bytes());
    entry[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    entry
}

fn raw_cluster(kind: FatKind, entry: &[u8]) -> u32 {
    let low = u32::from(u16::from_le_bytes([entry[26], entry[27]]));
    match kind {
        FatKind::Fat16 => low,
        FatKind::Fat32 => {
            low | (u32::from(u16::from_le_bytes([entry[20], entry[21]]) & 0x0FFF) << 16)
        }
    }
}

impl DirectoryCreation {
    pub(super) fn prepare(
        cx: &Cx,
        volume: &super::super::super::FatVolume,
        path: &str,
        now: u64,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let (date, time) = super::super::modified_timestamp(now)?;
        let (directory, leaf) = parent(cx, volume, path)?;
        let name = super::names::NativeName::plan(cx, volume, directory, &leaf)?;
        validate_boot_state(cx, volume)?;
        let before = volume.check(cx)?;
        if !before.clean || !before.complete || !before.namespace_complete {
            bail!(
                "directory creation requires a complete clean allocation/namespace check: {}",
                serde_json::to_string(&before)?
            );
        }

        let needed_slots = name.long_slots() + 1;
        let mut reservation = reserve_slots(cx, volume, directory, needed_slots)?;
        let total = 1_usize
            .checked_add(reservation.extra)
            .context("directory creation allocation overflow")?;
        let mut allocated = reserve_clusters(cx, volume, total, before.free_clusters)?;
        let directory_cluster = allocated[0];

        let extension = if let Some(tail) = reservation.tail {
            let extra = allocated.split_off(1);
            let cluster = *extra
                .first()
                .context("missing reserved parent-directory cluster")?;
            for &cluster in &extra {
                let start = volume.cluster_offset(cluster)?;
                for offset in
                    (start..start + u64::from(volume.geometry.cluster_bytes())).step_by(32)
                {
                    if reservation.slots.len() < needed_slots {
                        reservation.slots.push(read_slot(cx, volume, offset, true)?);
                    } else if reservation.successor.is_none() {
                        reservation.successor = Some(read_slot(cx, volume, offset, true)?);
                        break;
                    }
                }
            }
            Some(Extension {
                tail,
                cluster,
                additional: extra.get(1).copied(),
            })
        } else {
            None
        };

        let entry = reservation
            .slots
            .pop()
            .context("missing reserved directory short-entry slot")?;
        let parent_cluster = match directory {
            super::super::super::Directory::Root => 0,
            super::super::super::Directory::Cluster(cluster) => cluster,
        };
        let updated = directory_entry(&name.short, name.flags, directory_cluster, date, time);

        Ok(Self {
            path: path.to_owned(),
            namespace: Namespace {
                successor: reservation.successor,
                extension,
                entry,
                long_slots: reservation.slots,
                name,
            },
            directory_cluster,
            parent_cluster,
            updated,
            free_after: before.free_clusters - total as u64,
            files: before.files,
            directories: before
                .directories
                .checked_add(1)
                .context("FAT directory count overflow")?,
        })
    }

    fn report(&self, volume: &super::super::super::FatVolume, dry_run: bool) -> serde_json::Value {
        json!({
            "operation": "create_directory",
            "dry_run": dry_run,
            "created_directory": !dry_run,
            "format": format!("{:?}", volume.geometry.kind()),
            "volume_offset": volume.base,
            "volume_bytes": volume.geometry.volume_bytes(),
            "oem_code_page": volume.oem_code_page.label(),
            "path": self.path,
            "entry_offset": self.namespace.entry.offset,
            "directory_cluster": self.directory_cluster,
            "parent_cluster": self.parent_cluster,
            "new_parent_directory_clusters": self.namespace.directory_clusters(),
            "free_clusters_after": self.free_after,
            "name_profile": "portable_utf16_lfn_ascii_alias",
            "contract": "offline ordered directory creation; interrupted mutation may require native recovery; not atomic"
        })
    }

    pub(super) fn execute(
        &self,
        cx: &Cx,
        volume: &super::super::super::FatVolume,
    ) -> Result<serde_json::Value> {
        checkpoint(cx)?;
        self.namespace.validate(cx, volume)?;
        let mut table = super::super::FatTable::new(volume);
        if table.entry(cx, self.directory_cluster)? != ffs_ondisk::fat::FatEntry::Free {
            bail!("reserved directory cluster is no longer free");
        }
        let mut phase = "publishing dirty state";
        let result = (|| -> Result<serde_json::Value> {
            set_dirty(cx, volume, true)?;
            set_hints(cx, volume, u32::MAX)?;
            volume.device.sync(cx)?;

            phase = "initializing new directory contents";
            let mut bytes = super::super::allocate(volume.geometry.cluster_bytes() as usize)?;
            let date = u16::from_le_bytes(
                self.updated[16..18]
                    .try_into()
                    .expect("native directory date"),
            );
            let time = u16::from_le_bytes(
                self.updated[14..16]
                    .try_into()
                    .expect("native directory time"),
            );
            let dot = directory_entry(b".          ", 0, self.directory_cluster, date, time);
            let dotdot = directory_entry(b"..         ", 0, self.parent_cluster, date, time);
            bytes[..32].copy_from_slice(&dot);
            bytes[32..64].copy_from_slice(&dotdot);
            super::initialize_directory(
                cx,
                volume,
                &std::iter::once(self.directory_cluster),
                &bytes,
            )?;

            phase = "publishing new directory allocation";
            let end = match volume.geometry.kind() {
                FatKind::Fat16 => 0xFFFF,
                FatKind::Fat32 => 0x0FFF_FFFF,
            };
            change_fat(
                cx,
                volume,
                &std::iter::once((self.directory_cluster, 0, end)),
            )?;
            volume.device.sync(cx)?;

            // A dropped allocation write must not publish a parent entry that
            // references a free cluster. Use a fresh table, not the preflight
            // cache populated before the dirty-state and allocation writes.
            let mut table = super::super::FatTable::new(volume);
            if table.entry(cx, self.directory_cluster)? != ffs_ondisk::fat::FatEntry::End {
                bail!("new directory allocation failed readback before namespace publication");
            }

            phase = "publishing parent directory storage";
            self.namespace.stage(cx, volume)?;

            phase = "publishing parent namespace entry";
            let expected = if self.namespace.long_slots.is_empty() {
                self.namespace.entry.initialized()
            } else {
                deleted_slot()
            };
            patch_slot(
                cx,
                volume,
                self.namespace.entry.offset,
                &expected,
                &self.updated,
            )?;
            volume.device.sync(cx)?;

            phase = "verifying native directory readback";
            let entry = volume
                .resolve(cx, &self.path)?
                .context("created directory is missing from native readback")?;
            if !entry.native.is_directory()
                || entry.native.first_cluster != self.directory_cluster
                || entry.native.short_name != self.namespace.name.short
                || entry.native.case_flags != self.namespace.name.flags
            {
                bail!("created directory readback differs from the prepared native identity");
            }
            if !volume
                .list(
                    cx,
                    super::super::super::Directory::Cluster(self.directory_cluster),
                )?
                .is_empty()
            {
                bail!("new directory unexpectedly exposes children after publication");
            }
            let mut prefix = [0; 64];
            volume.read_exact(
                cx,
                volume.cluster_offset(self.directory_cluster)?,
                &mut prefix,
            )?;
            if &prefix[..11] != b".          "
                || prefix[11] != 0x10
                || raw_cluster(volume.geometry.kind(), &prefix[..32]) != self.directory_cluster
                || &prefix[32..43] != b"..         "
                || prefix[43] != 0x10
                || raw_cluster(volume.geometry.kind(), &prefix[32..64]) != self.parent_cluster
            {
                bail!("new directory native dot entries failed readback");
            }

            phase = "checking completed allocation and namespace";
            set_hints(cx, volume, self.free_after as u32)?;
            volume.device.sync(cx)?;
            let verification = volume.check(cx)?;
            if !verification.clean || !verification.complete || !verification.namespace_complete {
                bail!(
                    "directory creation verification failed: {}",
                    serde_json::to_string(&verification)?
                );
            }
            if verification.free_clusters != self.free_after {
                bail!(
                    "directory creation verification failed: {}",
                    serde_json::to_string(&verification)?
                );
            }
            if verification.files != self.files || verification.directories != self.directories {
                bail!(
                    "directory creation verification failed: {}",
                    serde_json::to_string(&verification)?
                );
            }

            phase = "synchronizing final clean state";
            set_dirty(cx, volume, false)?;
            volume.device.sync(cx)?;
            let mut report = self.report(volume, false);
            report["durability"] =
                "directory_contents_allocation_namespace_and_clean_state_synced".into();
            report["verification"] = serde_json::to_value(verification)?;
            Ok(report)
        })();
        result.with_context(|| {
            format!(
                "FAT directory creation failed while {phase}; image retained and may be dirty or partially changed; no rollback or atomicity is claimed"
            )
        })
    }
}

pub fn run_mkdir(cx: &Cx, args: &MkdirArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if !args.offline_image {
        bail!(
            "--offline-image is required; advisory locks do not exclude kernel or unrelated writers"
        );
    }
    let (volume, image_check) = if args.image.sidecar.is_some() {
        (
            super::super::open_volume(cx, &args.image, !args.dry_run)?,
            None,
        )
    } else {
        let (image, image_stamp) = open_regular(&args.image.image, !args.dry_run)?;
        let volume = super::super::super::FatVolume::from_device(
            cx,
            Box::new(ImageFile {
                file: Arc::clone(&image),
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
    let plan = DirectoryCreation::prepare(cx, &volume, &args.path, now)?;
    if let Some((ref image, image_stamp)) = image_check {
        stable(image, &args.image.image, image_stamp)?;
    }
    checkpoint(cx)?;
    if args.dry_run {
        return Ok(plan.report(&volume, true));
    }
    let mut report = plan.execute(cx, &volume)?;
    if args.image.sidecar.is_some() {
        report["sidecar_refreshed"] = true.into();
    }
    Ok(report)
}

pub fn mkdir_in_volume(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    path: &str,
    now: u64,
    dry_run: bool,
) -> Result<serde_json::Value> {
    let plan = DirectoryCreation::prepare(cx, volume, path, now)?;
    if dry_run {
        return Ok(plan.report(volume, true));
    }
    plan.execute(cx, volume)
}

fn find_entry_slots(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    directory: super::super::super::Directory,
    entry_offset: u64,
) -> Result<(Slot, Vec<Slot>)> {
    let (offsets, _) = directory_offsets(cx, volume, directory)?;
    let pos = offsets
        .iter()
        .position(|&offset| offset == entry_offset)
        .context("resolved FAT entry offset missing from parent directory")?;
    let short_slot = read_slot(cx, volume, entry_offset, false)?;
    let mut lfn_slots = Vec::new();
    let mut index = pos;
    while index > 0 {
        let slot = read_slot(cx, volume, offsets[index - 1], false)?;
        if slot.bytes[0] == 0 || slot.bytes[0] == 0xE5 || slot.bytes[11] != 0x0F {
            break;
        }
        let is_last = (slot.bytes[0] & 0x40) != 0;
        lfn_slots.push(slot);
        if is_last {
            break;
        }
        index -= 1;
    }
    Ok((short_slot, lfn_slots))
}

/// Set only the native deletion marker. Retaining the original cluster,
/// size, timestamps and LFN payload avoids gratuitously destroying recovery
/// evidence; it does not make undelete or crash recovery part of this writer.
fn retired_slot(slot: &Slot) -> [u8; 32] {
    let mut bytes = slot.bytes;
    bytes[0] = 0xE5;
    bytes
}

fn verify_retired_slot(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    slot: &Slot,
) -> Result<()> {
    if read_slot(cx, volume, slot.offset, false)?.bytes != retired_slot(slot) {
        bail!(
            "native namespace retirement readback failed at {}; allocation retained; image may be dirty and require recovery",
            slot.offset
        );
    }
    Ok(())
}

fn delete_entry_slots(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    short_slot: &Slot,
    lfn_slots: &[Slot],
) -> Result<()> {
    // Validate the complete captured name set before retiring any of it.
    validate_entry_slots(cx, volume, short_slot, lfn_slots)?;
    patch_slot(
        cx,
        volume,
        short_slot.offset,
        &short_slot.bytes,
        &retired_slot(short_slot),
    )?;
    volume.device.sync(cx)?;
    verify_retired_slot(cx, volume, short_slot)?;

    // A verified durable short-entry tombstone must precede LFN retirement.
    // Otherwise a lost acknowledged SFN write could expose its live alias
    // after its long name is deleted, or point at subsequently freed clusters.
    for slot in lfn_slots {
        patch_slot(cx, volume, slot.offset, &slot.bytes, &retired_slot(slot))?;
    }
    if !lfn_slots.is_empty() {
        volume.device.sync(cx)?;
    }
    // Recheck the short entry too: SFN/LFN slots can share a physical sector.
    // Callers may reclaim allocation only after this complete readback gate.
    for slot in std::iter::once(short_slot).chain(lfn_slots) {
        verify_retired_slot(cx, volume, slot)?;
    }
    checkpoint(cx)?;
    Ok(())
}

fn release_map(clusters: &[u32]) -> Vec<(u32, u32)> {
    let mut release: Vec<(u32, u32)> = clusters
        .iter()
        .copied()
        .enumerate()
        .map(|(index, cluster)| {
            (
                cluster,
                clusters
                    .get(index + 1)
                    .copied()
                    .unwrap_or(super::super::EXPECT_END),
            )
        })
        .collect();
    release.sort_unstable_by_key(|&(cluster, _)| cluster);
    release
}

pub fn unlink_in_volume(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    path: &str,
    dry_run: bool,
) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    let (directory, _) = parent(cx, volume, path)?;
    validate_boot_state(cx, volume)?;
    let entry = volume.resolve(cx, path)?.ok_or(FfsError::IsDirectory)?;
    if entry.native.is_directory() {
        return Err(FfsError::IsDirectory.into());
    }
    if entry.native.attributes & 0x01 != 0 {
        return Err(FfsError::PermissionDenied.into());
    }
    if entry.native.attributes & 0xC8 != 0 {
        bail!("unsupported native attributes on unlink target");
    }
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!(
            "unlink requires a complete clean allocation/namespace check: {}",
            serde_json::to_string(&before)?
        );
    }
    let chain = volume.file_chain(cx, &entry)?;
    let release = release_map(&chain.clusters);
    let (short_slot, lfn_slots) = find_entry_slots(cx, volume, directory, entry.offset)?;
    let free_after = before.free_clusters + release.len() as u64;
    let files_after = before.files.saturating_sub(1);
    let mut report = json!({
        "operation": "unlink_file",
        "dry_run": dry_run,
        "unlinked": !dry_run,
        "format": format!("{:?}", volume.geometry.kind()),
        "volume_offset": volume.base,
        "volume_bytes": volume.geometry.volume_bytes(),
        "path": path,
        "entry_offset": entry.offset,
        "released_clusters": release.len(),
        "free_clusters_after": free_after,
    });
    validate_entry_slots(cx, volume, &short_slot, &lfn_slots)?;
    checkpoint(cx)?;
    if dry_run {
        return Ok(report);
    }
    set_dirty(cx, volume, true)?;
    set_hints(cx, volume, u32::MAX)?;
    volume.device.sync(cx)?;
    delete_entry_slots(cx, volume, &short_slot, &lfn_slots)?;
    if !release.is_empty() {
        change_fat(
            cx,
            volume,
            &release
                .iter()
                .map(|&(cluster, expected)| (cluster, expected, 0)),
        )?;
        volume.device.sync(cx)?;
    }
    set_hints(cx, volume, free_after as u32)?;
    volume.device.sync(cx)?;
    let verification = volume.check(cx)?;
    if !verification.clean
        || !verification.complete
        || !verification.namespace_complete
        || verification.free_clusters != free_after
        || verification.files != files_after
        || verification.directories != before.directories
    {
        bail!(
            "unlink verification failed: {}",
            serde_json::to_string(&verification)?
        );
    }
    set_dirty(cx, volume, false)?;
    volume.device.sync(cx)?;
    report["verification"] = serde_json::to_value(verification)?;
    Ok(report)
}

pub fn rmdir_in_volume(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    path: &str,
    dry_run: bool,
) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    let (directory, _) = parent(cx, volume, path)?;
    validate_boot_state(cx, volume)?;
    let entry = volume
        .resolve(cx, path)?
        .ok_or_else(|| anyhow::anyhow!("cannot remove root directory"))?;
    if !entry.native.is_directory() {
        return Err(FfsError::NotDirectory.into());
    }
    if entry.native.attributes & 0x01 != 0 {
        return Err(FfsError::PermissionDenied.into());
    }
    let children = volume.list(
        cx,
        super::super::super::Directory::Cluster(entry.native.first_cluster),
    )?;
    if !children.is_empty() {
        return Err(FfsError::NotEmpty).context("FAT directory is not empty");
    }
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!(
            "rmdir requires a complete clean allocation/namespace check: {}",
            serde_json::to_string(&before)?
        );
    }
    let max_dir_clusters = (super::super::super::MAX_DIRECTORY_SLOTS * 32)
        .div_ceil(volume.geometry.cluster_bytes() as usize);
    let clusters = volume.allocation_chain(
        cx,
        entry.native.first_cluster,
        1,
        entry.offset,
        max_dir_clusters,
    )?;
    let release = release_map(&clusters);
    let (short_slot, lfn_slots) = find_entry_slots(cx, volume, directory, entry.offset)?;
    let free_after = before.free_clusters + release.len() as u64;
    let dirs_after = before.directories.saturating_sub(1);
    let mut report = json!({
        "operation": "remove_directory",
        "dry_run": dry_run,
        "removed_directory": !dry_run,
        "format": format!("{:?}", volume.geometry.kind()),
        "volume_offset": volume.base,
        "volume_bytes": volume.geometry.volume_bytes(),
        "path": path,
        "entry_offset": entry.offset,
        "released_clusters": release.len(),
        "free_clusters_after": free_after,
    });
    validate_entry_slots(cx, volume, &short_slot, &lfn_slots)?;
    checkpoint(cx)?;
    if dry_run {
        return Ok(report);
    }
    set_dirty(cx, volume, true)?;
    set_hints(cx, volume, u32::MAX)?;
    volume.device.sync(cx)?;
    delete_entry_slots(cx, volume, &short_slot, &lfn_slots)?;
    if !release.is_empty() {
        change_fat(
            cx,
            volume,
            &release
                .iter()
                .map(|&(cluster, expected)| (cluster, expected, 0)),
        )?;
        volume.device.sync(cx)?;
    }
    set_hints(cx, volume, free_after as u32)?;
    volume.device.sync(cx)?;
    let verification = volume.check(cx)?;
    if !verification.clean
        || !verification.complete
        || !verification.namespace_complete
        || verification.free_clusters != free_after
        || verification.files != before.files
        || verification.directories != dirs_after
    {
        bail!(
            "rmdir verification failed: {}",
            serde_json::to_string(&verification)?
        );
    }
    set_dirty(cx, volume, false)?;
    volume.device.sync(cx)?;
    report["verification"] = serde_json::to_value(verification)?;
    Ok(report)
}

/// An existing destination keeps its native name set and slot. In particular,
/// replacing a file must not unlink it to make room for a new name: that loses
/// acknowledged data on a later preflight failure and cannot work in dry runs.
enum RenameTarget {
    Existing {
        entry: Slot,
        long_slots: Vec<Slot>,
        release: Vec<(u32, u32)>,
    },
    New(Namespace),
}

impl RenameTarget {
    fn entry(&self) -> &Slot {
        match self {
            Self::Existing { entry, .. } => entry,
            Self::New(namespace) => &namespace.entry,
        }
    }

    fn directory_clusters(&self) -> usize {
        match self {
            Self::Existing { .. } => 0,
            Self::New(namespace) => namespace.directory_clusters(),
        }
    }

    fn release(&self) -> &[(u32, u32)] {
        match self {
            Self::Existing { release, .. } => release,
            Self::New(_) => &[],
        }
    }

    fn validate(&self, cx: &Cx, volume: &super::super::super::FatVolume) -> Result<()> {
        match self {
            Self::Existing {
                entry, long_slots, ..
            } => validate_entry_slots(cx, volume, entry, long_slots),
            Self::New(namespace) => namespace.validate(cx, volume),
        }
    }
}

fn validate_entry_slots(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    short: &Slot,
    long: &[Slot],
) -> Result<()> {
    for slot in std::iter::once(short).chain(long) {
        checkpoint(cx)?;
        if read_slot(cx, volume, slot.offset, false)?.bytes != slot.bytes {
            bail!(
                "native rename entry changed after preflight at {}",
                slot.offset
            );
        }
    }
    Ok(())
}

fn rename_chain(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    entry: &super::super::super::Entry,
) -> Result<Vec<u32>> {
    if !entry.native.is_directory() {
        return Ok(volume.file_chain(cx, entry)?.clusters);
    }
    let limit = (super::super::super::MAX_DIRECTORY_SLOTS * 32)
        .div_ceil(volume.geometry.cluster_bytes() as usize);
    Ok(volume.allocation_chain(cx, entry.native.first_cluster, 1, entry.offset, limit)?)
}

/// Walk the resolved destination ancestry rather than comparing path spellings.
/// Case folding, short aliases and redundant separators must not let a native
/// directory become reachable from itself. Image paths never follow native '..'.
fn validate_rename_ancestry(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    source_cluster: u32,
    to: &str,
) -> Result<()> {
    let parent_path = to.rsplit_once('/').map_or("", |(path, _)| path);
    let mut directory = super::super::super::Directory::Root;
    for component in parent_path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        checkpoint(cx)?;
        let entry = volume.lookup(cx, directory, component)?;
        directory = entry.directory()?;
        if entry.native.first_cluster == source_cluster {
            bail!("cannot rename directory into its own subtree (native cluster identity)");
        }
    }
    Ok(())
}

pub fn rename_in_volume(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    from: &str,
    to: &str,
    dry_run: bool,
) -> Result<serde_json::Value> {
    rename_with_mode(cx, volume, from, to, dry_run, false)
}

impl super::super::super::FatVolume {
    /// No-clobber rename under the caller's exclusive offline/mount writer gate.
    /// Destination admission and mutation belong to one serialized operation.
    pub fn rename_noreplace(
        &self,
        cx: &Cx,
        from: &str,
        to: &str,
        dry_run: bool,
    ) -> Result<serde_json::Value> {
        rename_with_mode(cx, self, from, to, dry_run, true)
    }
}

fn rename_with_mode(
    cx: &Cx,
    volume: &super::super::super::FatVolume,
    from: &str,
    to: &str,
    dry_run: bool,
    no_replace: bool,
) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    let (src_dir, _) = parent(cx, volume, from)?;
    let (dst_dir, dst_leaf) = parent(cx, volume, to)?;
    validate_boot_state(cx, volume)?;
    let src_entry = volume
        .resolve(cx, from)?
        .ok_or_else(|| anyhow::anyhow!("cannot rename root directory"))?;
    if src_entry.native.attributes & 0xC8 != 0 {
        bail!("unsupported native attributes on rename source");
    }
    if src_entry.native.is_directory() {
        validate_rename_ancestry(cx, volume, src_entry.native.first_cluster, to)?;
    }
    let dst_existing = match volume.lookup(cx, dst_dir, &dst_leaf) {
        Ok(entry) => Some(entry),
        Err(FfsError::NotFound(_)) => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(entry) = &dst_existing {
        if no_replace {
            return Err(FfsError::Exists.into());
        }
        if entry.offset == src_entry.offset {
            let displayed = src_entry.name()?;
            if displayed != dst_leaf
                && volume.oem_code_page.name_key(&displayed)
                    == volume.oem_code_page.name_key(&dst_leaf)
            {
                if src_dir != dst_dir {
                    bail!("same FAT entry is reachable through different native parents");
                }
                return spelling::rename(cx, volume, from, to, &src_entry, dry_run);
            }
            return Ok(json!({
                "operation": "rename",
                "dry_run": dry_run,
                "renamed": !dry_run,
                "unchanged": true,
                "from": from,
                "to": to,
                "entry_offset": src_entry.offset,
                "old_entry_offset": src_entry.offset,
                "new_entry_offset": src_entry.offset,
            }));
        }
        if src_entry.native.is_directory() && !entry.native.is_directory() {
            return Err(FfsError::NotDirectory.into());
        }
        if !src_entry.native.is_directory() && entry.native.is_directory() {
            return Err(FfsError::IsDirectory.into());
        }
        if entry.native.attributes & 0x01 != 0 {
            return Err(FfsError::PermissionDenied.into());
        }
        if entry.native.attributes & 0xC8 != 0 {
            bail!("unsupported native attributes on rename destination");
        }
        if entry.native.is_directory() && !volume.list(cx, entry.directory()?)?.is_empty() {
            return Err(FfsError::NotEmpty).context("FAT target directory is not empty");
        }
    }

    // This complete preflight is identical for dry-run and execution. No
    // destination entry, FAT allocation or dirty marker has been changed yet.
    let before = volume.check(cx)?;
    if !before.clean || !before.complete || !before.namespace_complete {
        bail!(
            "rename requires a complete clean allocation/namespace check: {}",
            serde_json::to_string(&before)?
        );
    }
    let source_chain = rename_chain(cx, volume, &src_entry)?;
    let (src_short, src_lfn) = find_entry_slots(cx, volume, src_dir, src_entry.offset)?;
    let replaced = dst_existing.is_some();
    let target = if let Some(entry) = dst_existing {
        let release = release_map(&rename_chain(cx, volume, &entry)?);
        let (entry, long_slots) = find_entry_slots(cx, volume, dst_dir, entry.offset)?;
        RenameTarget::Existing {
            entry,
            long_slots,
            release,
        }
    } else {
        let name = super::names::NativeName::plan(cx, volume, dst_dir, &dst_leaf)?;
        if src_dir == dst_dir
            && let Some(slots) = rename_in_place::reserve_before(
                cx,
                volume,
                src_dir,
                &src_short,
                &src_lfn,
                name.long_slots(),
            )?
        {
            // FAT16's fixed root cannot grow, and a same-directory rename
            // should not need a second free name set or any spare clusters.
            // Compare native parent identities, not case/alias path spellings.
            return rename_in_place::Rename {
                from,
                to,
                leaf: &dst_leaf,
                short: &src_short,
                long: &slots,
                name: &name,
                chain: &source_chain,
                before: &before,
            }
            .execute(cx, volume, dry_run);
        }
        let needed_slots = name.long_slots() + 1;
        let mut reservation = reserve_slots(cx, volume, dst_dir, needed_slots)?;
        let allocated = reserve_clusters(cx, volume, reservation.extra, before.free_clusters)?;
        let extension = if let Some(tail) = reservation.tail {
            let cluster = *allocated
                .first()
                .context("missing reserved destination directory cluster")?;
            for &ext_cluster in &allocated {
                let start = volume.cluster_offset(ext_cluster)?;
                for offset in
                    (start..start + u64::from(volume.geometry.cluster_bytes())).step_by(32)
                {
                    if reservation.slots.len() < needed_slots {
                        reservation.slots.push(read_slot(cx, volume, offset, true)?);
                    } else if reservation.successor.is_none() {
                        reservation.successor = Some(read_slot(cx, volume, offset, true)?);
                        break;
                    }
                }
            }
            Some(Extension {
                tail,
                cluster,
                additional: allocated.get(1).copied(),
            })
        } else {
            None
        };
        let entry = reservation
            .slots
            .pop()
            .context("missing reserved rename destination short-entry slot")?;
        RenameTarget::New(Namespace {
            successor: reservation.successor,
            extension,
            entry,
            long_slots: reservation.slots,
            name,
        })
    };
    let mut updated = src_short.bytes;
    match &target {
        RenameTarget::Existing { entry, .. } => {
            // Keep the destination's LFN checksum, aliases and case flags valid.
            updated[..11].copy_from_slice(&entry.bytes[..11]);
            updated[12] = entry.bytes[12];
        }
        RenameTarget::New(namespace) => {
            updated[..11].copy_from_slice(&namespace.name.short);
            updated[12] = namespace.name.flags;
        }
    }

    // Admit and capture the complete parent-link patch before mutation. FAT16's
    // EA index and FAT32's reserved high nibble are not cluster-address bits.
    let dotdot = if src_entry.native.is_directory() && dst_dir != src_dir {
        let parent_cluster = |directory| match directory {
            super::super::super::Directory::Root => 0,
            super::super::super::Directory::Cluster(cluster) => cluster,
        };
        let offset = volume.cluster_offset(src_entry.native.first_cluster)? + 32;
        let old = read_slot(cx, volume, offset, false)?;
        if &old.bytes[..11] != b"..         "
            || old.bytes[11] != 0x10
            || raw_cluster(volume.geometry.kind(), &old.bytes) != parent_cluster(src_dir)
            || old.bytes[28..32] != [0; 4]
        {
            bail!("native directory parent entry does not match rename source ancestry");
        }
        let cluster = parent_cluster(dst_dir);
        let mut new = old.bytes;
        if volume.geometry.kind() == FatKind::Fat32 {
            let high = u16::from_le_bytes([new[20], new[21]]) & 0xF000;
            new[20..22].copy_from_slice(&(high | ((cluster >> 16) as u16)).to_le_bytes());
        }
        new[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
        Some((old, new))
    } else {
        None
    };
    let free_after = before
        .free_clusters
        .checked_sub(target.directory_clusters() as u64)
        .and_then(|free| free.checked_add(target.release().len() as u64))
        .filter(|free| *free <= u64::from(volume.geometry.cluster_count()))
        .context("rename free-cluster accounting overflow")?;
    let files_after = before
        .files
        .checked_sub(u64::from(replaced && !src_entry.native.is_directory()))
        .context("rename file accounting underflow")?;
    let directories_after = before
        .directories
        .checked_sub(u64::from(replaced && src_entry.native.is_directory()))
        .context("rename directory accounting underflow")?;
    validate_entry_slots(cx, volume, &src_short, &src_lfn)?;
    target.validate(cx, volume)?;
    if let Some((old, _)) = &dotdot {
        validate_entry_slots(cx, volume, old, &[])?;
    }
    checkpoint(cx)?;
    let mut report = json!({
        "operation": "rename",
        "dry_run": dry_run,
        "renamed": !dry_run,
        "replaced_existing": replaced,
        "format": format!("{:?}", volume.geometry.kind()),
        "volume_offset": volume.base,
        "volume_bytes": volume.geometry.volume_bytes(),
        "from": from,
        "to": to,
        "old_entry_offset": src_short.offset,
        "new_entry_offset": target.entry().offset,
        "released_clusters": target.release().len(),
        "free_clusters_after": free_after,
        "contract": "ordered native rename; interrupted mutation may require recovery; not atomic",
    });
    if dry_run {
        return Ok(report);
    }

    let mut phase = "publishing dirty state";
    let result = (|| -> Result<serde_json::Value> {
        set_dirty(cx, volume, true)?;
        set_hints(cx, volume, u32::MAX)?;
        volume.device.sync(cx)?;

        phase = "preparing destination namespace";
        let expected = match &target {
            RenameTarget::Existing { entry, .. } => entry.bytes,
            RenameTarget::New(namespace) => {
                namespace.stage(cx, volume)?;
                if namespace.long_slots.is_empty() {
                    namespace.entry.initialized()
                } else {
                    deleted_slot()
                }
            }
        };
        phase = "publishing destination entry";
        patch_slot(cx, volume, target.entry().offset, &expected, &updated)?;
        volume.device.sync(cx)?;

        // Do not remove the source or reclaim the replaced object until the
        // ordinary native reader sees the exact published record and chain.
        phase = "verifying destination before source retirement";
        let published = volume
            .resolve(cx, to)?
            .context("renamed destination is missing")?;
        if published.offset != target.entry().offset
            || read_slot(cx, volume, published.offset, false)?.bytes != updated
            || rename_chain(cx, volume, &published)? != source_chain
        {
            bail!("rename destination readback differs from source identity or allocation");
        }
        if let RenameTarget::Existing { long_slots, .. } = &target {
            for slot in long_slots {
                if read_slot(cx, volume, slot.offset, false)?.bytes != slot.bytes {
                    bail!("rename changed the retained destination long name");
                }
            }
        }

        phase = "updating native directory parent";
        if let Some((old, new)) = &dotdot {
            patch_slot(cx, volume, old.offset, &old.bytes, new)?;
            volume.device.sync(cx)?;
            if read_slot(cx, volume, old.offset, false)?.bytes != *new {
                bail!("renamed directory parent failed native readback");
            }
        }

        phase = "retiring source namespace";
        delete_entry_slots(cx, volume, &src_short, &src_lfn)?;
        phase = "releasing replaced destination allocation";
        if !target.release().is_empty() {
            change_fat(
                cx,
                volume,
                &target
                    .release()
                    .iter()
                    .map(|&(cluster, expected)| (cluster, expected, 0)),
            )?;
            volume.device.sync(cx)?;
        }
        phase = "checking completed rename";
        set_hints(cx, volume, free_after as u32)?;
        volume.device.sync(cx)?;
        let verification = volume.check(cx)?;
        if !verification.clean
            || !verification.complete
            || !verification.namespace_complete
            || verification.free_clusters != free_after
            || verification.files != files_after
            || verification.directories != directories_after
        {
            bail!(
                "rename verification failed: {}",
                serde_json::to_string(&verification)?
            );
        }
        phase = "synchronizing final clean state";
        set_dirty(cx, volume, false)?;
        volume.device.sync(cx)?;
        report["durability"] = "namespace_allocation_and_clean_state_synced".into();
        report["verification"] = serde_json::to_value(verification)?;
        Ok(report)
    })();
    result.with_context(|| format!(
        "FAT rename failed while {phase}; image retained and may be dirty or partially changed; no rollback or atomicity is claimed"
    ))
}

pub fn run_unlink(cx: &Cx, args: &UnlinkArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if !args.offline_image {
        bail!("--offline-image is required");
    }
    let volume = if args.image.sidecar.is_some() {
        super::super::open_volume(cx, &args.image, !args.dry_run)?
    } else {
        let (image, image_stamp) = open_regular(&args.image.image, !args.dry_run)?;
        let volume = super::super::super::FatVolume::from_device(
            cx,
            Box::new(ImageFile {
                file: Arc::clone(&image),
                length: image_stamp.length,
                writable: !args.dry_run,
            }),
            args.image.offset,
            args.image
                .length
                .unwrap_or_else(|| image_stamp.length.saturating_sub(args.image.offset)),
        )?
        .with_oem_code_page(args.image.oem_code_page);
        stable(&image, &args.image.image, image_stamp)?;
        volume
    };
    let mut report = unlink_in_volume(cx, &volume, &args.path, args.dry_run)?;
    if !args.dry_run && args.image.sidecar.is_some() {
        report["sidecar_refreshed"] = true.into();
    }
    Ok(report)
}

pub fn run_rmdir(cx: &Cx, args: &RmdirArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if !args.offline_image {
        bail!("--offline-image is required");
    }
    let volume = if args.image.sidecar.is_some() {
        super::super::open_volume(cx, &args.image, !args.dry_run)?
    } else {
        let (image, image_stamp) = open_regular(&args.image.image, !args.dry_run)?;
        let volume = super::super::super::FatVolume::from_device(
            cx,
            Box::new(ImageFile {
                file: Arc::clone(&image),
                length: image_stamp.length,
                writable: !args.dry_run,
            }),
            args.image.offset,
            args.image
                .length
                .unwrap_or_else(|| image_stamp.length.saturating_sub(args.image.offset)),
        )?
        .with_oem_code_page(args.image.oem_code_page);
        stable(&image, &args.image.image, image_stamp)?;
        volume
    };
    let mut report = rmdir_in_volume(cx, &volume, &args.path, args.dry_run)?;
    if !args.dry_run && args.image.sidecar.is_some() {
        report["sidecar_refreshed"] = true.into();
    }
    Ok(report)
}

pub fn run_rename(cx: &Cx, args: &RenameArgs) -> Result<serde_json::Value> {
    checkpoint(cx)?;
    if !args.offline_image {
        bail!("--offline-image is required");
    }
    if args.exchange && args.no_replace {
        bail!("--exchange and --no-replace are mutually exclusive");
    }
    let volume = if args.image.sidecar.is_some() {
        super::super::open_volume(cx, &args.image, !args.dry_run)?
    } else {
        let (image, image_stamp) = open_regular(&args.image.image, !args.dry_run)?;
        let volume = super::super::super::FatVolume::from_device(
            cx,
            Box::new(ImageFile {
                file: Arc::clone(&image),
                length: image_stamp.length,
                writable: !args.dry_run,
            }),
            args.image.offset,
            args.image
                .length
                .unwrap_or_else(|| image_stamp.length.saturating_sub(args.image.offset)),
        )?
        .with_oem_code_page(args.image.oem_code_page);
        stable(&image, &args.image.image, image_stamp)?;
        volume
    };
    let mut report = if args.exchange {
        volume.rename_exchange(cx, &args.from, &args.to, args.dry_run)?
    } else {
        rename_with_mode(
            cx,
            &volume,
            &args.from,
            &args.to,
            args.dry_run,
            args.no_replace,
        )?
    };
    if !args.dry_run && args.image.sidecar.is_some() {
        report["sidecar_refreshed"] = true.into();
    }
    Ok(report)
}
