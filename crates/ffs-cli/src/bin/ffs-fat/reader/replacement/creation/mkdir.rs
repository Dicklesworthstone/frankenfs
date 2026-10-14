//! Ordered creation of one native FAT directory on an offline image.
//!
//! The new directory cluster, including native dot entries, is initialized and
//! synchronized before its FAT allocation or parent namespace entry is published.
//! Parent long-name and growth ordering is shared with file creation.

use super::super::{
    ImageFile, change_fat, checkpoint, open_regular, reserve_clusters, set_dirty, set_hints,
    stable, validate_boot_state, write_volume,
};
use super::{Extension, Namespace, deleted_slot, parent, patch_slot, read_slot, reserve_slots};
use crate::ImageArgs;
use anyhow::{Context, Result, bail};
use asupersync::{Cx, types::CancelKind};
use clap::Args;
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
            write_volume(
                cx,
                volume,
                volume.cluster_offset(self.directory_cluster)?,
                &bytes,
            )?;
            volume.device.sync(cx)?;

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
            if !verification.clean
                || !verification.complete
                || !verification.namespace_complete
            {
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
            if verification.files != self.files || verification.directories != self.directories
            {
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
    let signal = cx.clone();
    ctrlc::set_handler(move || {
        signal.cancel_with(
            CancelKind::User,
            Some("FAT directory creation interrupted by Ctrl+C"),
        );
    })
    .context("installing FAT mkdir cancellation handler; no mutation started")?;

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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock predates the Unix epoch")?
        .as_secs();
    let plan = DirectoryCreation::prepare(cx, &volume, &args.path, now)?;
    stable(&image, &args.image.image, image_stamp)?;
    checkpoint(cx)?;
    if args.dry_run {
        return Ok(plan.report(&volume, true));
    }
    plan.execute(cx, &volume)
}
