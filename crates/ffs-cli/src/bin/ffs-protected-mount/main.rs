#![forbid(unsafe_code)]
#![recursion_limit = "256"]
//! Explicitly authorized, sidecar-protected FUSE mounts.
//!
//! All format reads and writes go through the same admitted repair device.
//! Caller writes require --rw; read-only remains the default. The ordinary
//! mount command is unchanged, and startup differences never authorize rollback.

use ffs_fat as fat;
use ffs_ntfs as ntfs;
use ffs_zfs as zfs;

#[path = "../../mount_worker.rs"]
mod mount_worker;
mod scrub;

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::Parser;
use ffs_block::ByteDevice;
use ffs_core::{
    DetectedFilesystem, Ext4JournalReplayMode, FsOps, OpenFs, OpenOptions, RequestScope,
    detect_all_filesystems_on_device,
};
use ffs_error::FfsError;
use ffs_fuse::{MountConfig, MountOptions, mount_managed};
use ffs_ondisk::EXT4_VALID_FS;
use ffs_repair::decision::RepairLossCalibration;
use ffs_repair::por::PorKey;
use ffs_repair::sidecar::live::{
    ProtectedStorageSet, SharedEvidenceLedger, SidecarImageDevice, StorageSetOpenOptions,
    blake3_digest, open_shared_evidence_ledger,
};
use ffs_repair::sidecar::{MemberRole, NativeCommitBinding, ProtectedViewIdentity, TrustPolicy};
use ffs_types::{ByteOffset, InodeNumber};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Parser)]
#[command(
    name = "ffs-protected-mount",
    about = "Mount a clean image or storage set with RaptorQ protection (read-only unless --rw)"
)]
struct Args {
    image: PathBuf,
    sidecar: PathBuf,
    /// Existing empty directory. Omit only with --check.
    #[arg(required_unless_present = "check")]
    mountpoint: Option<PathBuf>,
    #[command(flatten)]
    authority: Authority,
    #[command(flatten)]
    scrub: scrub::Options,
    #[command(flatten)]
    set: SetOptions,
    /// Validate admission and filesystem opening without mounting or enabling writes.
    #[arg(long, conflicts_with = "mountpoint")]
    check: bool,
    /// Allow filesystem writes. Durability barriers also refresh sidecar protection.
    #[arg(long, conflicts_with = "check")]
    rw: bool,
    /// Periodic commit interval (ext4: 5s, btrfs: 30s); 0 disables the timer.
    #[arg(long, requires = "rw", conflicts_with = "check")]
    commit_interval_secs: Option<u64>,
    /// Let other users access the mount, subject to normal file permissions.
    #[arg(long, conflicts_with = "check")]
    allow_other: bool,
}

#[derive(Debug, clap::Args)]
struct Authority {
    /// Confirm no kernel mount or other program will access this image.
    #[arg(long, required = true)]
    exclusive_image: bool,
    /// Authorize verified repair writes to the image, even on a read-only mount.
    #[arg(long, required = true)]
    allow_repair: bool,
}

#[derive(Debug, Default, clap::Args)]
struct SetOptions {
    /// Whole-storage-set manifest (FFSRQSM3). Required for multi-member topologies.
    #[arg(long)]
    manifest: Option<PathBuf>,
    /// Additional data/mirror member pairs (<IMAGE> <SIDECAR>) in manifest order after member 0.
    #[arg(long = "member", num_args = 2, value_names = ["IMAGE", "SIDECAR"])]
    extra_members: Vec<PathBuf>,
    /// External log member pairs (<IMAGE> <SIDECAR>).
    #[arg(long = "log-member", num_args = 2, value_names = ["IMAGE", "SIDECAR"])]
    log_members: Vec<PathBuf>,
    /// Special/metadata member pairs (<IMAGE> <SIDECAR>).
    #[arg(long = "special-member", num_args = 2, value_names = ["IMAGE", "SIDECAR"])]
    special_members: Vec<PathBuf>,
    /// Partition/slice byte offset inside a standalone single-member image.
    #[arg(long)]
    offset: Option<u64>,
    /// Partition/slice byte length inside a standalone single-member image.
    #[arg(long)]
    length: Option<u64>,
    /// ZPL dataset path relative to the pool root. Defaults to the manifest view, or root without a manifest.
    #[arg(long)]
    zfs_dataset: Option<String>,
    /// Expected ZFS pool GUID (optional; verified against on-disk labels).
    #[arg(long)]
    pool_guid: Option<u64>,
    /// Explicit ZFS label index (0..=3) for writable TXG admission.
    #[arg(long)]
    zfs_label: Option<usize>,
    /// Explicit ZFS Uberblock ring slot for writable TXG admission.
    #[arg(long)]
    zfs_slot: Option<usize>,
    /// 32-byte raw or 64-hex PorKey file for cryptographic manifest provenance.
    #[arg(long)]
    trust_key_file: Option<PathBuf>,
    /// Require authenticated trusted-root provenance (refuses unkeyed checksums).
    #[arg(long)]
    require_trusted_root: bool,
    /// JSON string, file path, or "none" for two-stage repair loss calibration.
    #[arg(long)]
    repair_calibration: Option<String>,
    /// Append-only JSONL file path for protected repair gate and commit-ACK audit records.
    #[arg(long)]
    evidence_ledger: Option<PathBuf>,
}

/// Caller-write authority is independent of read-repair authority. Both modes
/// retain the same device and inode locks for every format I/O operation.
#[cfg(test)]
#[derive(Debug)]
struct ProtectedDevice {
    inner: Arc<SidecarImageDevice>,
    writable: bool,
}

#[cfg(test)]
impl ByteDevice for ProtectedDevice {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> ffs_error::Result<()> {
        self.inner.read_exact_at(cx, offset, out)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, data: &[u8]) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if !self.writable {
            return Err(FfsError::ReadOnly);
        }
        // The device durably fences the old protection before the first source
        // mutation and tracks the intended bytes until a successful sync.
        self.inner.write_all_at(cx, offset, data)
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        // Do not reduce this to source-file fsync: success must also mean that
        // the current repair archive was verified and durably published.
        self.inner.sync(cx)
    }

    fn begin_durability_commit(&self, cx: &Cx) -> ffs_error::Result<()> {
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

pub enum ProtectedFs {
    Core(Box<OpenFs>),
    Fat {
        fs: Box<fat::filesystem::FatFs>,
        writable: bool,
    },
    Ntfs(Box<ntfs::reader::filesystem::NtfsFs>),
    Zfs(Box<zfs::filesystem::ZfsFs>),
}

impl ProtectedFs {
    pub fn is_writable(&self) -> bool {
        match self {
            Self::Core(fs) => fs.is_writable(),
            Self::Fat { writable, .. } => *writable,
            Self::Ntfs(fs) => fs.is_writable(),
            Self::Zfs(fs) => fs.is_writable().unwrap_or(false),
        }
    }

    fn as_ops(&self) -> &dyn FsOps {
        match self {
            Self::Core(fs) => fs.as_ref(),
            Self::Fat { fs, .. } => fs.as_ref(),
            Self::Ntfs(fs) => fs.as_ref(),
            Self::Zfs(fs) => fs.as_ref(),
        }
    }
}

impl mount_worker::PeriodicCommitTarget for ProtectedFs {
    fn default_commit_interval(&self) -> Option<std::time::Duration> {
        match self {
            Self::Core(fs) => {
                mount_worker::PeriodicCommitTarget::default_commit_interval(fs.as_ref())
            }
            Self::Fat { fs, .. } => FsOps::default_commit_interval(fs.as_ref()),
            Self::Ntfs(fs) => FsOps::default_commit_interval(fs.as_ref()),
            Self::Zfs(fs) => FsOps::default_commit_interval(fs.as_ref()),
        }
    }

    fn periodic_commit(&self, cx: &Cx) -> ffs_error::Result<bool> {
        match self {
            Self::Core(fs) => fs.periodic_commit(cx),
            Self::Fat { fs, .. } => FsOps::periodic_commit(fs.as_ref(), cx),
            Self::Ntfs(fs) => FsOps::periodic_commit(fs.as_ref(), cx),
            Self::Zfs(fs) => FsOps::periodic_commit(fs.as_ref(), cx),
        }
    }
}

#[allow(clippy::too_many_arguments)]
impl FsOps for ProtectedFs {
    ffs_core::delegate_fs_ops!(self, self.as_ops());
}

struct Prepared {
    fs: Arc<ProtectedFs>,
    device: Arc<SidecarImageDevice>,
    storage_set: Arc<ProtectedStorageSet>,
    filesystem: &'static str,
    pool_guid: Option<u64>,
    mountpoint: Option<PathBuf>,
}

impl Prepared {
    fn finish(self, cx: &Cx) -> Result<()> {
        // Managed unmount can time out. Do NOT announce a clean shutdown or
        // release our final ownership while a dispatch thread still owns ops.
        let fs = Arc::try_unwrap(self.fs).map_err(|_| {
            anyhow::anyhow!("FUSE still owns the filesystem after unmount; shutdown is incomplete")
        })?;
        if fs.is_writable() {
            // Drain retained unlinked inodes/orphans and native durability state
            // while the filesystem still exists and dispatch is quiescent.
            (|| -> ffs_error::Result<()> {
                FsOps::flush_on_destroy(&fs, cx)?;
                FsOps::fsyncdir(
                    &fs,
                    cx,
                    &mut RequestScope::empty(),
                    InodeNumber(1),
                    0,
                    false,
                )?;
                Ok(())
            })()
            .context("checkpoint protected filesystem before shutdown")?;
        }
        drop(fs);
        let binding =
            compute_live_native_binding(cx, &self.storage_set, self.filesystem, self.pool_guid)
                .context("extract native commit binding before final seal")?;
        self.storage_set
            .seal_committed(cx, binding)
            .context("final protected-device sync")
    }
}

fn load_por_key(path: &Path) -> Result<PorKey> {
    let raw = std::fs::read(path).with_context(|| format!("read trust key {}", path.display()))?;
    if raw.len() == 32 {
        let mut key = [0_u8; 32];
        key.copy_from_slice(&raw);
        return Ok(key);
    }
    let trimmed = std::str::from_utf8(&raw)
        .context("trust key file must be 32 raw bytes or 64 hex characters")?
        .trim();
    if trimmed.len() != 64 {
        bail!("trust key file must be 32 raw bytes or 64 hex characters");
    }
    let mut key = [0_u8; 32];
    for (idx, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&trimmed[idx * 2..idx * 2 + 2], 16)
            .context("invalid hex digit in trust key file")?;
    }
    Ok(key)
}

fn load_calibration(spec: Option<&str>) -> Result<Option<RepairLossCalibration>> {
    let Some(raw_spec) = spec else {
        return Ok(Some(RepairLossCalibration::default_operator_exclusive()));
    };
    if raw_spec.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let payload = if Path::new(raw_spec).is_file() {
        std::fs::read_to_string(raw_spec)
            .with_context(|| format!("read repair calibration file {raw_spec}"))?
    } else {
        raw_spec.to_owned()
    };
    let parsed: RepairLossCalibration =
        serde_json::from_str(&payload).context("parse repair loss calibration JSON")?;
    parsed
        .validate()
        .map_err(|err| anyhow::anyhow!("invalid repair loss calibration: {err}"))?;
    Ok(Some(parsed))
}

fn open_evidence_ledger(path: Option<&Path>) -> Result<Option<SharedEvidenceLedger>> {
    path.map(|p| {
        open_shared_evidence_ledger(p)
            .with_context(|| format!("open evidence ledger {}", p.display()))
    })
    .transpose()
}

#[derive(Debug)]
struct CheckedInputs {
    member_paths: Vec<(PathBuf, PathBuf)>,
    manifest: Option<PathBuf>,
    mountpoint: Option<PathBuf>,
}

fn checked_paths(args: &Args) -> Result<CheckedInputs> {
    args.scrub.validate(args.check)?;
    if !args.authority.exclusive_image || !args.authority.allow_repair {
        bail!("--exclusive-image and --allow-repair are required");
    }
    if args.check && args.rw {
        bail!("--check cannot enable filesystem writes; omit --rw");
    }
    if args.commit_interval_secs.is_some() && !args.rw {
        bail!("--commit-interval-secs requires --rw");
    }
    if args.check == args.mountpoint.is_some() {
        bail!("choose a mountpoint or --check, but not both");
    }
    let has_extra_members = !args.set.extra_members.is_empty()
        || !args.set.log_members.is_empty()
        || !args.set.special_members.is_empty();
    if has_extra_members && args.set.manifest.is_none() {
        bail!("multi-member protected mounts require --manifest binding the complete storage set");
    }
    if args.set.manifest.is_some() && (args.set.offset.is_some() || args.set.length.is_some()) {
        bail!("--offset/--length cannot override slice geometry bound in --manifest");
    }
    let mountpoint = args
        .mountpoint
        .as_deref()
        .map(|path| -> Result<PathBuf> {
            let path = path.canonicalize().context("resolve mountpoint")?;
            if !path.is_dir() {
                bail!("mountpoint is not a directory");
            }
            if let Some(entry) = std::fs::read_dir(&path)?.next() {
                entry?;
                bail!("protected mount requires an empty mountpoint");
            }
            Ok(path)
        })
        .transpose()?;
    let mut member_paths = Vec::new();
    let primary_img = args.image.canonicalize().context("resolve image")?;
    let primary_rq = args.sidecar.canonicalize().context("resolve sidecar")?;
    member_paths.push((primary_img, primary_rq));
    for pair in args
        .set
        .extra_members
        .as_chunks::<2>()
        .0
        .iter()
        .chain(args.set.log_members.as_chunks::<2>().0.iter())
        .chain(args.set.special_members.as_chunks::<2>().0.iter())
    {
        let img = pair[0].canonicalize().context("resolve member image")?;
        let rq = pair[1].canonicalize().context("resolve member sidecar")?;
        member_paths.push((img, rq));
    }
    let manifest = args
        .set
        .manifest
        .as_deref()
        .map(|p| p.canonicalize().context("resolve storage-set manifest"))
        .transpose()?;
    if let Some(mp) = &mountpoint {
        for (img, rq) in &member_paths {
            if img.starts_with(mp) || rq.starts_with(mp) {
                bail!("mountpoint would hide a member image or repair archive");
            }
        }
        if let Some(manifest_path) = &manifest
            && manifest_path.starts_with(mp)
        {
            bail!("mountpoint would hide the storage-set manifest");
        }
    }
    Ok(CheckedInputs {
        member_paths,
        manifest,
        mountpoint,
    })
}

fn protected_dataset_components(
    filesystem: &str,
    requested: Option<&str>,
    bound: Option<&ProtectedViewIdentity>,
) -> Result<Vec<Vec<u8>>> {
    if filesystem != "zfs"
        && (requested.is_some() || bound.is_some_and(|view| !view.zfs_dataset.is_empty()))
    {
        bail!("a ZFS dataset view requires a ZFS pool");
    }
    let requested = requested
        .map(ProtectedViewIdentity::from_zfs_dataset)
        .transpose()?;
    if let (Some(view), Some(requested)) = (bound, &requested)
        && requested.zfs_dataset != view.zfs_dataset
    {
        bail!("requested ZFS dataset differs from the view bound in the storage-set manifest");
    }
    Ok(bound
        .or(requested.as_ref())
        .into_iter()
        .flat_map(|view| &view.zfs_dataset)
        .map(|part| part.as_bytes().to_vec())
        .collect())
}

fn clean_single_slice(
    cx: &Cx,
    device: &dyn ByteDevice,
    member_count: usize,
) -> Result<&'static str> {
    match detect_all_filesystems_on_device(cx, device).context("detect protected filesystem")? {
        DetectedFilesystem::Ext4(sb) => {
            if sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::RECOVER)
                || sb.state != EXT4_VALID_FS
                || sb.last_orphan != 0
            {
                bail!("ext4 needs recovery; reconcile offline and create fresh protection");
            }
            if sb.has_compat(ffs_ondisk::Ext4CompatFeatures::HAS_JOURNAL)
                && sb.journal_inum == 0
                && sb.journal_uuid != [0_u8; 16]
                && member_count == 1
            {
                bail!(
                    "ext4 uses an external journal device (journal_inum == 0); single-member sidecar omits required log member"
                );
            }
            Ok("ext4")
        }
        DetectedFilesystem::Btrfs(sb) => {
            if sb.log_root != 0 {
                bail!("btrfs has an active log tree; reconcile offline before protected mount");
            }
            if sb.num_devices != u64::try_from(member_count).unwrap_or(0) || sb.num_devices != 1 {
                bail!("protected mount requires a clean single-device btrfs image");
            }
            Ok("btrfs")
        }
        DetectedFilesystem::Fat16(_) => {
            if member_count != 1 {
                bail!("FAT16 requires a single data member");
            }
            Ok("fat16")
        }
        DetectedFilesystem::Fat32(_) => {
            if member_count != 1 {
                bail!("FAT32 requires a single data member");
            }
            Ok("fat32")
        }
        DetectedFilesystem::Ntfs(_) => {
            if member_count != 1 {
                bail!("NTFS requires a single data member");
            }
            Ok("ntfs")
        }
        DetectedFilesystem::Zfs(_) => Ok("zfs"),
    }
}

fn first_valid_zfs_label(
    cx: &Cx,
    leaf: &zfs::reader::Leaf,
) -> ffs_error::Result<zfs::reader::Label> {
    let mut last_err = None;
    for idx in 0..4 {
        match leaf.label(cx, idx) {
            Ok(label) => return Ok(label),
            Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| FfsError::Corruption {
        block: 0,
        detail: "no valid ZFS vdev label in copies 0..4".into(),
    }))
}

fn compute_live_native_binding(
    cx: &Cx,
    storage_set: &ProtectedStorageSet,
    filesystem: &str,
    pool_guid_hint: Option<u64>,
) -> ffs_error::Result<NativeCommitBinding> {
    let primary = storage_set.members()[0].open_bounded_device(false)?;
    let len = storage_set.members()[0].length;
    match filesystem {
        "ext4" => match detect_all_filesystems_on_device(cx, primary.as_ref())
            .map_err(|err| FfsError::Format(err.to_string()))?
        {
            DetectedFilesystem::Ext4(sb) => Ok(NativeCommitBinding::Ext4 {
                uuid: sb.uuid,
                blocks_count: sb.blocks_count,
                journal_uuid: sb.journal_uuid,
                journal_inum: sb.journal_inum,
                state: sb.state,
            }),
            _ => Err(FfsError::Format("expected ext4 superblock".into())),
        },
        "btrfs" => match detect_all_filesystems_on_device(cx, primary.as_ref())
            .map_err(|err| FfsError::Format(err.to_string()))?
        {
            DetectedFilesystem::Btrfs(sb) => Ok(NativeCommitBinding::Btrfs {
                fsid: sb.fsid,
                generation: sb.generation,
                root_bytenr: sb.root,
                chunk_root_bytenr: sb.chunk_root,
                log_root: sb.log_root,
                num_devices: sb.num_devices,
            }),
            _ => Err(FfsError::Format("expected btrfs superblock".into())),
        },
        "fat16" | "fat32" => {
            let (DetectedFilesystem::Fat16(summary) | DetectedFilesystem::Fat32(summary)) =
                detect_all_filesystems_on_device(cx, primary.as_ref())
                    .map_err(|err| FfsError::Format(err.to_string()))?
            else {
                return Err(FfsError::Format("expected FAT boot sector".into()));
            };
            let mut boot = [0_u8; 512];
            primary.read_exact_at(cx, ByteOffset(0), &mut boot)?;
            let ext_offset = if filesystem == "fat32" { 64 } else { 36 };
            let volume_id = if matches!(boot[ext_offset + 2], 0x28 | 0x29) {
                u32::from_le_bytes([
                    boot[ext_offset + 3],
                    boot[ext_offset + 4],
                    boot[ext_offset + 5],
                    boot[ext_offset + 6],
                ])
            } else {
                0
            };
            let volume = fat::reader::FatVolume::from_device(cx, primary, 0, len)?;
            let check = volume.check(cx)?;
            let total_sectors = if summary.sector_bytes == 0 {
                0
            } else {
                len / u64::from(summary.sector_bytes)
            };
            Ok(NativeCommitBinding::Fat {
                kind: filesystem.to_owned(),
                volume_id,
                total_sectors,
                clean: check.clean,
            })
        }
        "ntfs" => {
            let mut boot = [0_u8; 512];
            primary.read_exact_at(cx, ByteOffset(0), &mut boot)?;
            let boot_blake3 = blake3_digest(&boot);
            let volume = ntfs::reader::NtfsVolume::from_device(cx, primary, 0, len)?;
            let geo = &volume.geometry;
            let restart_lsn = volume
                .record(cx, 2, None)
                .and_then(|rec2| volume.data_stream(cx, &rec2, &[]))
                .and_then(|stream| volume.read(cx, &stream, 0, 8192))
                .ok()
                .and_then(|raw_lf| ffs_ondisk::ntfs::parse_ntfs_logfile(&raw_lf).ok())
                .map_or(0, |plan| plan.restart.current_lsn);
            Ok(NativeCommitBinding::Ntfs {
                volume_serial: geo.serial(),
                volume_bytes: geo.volume_bytes(),
                cluster_bytes: geo.cluster_bytes(),
                record_bytes: geo.record_bytes(),
                index_bytes: geo.index_bytes(),
                mft_cluster: geo.mft_cluster(),
                mirror_cluster: geo.mirror_cluster(),
                boot_blake3,
                transaction_id: 0,
                commit_lsn: restart_lsn,
                checkpoint_lsn: (restart_lsn != 0).then_some(restart_lsn),
                generation: restart_lsn,
                operation_digest: [0_u8; 32],
            })
        }
        "zfs" => {
            let mut leaves = Vec::with_capacity(storage_set.members().len());
            let mut member_guids = Vec::with_capacity(storage_set.members().len());
            let mut first_cfg = None;
            for m in storage_set.members() {
                if m.role != MemberRole::Data {
                    return Err(FfsError::UnsupportedFeature(
                        "separate ZFS log/special devices are outside the protected ZFS profile"
                            .into(),
                    ));
                }
                let dev = m.open_bounded_device(false)?;
                let leaf = zfs::reader::Leaf::from_device(cx, dev, 0, m.length)?;
                let lbl0 = first_valid_zfs_label(cx, &leaf)?;
                let m_guid = lbl0.config.unsigned("guid").unwrap_or(0);
                if first_cfg.is_none() {
                    let pool_guid = lbl0.config.unsigned("pool_guid").unwrap_or(0);
                    let top_guid = lbl0.config.unsigned("top_guid").unwrap_or(0);
                    let version = lbl0.config.unsigned("version").unwrap_or(0);
                    let label_txg = lbl0.config.unsigned("txg").unwrap_or(0);
                    let vdev_children = lbl0.config.unsigned("vdev_children").unwrap_or(1);
                    let required_children = lbl0
                        .config
                        .list("vdev_tree")
                        .and_then(|tree| match tree.fields.get("children") {
                            Some(ffs_ondisk::zfs::nvlist::Value::Lists(items)) => Some(items.len()),
                            _ => None,
                        })
                        .unwrap_or(1);
                    if (vdev_children > 1 && storage_set.members().len() == 1)
                        || required_children > storage_set.members().len()
                    {
                        return Err(FfsError::UnsupportedFeature(
                            "multi-member ZFS pool requires a complete storage-set manifest (--manifest + --member) covering every vdev member"
                                .into(),
                        ));
                    }
                    let (ashift, asize) = lbl0.config.list("vdev_tree").map_or((0, 0), |tree| {
                        let ashift =
                            u8::try_from(tree.unsigned("ashift").unwrap_or(0)).unwrap_or(0);
                        let asize = tree.unsigned("asize").unwrap_or(0);
                        (ashift, asize)
                    });
                    first_cfg = Some((pool_guid, top_guid, version, label_txg, ashift, asize));
                }
                member_guids.push(m_guid);
                leaves.push(leaf);
            }
            let (pool_guid, top_guid, version, label_txg, ashift, asize) =
                first_cfg.unwrap_or((0, 0, 0, 0, 0, 0));
            let pool = zfs::reader::Pool::from_leaves(leaves)?;
            let (_, active_slot, root_block) = pool.import_active(cx, pool_guid_hint)?;
            let root_bp_blake3 =
                blake3_digest(format!("{:?}", root_block.uberblock.root).as_bytes());
            let published_slot = u32::try_from(active_slot).unwrap_or(u32::MAX);
            Ok(NativeCommitBinding::Zfs {
                pool_guid,
                top_guid,
                member_guids,
                guid_sum: root_block.uberblock.guid_sum,
                version,
                ashift,
                asize,
                label_txg,
                committed_txg: root_block.uberblock.txg,
                published_slot,
                root_bp_blake3,
                generation: root_block.uberblock.txg,
                operation_digest: [0_u8; 32],
            })
        }
        other => Err(FfsError::UnsupportedFeature(format!(
            "unsupported protected filesystem {other}"
        ))),
    }
}

fn verify_manifest_native_binding(
    manifest_fs: &str,
    expected: &NativeCommitBinding,
    actual_fs: &str,
    actual: &NativeCommitBinding,
) -> Result<()> {
    if manifest_fs != "raw" && manifest_fs != actual_fs {
        bail!("storage-set manifest binds filesystem '{manifest_fs}', but detected '{actual_fs}'");
    }
    match (expected, actual) {
        (NativeCommitBinding::UninterpretedRaw, _) => Ok(()),
        (
            NativeCommitBinding::Ext4 {
                uuid: eu,
                blocks_count: eb,
                journal_inum: ej,
                ..
            },
            NativeCommitBinding::Ext4 {
                uuid: au,
                blocks_count: ab,
                journal_inum: aj,
                ..
            },
        ) => {
            if eu != au || eb != ab || ej != aj {
                bail!("storage-set manifest Ext4 identity disagrees with on-disk superblock");
            }
            Ok(())
        }
        (
            NativeCommitBinding::Btrfs {
                fsid: ef,
                generation: eg,
                root_bytenr: er,
                ..
            },
            NativeCommitBinding::Btrfs {
                fsid: af,
                generation: ag,
                root_bytenr: ar,
                ..
            },
        ) => {
            if ef != af || eg != ag || er != ar {
                bail!(
                    "storage-set manifest Btrfs generation/fsid disagrees with on-disk superblock"
                );
            }
            Ok(())
        }
        (
            NativeCommitBinding::Fat {
                kind: ek,
                volume_id: ev,
                total_sectors: es,
                ..
            },
            NativeCommitBinding::Fat {
                kind: ak,
                volume_id: av,
                total_sectors: as_,
                ..
            },
        ) => {
            if ek != ak || es != as_ || ev != av {
                bail!(
                    "storage-set manifest FAT geometry or volume serial disagrees with on-disk boot sector"
                );
            }
            Ok(())
        }
        (
            NativeCommitBinding::Ntfs {
                volume_serial: es,
                volume_bytes: eb,
                cluster_bytes: ec,
                record_bytes: er,
                mft_cluster: em,
                boot_blake3: ebh,
                commit_lsn: el,
                ..
            },
            NativeCommitBinding::Ntfs {
                volume_serial: as_,
                volume_bytes: ab,
                cluster_bytes: ac,
                record_bytes: ar,
                mft_cluster: am,
                boot_blake3: abh,
                commit_lsn: al,
                ..
            },
        ) => {
            if es != as_
                || eb != ab
                || (*ec != 0 && ec != ac)
                || (*er != 0 && er != ar)
                || (*em != 0 && em != am)
                || (*ebh != [0_u8; 32] && ebh != abh)
                || (*el != 0 && el != al)
            {
                bail!(
                    "storage-set manifest NTFS volume identity, boot digest, or committed LSN disagrees with on-disk volume"
                );
            }
            Ok(())
        }
        (
            NativeCommitBinding::Zfs {
                pool_guid: ep,
                top_guid: et,
                member_guids: em,
                committed_txg: ex,
                root_bp_blake3: erb,
                ..
            },
            NativeCommitBinding::Zfs {
                pool_guid: ap,
                top_guid: at,
                member_guids: am,
                committed_txg: ax,
                root_bp_blake3: arb,
                ..
            },
        ) => {
            if ep != ap || et != at || em != am || ex != ax || (*erb != [0_u8; 32] && erb != arb) {
                bail!(
                    "storage-set manifest ZFS pool/member GUIDs, root digest, or committed TXG ({ex} vs {ax}) disagrees with on-disk pool"
                );
            }
            Ok(())
        }
        _ => bail!("storage-set manifest native commit binding kind disagrees with filesystem"),
    }
}

type NativeBindingExtractor =
    Arc<dyn Fn(&Cx) -> ffs_error::Result<NativeCommitBinding> + Send + Sync>;

fn prepare(cx: &Cx, args: &Args) -> Result<Prepared> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let checked = checked_paths(args)?;
    let signing_key = args
        .set
        .trust_key_file
        .as_deref()
        .map(load_por_key)
        .transpose()?;
    let trust_policy = match (args.set.require_trusted_root, signing_key) {
        (_, Some(key)) => TrustPolicy::RequireTrustedRoot { key },
        (true, None) => TrustPolicy::RequireTrustedRoot { key: [0_u8; 32] },
        (false, None) => TrustPolicy::AllowUnauthenticated,
    };
    if args.set.require_trusted_root && signing_key.is_none() {
        bail!(
            "trusted-root provenance required (--require-trusted-root), but no --trust-key-file was supplied"
        );
    }
    let calibration = load_calibration(args.set.repair_calibration.as_deref())?;
    let evidence_ledger = open_evidence_ledger(args.set.evidence_ledger.as_deref())?;
    let open_opts = StorageSetOpenOptions {
        read_only: false,
        allow_automatic_repair: args.authority.allow_repair,
        trust_policy,
        signing_key,
        calibration,
        evidence_ledger,
    };

    let storage_set = Arc::new(if let Some(manifest_path) = &checked.manifest {
        ProtectedStorageSet::open_manifest(cx, manifest_path, &checked.member_paths, &open_opts)
            .context("admit storage-set manifest and member sidecars")?
    } else {
        ProtectedStorageSet::open_standalone(
            cx,
            &checked.member_paths[0].0,
            &checked.member_paths[0].1,
            args.set.offset.unwrap_or(0),
            args.set.length,
            &open_opts,
        )
        .context("admit image and existing repair protection")?
    });

    if !args.set.log_members.is_empty() || !args.set.special_members.is_empty() {
        bail!(
            "external log/special member topologies are refused until native split-device recovery is admitted"
        );
    }

    let device = Arc::clone(storage_set.primary_device());
    let probe_slice = storage_set.members()[0]
        .open_bounded_device(false)
        .context("open bounded primary member slice")?;
    let filesystem = clean_single_slice(cx, probe_slice.as_ref(), storage_set.members().len())?;
    drop(probe_slice);

    let manifest = storage_set.manifest();
    let dataset_components = protected_dataset_components(
        filesystem,
        args.set.zfs_dataset.as_deref(),
        manifest.as_ref().map(|m| &m.view),
    )?;
    let live_binding =
        compute_live_native_binding(cx, &storage_set, filesystem, args.set.pool_guid)
            .context("verify native filesystem commit identity across storage set")?;
    if let Some(manifest) = manifest {
        verify_manifest_native_binding(
            &manifest.filesystem,
            &manifest.native_binding,
            filesystem,
            &live_binding,
        )?;
        for (idx, m) in storage_set.members().iter().enumerate() {
            if m.native_member_id != [0_u8; 16]
                && let NativeCommitBinding::Zfs { member_guids, .. } = &live_binding
                && let Some(&actual_guid) = member_guids.get(idx)
            {
                let mut expected_guid_bytes = [0_u8; 8];
                expected_guid_bytes.copy_from_slice(&m.native_member_id[..8]);
                if u64::from_le_bytes(expected_guid_bytes) != actual_guid {
                    bail!(
                        "storage-set manifest member {idx} native GUID disagrees with physical ZFS label"
                    );
                }
            }
        }
    }
    storage_set.record_native_commit(&live_binding);

    let extractor_set = Arc::clone(&storage_set);
    let pool_guid_hint = args.set.pool_guid;
    let extractor: NativeBindingExtractor = Arc::new(move |seal_cx: &Cx| {
        compute_live_native_binding(seal_cx, &extractor_set, filesystem, pool_guid_hint)
    });

    let primary_len = storage_set.members()[0].length;
    let uid = nix::unistd::Uid::current().as_raw();
    let gid = nix::unistd::Gid::current().as_raw();
    let fs = match filesystem {
        "ext4" | "btrfs" => {
            let protected_device = storage_set
                .open_member_device_with_auto_seal(0, args.rw, Arc::clone(&extractor))
                .context("open primary protected device")?;
            let options = OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::Skip,
                ..OpenOptions::default()
            };
            let mut fs = OpenFs::from_device(cx, protected_device, &options)
                .context("open filesystem through the protected device")?;
            FsOps::getattr(&fs, cx, &mut RequestScope::empty(), InodeNumber(1))
                .context("read protected filesystem root")?;
            if args.rw {
                fs.attach_ext4_internal_jbd2_writer(cx)
                    .context("attach the protected ext4 internal JBD2 writer")?;
                if fs
                    .ext4_superblock()
                    .is_some_and(|sb| sb.has_compat(ffs_ondisk::Ext4CompatFeatures::HAS_JOURNAL))
                    && !fs.has_jbd2_writer()
                {
                    bail!(
                        "refusing writable journalled ext4 mount: no JBD2 writer is attached, so the durability checkpoint would skip the journal's descriptor and commit blocks"
                    );
                }
                fs.enable_writes(cx)
                    .context("enable protected filesystem writes")?;
            }
            ProtectedFs::Core(Box::new(fs))
        }
        "fat16" | "fat32" => {
            let protected_device = storage_set
                .open_member_device_with_auto_seal(0, args.rw, Arc::clone(&extractor))
                .context("open primary protected FAT device")?;
            let volume = fat::reader::FatVolume::from_device(cx, protected_device, 0, primary_len)
                .context("open FAT volume through the protected device")?;
            if args.rw {
                let check = volume
                    .check(cx)
                    .context("check FAT volume before enabling protected writes")?;
                if !check.clean || !check.complete || !check.namespace_complete {
                    bail!("FAT volume is dirty or incomplete; reconcile offline before --rw");
                }
            }
            let fat_fs = fat::filesystem::FatFs::new_with_mode(cx, volume, uid, gid, args.rw)
                .context("initialize protected FAT filesystem")?;
            FsOps::getattr(&fat_fs, cx, &mut RequestScope::empty(), InodeNumber(1))
                .context("read protected FAT filesystem root")?;
            ProtectedFs::Fat {
                fs: Box::new(fat_fs),
                writable: args.rw,
            }
        }
        "ntfs" => {
            let protected_device = storage_set
                .open_member_device_with_auto_seal(0, args.rw, Arc::clone(&extractor))
                .context("open primary protected NTFS device")?;
            let ntfs_fs = if args.rw {
                let engine = ntfs::transaction::NtfsTransactionEngine::from_device(
                    cx,
                    protected_device.into(),
                    0,
                    primary_len,
                    ntfs::NtfsWriteOptions {
                        offline_image: args.authority.exclusive_image,
                        allow_write: true,
                        recover_dirty: false,
                    },
                )
                .context("admit clean NTFS volume for protected native writes")?;
                ntfs::reader::filesystem::NtfsFs::from_engine(cx, engine, uid, gid)
                    .context("initialize writable protected NTFS filesystem")?
            } else {
                let volume =
                    ntfs::reader::NtfsVolume::from_device(cx, protected_device, 0, primary_len)
                        .context("open NTFS volume through the protected device")?;
                ntfs::reader::filesystem::NtfsFs::new(cx, volume, uid, gid)
                    .context("initialize protected NTFS filesystem")?
            };
            FsOps::getattr(&ntfs_fs, cx, &mut RequestScope::empty(), InodeNumber(1))
                .context("read protected NTFS filesystem root")?;
            ProtectedFs::Ntfs(Box::new(ntfs_fs))
        }
        "zfs" => {
            let zfs_fs = if args.rw {
                let mut probe_leaves = Vec::with_capacity(storage_set.members().len());
                let mut member_devices = Vec::with_capacity(storage_set.members().len());
                for idx in 0..storage_set.members().len() {
                    let member_len = storage_set.members()[idx].length;
                    let probe_dev = storage_set.members()[idx]
                        .open_bounded_device(false)
                        .with_context(|| format!("open probe ZFS member {idx}"))?;
                    let leaf = zfs::reader::Leaf::from_device(cx, probe_dev, 0, member_len)
                        .with_context(|| format!("admit protected ZFS leaf {idx}"))?;
                    probe_leaves.push(leaf);
                    let mutable_dev = storage_set
                        .open_member_device_with_auto_seal(idx, true, Arc::clone(&extractor))
                        .with_context(|| format!("open writable protected ZFS member {idx}"))?;
                    member_devices.push(mutable_dev);
                }
                let discovered_pool_guid = first_valid_zfs_label(cx, &probe_leaves[0])
                    .ok()
                    .and_then(|l| l.config.unsigned("pool_guid"))
                    .unwrap_or(0);
                let probe_pool = zfs::reader::Pool::from_leaves(probe_leaves)
                    .context("admit complete ZFS pool topology for protected writes")?;
                let (active_label, active_slot, _) = probe_pool
                    .import_active(cx, args.set.pool_guid)
                    .context("discover active ZFS Uberblock across protected storage set")?;
                let write_opts = zfs::ZfsWriteOptions {
                    offline_image: args.authority.exclusive_image,
                    allow_write: true,
                    pool_guid: args.set.pool_guid.unwrap_or(discovered_pool_guid),
                    label: args.set.zfs_label.unwrap_or(active_label),
                    slot: args.set.zfs_slot.unwrap_or(active_slot),
                    reconcile_torn_uberblocks: false,
                };
                let engine =
                    zfs::ZfsTransactionEngine::from_devices(cx, member_devices, write_opts)
                        .context("admit ZFS transaction engine across protected storage set")?;
                zfs::filesystem::ZfsFs::with_writer_options(
                    cx,
                    engine,
                    dataset_components,
                    zfs::filesystem::ZfsMountWriteOptions {
                        allow_mode_and_owner_setattr: true,
                    },
                )
                .context("initialize writable protected ZFS filesystem")?
            } else {
                let mut leaves = Vec::with_capacity(storage_set.members().len());
                for idx in 0..storage_set.members().len() {
                    let member_len = storage_set.members()[idx].length;
                    let member_dev = storage_set
                        .open_member_device_with_auto_seal(idx, false, Arc::clone(&extractor))
                        .with_context(|| format!("open protected ZFS member {idx}"))?;
                    let leaf = zfs::reader::Leaf::from_device(cx, member_dev, 0, member_len)
                        .with_context(|| format!("admit protected ZFS leaf {idx}"))?;
                    leaves.push(leaf);
                }
                let pool = zfs::reader::Pool::from_leaves(leaves)
                    .context("admit complete protected ZFS pool")?;
                let mut objects = pool.import_objects(cx, args.set.pool_guid).context(
                    "import active ZFS MOS object set through the protected storage set",
                )?;
                let view = objects
                    .zpl(cx, &dataset_components)
                    .context("open ZPL dataset through the protected storage set")?;
                zfs::filesystem::ZfsFs::new(cx, view, uid, gid)
                    .context("initialize protected ZFS filesystem")?
            };
            FsOps::getattr(&zfs_fs, cx, &mut RequestScope::empty(), InodeNumber(1))
                .context("read protected ZFS filesystem root")?;
            ProtectedFs::Zfs(Box::new(zfs_fs))
        }
        other => bail!("unsupported protected filesystem {other}"),
    };
    Ok(Prepared {
        fs: Arc::new(fs),
        device,
        storage_set,
        filesystem,
        pool_guid: args.set.pool_guid,
        mountpoint: checked.mountpoint,
    })
}

fn mount_options(args: &Args) -> MountOptions {
    MountOptions {
        read_only: !args.rw,
        allow_other: args.allow_other,
        auto_unmount: true,
        ..MountOptions::default()
    }
}

#[derive(Serialize)]
struct Status<'a> {
    event: &'a str,
    filesystem: &'a str,
    image_bytes: u64,
    member_count: usize,
    read_only: bool,
    repair_writes_authorized: bool,
    authenticated_provenance: bool,
}

fn emit(event: &str, prepared: &Prepared) -> Result<()> {
    let status = Status {
        event,
        filesystem: prepared.filesystem,
        image_bytes: prepared.device.len_bytes(),
        member_count: prepared.storage_set.members().len(),
        read_only: !prepared.fs.is_writable(),
        repair_writes_authorized: true,
        authenticated_provenance: prepared.storage_set.is_authenticated(),
    };
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &status)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn serve(
    cx: &Cx,
    runtime: Option<&Arc<asupersync::runtime::Runtime>>,
    args: &Args,
    prepared: &Prepared,
    stopped: &AtomicBool,
    shutdown: &Mutex<Option<Arc<AtomicBool>>>,
) -> Result<()> {
    if args.check {
        return emit("checked_not_mounted", prepared);
    }
    if (args.rw || args.scrub.interval_secs.is_some()) && runtime.is_none() {
        bail!("protected background workers require their mount runtime");
    }
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let mountpoint = prepared.mountpoint.as_ref().context("missing mountpoint")?;
    let config = MountConfig {
        options: mount_options(args),
        commit_interval: Some(std::time::Duration::ZERO),
        ..MountConfig::default()
    };
    let handle = mount_managed(cx, Box::new(Arc::clone(&prepared.fs)), mountpoint, &config)
        .context("mount protected filesystem")?;
    let flag = Arc::clone(handle.shutdown_flag());
    *shutdown
        .lock()
        .map_err(|_| anyhow::anyhow!("shutdown state poisoned"))? = Some(Arc::clone(&flag));
    if stopped.load(Ordering::Acquire) {
        flag.store(true, Ordering::Release);
    }
    let announce = emit("mounted", prepared);
    let mut periodic = if announce.is_ok() && !flag.load(Ordering::Acquire) && args.rw {
        mount_worker::start_periodic_commit(
            cx,
            runtime.context("protected periodic commit requires its mount runtime")?,
            &prepared.fs,
            args.commit_interval_secs
                .map(std::time::Duration::from_secs),
            "protected-mount",
        )
    } else {
        Ok(None)
    };
    let background: Result<Vec<scrub::ScrubGuard>> =
        if announce.is_ok() && !flag.load(Ordering::Acquire) {
            if let Some(seconds) = args.scrub.interval_secs {
                let rt = runtime.context("protected scrub requires its mount runtime")?;
                let mut guards = Vec::with_capacity(prepared.storage_set.members().len());
                let mut start_err = None;
                for member in prepared.storage_set.members() {
                    match scrub::ScrubGuard::start(
                        cx,
                        rt,
                        Arc::clone(&member.device),
                        Arc::clone(&flag),
                        std::time::Duration::from_secs(seconds),
                        args.scrub.parity,
                    ) {
                        Ok(g) => guards.push(g),
                        Err(e) => {
                            start_err = Some(e);
                            break;
                        }
                    }
                }
                if let Some(err) = start_err {
                    flag.store(true, Ordering::Release);
                    for mut g in guards {
                        let _ = g.stop();
                    }
                    Err(err)
                } else {
                    Ok(guards)
                }
            } else {
                Ok(Vec::new())
            }
        } else {
            Ok(Vec::new())
        };
    if announce.is_err() || periodic.is_err() || background.is_err() {
        flag.store(true, Ordering::Release);
    }
    let mount_result = handle.wait().context("protected FUSE mount cleanup failed");
    // Cancel both workers before draining either. Final filesystem cleanup must
    // not race a periodic boundary or lose either worker's completion receipt.
    let commit_cancel = match periodic.as_ref() {
        Ok(Some(worker)) => worker.request_stop(),
        _ => Ok(()),
    };
    let mut scrub_cancel = Ok(());
    if let Ok(guards) = background.as_ref() {
        for guard in guards {
            if let Err(err) = guard.request_stop()
                && scrub_cancel.is_ok()
            {
                scrub_cancel = Err(err);
            }
        }
    }
    let commit_result = match periodic.as_mut() {
        Ok(Some(worker)) => worker.stop().map(|_| ()),
        _ => Ok(()),
    };
    let scrub_result = match background {
        Ok(mut guards) => {
            let mut first_err = Ok(());
            for guard in &mut guards {
                if let Err(err) = guard.stop()
                    && first_err.is_ok()
                {
                    first_err = Err(err);
                }
            }
            first_err
        }
        Err(error) => Err(error),
    };
    announce?;
    drop(periodic?);
    commit_cancel?;
    scrub_cancel?;
    mount_result?;
    commit_result.and(scrub_result)
}

fn run(args: &Args) -> Result<()> {
    let runtime = (!args.check)
        .then(mount_worker::mount_background_runtime)
        .transpose()?;
    let fallback_runtime = if runtime.is_none() {
        Some(
            asupersync::runtime::RuntimeBuilder::current_thread()
                .blocking_threads(0, 0)
                .build()
                .context("failed to create protected mount request runtime")?,
        )
    } else {
        None
    };
    let cx_runtime = runtime
        .as_deref()
        .or(fallback_runtime.as_ref())
        .expect("runtime or fallback_runtime must exist");
    let cx = cx_runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let cancellation = cx.clone();
    let stopped = Arc::new(AtomicBool::new(false));
    let shutdown: Arc<Mutex<Option<Arc<AtomicBool>>>> = Arc::new(Mutex::new(None));
    let signal_stopped = Arc::clone(&stopped);
    let signal_shutdown = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        signal_stopped.store(true, Ordering::Release);
        cancellation.cancel_with(
            asupersync::types::CancelKind::User,
            Some("protected mount stopping"),
        );
        if let Ok(target) = signal_shutdown.lock()
            && let Some(flag) = target.as_ref()
        {
            flag.store(true, Ordering::Release);
        }
    })
    .context("install shutdown handler")?;

    let prepared = prepare(&cx, args)?;
    let operation = serve(&cx, runtime.as_ref(), args, &prepared, &stopped, &shutdown);
    // Every exit after successful preparation attempts cleanup, including
    // mount failure, announcement failure and startup cancellation. Cleanup
    // has its own capability; Ctrl-C must not cancel the durability barrier.
    let cleanup_cx = cx_runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let cleanup = prepared.finish(&cleanup_cx);
    match (operation, cleanup) {
        (Ok(()), cleanup) => cleanup,
        (Err(operation), Ok(())) => Err(operation),
        (Err(operation), Err(cleanup)) => {
            Err(cleanup).context(format!("protected operation also failed: {operation:#}"))
        }
    }
}

fn main() -> ExitCode {
    // Shared mount workers report failed commits here as they do for ordinary
    // mounts; debug logging also exposes successful periodic boundaries.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    match run(&Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ffs-protected-mount: {error:#}");
            ExitCode::from(
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<FfsError>()
                        .is_some_and(|error| matches!(error, FfsError::Cancelled))
                }) {
                    130
                } else {
                    4
                },
            )
        }
    }
}

#[cfg(test)]
mod tests;
