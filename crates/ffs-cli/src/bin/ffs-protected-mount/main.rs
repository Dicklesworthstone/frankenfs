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
use ffs_core::vfs::XattrPresence;
use ffs_core::{
    DetectedFilesystem, Ext4JournalReplayMode, FiemapExtent, FsOps, FsStat, InodeAttr, OpenFs,
    OpenOptions, ReaddirPage, ReleaseRequest, RequestOp, RequestScope, SeekWhence, SetAttrRequest,
    XattrSetMode, detect_all_filesystems_on_device,
};
use ffs_error::FfsError;
use ffs_fuse::{MountConfig, MountOptions, mount_managed};
use ffs_ondisk::EXT4_VALID_FS;
use ffs_repair::sidecar::live::SidecarImageDevice;
use ffs_types::{ByteOffset, CommitSeq, InodeNumber};
use serde::Serialize;
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Parser)]
#[command(
    name = "ffs-protected-mount",
    about = "Mount a clean image with RaptorQ protection (read-only unless --rw)"
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

/// Caller-write authority is independent of read-repair authority. Both modes
/// retain the same device and inode locks for every format I/O operation.
#[derive(Debug)]
struct ProtectedDevice {
    inner: Arc<SidecarImageDevice>,
    writable: bool,
}

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
            Self::Ntfs(_) | Self::Zfs(_) => false,
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
            Self::Fat { .. } | Self::Ntfs(_) | Self::Zfs(_) => None,
        }
    }

    fn periodic_commit(&self, cx: &Cx) -> ffs_error::Result<bool> {
        match self {
            Self::Core(fs) => fs.periodic_commit(cx),
            Self::Fat { .. } | Self::Ntfs(_) | Self::Zfs(_) => Ok(false),
        }
    }
}

impl FsOps for ProtectedFs {
    fn xattr_presence(&self, cx: &Cx) -> XattrPresence {
        self.as_ops().xattr_presence(cx)
    }

    fn getattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ops().getattr(cx, scope, ino)
    }

    fn getattr_batch(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        inos: &[InodeNumber],
    ) -> Vec<ffs_error::Result<InodeAttr>> {
        self.as_ops().getattr_batch(cx, scope, inos)
    }

    fn lookup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ops().lookup(cx, scope, parent, name)
    }

    fn readdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        self.as_ops().readdir(cx, scope, ino, offset)
    }

    fn read(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ops().read(cx, scope, ino, offset, size)
    }

    fn open(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        flags: i32,
    ) -> ffs_error::Result<(u64, u32)> {
        self.as_ops().open(cx, scope, ino, flags)
    }

    fn readlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        self.as_ops().readlink(cx, scope, ino)
    }

    fn statfs(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<FsStat> {
        self.as_ops().statfs(cx, scope, ino)
    }

    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<String>> {
        self.as_ops().listxattr(cx, ino)
    }

    fn getxattr(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<Option<Vec<u8>>> {
        self.as_ops().getxattr(cx, ino, name)
    }

    fn setxattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        name: &str,
        value: &[u8],
        mode: XattrSetMode,
    ) -> ffs_error::Result<()> {
        self.as_ops().setxattr(cx, scope, ino, name, value, mode)
    }

    fn removexattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<bool> {
        self.as_ops().removexattr(cx, scope, ino, name)
    }

    fn create(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ops()
            .create(cx, scope, parent, name, mode, uid, gid)
    }

    fn touch_atime(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        now: SystemTime,
        strict: bool,
    ) -> ffs_error::Result<bool> {
        self.as_ops().touch_atime(cx, scope, ino, now, strict)
    }

    fn tmpfile(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ops().tmpfile(cx, scope, parent, mode, uid, gid)
    }

    fn mkdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ops().mkdir(cx, scope, parent, name, mode, uid, gid)
    }

    fn unlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<()> {
        self.as_ops().unlink(cx, scope, parent, name)
    }

    fn rmdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<()> {
        self.as_ops().rmdir(cx, scope, parent, name)
    }

    fn rename(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> ffs_error::Result<()> {
        self.as_ops()
            .rename(cx, scope, parent, name, new_parent, new_name)
    }

    fn mknod(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ops()
            .mknod(cx, scope, parent, name, mode, rdev, uid, gid)
    }

    fn rename2(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
        flags: u32,
    ) -> ffs_error::Result<()> {
        self.as_ops()
            .rename2(cx, scope, parent, name, new_parent, new_name, flags)
    }

    fn write(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> ffs_error::Result<u32> {
        self.as_ops().write(cx, scope, ino, offset, data)
    }

    fn copy_file_range(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino_in: InodeNumber,
        offset_in: u64,
        ino_out: InodeNumber,
        offset_out: u64,
        len: u64,
    ) -> ffs_error::Result<u64> {
        self.as_ops()
            .copy_file_range(cx, scope, ino_in, offset_in, ino_out, offset_out, len)
    }

    fn link(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ops().link(cx, scope, ino, new_parent, new_name)
    }

    fn symlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        target: &Path,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ops()
            .symlink(cx, scope, parent, name, target, uid, gid)
    }

    fn fallocate(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        length: u64,
        mode: i32,
    ) -> ffs_error::Result<()> {
        self.as_ops()
            .fallocate(cx, scope, ino, offset, length, mode)
    }

    fn fiemap(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        start: u64,
        length: u64,
    ) -> ffs_error::Result<Vec<FiemapExtent>> {
        self.as_ops().fiemap(cx, scope, ino, start, length)
    }

    fn lseek(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        whence: SeekWhence,
    ) -> ffs_error::Result<u64> {
        self.as_ops().lseek(cx, scope, ino, offset, whence)
    }

    fn setattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> ffs_error::Result<InodeAttr> {
        self.as_ops().setattr(cx, scope, ino, attrs)
    }

    fn flush(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        lock_owner: u64,
    ) -> ffs_error::Result<()> {
        self.as_ops().flush(cx, scope, ino, fh, lock_owner)
    }

    fn release(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        request: ReleaseRequest,
    ) -> ffs_error::Result<()> {
        self.as_ops().release(cx, scope, request)
    }

    fn fsync(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        datasync: bool,
    ) -> ffs_error::Result<()> {
        self.as_ops().fsync(cx, scope, ino, fh, datasync)
    }

    fn fsyncdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        datasync: bool,
    ) -> ffs_error::Result<()> {
        self.as_ops().fsyncdir(cx, scope, ino, fh, datasync)
    }

    fn sync_fs(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<()> {
        self.as_ops().sync_fs(cx, scope)
    }

    fn begin_request_scope(&self, cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
        self.as_ops().begin_request_scope(cx, op)
    }

    fn end_request_scope(
        &self,
        cx: &Cx,
        op: RequestOp,
        scope: RequestScope,
    ) -> ffs_error::Result<()> {
        self.as_ops().end_request_scope(cx, op, scope)
    }

    fn commit_request_scope(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
    ) -> ffs_error::Result<CommitSeq> {
        self.as_ops().commit_request_scope(cx, scope)
    }

    fn flush_on_destroy(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.as_ops().flush_on_destroy(cx)
    }
}

struct Prepared {
    fs: Arc<ProtectedFs>,
    device: Arc<SidecarImageDevice>,
    filesystem: &'static str,
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
            // Device sync alone cannot drain committed MVCC writes or publish
            // btrfs CoW roots. Use the filesystem's durable full-commit path
            // first, while the filesystem still exists and dispatch is quiescent.
            FsOps::fsyncdir(
                &fs,
                cx,
                &mut RequestScope::empty(),
                InodeNumber(1),
                0,
                false,
            )
            .context("checkpoint protected filesystem before shutdown")?;
        }
        drop(fs);
        self.device.sync(cx).context("final protected-device sync")
    }
}

fn checked_paths(args: &Args) -> Result<(PathBuf, PathBuf, Option<PathBuf>)> {
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
    let image = args.image.canonicalize().context("resolve image")?;
    let sidecar = args.sidecar.canonicalize().context("resolve sidecar")?;
    if let Some(mountpoint) = &mountpoint
        && (image.starts_with(mountpoint) || sidecar.starts_with(mountpoint))
    {
        bail!("mountpoint would hide the image or repair archive");
    }
    Ok((image, sidecar, mountpoint))
}

fn clean_single_image(cx: &Cx, device: &dyn ByteDevice) -> Result<&'static str> {
    match detect_all_filesystems_on_device(cx, device).context("detect protected filesystem")? {
        DetectedFilesystem::Ext4(sb) => {
            // RECOVER and the orphan/error states require filesystem recovery,
            // not RaptorQ rollback. Admit only clean protection points, including
            // for --rw; Skip below is never a dirty-mount bypass.
            if sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::RECOVER)
                || sb.state != EXT4_VALID_FS
                || sb.last_orphan != 0
            {
                bail!("ext4 needs recovery; reconcile offline and create fresh protection");
            }
            Ok("ext4")
        }
        DetectedFilesystem::Btrfs(sb) => {
            if sb.num_devices != 1 || sb.log_root != 0 {
                bail!("protected mount requires a clean single-device btrfs image");
            }
            Ok("btrfs")
        }
        DetectedFilesystem::Fat16(_) => Ok("fat16"),
        DetectedFilesystem::Fat32(_) => Ok("fat32"),
        DetectedFilesystem::Ntfs(_) => Ok("ntfs"),
        DetectedFilesystem::Zfs(_) => Ok("zfs"),
    }
}

fn prepare(cx: &Cx, args: &Args) -> Result<Prepared> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let (image, sidecar, mountpoint) = checked_paths(args)?;
    let device = Arc::new(
        SidecarImageDevice::open(cx, &image, &sidecar)
            .context("admit image and existing repair protection")?,
    );
    let filesystem = clean_single_image(cx, device.as_ref())?;
    let protected_device = Box::new(ProtectedDevice {
        inner: Arc::clone(&device),
        writable: args.rw,
    });
    let len = device.len_bytes();
    let uid = nix::unistd::Uid::current().as_raw();
    let gid = nix::unistd::Gid::current().as_raw();
    let fs = match filesystem {
        "ext4" | "btrfs" => {
            let options = OpenOptions {
                ext4_journal_replay_mode: Ext4JournalReplayMode::Skip,
                ..OpenOptions::default()
            };
            let mut fs = OpenFs::from_device(cx, protected_device, &options)
                .context("open filesystem through the protected device")?;
            // Exercise the actual FUSE root alias before enabling caller writes.
            FsOps::getattr(&fs, cx, &mut RequestScope::empty(), InodeNumber(1))
                .context("read protected filesystem root")?;
            if args.rw {
                // Match ordinary mount admission: a journalled ext4 image may not
                // silently take the direct home-block durability path. The writer uses
                // this same protected device, so journal and checkpoint syncs also
                // publish fresh sidecar coverage. Clean admission above establishes
                // the attachment helper's prerequisite that no replay is pending.
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
                // Preserve all ordinary format/profile/feature write-admission checks.
                // No ephemeral btrfs mode or kernel writeback cache is enabled here.
                fs.enable_writes(cx)
                    .context("enable protected filesystem writes")?;
            }
            ProtectedFs::Core(Box::new(fs))
        }
        "fat16" | "fat32" => {
            let volume = fat::reader::FatVolume::from_device(cx, protected_device, 0, len)
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
            if args.rw {
                bail!("protected mount supports NTFS in read-only mode only; omit --rw");
            }
            let volume = ntfs::reader::NtfsVolume::from_device(cx, protected_device, 0, len)
                .context("open NTFS volume through the protected device")?;
            let ntfs_fs = ntfs::reader::filesystem::NtfsFs::new(cx, volume, uid, gid)
                .context("initialize protected NTFS filesystem")?;
            FsOps::getattr(&ntfs_fs, cx, &mut RequestScope::empty(), InodeNumber(1))
                .context("read protected NTFS filesystem root")?;
            ProtectedFs::Ntfs(Box::new(ntfs_fs))
        }
        "zfs" => {
            if args.rw {
                bail!("protected mount supports ZFS in read-only mode only; omit --rw");
            }
            let leaf = zfs::reader::Leaf::from_device(cx, protected_device, 0, len)
                .context("open ZFS leaf through the protected device")?;
            let pool = zfs::reader::Pool::from_leaves(vec![leaf])
                .context("admit single-device protected ZFS pool")?;
            let mut objects = pool
                .import_objects(cx, None)
                .context("import active ZFS MOS object set through the protected device")?;
            let view = objects
                .zpl(cx, &[])
                .context("open root ZPL dataset through the protected device")?;
            let zfs_fs = zfs::filesystem::ZfsFs::new(cx, view, uid, gid)
                .context("initialize protected ZFS filesystem")?;
            FsOps::getattr(&zfs_fs, cx, &mut RequestScope::empty(), InodeNumber(1))
                .context("read protected ZFS filesystem root")?;
            ProtectedFs::Zfs(Box::new(zfs_fs))
        }
        other => bail!("unsupported protected filesystem {other}"),
    };
    Ok(Prepared {
        fs: Arc::new(fs),
        device,
        filesystem,
        mountpoint,
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
    read_only: bool,
    repair_writes_authorized: bool,
}

fn emit(event: &str, prepared: &Prepared) -> Result<()> {
    let status = Status {
        event,
        filesystem: prepared.filesystem,
        image_bytes: prepared.device.len_bytes(),
        read_only: !prepared.fs.is_writable(),
        repair_writes_authorized: true,
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
        ..MountConfig::default()
    };
    let handle = mount_managed(Box::new(Arc::clone(&prepared.fs)), mountpoint, &config)
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
    let background = if announce.is_ok() && !flag.load(Ordering::Acquire) {
        args.scrub
            .interval_secs
            .map(|seconds| {
                scrub::ScrubGuard::start(
                    cx,
                    runtime.context("protected scrub requires its mount runtime")?,
                    Arc::clone(&prepared.device),
                    Arc::clone(&flag),
                    std::time::Duration::from_secs(seconds),
                    args.scrub.parity,
                )
            })
            .transpose()
    } else {
        Ok(None)
    };
    if announce.is_err() || periodic.is_err() || background.is_err() {
        flag.store(true, Ordering::Release);
    }
    let _metrics = handle.wait();
    // Cancel both workers before draining either. Final filesystem cleanup must
    // not race a periodic boundary or lose either worker's completion receipt.
    let commit_cancel = match periodic.as_ref() {
        Ok(Some(worker)) => worker.request_stop(),
        _ => Ok(()),
    };
    let scrub_cancel = match background.as_ref() {
        Ok(Some(guard)) => guard.request_stop(),
        _ => Ok(()),
    };
    let commit_result = match periodic.as_mut() {
        Ok(Some(worker)) => worker.stop().map(|_| ()),
        _ => Ok(()),
    };
    let scrub_result = match background {
        Ok(Some(mut guard)) => guard.stop(),
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    announce?;
    drop(periodic?);
    commit_cancel?;
    scrub_cancel?;
    commit_result.and(scrub_result)
}

fn run(args: &Args) -> Result<()> {
    let runtime = (args.rw || args.scrub.interval_secs.is_some())
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
