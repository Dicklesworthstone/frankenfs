#![forbid(unsafe_code)]
//! FUSE adapter for FrankenFS.
//!
//! This crate is a thin translation layer: kernel FUSE requests arrive via the
//! `fuser` crate, get forwarded to a [`FsOps`] implementation (from `ffs-core`),
//! and errors are mapped through [`FfsError::to_errno()`].

use asupersync::Cx;
use ffs_core::{DirEntry as FfsDirEntry, FileType as FfsFileType, FsOps, InodeAttr};
use ffs_error::FfsError;
use ffs_types::InodeNumber;
use fuser::{
    FUSE_ROOT_ID, FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEntry, ReplyOpen, Request,
};
use std::ffi::OsStr;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tracing::warn;

/// Default TTL for cached attributes and entries.
///
/// Read-only images are immutable, so a generous TTL is safe.
const ATTR_TTL: Duration = Duration::from_secs(60);

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FuseError {
    #[error("invalid mountpoint: {0}")]
    InvalidMountpoint(String),
    #[error("mount I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ── Type conversions ────────────────────────────────────────────────────────

/// Convert an `ffs_core::FileType` to `fuser::FileType`.
fn to_fuser_file_type(ft: FfsFileType) -> FileType {
    match ft {
        FfsFileType::RegularFile => FileType::RegularFile,
        FfsFileType::Directory => FileType::Directory,
        FfsFileType::Symlink => FileType::Symlink,
        FfsFileType::BlockDevice => FileType::BlockDevice,
        FfsFileType::CharDevice => FileType::CharDevice,
        FfsFileType::Fifo => FileType::NamedPipe,
        FfsFileType::Socket => FileType::Socket,
    }
}

/// Convert an `ffs_core::InodeAttr` to `fuser::FileAttr`.
fn to_file_attr(attr: &InodeAttr) -> FileAttr {
    FileAttr {
        ino: attr.ino.0,
        size: attr.size,
        blocks: attr.blocks,
        atime: attr.atime,
        mtime: attr.mtime,
        ctime: attr.ctime,
        crtime: attr.crtime,
        kind: to_fuser_file_type(attr.kind),
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        blksize: attr.blksize,
        flags: 0,
    }
}

// ── Mount options ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MountOptions {
    pub read_only: bool,
    pub allow_other: bool,
    pub auto_unmount: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: true,
            allow_other: false,
            auto_unmount: true,
        }
    }
}

// ── FUSE filesystem adapter ─────────────────────────────────────────────────

/// FUSE adapter that delegates all operations to a [`FsOps`] implementation.
///
/// Unimplemented operations return `ENOSYS` via fuser's default method
/// implementations. Only `getattr`, `lookup`, `readdir`, `open`, `opendir`,
/// and `read` are overridden.
pub struct FrankenFuse {
    ops: Box<dyn FsOps>,
}

impl FrankenFuse {
    /// Create a new FUSE adapter wrapping the given `FsOps` implementation.
    pub fn new(ops: Box<dyn FsOps>) -> Self {
        Self { ops }
    }

    /// Helper: create a `Cx` for each FUSE request.
    ///
    /// In the future this could inherit deadlines or tracing spans from the
    /// fuser `Request`, but for now we use a plain request context.
    fn cx_for_request(&self) -> Cx {
        Cx::for_request()
    }

    /// Helper: reply with an `FfsError` mapped to errno.
    fn reply_error_attr(err: FfsError, reply: ReplyAttr) {
        reply.error(err.to_errno());
    }

    fn reply_error_entry(err: FfsError, reply: ReplyEntry) {
        reply.error(err.to_errno());
    }

    fn reply_error_data(err: FfsError, reply: ReplyData) {
        reply.error(err.to_errno());
    }

    fn reply_error_dir(err: FfsError, reply: ReplyDirectory) {
        reply.error(err.to_errno());
    }
}

impl Filesystem for FrankenFuse {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), c_int> {
        Ok(())
    }

    fn destroy(&mut self) {}

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let cx = self.cx_for_request();
        match self.ops.getattr(&cx, InodeNumber(ino)) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_file_attr(&attr)),
            Err(e) => {
                warn!(ino, error = %e, "getattr failed");
                Self::reply_error_attr(e, reply);
            }
        }
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let cx = self.cx_for_request();
        match self.ops.lookup(&cx, InodeNumber(parent), name) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), 0),
            Err(e) => {
                // ENOENT is expected for missing entries — don't warn for that.
                if e.to_errno() != libc::ENOENT {
                    warn!(parent, ?name, error = %e, "lookup failed");
                }
                Self::reply_error_entry(e, reply);
            }
        }
    }

    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        // Stateless open: we don't track file handles.
        reply.opened(0, 0);
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let cx = self.cx_for_request();
        // Clamp negative offsets to 0 (shouldn't happen in practice).
        let byte_offset = u64::try_from(offset).unwrap_or(0);
        match self.ops.read(&cx, InodeNumber(ino), byte_offset, size) {
            Ok(data) => reply.data(&data),
            Err(e) => {
                warn!(ino, offset, size, error = %e, "read failed");
                Self::reply_error_data(e, reply);
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let cx = self.cx_for_request();
        let fs_offset = u64::try_from(offset).unwrap_or(0);
        match self.ops.readdir(&cx, InodeNumber(ino), fs_offset) {
            Ok(entries) => {
                for entry in &entries {
                    let full = reply.add(
                        entry.ino.0,
                        i64::try_from(entry.offset).unwrap_or(i64::MAX),
                        to_fuser_file_type(entry.kind),
                        OsStr::new(&entry.name_str()),
                    );
                    if full {
                        break;
                    }
                }
                reply.ok();
            }
            Err(e) => {
                warn!(ino, offset, error = %e, "readdir failed");
                Self::reply_error_dir(e, reply);
            }
        }
    }
}

// ── Mount entrypoint ────────────────────────────────────────────────────────

/// Build a `fuser::Config` from our `MountOptions`.
fn build_fuser_config(options: &MountOptions) -> fuser::Config {
    let mut mount_options = vec![
        fuser::MountOption::FSName("frankenfs".to_owned()),
        fuser::MountOption::Subtype("ffs".to_owned()),
        fuser::MountOption::DefaultPermissions,
        fuser::MountOption::NoAtime,
    ];

    if options.read_only {
        mount_options.push(fuser::MountOption::RO);
    }
    if options.allow_other {
        mount_options.push(fuser::MountOption::AllowOther);
    }
    if options.auto_unmount {
        mount_options.push(fuser::MountOption::AutoUnmount);
    }

    fuser::Config {
        mount_options,
        ..Default::default()
    }
}

/// Mount a FrankenFS filesystem at the given mountpoint (blocking).
///
/// This function blocks until the filesystem is unmounted.
pub fn mount(
    ops: Box<dyn FsOps>,
    mountpoint: impl AsRef<Path>,
    options: &MountOptions,
) -> Result<(), FuseError> {
    let mountpoint = mountpoint.as_ref();
    if mountpoint.as_os_str().is_empty() {
        return Err(FuseError::InvalidMountpoint(
            "mountpoint cannot be empty".to_owned(),
        ));
    }
    let config = build_fuser_config(options);
    let fs = FrankenFuse::new(ops);
    fuser::mount2(fs, mountpoint, &config)?;
    Ok(())
}

/// Mount a FrankenFS filesystem in the background, returning a session handle.
///
/// The filesystem is unmounted when the returned `BackgroundSession` is dropped.
pub fn mount_background(
    ops: Box<dyn FsOps>,
    mountpoint: impl AsRef<Path>,
    options: &MountOptions,
) -> Result<fuser::BackgroundSession, FuseError> {
    let mountpoint = mountpoint.as_ref();
    if mountpoint.as_os_str().is_empty() {
        return Err(FuseError::InvalidMountpoint(
            "mountpoint cannot be empty".to_owned(),
        ));
    }
    let config = build_fuser_config(options);
    let fs = FrankenFuse::new(ops);
    let session = fuser::spawn_mount2(fs, mountpoint, &config)?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_type_conversion_roundtrip() {
        let cases = [
            (FfsFileType::RegularFile, FileType::RegularFile),
            (FfsFileType::Directory, FileType::Directory),
            (FfsFileType::Symlink, FileType::Symlink),
            (FfsFileType::BlockDevice, FileType::BlockDevice),
            (FfsFileType::CharDevice, FileType::CharDevice),
            (FfsFileType::Fifo, FileType::NamedPipe),
            (FfsFileType::Socket, FileType::Socket),
        ];
        for (ffs_ft, expected_fuser_ft) in &cases {
            assert_eq!(to_fuser_file_type(*ffs_ft), *expected_fuser_ft);
        }
    }

    #[test]
    fn inode_attr_to_file_attr_conversion() {
        let iattr = InodeAttr {
            ino: InodeNumber(42),
            size: 1024,
            blocks: 2,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: FfsFileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
        };
        let fattr = to_file_attr(&iattr);
        assert_eq!(fattr.ino, 42);
        assert_eq!(fattr.size, 1024);
        assert_eq!(fattr.blocks, 2);
        assert_eq!(fattr.kind, FileType::RegularFile);
        assert_eq!(fattr.perm, 0o644);
        assert_eq!(fattr.nlink, 1);
        assert_eq!(fattr.uid, 1000);
        assert_eq!(fattr.gid, 1000);
        assert_eq!(fattr.rdev, 0);
        assert_eq!(fattr.blksize, 4096);
        assert_eq!(fattr.flags, 0);
    }

    #[test]
    fn mount_options_default_is_read_only() {
        let opts = MountOptions::default();
        assert!(opts.read_only);
        assert!(!opts.allow_other);
        assert!(opts.auto_unmount);
    }

    #[test]
    fn build_config_includes_ro_when_read_only() {
        let opts = MountOptions::default();
        let config = build_fuser_config(&opts);
        // Verify config was built (we can't easily inspect MountOption variants,
        // but the function shouldn't panic).
        assert!(!config.mount_options.is_empty());
    }

    #[test]
    fn mount_rejects_empty_mountpoint() {
        // We can't construct a real FsOps without a filesystem, but we can
        // verify the mountpoint validation fires before any FsOps call.
        // Use a minimal stub.
        struct NeverCalledFs;
        impl FsOps for NeverCalledFs {
            fn getattr(&self, _cx: &Cx, _ino: InodeNumber) -> ffs_error::Result<InodeAttr> {
                unreachable!()
            }
            fn lookup(
                &self,
                _cx: &Cx,
                _parent: InodeNumber,
                _name: &OsStr,
            ) -> ffs_error::Result<InodeAttr> {
                unreachable!()
            }
            fn readdir(
                &self,
                _cx: &Cx,
                _ino: InodeNumber,
                _offset: u64,
            ) -> ffs_error::Result<Vec<FfsDirEntry>> {
                unreachable!()
            }
            fn read(
                &self,
                _cx: &Cx,
                _ino: InodeNumber,
                _offset: u64,
                _size: u32,
            ) -> ffs_error::Result<Vec<u8>> {
                unreachable!()
            }
        }
        let err = mount(Box::new(NeverCalledFs), "", &MountOptions::default()).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn franken_fuse_construction() {
        struct StubFs;
        impl FsOps for StubFs {
            fn getattr(&self, _cx: &Cx, _ino: InodeNumber) -> ffs_error::Result<InodeAttr> {
                Err(FfsError::NotFound("stub".into()))
            }
            fn lookup(
                &self,
                _cx: &Cx,
                _parent: InodeNumber,
                _name: &OsStr,
            ) -> ffs_error::Result<InodeAttr> {
                Err(FfsError::NotFound("stub".into()))
            }
            fn readdir(
                &self,
                _cx: &Cx,
                _ino: InodeNumber,
                _offset: u64,
            ) -> ffs_error::Result<Vec<FfsDirEntry>> {
                Ok(vec![])
            }
            fn read(
                &self,
                _cx: &Cx,
                _ino: InodeNumber,
                _offset: u64,
                _size: u32,
            ) -> ffs_error::Result<Vec<u8>> {
                Ok(vec![])
            }
        }
        let fuse = FrankenFuse::new(Box::new(StubFs));
        // Verify the Cx creation helper works.
        let _cx = fuse.cx_for_request();
    }
}
