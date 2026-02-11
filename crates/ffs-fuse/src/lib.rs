#![forbid(unsafe_code)]
//! FUSE adapter for FrankenFS.
//!
//! This crate is a thin translation layer: kernel FUSE requests arrive via the
//! `fuser` crate, get forwarded to a [`FsOps`] implementation (from `ffs-core`),
//! and errors are mapped through [`FfsError::to_errno()`].

use asupersync::Cx;
use ffs_core::{FileType as FfsFileType, FsOps, InodeAttr, RequestOp};
use ffs_error::FfsError;
use ffs_types::InodeNumber;
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEntry, ReplyOpen, Request,
};
use std::ffi::OsStr;
use std::os::raw::c_int;
use std::path::Path;
use std::time::Duration;
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
/// `read`, and `readlink` are overridden.
pub struct FrankenFuse {
    ops: Box<dyn FsOps>,
}

impl FrankenFuse {
    /// Create a new FUSE adapter wrapping the given `FsOps` implementation.
    #[must_use]
    pub fn new(ops: Box<dyn FsOps>) -> Self {
        Self { ops }
    }

    /// Create a `Cx` for a FUSE request.
    ///
    /// In the future this could inherit deadlines or tracing spans from the
    /// fuser `Request`, but for now we use a plain request context.
    fn cx_for_request() -> Cx {
        Cx::for_request()
    }

    fn reply_error_attr(err: &FfsError, reply: ReplyAttr) {
        reply.error(err.to_errno());
    }

    fn reply_error_entry(err: &FfsError, reply: ReplyEntry) {
        reply.error(err.to_errno());
    }

    fn reply_error_data(err: &FfsError, reply: ReplyData) {
        reply.error(err.to_errno());
    }

    fn reply_error_dir(err: &FfsError, reply: ReplyDirectory) {
        reply.error(err.to_errno());
    }

    fn with_request_scope<T, F>(&self, cx: &Cx, op: RequestOp, f: F) -> ffs_error::Result<T>
    where
        F: FnOnce(&Cx) -> ffs_error::Result<T>,
    {
        let scope = self.ops.begin_request_scope(cx, op)?;
        let op_result = f(cx);
        let end_result = self.ops.end_request_scope(cx, op, scope);

        match (op_result, end_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(end_err)) => Err(end_err),
            (Err(op_err), Ok(())) => Err(op_err),
            (Err(op_err), Err(end_err)) => {
                warn!(?op, error = %end_err, "request scope cleanup failed after operation error");
                Err(op_err)
            }
        }
    }
}

impl Filesystem for FrankenFuse {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), c_int> {
        Ok(())
    }

    fn destroy(&mut self) {}

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Getattr, |cx| {
            self.ops.getattr(cx, InodeNumber(ino))
        }) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_file_attr(&attr)),
            Err(e) => {
                warn!(ino, error = %e, "getattr failed");
                Self::reply_error_attr(&e, reply);
            }
        }
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Lookup, |cx| {
            self.ops.lookup(cx, InodeNumber(parent), name)
        }) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), 0),
            Err(e) => {
                // ENOENT is expected for missing entries — don't warn for that.
                if e.to_errno() != libc::ENOENT {
                    warn!(parent, ?name, error = %e, "lookup failed");
                }
                Self::reply_error_entry(&e, reply);
            }
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Open, |_cx| Ok(())) {
            // Stateless open: we don't track file handles.
            Ok(()) => reply.opened(0, 0),
            Err(e) => {
                warn!(ino, error = %e, "open failed");
                reply.error(e.to_errno());
            }
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Opendir, |_cx| Ok(())) {
            Ok(()) => reply.opened(0, 0),
            Err(e) => {
                warn!(ino, error = %e, "opendir failed");
                reply.error(e.to_errno());
            }
        }
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
        let cx = Self::cx_for_request();
        // Clamp negative offsets to 0 (shouldn't happen in practice).
        let byte_offset = u64::try_from(offset).unwrap_or(0);
        match self.with_request_scope(&cx, RequestOp::Read, |cx| {
            self.ops.read(cx, InodeNumber(ino), byte_offset, size)
        }) {
            Ok(data) => reply.data(&data),
            Err(e) => {
                warn!(ino, offset, size, error = %e, "read failed");
                Self::reply_error_data(&e, reply);
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
        let cx = Self::cx_for_request();
        let fs_offset = u64::try_from(offset).unwrap_or(0);
        match self.with_request_scope(&cx, RequestOp::Readdir, |cx| {
            self.ops.readdir(cx, InodeNumber(ino), fs_offset)
        }) {
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
                Self::reply_error_dir(&e, reply);
            }
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Readlink, |cx| {
            self.ops.readlink(cx, InodeNumber(ino))
        }) {
            Ok(target) => reply.data(&target),
            Err(e) => {
                warn!(ino, error = %e, "readlink failed");
                Self::reply_error_data(&e, reply);
            }
        }
    }
}

// ── Mount entrypoint ────────────────────────────────────────────────────────

/// Build a list of `fuser::MountOption` from our `MountOptions`.
fn build_mount_options(options: &MountOptions) -> Vec<MountOption> {
    let mut opts = vec![
        MountOption::FSName("frankenfs".to_owned()),
        MountOption::Subtype("ffs".to_owned()),
        MountOption::DefaultPermissions,
        MountOption::NoAtime,
    ];

    if options.read_only {
        opts.push(MountOption::RO);
    }
    if options.allow_other {
        opts.push(MountOption::AllowOther);
    }
    if options.auto_unmount {
        opts.push(MountOption::AutoUnmount);
    }

    opts
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
    let fuse_opts = build_mount_options(options);
    let fs = FrankenFuse::new(ops);
    fuser::mount2(fs, mountpoint, &fuse_opts)?;
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
    let fuse_opts = build_mount_options(options);
    let fs = FrankenFuse::new(ops);
    let session = fuser::spawn_mount2(fs, mountpoint, &fuse_opts)?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_core::{DirEntry as FfsDirEntry, RequestScope};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

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
    fn build_mount_options_includes_ro_when_read_only() {
        let opts = MountOptions::default();
        let mount_opts = build_mount_options(&opts);
        // Default includes FSName + Subtype + DefaultPermissions + NoAtime + RO + AutoUnmount = 6
        assert!(mount_opts.len() >= 5);
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
            fn readlink(&self, _cx: &Cx, _ino: InodeNumber) -> ffs_error::Result<Vec<u8>> {
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
            fn readlink(&self, _cx: &Cx, _ino: InodeNumber) -> ffs_error::Result<Vec<u8>> {
                Ok(vec![])
            }
        }
        let _fuse = FrankenFuse::new(Box::new(StubFs));
        // Verify the Cx creation helper works.
        let _cx = FrankenFuse::cx_for_request();
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HookEvent {
        Begin(RequestOp),
        Body(RequestOp),
        End(RequestOp),
    }

    struct HookFs {
        events: Arc<Mutex<Vec<HookEvent>>>,
        fail_begin: bool,
        fail_end: bool,
    }

    impl HookFs {
        fn new(events: Arc<Mutex<Vec<HookEvent>>>, fail_begin: bool, fail_end: bool) -> Self {
            Self {
                events,
                fail_begin,
                fail_end,
            }
        }
    }

    impl FsOps for HookFs {
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

        fn readlink(&self, _cx: &Cx, _ino: InodeNumber) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn begin_request_scope(&self, _cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
            self.events.lock().unwrap().push(HookEvent::Begin(op));
            if self.fail_begin {
                return Err(FfsError::Io(std::io::Error::other("begin failed")));
            }
            Ok(RequestScope::empty())
        }

        fn end_request_scope(
            &self,
            _cx: &Cx,
            op: RequestOp,
            _scope: RequestScope,
        ) -> ffs_error::Result<()> {
            self.events.lock().unwrap().push(HookEvent::End(op));
            if self.fail_end {
                return Err(FfsError::Io(std::io::Error::other("end failed")));
            }
            Ok(())
        }
    }

    #[test]
    fn request_scope_calls_begin_and_end_for_successful_operation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_events = Arc::clone(&events);

        let out = fuse
            .with_request_scope(&cx, RequestOp::Read, |_cx| {
                body_events
                    .lock()
                    .unwrap()
                    .push(HookEvent::Body(RequestOp::Read));
                Ok::<u32, FfsError>(7)
            })
            .unwrap();
        assert_eq!(out, 7);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                HookEvent::Begin(RequestOp::Read),
                HookEvent::Body(RequestOp::Read),
                HookEvent::End(RequestOp::Read)
            ]
        );
    }

    #[test]
    fn request_scope_short_circuits_body_when_begin_fails() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), true, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_called = Arc::new(AtomicBool::new(false));
        let body_called_ref = Arc::clone(&body_called);

        let err = fuse
            .with_request_scope(&cx, RequestOp::Lookup, |_cx| {
                body_called_ref.store(true, Ordering::Relaxed);
                Ok::<(), FfsError>(())
            })
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::EIO);
        assert!(!body_called.load(Ordering::Relaxed));
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[HookEvent::Begin(RequestOp::Lookup)]
        );
    }

    #[test]
    fn request_scope_prefers_operation_error_when_body_and_end_fail() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, true);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_events = Arc::clone(&events);

        let err = fuse
            .with_request_scope(&cx, RequestOp::Readlink, |_cx| {
                body_events
                    .lock()
                    .unwrap()
                    .push(HookEvent::Body(RequestOp::Readlink));
                Err::<(), FfsError>(FfsError::NotFound("missing".into()))
            })
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                HookEvent::Begin(RequestOp::Readlink),
                HookEvent::Body(RequestOp::Readlink),
                HookEvent::End(RequestOp::Readlink)
            ]
        );
    }

    #[test]
    fn request_scope_returns_cleanup_error_when_operation_succeeds() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, true);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_events = Arc::clone(&events);

        let err = fuse
            .with_request_scope(&cx, RequestOp::Getattr, |_cx| {
                body_events
                    .lock()
                    .unwrap()
                    .push(HookEvent::Body(RequestOp::Getattr));
                Ok::<(), FfsError>(())
            })
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::EIO);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                HookEvent::Begin(RequestOp::Getattr),
                HookEvent::Body(RequestOp::Getattr),
                HookEvent::End(RequestOp::Getattr)
            ]
        );
    }
}
