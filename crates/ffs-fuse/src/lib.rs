#![forbid(unsafe_code)]
//! FUSE adapter for FrankenFS.
//!
//! This crate is a thin translation layer: kernel FUSE requests arrive via the
//! `fuser` crate, get forwarded to a [`FsOps`] implementation (from `ffs-core`),
//! and errors are mapped through [`FfsError::to_errno()`].

use asupersync::Cx;
use ffs_core::{FileType as FfsFileType, FsOps, InodeAttr, RequestOp, SetAttrRequest};
use ffs_error::FfsError;
use ffs_types::InodeNumber;
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, ReplyXattr, Request, TimeOrNow,
};
use std::ffi::OsStr;
use std::os::raw::c_int;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tracing::{info, trace, warn};

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

// ── FUSE error context ─────────────────────────────────────────────────────

/// Structured error context for FUSE operation failures.
///
/// Captures the operation name, inode, optional offset, and the underlying
/// error. Used to produce consistent, structured tracing for every FUSE
/// error reply.
pub struct FuseErrorContext<'a> {
    pub error: &'a FfsError,
    pub operation: &'static str,
    pub ino: u64,
    pub offset: Option<u64>,
}

impl FuseErrorContext<'_> {
    /// Log this error context via tracing and return the errno for the reply.
    pub fn log_and_errno(&self) -> c_int {
        let errno = self.error.to_errno();
        // ENOENT on lookup is normal — log at trace instead of warn.
        if errno == libc::ENOENT {
            trace!(
                op = self.operation,
                ino = self.ino,
                errno,
                error = %self.error,
                "FUSE op returned ENOENT"
            );
        } else {
            warn!(
                op = self.operation,
                ino = self.ino,
                offset = self.offset,
                errno,
                error = %self.error,
                "FUSE op failed"
            );
        }
        errno
    }
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
    /// Number of worker threads for FUSE dispatch.
    ///
    /// Currently fuser 0.16 processes requests sequentially; this field
    /// is reserved for future multi-threaded dispatch (e.g. via
    /// `Session::run()` clones or a fuser upgrade). A value of 0 means
    /// "use default" (min(num_cpus, 8) when multi-threading is enabled).
    pub worker_threads: usize,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: true,
            allow_other: false,
            auto_unmount: true,
            worker_threads: 0,
        }
    }
}

impl MountOptions {
    /// Resolved thread count.
    ///
    /// `worker_threads == 0` means "auto": `min(available_parallelism, 8)`.
    /// Non-zero values are returned as-is (clamped to at least 1).
    #[must_use]
    pub fn resolved_thread_count(&self) -> usize {
        if self.worker_threads == 0 {
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(8)
        } else {
            self.worker_threads.max(1)
        }
    }
}

// ── Cache-line padding ──────────────────────────────────────────────────────

/// Pad a value to 64 bytes to avoid false sharing between hot counters
/// updated on different CPU cores.
#[repr(C, align(64))]
pub struct CacheLinePadded<T>(pub T);

impl<T: std::fmt::Debug> std::fmt::Debug for CacheLinePadded<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// ── Atomic metrics ──────────────────────────────────────────────────────────

/// Lock-free per-mount request counters.
///
/// Each counter sits on its own cache line (64 B) so cores updating
/// different counters never invalidate each other's L1 lines.
#[repr(C)]
pub struct AtomicMetrics {
    pub requests_total: CacheLinePadded<AtomicU64>,
    pub requests_ok: CacheLinePadded<AtomicU64>,
    pub requests_err: CacheLinePadded<AtomicU64>,
    pub bytes_read: CacheLinePadded<AtomicU64>,
}

impl AtomicMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests_total: CacheLinePadded(AtomicU64::new(0)),
            requests_ok: CacheLinePadded(AtomicU64::new(0)),
            requests_err: CacheLinePadded(AtomicU64::new(0)),
            bytes_read: CacheLinePadded(AtomicU64::new(0)),
        }
    }

    fn record_ok(&self) {
        self.requests_total.0.fetch_add(1, Ordering::Relaxed);
        self.requests_ok.0.fetch_add(1, Ordering::Relaxed);
    }

    fn record_err(&self) {
        self.requests_total.0.fetch_add(1, Ordering::Relaxed);
        self.requests_err.0.fetch_add(1, Ordering::Relaxed);
    }

    fn record_bytes_read(&self, n: u64) {
        self.bytes_read.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Snapshot of all counters (for diagnostics / reporting).
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.0.load(Ordering::Relaxed),
            requests_ok: self.requests_ok.0.load(Ordering::Relaxed),
            requests_err: self.requests_err.0.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.0.load(Ordering::Relaxed),
        }
    }
}

impl Default for AtomicMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AtomicMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.snapshot();
        f.debug_struct("AtomicMetrics")
            .field("requests_total", &s.requests_total)
            .field("requests_ok", &s.requests_ok)
            .field("requests_err", &s.requests_err)
            .field("bytes_read", &s.bytes_read)
            .finish()
    }
}

/// Point-in-time snapshot of metrics (all plain `u64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_ok: u64,
    pub requests_err: u64,
    pub bytes_read: u64,
}

// ── Shared FUSE inner state ─────────────────────────────────────────────────

/// Thread-safe shared state for the FUSE backend.
///
/// All fields are `Send + Sync`:
/// - `ops` delegates to `FsOps` which is `Send + Sync` by trait bound.
/// - `metrics` uses atomic counters with cache-line padding.
/// - `thread_count` is immutable after mount.
struct FuseInner {
    ops: Arc<dyn FsOps>,
    metrics: Arc<AtomicMetrics>,
    thread_count: usize,
    read_only: bool,
}

impl std::fmt::Debug for FuseInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuseInner")
            .field("metrics", &self.metrics)
            .field("thread_count", &self.thread_count)
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

// ── FUSE filesystem adapter ─────────────────────────────────────────────────

/// FUSE adapter that delegates all operations to a [`FsOps`] implementation.
///
/// Internally wraps all state in `Arc<FuseInner>` so it is `Send + Sync`
/// and ready for multi-threaded FUSE dispatch.  All `FsOps` calls go
/// through `self.inner.ops` (which is `Arc<dyn FsOps>`), and lock-free
/// [`AtomicMetrics`] are updated on every request.
pub struct FrankenFuse {
    inner: Arc<FuseInner>,
}

// Compile-time assertions: FrankenFuse must be Send + Sync.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<FrankenFuse>;
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XattrReplyPlan {
    Size(u32),
    Data,
    Error(c_int),
}

impl FrankenFuse {
    /// Create a new FUSE adapter wrapping the given `FsOps` implementation.
    ///
    /// Uses default thread count (auto-detected).
    #[must_use]
    pub fn new(ops: Box<dyn FsOps>) -> Self {
        Self::with_options(ops, &MountOptions::default())
    }

    /// Create a new FUSE adapter with explicit mount options.
    ///
    /// The resolved `thread_count` is logged at info level.
    #[must_use]
    pub fn with_options(ops: Box<dyn FsOps>, options: &MountOptions) -> Self {
        let thread_count = options.resolved_thread_count();
        info!(thread_count, "FrankenFuse initialized");
        Self {
            inner: Arc::new(FuseInner {
                ops: Arc::from(ops),
                metrics: Arc::new(AtomicMetrics::new()),
                thread_count,
                read_only: options.read_only,
            }),
        }
    }

    /// Get a reference to the shared metrics.
    #[must_use]
    pub fn metrics(&self) -> &AtomicMetrics {
        &self.inner.metrics
    }

    /// Configured thread count.
    #[must_use]
    pub fn thread_count(&self) -> usize {
        self.inner.thread_count
    }

    /// Create a `Cx` for a FUSE request.
    ///
    /// In the future this could inherit deadlines or tracing spans from the
    /// fuser `Request`, but for now we use a plain request context.
    fn cx_for_request() -> Cx {
        Cx::for_request()
    }

    fn reply_error_attr(ctx: &FuseErrorContext<'_>, reply: ReplyAttr) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_entry(ctx: &FuseErrorContext<'_>, reply: ReplyEntry) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_data(ctx: &FuseErrorContext<'_>, reply: ReplyData) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_dir(ctx: &FuseErrorContext<'_>, reply: ReplyDirectory) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_xattr(ctx: &FuseErrorContext<'_>, reply: ReplyXattr) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_empty(ctx: &FuseErrorContext<'_>, reply: ReplyEmpty) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_write(ctx: &FuseErrorContext<'_>, reply: ReplyWrite) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_create(ctx: &FuseErrorContext<'_>, reply: ReplyCreate) {
        reply.error(ctx.log_and_errno());
    }

    fn classify_xattr_reply(size: u32, payload_len: usize) -> XattrReplyPlan {
        match u32::try_from(payload_len) {
            Ok(payload_len_u32) if size == 0 => XattrReplyPlan::Size(payload_len_u32),
            Ok(payload_len_u32) if payload_len_u32 <= size => XattrReplyPlan::Data,
            Ok(_) => XattrReplyPlan::Error(libc::ERANGE),
            Err(_) => XattrReplyPlan::Error(libc::EOVERFLOW),
        }
    }

    fn reply_xattr_payload(size: u32, payload: &[u8], reply: ReplyXattr) {
        match Self::classify_xattr_reply(size, payload.len()) {
            XattrReplyPlan::Size(payload_len) => reply.size(payload_len),
            XattrReplyPlan::Data => reply.data(payload),
            XattrReplyPlan::Error(errno) => reply.error(errno),
        }
    }

    #[cfg(target_os = "linux")]
    const fn missing_xattr_errno() -> c_int {
        libc::ENODATA
    }

    #[cfg(not(target_os = "linux"))]
    const fn missing_xattr_errno() -> c_int {
        libc::ENOATTR
    }

    fn encode_xattr_names(names: &[String]) -> Vec<u8> {
        let total_len = names.iter().map(|name| name.len() + 1).sum();
        let mut bytes = Vec::with_capacity(total_len);
        for name in names {
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    fn with_request_scope<T, F>(&self, cx: &Cx, op: RequestOp, f: F) -> ffs_error::Result<T>
    where
        F: FnOnce(&Cx) -> ffs_error::Result<T>,
    {
        let scope = self.inner.ops.begin_request_scope(cx, op)?;
        let op_result = f(cx);
        let end_result = self.inner.ops.end_request_scope(cx, op, scope);

        match (op_result, end_result) {
            (Ok(value), Ok(())) => {
                self.inner.metrics.record_ok();
                Ok(value)
            }
            (Ok(_), Err(end_err)) => {
                self.inner.metrics.record_err();
                Err(end_err)
            }
            (Err(op_err), Ok(())) => {
                self.inner.metrics.record_err();
                Err(op_err)
            }
            (Err(op_err), Err(end_err)) => {
                self.inner.metrics.record_err();
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
            self.inner.ops.getattr(cx, InodeNumber(ino))
        }) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_file_attr(&attr)),
            Err(e) => {
                Self::reply_error_attr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "getattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Lookup, |cx| {
            self.inner.ops.lookup(cx, InodeNumber(parent), name)
        }) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), 0),
            Err(e) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &e,
                        operation: "lookup",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Open, |_cx| Ok(())) {
            // Stateless open: we don't track file handles.
            Ok(()) => reply.opened(0, 0),
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "open",
                    ino,
                    offset: None,
                };
                reply.error(ctx.log_and_errno());
            }
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Opendir, |_cx| Ok(())) {
            Ok(()) => reply.opened(0, 0),
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "opendir",
                    ino,
                    offset: None,
                };
                reply.error(ctx.log_and_errno());
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
            self.inner.ops.read(cx, InodeNumber(ino), byte_offset, size)
        }) {
            Ok(data) => {
                self.inner
                    .metrics
                    .record_bytes_read(u64::try_from(data.len()).unwrap_or(u64::MAX));
                reply.data(&data);
            }
            Err(e) => {
                Self::reply_error_data(
                    &FuseErrorContext {
                        error: &e,
                        operation: "read",
                        ino,
                        offset: Some(byte_offset),
                    },
                    reply,
                );
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
            self.inner.ops.readdir(cx, InodeNumber(ino), fs_offset)
        }) {
            Ok(entries) => {
                for entry in &entries {
                    #[cfg(unix)]
                    let name = OsStr::from_bytes(&entry.name);
                    #[cfg(not(unix))]
                    let owned_name = entry.name_str();
                    #[cfg(not(unix))]
                    let name = OsStr::new(&owned_name);

                    let full = reply.add(
                        entry.ino.0,
                        i64::try_from(entry.offset).unwrap_or(i64::MAX),
                        to_fuser_file_type(entry.kind),
                        name,
                    );
                    if full {
                        break;
                    }
                }
                reply.ok();
            }
            Err(e) => {
                Self::reply_error_dir(
                    &FuseErrorContext {
                        error: &e,
                        operation: "readdir",
                        ino,
                        offset: Some(fs_offset),
                    },
                    reply,
                );
            }
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Readlink, |cx| {
            self.inner.ops.readlink(cx, InodeNumber(ino))
        }) {
            Ok(target) => reply.data(&target),
            Err(e) => {
                Self::reply_error_data(
                    &FuseErrorContext {
                        error: &e,
                        operation: "readlink",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Getxattr, |cx| {
            self.inner.ops.getxattr(cx, InodeNumber(ino), name)
        }) {
            Ok(Some(value)) => Self::reply_xattr_payload(size, &value, reply),
            Ok(None) => reply.error(Self::missing_xattr_errno()),
            Err(e) => {
                Self::reply_error_xattr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "getxattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Listxattr, |cx| {
            self.inner.ops.listxattr(cx, InodeNumber(ino))
        }) {
            Ok(names) => {
                let payload = Self::encode_xattr_names(&names);
                Self::reply_xattr_payload(size, &payload, reply);
            }
            Err(e) => {
                Self::reply_error_xattr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "listxattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    // ── Write operations ─────────────────────────────────────────────────

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        let resolve_time = |t: TimeOrNow| -> SystemTime {
            match t {
                TimeOrNow::SpecificTime(st) => st,
                TimeOrNow::Now => SystemTime::now(),
            }
        };
        let attrs = SetAttrRequest {
            #[allow(clippy::cast_possible_truncation)]
            mode: mode.map(|m| m as u16), // FUSE mode is u32, ext4 mode is u16
            uid,
            gid,
            size,
            atime: atime.map(resolve_time),
            mtime: mtime.map(resolve_time),
        };
        match self.with_request_scope(&cx, RequestOp::Setattr, |cx| {
            self.inner.ops.setattr(cx, InodeNumber(ino), &attrs)
        }) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_file_attr(&attr)),
            Err(e) => {
                Self::reply_error_attr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "setattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)] // FUSE mode u32 → ext4 u16
    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Mkdir, |cx| {
            self.inner.ops.mkdir(
                cx,
                InodeNumber(parent),
                name,
                mode as u16,
                req.uid(),
                req.gid(),
            )
        }) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), 0),
            Err(e) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &e,
                        operation: "mkdir",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Unlink, |cx| {
            self.inner.ops.unlink(cx, InodeNumber(parent), name)
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "unlink",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Rmdir, |cx| {
            self.inner.ops.rmdir(cx, InodeNumber(parent), name)
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "rmdir",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Rename, |cx| {
            self.inner.ops.rename(
                cx,
                InodeNumber(parent),
                name,
                InodeNumber(newparent),
                newname,
            )
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "rename",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        let byte_offset = u64::try_from(offset).unwrap_or(0);
        match self.with_request_scope(&cx, RequestOp::Write, |cx| {
            self.inner
                .ops
                .write(cx, InodeNumber(ino), byte_offset, data)
        }) {
            Ok(written) => reply.written(written),
            Err(e) => {
                Self::reply_error_write(
                    &FuseErrorContext {
                        error: &e,
                        operation: "write",
                        ino,
                        offset: Some(byte_offset),
                    },
                    reply,
                );
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)] // FUSE mode u32 → ext4 u16
    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Create, |cx| {
            self.inner.ops.create(
                cx,
                InodeNumber(parent),
                name,
                mode as u16,
                req.uid(),
                req.gid(),
            )
        }) {
            Ok(attr) => {
                reply.created(&ATTR_TTL, &to_file_attr(&attr), 0, 0, 0);
            }
            Err(e) => {
                Self::reply_error_create(
                    &FuseErrorContext {
                        error: &e,
                        operation: "create",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
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
    let fs = FrankenFuse::with_options(ops, options);
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
    let fs = FrankenFuse::with_options(ops, options);
    let session = fuser::spawn_mount2(fs, mountpoint, &fuse_opts)?;
    Ok(session)
}

// ── Mount lifecycle ─────────────────────────────────────────────────────────

/// Configuration for a managed mount with lifecycle control.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Base mount options (RO, allow_other, threads, etc.).
    pub options: MountOptions,
    /// Grace period for in-flight requests during unmount.
    pub unmount_timeout: Duration,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            options: MountOptions::default(),
            unmount_timeout: Duration::from_secs(30),
        }
    }
}

/// Handle for a live FUSE mount with lifecycle control.
///
/// Dropping the handle triggers a clean unmount.  Call [`wait`] to block
/// until external shutdown (Ctrl+C / programmatic `shutdown()`).
///
/// # Signal Handling
///
/// `MountHandle` exposes a shared `shutdown` flag (`Arc<AtomicBool>`).
/// The CLI (or any owner) should wire SIGTERM / SIGINT handlers that set
/// this flag.  [`wait`] polls the flag and triggers unmount when set.
/// The `AutoUnmount` fuser option provides a safety net: the kernel
/// unmounts the filesystem if the process exits without a clean unmount.
pub struct MountHandle {
    session: Option<fuser::BackgroundSession>,
    mountpoint: PathBuf,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    metrics: Arc<AtomicMetrics>,
    config: MountConfig,
}

impl MountHandle {
    /// The mountpoint path.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Shared shutdown flag.
    ///
    /// Set this to `true` (from a signal handler or another thread) to
    /// trigger a graceful unmount.
    #[must_use]
    pub fn shutdown_flag(&self) -> &Arc<std::sync::atomic::AtomicBool> {
        &self.shutdown
    }

    /// Get a snapshot of the mount metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Block until the shutdown flag is set, then unmount cleanly.
    ///
    /// Returns the final metrics snapshot.
    #[must_use]
    pub fn wait(mut self) -> MetricsSnapshot {
        info!(mountpoint = %self.mountpoint.display(), "waiting for shutdown signal");
        while !self.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(100));
        }
        info!(mountpoint = %self.mountpoint.display(), "shutdown signal received");
        self.do_unmount()
    }

    /// Trigger a graceful unmount.
    ///
    /// Returns the final metrics snapshot.
    #[must_use]
    pub fn unmount(mut self) -> MetricsSnapshot {
        self.do_unmount()
    }

    fn do_unmount(&mut self) -> MetricsSnapshot {
        let snap = self.metrics.snapshot();
        if let Some(session) = self.session.take() {
            info!(
                mountpoint = %self.mountpoint.display(),
                requests_total = snap.requests_total,
                requests_ok = snap.requests_ok,
                requests_err = snap.requests_err,
                bytes_read = snap.bytes_read,
                "unmounting FUSE filesystem"
            );
            // Dropping the BackgroundSession triggers FUSE unmount.
            drop(session);
            info!(mountpoint = %self.mountpoint.display(), "unmount complete");
        }
        snap
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        if self.session.is_some() {
            self.do_unmount();
        }
    }
}

impl std::fmt::Debug for MountHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountHandle")
            .field("mountpoint", &self.mountpoint)
            .field("active", &self.session.is_some())
            .field(
                "shutdown",
                &self.shutdown.load(std::sync::atomic::Ordering::Relaxed),
            )
            .field("metrics", &self.metrics.snapshot())
            .field("unmount_timeout", &self.config.unmount_timeout)
            .finish()
    }
}

/// Mount a FrankenFS filesystem with full lifecycle control.
///
/// Returns a [`MountHandle`] that can be used to wait for signals,
/// query metrics, and trigger a clean unmount.
///
/// # Example
/// ```no_run
/// # use ffs_fuse::{MountConfig, mount_managed};
/// # fn example(ops: Box<dyn ffs_core::FsOps>) {
/// let handle = mount_managed(ops, "/mnt/ffs", &MountConfig::default()).unwrap();
/// // Wire Ctrl+C to the shutdown flag (e.g. via ctrlc crate):
/// let flag = handle.shutdown_flag().clone();
/// // ... register signal handler that sets `flag.store(true, ...)` ...
/// let stats = handle.wait();
/// println!("served {} requests", stats.requests_total);
/// # }
/// ```
pub fn mount_managed(
    ops: Box<dyn FsOps>,
    mountpoint: impl AsRef<Path>,
    config: &MountConfig,
) -> Result<MountHandle, FuseError> {
    let mountpoint = mountpoint.as_ref();
    if mountpoint.as_os_str().is_empty() {
        return Err(FuseError::InvalidMountpoint(
            "mountpoint cannot be empty".to_owned(),
        ));
    }
    if !mountpoint.exists() {
        return Err(FuseError::InvalidMountpoint(format!(
            "mountpoint does not exist: {}",
            mountpoint.display()
        )));
    }

    let thread_count = config.options.resolved_thread_count();
    info!(
        mountpoint = %mountpoint.display(),
        thread_count,
        read_only = config.options.read_only,
        unmount_timeout_secs = config.unmount_timeout.as_secs(),
        "mounting FrankenFS"
    );

    let fuse_opts = build_mount_options(&config.options);
    let fs = FrankenFuse::with_options(ops, &config.options);
    let metrics_ref = Arc::clone(&fs.inner.metrics);

    let session = fuser::spawn_mount2(fs, mountpoint, &fuse_opts)?;

    info!(mountpoint = %mountpoint.display(), "FUSE mount active");

    Ok(MountHandle {
        session: Some(session),
        mountpoint: mountpoint.to_owned(),
        shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        metrics: metrics_ref,
        config: config.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_core::{DirEntry as FfsDirEntry, RequestScope};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    /// Minimal FsOps stub for tests that don't need real filesystem behavior.
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
        let _fuse = FrankenFuse::new(Box::new(StubFs));
        // Verify the Cx creation helper works.
        let _cx = FrankenFuse::cx_for_request();
    }

    #[test]
    fn encode_xattr_names_empty_is_empty_payload() {
        let encoded = FrankenFuse::encode_xattr_names(&[]);
        assert!(encoded.is_empty());
    }

    #[test]
    fn encode_xattr_names_produces_nul_separated_list() {
        let encoded = FrankenFuse::encode_xattr_names(&[
            "user.project".to_owned(),
            "security.selinux".to_owned(),
        ]);
        assert_eq!(encoded, b"user.project\0security.selinux\0");
    }

    #[test]
    fn classify_xattr_reply_size_probe_returns_size() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(0, 11),
            XattrReplyPlan::Size(11)
        );
    }

    #[test]
    fn classify_xattr_reply_data_when_buffer_fits() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(64, 32),
            XattrReplyPlan::Data
        );
    }

    #[test]
    fn classify_xattr_reply_erange_when_buffer_too_small() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(8, 32),
            XattrReplyPlan::Error(libc::ERANGE)
        );
    }

    #[test]
    fn classify_xattr_reply_eoverflow_for_oversized_payload() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(0, usize::MAX),
            XattrReplyPlan::Error(libc::EOVERFLOW)
        );
    }

    #[test]
    fn missing_xattr_errno_matches_platform() {
        #[cfg(target_os = "linux")]
        assert_eq!(FrankenFuse::missing_xattr_errno(), libc::ENODATA);

        #[cfg(not(target_os = "linux"))]
        assert_eq!(FrankenFuse::missing_xattr_errno(), libc::ENOATTR);
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

    #[test]
    fn fuse_error_context_returns_correct_errno() {
        let cases: Vec<(FfsError, libc::c_int)> = vec![
            (FfsError::NotFound("test".into()), libc::ENOENT),
            (FfsError::PermissionDenied, libc::EACCES),
            (FfsError::IsDirectory, libc::EISDIR),
            (FfsError::NotDirectory, libc::ENOTDIR),
            (FfsError::ReadOnly, libc::EROFS),
            (FfsError::NoSpace, libc::ENOSPC),
            (FfsError::NameTooLong, libc::ENAMETOOLONG),
            (FfsError::NotEmpty, libc::ENOTEMPTY),
            (FfsError::Exists, libc::EEXIST),
            (FfsError::Cancelled, libc::EINTR),
            (FfsError::MvccConflict { tx: 1, block: 2 }, libc::EAGAIN),
            (
                FfsError::Corruption {
                    block: 0,
                    detail: "bad csum".into(),
                },
                libc::EIO,
            ),
            (FfsError::Format("bad".into()), libc::EINVAL),
            (
                FfsError::UnsupportedFeature("ENCRYPT".into()),
                libc::EOPNOTSUPP,
            ),
            (FfsError::RepairFailed("irrecoverable".into()), libc::EIO),
        ];

        for (error, expected) in &cases {
            let ctx = FuseErrorContext {
                error,
                operation: "test_op",
                ino: 42,
                offset: None,
            };
            assert_eq!(ctx.log_and_errno(), *expected, "wrong errno for {error:?}",);
        }
    }

    #[test]
    fn fuse_error_context_with_offset() {
        let error = FfsError::NotFound("file.txt".into());
        let ctx = FuseErrorContext {
            error: &error,
            operation: "read",
            ino: 100,
            offset: Some(4096),
        };
        assert_eq!(ctx.log_and_errno(), libc::ENOENT);
    }

    // ── Thread safety tests ──────────────────────────────────────────────

    #[test]
    fn franken_fuse_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FrankenFuse>();
        assert_send_sync::<FuseInner>();
        assert_send_sync::<AtomicMetrics>();
    }

    #[test]
    fn mount_options_resolved_thread_count() {
        let mut opts = MountOptions::default();
        assert_eq!(opts.worker_threads, 0);
        // Auto resolution gives at least 1.
        assert!(opts.resolved_thread_count() >= 1);
        assert!(opts.resolved_thread_count() <= 8);

        opts.worker_threads = 4;
        assert_eq!(opts.resolved_thread_count(), 4);
    }

    #[test]
    fn franken_fuse_with_options_sets_thread_count() {
        let opts = MountOptions {
            worker_threads: 6,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(Box::new(StubFs), &opts);
        assert_eq!(fuse.thread_count(), 6);
    }

    #[test]
    fn atomic_metrics_snapshot_initially_zero() {
        let m = AtomicMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.requests_total, 0);
        assert_eq!(s.requests_ok, 0);
        assert_eq!(s.requests_err, 0);
        assert_eq!(s.bytes_read, 0);
    }

    #[test]
    fn atomic_metrics_record_ok_and_err() {
        let m = AtomicMetrics::new();
        m.record_ok();
        m.record_ok();
        m.record_err();
        m.record_bytes_read(1024);
        let s = m.snapshot();
        assert_eq!(s.requests_total, 3);
        assert_eq!(s.requests_ok, 2);
        assert_eq!(s.requests_err, 1);
        assert_eq!(s.bytes_read, 1024);
    }

    #[test]
    fn cache_line_padded_alignment() {
        let padded = CacheLinePadded(AtomicU64::new(0));
        let ptr = std::ptr::addr_of!(padded) as usize;
        // Must be 64-byte aligned.
        assert_eq!(ptr % 64, 0);
    }

    #[test]
    fn request_scope_updates_metrics() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();

        // Successful request.
        let _ = fuse.with_request_scope(&cx, RequestOp::Read, |_cx| Ok::<u32, FfsError>(7));

        let s = fuse.metrics().snapshot();
        assert_eq!(s.requests_total, 1);
        assert_eq!(s.requests_ok, 1);
        assert_eq!(s.requests_err, 0);
    }

    #[test]
    fn request_scope_records_err_metric() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();

        let _ = fuse.with_request_scope(&cx, RequestOp::Read, |_cx| {
            Err::<u32, FfsError>(FfsError::NotFound("gone".into()))
        });

        let s = fuse.metrics().snapshot();
        assert_eq!(s.requests_total, 1);
        assert_eq!(s.requests_ok, 0);
        assert_eq!(s.requests_err, 1);
    }

    #[test]
    fn concurrent_fsops_access_no_deadlock() {
        // Verify FsOps can be called concurrently from multiple threads
        // via Arc<dyn FsOps>.
        let fs: Arc<dyn FsOps> = Arc::new(StubFs);
        let barrier = Arc::new(std::sync::Barrier::new(10));

        std::thread::scope(|s| {
            for _ in 0..10 {
                let fs: Arc<dyn FsOps> = Arc::clone(&fs);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    let cx = Cx::for_testing();
                    barrier.wait();
                    for _ in 0..100 {
                        let _ = fs.getattr(&cx, InodeNumber(1));
                        let _ = fs.readdir(&cx, InodeNumber(1), 0);
                        let _ = fs.read(&cx, InodeNumber(1), 0, 4096);
                    }
                });
            }
        });
    }

    #[test]
    fn concurrent_metrics_stress() {
        // 10 threads x 1000 increments each.
        let metrics = Arc::new(AtomicMetrics::new());
        let barrier = Arc::new(std::sync::Barrier::new(10));

        std::thread::scope(|s| {
            for _ in 0..10 {
                let m = Arc::clone(&metrics);
                let b = Arc::clone(&barrier);
                s.spawn(move || {
                    b.wait();
                    for _ in 0..1000 {
                        m.record_ok();
                        m.record_bytes_read(512);
                    }
                });
            }
        });

        let s = metrics.snapshot();
        assert_eq!(s.requests_total, 10_000);
        assert_eq!(s.requests_ok, 10_000);
        assert_eq!(s.requests_err, 0);
        assert_eq!(s.bytes_read, 10_000 * 512);
    }

    #[test]
    fn fuse_inner_shared_across_threads() {
        // Simulate multi-threaded FUSE dispatch: multiple threads share
        // the same FuseInner via Arc and call FsOps concurrently.
        let inner = Arc::new(FuseInner {
            ops: Arc::new(StubFs),
            metrics: Arc::new(AtomicMetrics::new()),
            thread_count: 4,
            read_only: true,
        });
        let barrier = Arc::new(std::sync::Barrier::new(10));

        std::thread::scope(|s| {
            for _ in 0..10 {
                let inner = Arc::clone(&inner);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    let cx = Cx::for_testing();
                    barrier.wait();
                    for _ in 0..1000 {
                        let _ = inner.ops.getattr(&cx, InodeNumber(2));
                        inner.metrics.record_ok();
                        let _ = inner.ops.read(&cx, InodeNumber(2), 0, 4096);
                        inner.metrics.record_bytes_read(4096);
                    }
                });
            }
        });

        let snap = inner.metrics.snapshot();
        assert_eq!(snap.requests_ok, 10_000);
        assert_eq!(snap.bytes_read, 10_000 * 4096);
    }

    // ── Mount lifecycle tests ─────────────────────────────────────────

    #[test]
    fn mount_config_default_has_30s_timeout() {
        let cfg = MountConfig::default();
        assert_eq!(cfg.unmount_timeout, Duration::from_secs(30));
        assert!(cfg.options.read_only);
    }

    #[test]
    fn mount_managed_rejects_empty_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(StubFs);
        let err = mount_managed(ops, "", &MountConfig::default()).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "expected 'empty' in error: {err}"
        );
    }

    #[test]
    fn mount_managed_rejects_nonexistent_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(StubFs);
        let err = mount_managed(
            ops,
            "/tmp/frankenfs_no_such_dir_xyzzy",
            &MountConfig::default(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "expected 'does not exist' in error: {err}"
        );
    }

    #[test]
    fn mount_handle_shutdown_flag_lifecycle() {
        // Build a MountHandle manually (without a real FUSE session) to
        // exercise the shutdown flag + metrics plumbing.
        let metrics = Arc::new(AtomicMetrics::new());
        metrics.record_ok();
        metrics.record_ok();
        metrics.record_bytes_read(8192);

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/test"),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::clone(&metrics),
            config: MountConfig::default(),
        };

        // Shutdown flag starts false.
        assert!(!handle.shutdown_flag().load(Ordering::Relaxed));

        // Metrics snapshot reflects pre-recorded data.
        let snap = handle.metrics_snapshot();
        assert_eq!(snap.requests_ok, 2);
        assert_eq!(snap.bytes_read, 8192);

        // Unmount returns final snapshot.
        let final_snap = handle.unmount();
        assert_eq!(final_snap.requests_ok, 2);
    }

    #[test]
    fn mount_handle_debug_format() {
        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/dbg"),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(AtomicMetrics::new()),
            config: MountConfig::default(),
        };
        let dbg = format!("{handle:?}");
        assert!(dbg.contains("MountHandle"), "missing struct name: {dbg}");
        assert!(dbg.contains("/mnt/dbg"), "missing mountpoint: {dbg}");
        assert!(dbg.contains("active: false"), "missing active: {dbg}");
        assert!(dbg.contains("shutdown: false"), "missing shutdown: {dbg}");
    }

    #[test]
    fn mount_handle_drop_is_safe_without_session() {
        // Verify that dropping a MountHandle with no session doesn't panic.
        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/drop"),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(AtomicMetrics::new()),
            config: MountConfig::default(),
        };
        drop(handle);
    }

    #[test]
    fn mount_handle_wait_returns_on_shutdown() {
        let metrics = Arc::new(AtomicMetrics::new());
        metrics.record_ok();

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/wait"),
            shutdown: Arc::clone(&shutdown),
            metrics,
            config: MountConfig::default(),
        };

        // Set the shutdown flag from another thread after a short delay.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        let snap = handle.wait();
        assert_eq!(snap.requests_ok, 1);
    }
}
