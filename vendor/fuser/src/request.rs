//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.
//!
//! TODO: This module is meant to go away soon in favor of `ll::Request`.

use crate::ll::{Errno, Response, fuse_abi as abi};
use log::{debug, error, warn};
use std::convert::TryFrom;
use std::io::IoSlice;
#[cfg(feature = "abi-7-40")]
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::Filesystem;
use crate::PollHandle;
use crate::channel::ChannelSender;
use crate::ll::Request as _;
#[cfg(feature = "abi-7-40")]
use crate::passthrough::BackingId;
#[cfg(feature = "abi-7-21")]
use crate::reply::ReplyDirectoryPlus;
use crate::reply::{Reply, ReplyDirectory, ReplySender};
use crate::session::{Session, SessionACL};
use crate::{KernelConfig, ll};

#[derive(Clone)]
enum RequestSender {
    Classic(ChannelSender),
    Shared(Arc<dyn ReplySender>),
}

impl ReplySender for RequestSender {
    fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()> {
        match self {
            Self::Classic(sender) => sender.send(data),
            Self::Shared(sender) => sender.send(data),
        }
    }

    #[cfg(feature = "abi-7-40")]
    fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
        match self {
            Self::Classic(sender) => sender.open_backing(fd),
            Self::Shared(sender) => sender.open_backing(fd),
        }
    }
}

/// Request data structure
pub struct Request<'a> {
    /// Transport used to send this request's reply.
    sender: RequestSender,
    /// Request raw data
    #[allow(unused)]
    data: &'a [u8],
    /// Parsed request
    request: ll::AnyRequest<'a>,
}

/// Per-opcode counts of requests that crossed the FUSE boundary (bd-xfe7z).
///
/// Incremented in [`Request::dispatch`], which is the single point every
/// decoded request passes through BEFORE any filesystem handler, memo, cache or
/// early return can answer it. That placement is the whole point: `ffs-fuse`'s
/// `requests_total` counted request SCOPES and missed 5979 of 6001 warm stats
/// because the capability-probe memo returned before the scope was opened
/// (bdd0fd1b). One device read is one dispatch; anything skippable is not the
/// boundary.
///
/// A process-global because `Request` has no handle to the filesystem's state
/// and one daemon serves one mount. Relaxed ordering: these are read once at
/// the end of a run and order nothing.
///
/// The index order is mirrored by `ffs_fuse::crossings::CrossingOp`, and the two
/// are pinned against each other by a test there -- a silent drift would
/// mislabel every count.
pub static CROSSING_COUNTS: [std::sync::atomic::AtomicU64; CROSSING_SLOTS] =
    [const { std::sync::atomic::AtomicU64::new(0) }; CROSSING_SLOTS];

/// Number of opcode slots, last one being "everything else".
pub const CROSSING_SLOTS: usize = 10;

/// Slot for one operation. Must agree with `CrossingOp::index` in `ffs-fuse`.
fn crossing_slot(op: &ll::Operation<'_>) -> usize {
    match op {
        ll::Operation::Lookup(_) => 0,
        ll::Operation::GetAttr(_) => 1,
        ll::Operation::GetXAttr(_) => 2,
        ll::Operation::ReadDir(_) => 3,
        ll::Operation::ReadDirPlus(_) => 4,
        ll::Operation::Open(_) => 5,
        ll::Operation::OpenDir(_) => 6,
        ll::Operation::Release(_) => 7,
        ll::Operation::ReleaseDir(_) => 8,
        _ => 9,
    }
}

/// Nanoseconds spent in dispatch, per opcode (bd-xfe7z).
///
/// Timed at the SAME boundary the counts are taken at, so "crossings" and
/// "nanoseconds" describe the same events and can be divided by each other
/// without an alignment argument. It measures the whole of what the daemon does
/// for a request -- handler, format layer, reply construction -- because that is
/// what the residue is made of.
///
/// The existing `HandlerTimer` cannot answer this: it is attached to six
/// handlers and `readdirplus` is not one of them, so on a readdir+stat pass it
/// timed 43 invocations out of 260 crossings and missed the handler carrying the
/// cost.
pub static CROSSING_NANOS: [std::sync::atomic::AtomicU64; CROSSING_SLOTS] =
    [const { std::sync::atomic::AtomicU64::new(0) }; CROSSING_SLOTS];

/// Whether to time dispatch at all.
///
/// Read once. `Instant::now()` twice per request is cheap but not free, and this
/// sits on the path whose cost is under investigation -- an instrument that
/// changes the thing it measures by more than it resolves is worse than no
/// instrument. Gated on the same `FFS_MOUNT_BENCH_EVIDENCE` that decides whether
/// the numbers are ever printed, so the default mount pays nothing.
fn dispatch_timing_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("FFS_MOUNT_BENCH_EVIDENCE").is_ok_and(|value| value != "0")
    })
}

/// Accumulates dispatch time on DROP, so no return path can skip it.
///
/// The first version of this timer added the elapsed time after the reply was
/// sent, and `dispatch` has an early `Ok(None) => return` for handlers that
/// answer through their reply object rather than returning a response --
/// `readdirplus` among them. The result: `crossings_readdirplus=209` and
/// `dispatch_ns_readdirplus=0`, a timer that missed exactly the handler it was
/// built to measure.
///
/// That is the bdd0fd1b defect verbatim -- a counter inside a branch that can be
/// skipped -- committed by me two hours after writing the comment warning
/// against it. A guard cannot be forgotten on a path, which is why the
/// `HandlerTimer` in ffs-fuse is also RAII.
struct DispatchTimer {
    slot: usize,
    started: std::time::Instant,
}

impl Drop for DispatchTimer {
    fn drop(&mut self) {
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        CROSSING_NANOS[self.slot].fetch_add(elapsed, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Read the per-opcode dispatch nanoseconds.
#[must_use]
pub fn crossing_nanos() -> [u64; CROSSING_SLOTS] {
    let mut out = [0_u64; CROSSING_SLOTS];
    for (slot, counter) in CROSSING_NANOS.iter().enumerate() {
        out[slot] = counter.load(std::sync::atomic::Ordering::Relaxed);
    }
    out
}

/// Read the counts. Returned by value so a caller cannot hold a reference into
/// live counters while formatting them.
#[must_use]
pub fn crossing_counts() -> [u64; CROSSING_SLOTS] {
    let mut out = [0_u64; CROSSING_SLOTS];
    for (slot, counter) in CROSSING_COUNTS.iter().enumerate() {
        out[slot] = counter.load(std::sync::atomic::Ordering::Relaxed);
    }
    out
}

impl<'a> Request<'a> {
    /// Create a new request from the given data
    pub(crate) fn new(ch: ChannelSender, data: &'a [u8]) -> Option<Request<'a>> {
        Self::parse(RequestSender::Classic(ch), data)
    }

    /// Create a request whose reply uses a non-classic transport.
    pub(crate) fn new_with_sender(
        sender: Arc<dyn ReplySender>,
        data: &'a [u8],
    ) -> Option<Request<'a>> {
        Self::parse(RequestSender::Shared(sender), data)
    }

    fn parse(sender: RequestSender, data: &'a [u8]) -> Option<Request<'a>> {
        let request = match ll::AnyRequest::try_from(data) {
            Ok(request) => request,
            Err(err) => {
                error!("{err}");
                return None;
            }
        };

        Some(Self {
            sender,
            data,
            request,
        })
    }

    /// Whether this request may be dispatched concurrently with other
    /// concurrency-safe requests.
    ///
    /// The set is deliberately narrow: it holds only operations that read
    /// filesystem state and publish nothing. Every mutation, every handle
    /// lifecycle operation (`Open`/`Release`/`Flush`), `Forget` (which retires
    /// inode references a concurrent `Lookup` may be taking) and the session
    /// handshake stay outside it, so they keep the exact whole-session
    /// exclusion the single-threaded loop always gave them.
    pub(crate) fn is_concurrency_safe(&self) -> bool {
        let Ok(operation) = self.request.operation() else {
            return false;
        };
        match operation {
            ll::Operation::Lookup(_)
            | ll::Operation::GetAttr(_)
            | ll::Operation::ReadLink(_)
            | ll::Operation::Read(_)
            | ll::Operation::StatFs(_)
            | ll::Operation::GetXAttr(_)
            | ll::Operation::ListXAttr(_)
            | ll::Operation::ReadDir(_)
            | ll::Operation::Access(_)
            | ll::Operation::BMap(_) => true,
            #[cfg(feature = "abi-7-21")]
            ll::Operation::ReadDirPlus(_) => true,
            #[cfg(feature = "abi-7-24")]
            ll::Operation::Lseek(_) => true,
            #[cfg(feature = "abi-7-40")]
            ll::Operation::Statx(_) => true,
            _ => false,
        }
    }

    /// Dispatch request to the given filesystem.
    /// This calls the appropriate filesystem operation method for the
    /// request and sends back the returned reply to the kernel
    pub(crate) fn dispatch<FS: Filesystem>(&self, se: &mut Session<FS>) {
        debug!("{}", self.request);
        // bd-xfe7z: count the crossing HERE -- before dispatch_req, before any
        // handler, memo, cache or early return. A request that reached this
        // line crossed the boundary regardless of how it is answered.
        let slot = match self.request.operation() {
            Ok(operation) => crossing_slot(&operation),
            Err(_) => CROSSING_SLOTS - 1,
        };
        CROSSING_COUNTS[slot].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Timed around the whole of dispatch, not just the handler: the residue
        // being chased is everything the daemon does per entry, and a timer that
        // stopped at the handler boundary would exclude reply construction.
        let _timer = dispatch_timing_enabled().then(|| DispatchTimer {
            slot,
            started: std::time::Instant::now(),
        });
        let unique = self.request.unique();

        let res = match self.dispatch_req(se) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => self.request.reply_err(errno),
        }
        .with_iovec(unique, |iov| self.sender.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}");
        }
    }

    fn dispatch_req<FS: Filesystem>(
        &self,
        se: &mut Session<FS>,
    ) -> Result<Option<Response<'_>>, Errno> {
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        // Implement allow_root & access check for auto_unmount
        if (se.allowed == SessionACL::RootAndOwner
            && self.request.uid() != se.session_owner
            && self.request.uid() != 0)
            || (se.allowed == SessionACL::Owner && self.request.uid() != se.session_owner)
        {
            #[cfg(feature = "abi-7-21")]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::ReadDirPlus(_)
                    | ll::Operation::BatchForget(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err(Errno::EACCES);
                    }
                }
            }
            #[cfg(not(feature = "abi-7-21"))]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::BatchForget(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err(Errno::EACCES);
                    }
                }
            }
        }
        match op {
            // Filesystem initialization
            ll::Operation::Init(x) => {
                // We don't support ABI versions before 7.6
                let v = x.version();
                if v < ll::Version(7, 6) {
                    error!("Unsupported FUSE ABI version {v}");
                    return Err(Errno::EPROTO);
                }
                // Remember ABI version supported by kernel
                se.proto_major = v.major();
                se.proto_minor = v.minor();

                let mut config = KernelConfig::new(x.capabilities(), x.max_readahead());
                // Call filesystem init method and give it a chance to return an error
                se.filesystem
                    .init(self, &mut config)
                    .map_err(Errno::from_i32)?;

                #[cfg(all(target_os = "linux", feature = "abi-7-42"))]
                if se.io_uring_requested {
                    match config.add_capabilities(abi::consts::FUSE_OVER_IO_URING) {
                        Ok(()) => {
                            let payload_size = se.io_uring_payload_size.max(8 * 1024);
                            let _ = config.set_max_write(payload_size);
                            let _ = config.set_max_readahead(payload_size);
                            se.io_uring_negotiated = true;
                        }
                        Err(missing) => {
                            debug!(
                                "kernel did not offer FUSE-over-io_uring capability {missing:#x}"
                            );
                        }
                    }
                }

                // Reply with our desired version and settings. If the kernel supports a
                // larger major version, it'll re-send a matching init message. If it
                // supports only lower major versions, we replied with an error above.
                debug!(
                    "INIT response: ABI {}.{}, flags {:#x}, max readahead {}, max write {}",
                    abi::FUSE_KERNEL_VERSION,
                    abi::FUSE_KERNEL_MINOR_VERSION,
                    x.capabilities() & config.requested,
                    config.max_readahead,
                    config.max_write
                );
                se.initialized = true;
                return Ok(Some(x.reply(&config)));
            }
            // Any operation is invalid before initialization
            _ if !se.initialized => {
                warn!("Ignoring FUSE operation before init: {}", self.request);
                return Err(Errno::EIO);
            }
            // Filesystem destroyed
            ll::Operation::Destroy(x) => {
                if !se.destroy_called.swap(true, Ordering::AcqRel) {
                    se.filesystem.destroy();
                }
                se.destroyed = true;
                return Ok(Some(x.reply()));
            }
            // Any operation is invalid after destroy
            _ if se.destroy_called.load(Ordering::Acquire) => {
                warn!("Ignoring FUSE operation after destroy: {}", self.request);
                return Err(Errno::EIO);
            }

            ll::Operation::Interrupt(_) => {
                // TODO: handle FUSE_INTERRUPT
                return Err(Errno::ENOSYS);
            }

            ll::Operation::Lookup(x) => {
                se.filesystem.lookup(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::Forget(x) => {
                se.filesystem
                    .forget(self, self.request.nodeid().into(), x.nlookup()); // no reply
            }
            ll::Operation::GetAttr(_attr) => {
                se.filesystem.getattr(
                    self,
                    self.request.nodeid().into(),
                    _attr.file_handle().map(|fh| fh.into()),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-40")]
            ll::Operation::Statx(x) => {
                se.filesystem.statx(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().map(|fh| fh.into()),
                    x.flags(),
                    x.mask(),
                    self.reply(),
                );
            }
            ll::Operation::SetAttr(x) => {
                se.filesystem.setattr(
                    self,
                    self.request.nodeid().into(),
                    x.mode(),
                    x.uid(),
                    x.gid(),
                    x.size(),
                    x.atime(),
                    x.mtime(),
                    x.ctime(),
                    x.file_handle().map(|fh| fh.into()),
                    x.crtime(),
                    x.chgtime(),
                    x.bkuptime(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::ReadLink(_) => {
                se.filesystem
                    .readlink(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::MkNod(x) => {
                se.filesystem.mknod(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.rdev(),
                    self.reply(),
                );
            }
            ll::Operation::MkDir(x) => {
                se.filesystem.mkdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    self.reply(),
                );
            }
            ll::Operation::Unlink(x) => {
                se.filesystem.unlink(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::RmDir(x) => {
                se.filesystem.rmdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::SymLink(x) => {
                se.filesystem.symlink(
                    self,
                    self.request.nodeid().into(),
                    x.link_name().as_ref(),
                    Path::new(x.target()),
                    self.reply(),
                );
            }
            ll::Operation::Rename(x) => {
                se.filesystem.rename(
                    self,
                    self.request.nodeid().into(),
                    x.src().name.as_ref(),
                    x.dest().dir.into(),
                    x.dest().name.as_ref(),
                    0,
                    self.reply(),
                );
            }
            ll::Operation::Link(x) => {
                se.filesystem.link(
                    self,
                    x.inode_no().into(),
                    self.request.nodeid().into(),
                    x.dest().name.as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::Open(x) => {
                se.filesystem
                    .open(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::Read(x) => {
                se.filesystem.read(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.size(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into()),
                    self.reply(),
                );
            }
            ll::Operation::Write(x) => {
                se.filesystem.write(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.data(),
                    x.write_flags(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into()),
                    self.reply(),
                );
            }
            ll::Operation::Flush(x) => {
                se.filesystem.flush(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    self.reply(),
                );
            }
            ll::Operation::Release(x) => {
                se.filesystem.release(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    x.lock_owner().map(|x| x.into()),
                    x.flush(),
                    self.reply(),
                );
            }
            ll::Operation::FSync(x) => {
                se.filesystem.fsync(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::OpenDir(x) => {
                se.filesystem
                    .opendir(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::ReadDir(x) => {
                se.filesystem.readdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectory::new(
                        self.request.unique().into(),
                        self.sender.clone(),
                        x.size() as usize,
                    ),
                );
            }
            ll::Operation::ReleaseDir(x) => {
                se.filesystem.releasedir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::FSyncDir(x) => {
                se.filesystem.fsyncdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::StatFs(_) => {
                se.filesystem
                    .statfs(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::SetXAttr(x) => {
                se.filesystem.setxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.value(),
                    x.flags(),
                    x.position(),
                    self.reply(),
                );
            }
            ll::Operation::GetXAttr(x) => {
                se.filesystem.getxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.size_u32(),
                    self.reply(),
                );
            }
            ll::Operation::ListXAttr(x) => {
                se.filesystem
                    .listxattr(self, self.request.nodeid().into(), x.size(), self.reply());
            }
            ll::Operation::RemoveXAttr(x) => {
                se.filesystem.removexattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    self.reply(),
                );
            }
            ll::Operation::Access(x) => {
                se.filesystem
                    .access(self, self.request.nodeid().into(), x.mask(), self.reply());
            }
            ll::Operation::Create(x) => {
                se.filesystem.create(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::GetLk(x) => {
                se.filesystem.getlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    self.reply(),
                );
            }
            ll::Operation::SetLk(x) => {
                se.filesystem.setlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    false,
                    self.reply(),
                );
            }
            ll::Operation::SetLkW(x) => {
                se.filesystem.setlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    true,
                    self.reply(),
                );
            }
            ll::Operation::BMap(x) => {
                se.filesystem.bmap(
                    self,
                    self.request.nodeid().into(),
                    x.block_size(),
                    x.block(),
                    self.reply(),
                );
            }

            ll::Operation::IoCtl(x) => {
                se.filesystem.ioctl(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    x.command(),
                    x.in_data(),
                    x.out_size(),
                    self.reply(),
                );
            }
            ll::Operation::Poll(x) => {
                let ph = PollHandle::new(se.ch.sender(), x.kernel_handle());

                se.filesystem.poll(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    ph,
                    x.events(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::NotifyReply(_) => {
                // TODO: handle FUSE_NOTIFY_REPLY
                return Err(Errno::ENOSYS);
            }
            ll::Operation::BatchForget(x) => {
                se.filesystem.batch_forget(self, x.nodes()); // no reply
            }
            #[cfg(feature = "abi-7-19")]
            ll::Operation::FAllocate(x) => {
                se.filesystem.fallocate(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.len(),
                    x.mode(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-21")]
            ll::Operation::ReadDirPlus(x) => {
                se.filesystem.readdirplus(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectoryPlus::new(
                        self.request.unique().into(),
                        self.sender.clone(),
                        x.size() as usize,
                    ),
                );
            }
            #[cfg(feature = "abi-7-23")]
            ll::Operation::Rename2(x) => {
                se.filesystem.rename(
                    self,
                    x.from().dir.into(),
                    x.from().name.as_ref(),
                    x.to().dir.into(),
                    x.to().name.as_ref(),
                    x.flags(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-24")]
            ll::Operation::Lseek(x) => {
                se.filesystem.lseek(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.whence(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-28")]
            ll::Operation::CopyFileRange(x) => {
                let (i, o) = (x.src(), x.dest());
                se.filesystem.copy_file_range(
                    self,
                    i.inode.into(),
                    i.file_handle.into(),
                    i.offset,
                    o.inode.into(),
                    o.file_handle.into(),
                    o.offset,
                    x.len(),
                    u32::try_from(x.flags()).unwrap_or(u32::MAX),
                    self.reply(),
                );
            }
            #[cfg(target_os = "macos")]
            ll::Operation::SetVolName(x) => {
                se.filesystem.setvolname(self, x.name(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::GetXTimes(x) => {
                se.filesystem
                    .getxtimes(self, x.nodeid().into(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::Exchange(x) => {
                se.filesystem.exchange(
                    self,
                    x.from().dir.into(),
                    x.from().name.as_ref(),
                    x.to().dir.into(),
                    x.to().name.as_ref(),
                    x.options(),
                    self.reply(),
                );
            }

            ll::Operation::CuseInit(_) => {
                // TODO: handle CUSE_INIT
                return Err(Errno::ENOSYS);
            }
        }
        Ok(None)
    }

    /// Create a reply object for this request that can be passed to the filesystem
    /// implementation and makes sure that a request is replied exactly once
    fn reply<T: Reply>(&self) -> T {
        Reply::new(self.request.unique().into(), self.sender.clone())
    }

    /// Returns the unique identifier of this request
    #[inline]
    pub fn unique(&self) -> u64 {
        self.request.unique().into()
    }

    /// Returns the uid of this request
    #[inline]
    pub fn uid(&self) -> u32 {
        self.request.uid()
    }

    /// Returns the gid of this request
    #[inline]
    pub fn gid(&self) -> u32 {
        self.request.gid()
    }

    /// Returns the pid of this request
    #[inline]
    pub fn pid(&self) -> u32 {
        self.request.pid()
    }
}

impl std::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}
