//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
use log::{info, warn};
use nix::unistd::geteuid;
use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::{io, ops::DerefMut};

use crate::Filesystem;
use crate::MountOption;
use crate::ll::fuse_abi as abi;
use crate::request::Request;
use crate::{channel::Channel, mnt::Mount};
use crate::{channel::ChannelSender, notify::Notifier};

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// Size of the buffer for reading a request from the kernel. Since the kernel may send
/// up to MAX_WRITE_SIZE bytes in a write request, we use that value plus some extra space.
const BUFFER_SIZE: usize = MAX_WRITE_SIZE + 4096;

/// One dispatch-gate slot, padded to its own cache line.
///
/// The padding is the whole point: an unpadded `RwLock<()>` array would put
/// several workers' lock words in one line and reintroduce exactly the
/// coherence traffic this type exists to remove.
#[derive(Debug, Default)]
#[repr(align(64))]
pub(crate) struct DispatchSlot(RwLock<()>);

/// Per-worker dispatch gate — a "big reader" lock (bd-svhrq).
///
/// # Why not one `RwLock`
///
/// The previous gate was a single `RwLock<()>`: every concurrency-safe request
/// on every worker took `read()` on ONE lock word, so N dispatch workers
/// ping-ponged one cache line on the hot path of a metadata workload whose
/// requests are ~100% shared-set. The exclusion the gate provides was never the
/// problem; the shared word was.
///
/// # The replacement, and why it is semantically identical
///
/// One slot per worker. A shared acquisition takes only *its own* worker's
/// slot, so two readers never contend and a reader's lock word is private to
/// its thread. An exclusive acquisition takes *every* slot, so it still
/// excludes every concurrent request exactly as the single lock did:
///
/// * reader ∥ reader — different slots, no interaction (was: same word).
/// * reader ∥ writer — the writer holds that reader's slot, so they exclude.
/// * writer ∥ writer — both take all slots, so they exclude.
///
/// The exclusion SET is unchanged. Only the cost of the common case moved.
///
/// # Deadlock argument
///
/// Writers acquire slots in ascending index order, so two writers cannot form
/// an AB-BA cycle. A reader holds at most one slot and never blocks on a
/// second, so no reader can be part of a cycle either. A writer blocked at
/// slot `i` therefore waits only on readers, which always make progress.
#[derive(Debug)]
pub(crate) struct DispatchGate {
    slots: Box<[DispatchSlot]>,
}

impl DispatchGate {
    /// Build a gate with one slot per dispatch worker (at least one).
    pub(crate) fn new(worker_count: usize) -> Self {
        let slots = (0..worker_count.max(1))
            .map(|_| DispatchSlot::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { slots }
    }

    /// Take this worker's slot shared. Concurrency-safe requests only.
    ///
    /// `worker` is reduced modulo the slot count rather than asserted, because
    /// an out-of-range index must degrade to "shares a slot with someone" — a
    /// performance loss — and never to a missing exclusion.
    fn shared(&self, worker: usize) -> std::sync::RwLockReadGuard<'_, ()> {
        let slot = &self.slots[worker % self.slots.len()];
        slot.0
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Take every slot exclusively, in ascending index order.
    fn exclusive(&self) -> Vec<std::sync::RwLockWriteGuard<'_, ()>> {
        self.slots
            .iter()
            .map(|slot| {
                slot.0
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            })
            .collect()
    }

    /// Number of slots, i.e. the worker count this gate was built for.
    #[cfg(test)]
    pub(crate) fn slot_count(&self) -> usize {
        self.slots.len()
    }
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
/// How requests should be filtered based on the calling UID.
pub enum SessionACL {
    /// Allow requests from any user. Corresponds to the `allow_other` mount option.
    All,
    /// Allow requests from root. Corresponds to the `allow_root` mount option.
    RootAndOwner,
    /// Allow requests from the owning UID. This is FUSE's default mode of operation.
    #[default]
    Owner,
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations
    pub(crate) filesystem: FS,
    /// Communication channel to the kernel driver
    pub(crate) ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: Arc<Mutex<Option<(PathBuf, Mount)>>>,
    /// Whether to restrict access to owner, root + owner, or unrestricted
    /// Used to implement allow_root and auto_unmount
    pub(crate) allowed: SessionACL,
    /// User that launched the fuser process
    pub(crate) session_owner: u32,
    /// FUSE protocol major version
    pub(crate) proto_major: u32,
    /// FUSE protocol minor version
    pub(crate) proto_minor: u32,
    /// True if the filesystem is initialized (init operation done)
    pub(crate) initialized: bool,
    /// True if the filesystem was destroyed (destroy operation done)
    pub(crate) destroyed: bool,
    /// One-shot destroy guard shared by classic and io_uring workers.
    pub(crate) destroy_called: Arc<AtomicBool>,
    /// Only the mount-owning session runs `Filesystem::destroy` from `Drop`.
    destroy_on_drop: bool,
    /// Serialize filesystem callbacks when transport workers are concurrent.
    pub(crate) dispatch_lock: Option<Arc<Mutex<()>>>,
    /// Reader/writer gate used by [`Session::run_with_workers`]: concurrency-safe
    /// requests take it shared, everything else takes it exclusively. `None`
    /// (the default) means single-threaded dispatch and costs nothing.
    pub(crate) dispatch_gate: Option<Arc<DispatchGate>>,
    /// Index of this session clone among the dispatch workers (bd-svhrq).
    ///
    /// Selects which [`DispatchGate`] slot the shared path takes, so two workers
    /// never touch the same lock word on the hot path. The mount-owning session
    /// is worker 0; `run_with_workers` hands out 1..N.
    pub(crate) dispatch_worker: usize,
    /// Request FUSE-over-io_uring during the INIT handshake.
    pub(crate) io_uring_requested: bool,
    /// The kernel accepted FUSE-over-io_uring for this connection.
    pub(crate) io_uring_negotiated: bool,
    /// Payload size advertised by every io_uring queue entry.
    pub(crate) io_uring_payload_size: u32,
}

impl<FS: Filesystem> AsFd for Session<FS> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.ch.as_fd()
    }
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    pub fn new<P: AsRef<Path>>(
        filesystem: FS,
        mountpoint: P,
        options: &[MountOption],
    ) -> io::Result<Session<FS>> {
        let mountpoint = mountpoint.as_ref();
        info!("Mounting {}", mountpoint.display());
        // If AutoUnmount is requested, but not AllowRoot or AllowOther we enforce the ACL
        // ourself and implicitly set AllowOther because fusermount needs allow_root or allow_other
        // to handle the auto_unmount option
        let (file, mount) = if options.contains(&MountOption::AutoUnmount)
            && !(options.contains(&MountOption::AllowRoot)
                || options.contains(&MountOption::AllowOther))
        {
            warn!(
                "Given auto_unmount without allow_root or allow_other; adding allow_other, with userspace permission handling"
            );
            let mut modified_options = options.to_vec();
            modified_options.push(MountOption::AllowOther);
            Mount::new(mountpoint, &modified_options)?
        } else {
            Mount::new(mountpoint, options)?
        };

        let ch = Channel::new(file);
        let allowed = if options.contains(&MountOption::AllowRoot) {
            SessionACL::RootAndOwner
        } else if options.contains(&MountOption::AllowOther) {
            SessionACL::All
        } else {
            SessionACL::Owner
        };

        Ok(Session {
            filesystem,
            ch,
            mount: Arc::new(Mutex::new(Some((mountpoint.to_owned(), mount)))),
            allowed,
            session_owner: geteuid().as_raw(),
            proto_major: 0,
            proto_minor: 0,
            initialized: false,
            destroyed: false,
            destroy_called: Arc::new(AtomicBool::new(false)),
            destroy_on_drop: true,
            dispatch_lock: None,
            dispatch_gate: None,
            dispatch_worker: 0,
            io_uring_requested: false,
            io_uring_negotiated: false,
            io_uring_payload_size: 0,
        })
    }

    /// Wrap an existing /dev/fuse file descriptor. This doesn't mount the
    /// filesystem anywhere; that must be done separately.
    pub fn from_fd(filesystem: FS, fd: OwnedFd, acl: SessionACL) -> Self {
        let ch = Channel::new(Arc::new(fd.into()));
        Session {
            filesystem,
            ch,
            mount: Arc::new(Mutex::new(None)),
            allowed: acl,
            session_owner: geteuid().as_raw(),
            proto_major: 0,
            proto_minor: 0,
            initialized: false,
            destroyed: false,
            destroy_called: Arc::new(AtomicBool::new(false)),
            destroy_on_drop: true,
            dispatch_lock: None,
            dispatch_gate: None,
            dispatch_worker: 0,
            io_uring_requested: false,
            io_uring_negotiated: false,
            io_uring_payload_size: 0,
        }
    }

    fn dispatch_request(&mut self, req: &Request<'_>) {
        let dispatch_lock = self.dispatch_lock.clone();
        if let Some(lock) = dispatch_lock {
            let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            return req.dispatch(self);
        }
        let dispatch_gate = self.dispatch_gate.clone();
        let Some(gate) = dispatch_gate else {
            return req.dispatch(self);
        };
        if req.is_concurrency_safe() {
            let _shared = gate.shared(self.dispatch_worker);
            req.dispatch(self);
        } else {
            let _exclusive = gate.exclusive();
            req.dispatch(self);
        }
    }

    fn dispatch_next(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        match self.ch.receive(buf) {
            Ok(size) => match Request::new(self.ch.sender(), &buf[..size]) {
                Some(req) => {
                    self.dispatch_request(&req);
                    Ok(true)
                }
                None => Ok(false),
            },
            Err(err) => match err.raw_os_error() {
                Some(ENOENT | EINTR | EAGAIN) => Ok(true),
                Some(ENODEV) => Ok(false),
                _ => Err(err),
            },
        }
    }

    pub(crate) fn run_classic_loop(&mut self, buf: &mut [u8]) -> io::Result<()> {
        while self.dispatch_next(buf)? {}
        Ok(())
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    pub fn run(&mut self) -> io::Result<()> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buffer = vec![0; BUFFER_SIZE];
        let buf = aligned_sub_buf(
            buffer.deref_mut(),
            std::mem::align_of::<abi::fuse_in_header>(),
        );
        self.run_classic_loop(buf)
    }

    /// Run the session loop on `worker_count` concurrent dispatch threads.
    ///
    /// Every worker reads from the same `/dev/fuse` fd — the kernel hands each
    /// blocked reader a different pending request — so `worker_count` requests
    /// can be in flight at once instead of one. Requests are still ordered
    /// against each other by [`Session::dispatch_request`]'s reader/writer
    /// gate: concurrency-safe reads run in parallel, and everything else keeps
    /// the whole-session exclusion of the single-threaded loop. The gate is
    /// per-worker ([`DispatchGate`]), so the shared path costs each worker one
    /// uncontended lock on a private cache line rather than a shared word.
    ///
    /// INIT is always handled on this thread before any worker starts, so the
    /// worker clones inherit a fully negotiated session.
    pub fn run_with_workers(&mut self, worker_count: usize) -> io::Result<()>
    where
        FS: Clone + Send,
    {
        let mut buffer = vec![0; BUFFER_SIZE];
        let buf = aligned_sub_buf(
            buffer.deref_mut(),
            std::mem::align_of::<abi::fuse_in_header>(),
        );
        if worker_count <= 1 {
            return self.run_classic_loop(buf);
        }
        while !self.initialized {
            if !self.dispatch_next(buf)? {
                return Ok(());
            }
        }

        self.dispatch_gate = Some(Arc::new(DispatchGate::new(worker_count)));
        self.dispatch_worker = 0;
        info!("FUSE dispatch workers: {worker_count}");
        thread::scope(|scope| {
            let mut workers = Vec::with_capacity(worker_count - 1);
            for index in 1..worker_count {
                let mut worker = self.worker_clone(index);
                workers.push(
                    thread::Builder::new()
                        .name(format!("fuse-dispatch-{index}"))
                        .spawn_scoped(scope, move || {
                            let mut worker_buffer = vec![0; BUFFER_SIZE];
                            let worker_buf = aligned_sub_buf(
                                worker_buffer.deref_mut(),
                                std::mem::align_of::<abi::fuse_in_header>(),
                            );
                            worker.run_classic_loop(worker_buf)
                        })?,
                );
            }
            let primary = self.run_classic_loop(buf);
            for worker in workers {
                match worker.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => warn!("FUSE dispatch worker failed: {error}"),
                    Err(_) => warn!("FUSE dispatch worker panicked"),
                }
            }
            primary
        })
    }

    /// A handle onto the same connection and filesystem for a dispatch worker.
    ///
    /// The clone must never run `Filesystem::destroy` from `Drop` and must never
    /// own the mount: both belong to the session that created the connection.
    fn worker_clone(&self, dispatch_worker: usize) -> Self
    where
        FS: Clone,
    {
        Self {
            filesystem: self.filesystem.clone(),
            ch: self.ch.clone(),
            mount: Arc::new(Mutex::new(None)),
            allowed: self.allowed,
            session_owner: self.session_owner,
            proto_major: self.proto_major,
            proto_minor: self.proto_minor,
            initialized: self.initialized,
            destroyed: self.destroyed,
            destroy_called: Arc::clone(&self.destroy_called),
            destroy_on_drop: false,
            dispatch_lock: self.dispatch_lock.clone(),
            dispatch_gate: self.dispatch_gate.clone(),
            dispatch_worker,
            io_uring_requested: self.io_uring_requested,
            io_uring_negotiated: self.io_uring_negotiated,
            io_uring_payload_size: self.io_uring_payload_size,
        }
    }

    /// Run a hybrid classic/io_uring session on Linux.
    ///
    /// INIT, interrupts, and notifications retain the classic `/dev/fuse`
    /// channel. Once the kernel accepts `FUSE_OVER_IO_URING`, normal requests
    /// use per-CPU rings. If the capability is unavailable, this falls back to
    /// the classic loop without changing request semantics.
    #[cfg(target_os = "linux")]
    pub fn run_with_io_uring(&mut self, queue_depth: usize, payload_size: u32) -> io::Result<()>
    where
        FS: Clone + Send,
    {
        self.io_uring_requested = true;
        self.io_uring_payload_size = payload_size;

        let mut buffer = vec![0; BUFFER_SIZE];
        let buf = aligned_sub_buf(
            buffer.deref_mut(),
            std::mem::align_of::<abi::fuse_in_header>(),
        );
        while !self.initialized {
            if !self.dispatch_next(buf)? {
                return Ok(());
            }
        }

        if !self.io_uring_negotiated {
            warn!("kernel declined FUSE-over-io_uring; using classic transport");
            return self.run_classic_loop(buf);
        }

        self.dispatch_lock = Some(Arc::new(Mutex::new(())));
        crate::io_uring::run_hybrid(self, queue_depth, payload_size, buf)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn ring_worker_clone(&self) -> Self
    where
        FS: Clone,
    {
        Self {
            filesystem: self.filesystem.clone(),
            ch: self.ch.clone(),
            mount: Arc::new(Mutex::new(None)),
            allowed: self.allowed,
            session_owner: self.session_owner,
            proto_major: self.proto_major,
            proto_minor: self.proto_minor,
            initialized: self.initialized,
            destroyed: self.destroyed,
            destroy_called: Arc::clone(&self.destroy_called),
            destroy_on_drop: false,
            dispatch_lock: self.dispatch_lock.clone(),
            dispatch_gate: self.dispatch_gate.clone(),
            dispatch_worker: self.dispatch_worker,
            io_uring_requested: self.io_uring_requested,
            io_uring_negotiated: self.io_uring_negotiated,
            io_uring_payload_size: self.io_uring_payload_size,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn dispatch_ring_request(&mut self, req: &Request<'_>) {
        self.dispatch_request(req);
    }

    /// Unmount the filesystem
    pub fn unmount(&mut self) {
        drop(std::mem::take(&mut *self.mount.lock().unwrap()));
    }

    /// Returns a thread-safe object that can be used to unmount the Filesystem
    pub fn unmount_callable(&mut self) -> SessionUnmounter {
        SessionUnmounter {
            mount: self.mount.clone(),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.ch.sender())
    }
}

#[derive(Clone, Debug)]
/// A thread-safe object that can be used to unmount a Filesystem
pub struct SessionUnmounter {
    mount: Arc<Mutex<Option<(PathBuf, Mount)>>>,
}

impl SessionUnmounter {
    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        drop(std::mem::take(&mut *self.mount.lock().unwrap()));
        Ok(())
    }
}

fn aligned_sub_buf(buf: &mut [u8], alignment: usize) -> &mut [u8] {
    let off = alignment - (buf.as_ptr() as usize) % alignment;
    if off == alignment {
        buf
    } else {
        &mut buf[off..]
    }
}

impl<FS: 'static + Filesystem + Send> Session<FS> {
    /// Run the session loop in a background thread
    pub fn spawn(self) -> io::Result<BackgroundSession> {
        BackgroundSession::new(self)
    }
}

impl<FS: Filesystem> Drop for Session<FS> {
    fn drop(&mut self) {
        if self.destroy_on_drop && !self.destroy_called.swap(true, Ordering::AcqRel) {
            self.filesystem.destroy();
            self.destroyed = true;
        }

        if let Some((mountpoint, _mount)) = std::mem::take(&mut *self.mount.lock().unwrap()) {
            info!("unmounting session at {}", mountpoint.display());
        }
    }
}

/// The background session data structure
pub struct BackgroundSession {
    /// Thread guard of the background session
    pub guard: JoinHandle<io::Result<()>>,
    /// Object for creating Notifiers for client use
    sender: ChannelSender,
    /// Ensures the filesystem is unmounted when the session ends
    _mount: Option<Mount>,
}

impl BackgroundSession {
    /// Create a new background session for the given session by running its
    /// session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub fn new<FS: Filesystem + Send + 'static>(se: Session<FS>) -> io::Result<BackgroundSession> {
        let sender = se.ch.sender();
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut *se.mount.lock().unwrap()).map(|(_, mount)| mount);
        let guard = thread::spawn(move || {
            let mut se = se;
            se.run()
        });
        Ok(BackgroundSession {
            guard,
            sender,
            _mount: mount,
        })
    }

    /// Like [`BackgroundSession::new`], but dispatches on `worker_count`
    /// concurrent threads (see [`Session::run_with_workers`]). A count of 1 is
    /// the historical single-threaded loop.
    pub fn new_with_workers<FS: Filesystem + Clone + Send + 'static>(
        se: Session<FS>,
        worker_count: usize,
    ) -> io::Result<BackgroundSession> {
        let sender = se.ch.sender();
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut *se.mount.lock().unwrap()).map(|(_, mount)| mount);
        let guard = thread::spawn(move || {
            let mut se = se;
            se.run_with_workers(worker_count)
        });
        Ok(BackgroundSession {
            guard,
            sender,
            _mount: mount,
        })
    }
    /// Unmount the filesystem and join the background thread.
    pub fn join(self) {
        let Self {
            guard,
            sender: _,
            _mount,
        } = self;
        drop(_mount);
        guard.join().unwrap().unwrap();
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.sender.clone())
    }
}

// replace with #[derive(Debug)] if Debug ever gets implemented for
// thread_scoped::JoinGuard
impl fmt::Debug for BackgroundSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "BackgroundSession {{ guard: JoinGuard<()> }}",)
    }
}

#[cfg(test)]
mod dispatch_gate_tests {
    use super::DispatchGate;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[test]
    fn gate_has_one_slot_per_worker_and_never_zero() {
        assert_eq!(DispatchGate::new(8).slot_count(), 8);
        assert_eq!(DispatchGate::new(1).slot_count(), 1);
        // A zero worker count must still produce a usable gate: `shared` indexes
        // modulo the slot count and would panic on an empty slice.
        assert_eq!(DispatchGate::new(0).slot_count(), 1);
    }

    #[test]
    fn two_workers_take_the_shared_path_at_the_same_time() {
        // The whole point of the per-worker gate: readers on distinct workers
        // must not exclude each other. A single `RwLock` also passes this (read
        // locks are shared), so this is the baseline, not the discriminator.
        let gate = DispatchGate::new(2);
        let first = gate.shared(0);
        let second = gate.shared(1);
        drop((first, second));
    }

    #[test]
    fn exclusive_still_excludes_every_worker_slot() {
        // THE NEGATIVE CASE. A naive per-worker gate that made `exclusive` take
        // only the caller's own slot would leave every other worker running
        // concurrently with a mutation — the exact bug this shape invites. Hold
        // the exclusive guard, then prove from another thread that a shared
        // acquisition on a DIFFERENT worker index cannot complete.
        let gate = Arc::new(DispatchGate::new(4));
        let entered = Arc::new(AtomicBool::new(false));
        let guards = gate.exclusive();

        let handle = {
            let gate = Arc::clone(&gate);
            let entered = Arc::clone(&entered);
            std::thread::spawn(move || {
                let held = gate.shared(3);
                entered.store(true, Ordering::SeqCst);
                drop(held);
            })
        };

        // Give the spawned thread a real chance to acquire if the gate is broken.
        let deadline = Instant::now() + Duration::from_millis(250);
        while Instant::now() < deadline {
            assert!(
                !entered.load(Ordering::SeqCst),
                "a shared acquisition on worker 3 completed while an exclusive \
                 guard was held: exclusive() is not covering every slot"
            );
            std::thread::yield_now();
        }

        drop(guards);
        handle.join().expect("shared waiter panicked");
        assert!(
            entered.load(Ordering::SeqCst),
            "the shared waiter never made progress after the exclusive guard was released"
        );
    }

    #[test]
    fn concurrent_writers_do_not_deadlock_against_concurrent_readers() {
        // Writers take all slots in ascending order and readers take exactly one,
        // so no cycle is possible. Exercised under contention with a watchdog:
        // an ordering mistake here hangs a mount rather than slowing it.
        let gate = Arc::new(DispatchGate::new(4));
        let writes = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for worker in 0..4 {
            let gate = Arc::clone(&gate);
            let reads = Arc::clone(&reads);
            handles.push(std::thread::spawn(move || {
                for _ in 0..2_000 {
                    let held = gate.shared(worker);
                    reads.fetch_add(1, Ordering::Relaxed);
                    drop(held);
                }
            }));
        }
        for _ in 0..2 {
            let gate = Arc::clone(&gate);
            let writes = Arc::clone(&writes);
            handles.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    let held = gate.exclusive();
                    writes.fetch_add(1, Ordering::Relaxed);
                    drop(held);
                }
            }));
        }

        let deadline = Instant::now() + Duration::from_secs(30);
        for handle in handles {
            assert!(
                Instant::now() < deadline,
                "dispatch gate contention exceeded its watchdog: suspect a lock cycle"
            );
            handle.join().expect("gate contender panicked");
        }
        assert_eq!(reads.load(Ordering::Relaxed), 8_000);
        assert_eq!(writes.load(Ordering::Relaxed), 1_000);
    }

    #[test]
    fn an_out_of_range_worker_index_shares_a_slot_rather_than_panicking() {
        // Degrades to contention, never to a missing exclusion.
        let gate = DispatchGate::new(2);
        let held = gate.shared(9);
        drop(held);
    }
}
