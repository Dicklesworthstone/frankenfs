//! Protocol and dispatch integration without requiring a privileged mount.

use super::*;
use crate::ll::test::AlignedData;
use crate::{ReplyData, ReplySender, ReplyWrite, RequestInterrupt};
use std::io::IoSlice;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

#[derive(Default)]
struct Wire {
    replies: Mutex<Vec<Vec<u8>>>,
    fail: AtomicBool,
}

impl ReplySender for Wire {
    fn send(&self, data: &[IoSlice<'_>]) -> io::Result<()> {
        if self.fail.load(Ordering::Acquire) {
            return Err(io::Error::other("injected reply failure"));
        }
        self.replies
            .lock()
            .unwrap()
            .push(data.iter().flat_map(|part| part.iter().copied()).collect());
        Ok(())
    }

    #[cfg(feature = "abi-7-40")]
    fn open_backing(&self, _fd: BorrowedFd<'_>) -> io::Result<crate::BackingId> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "test transport"))
    }
}

#[derive(Clone, Default)]
struct DeferredFs {
    reply: Arc<Mutex<Option<ReplyData>>>,
    token: Arc<Mutex<Option<RequestInterrupt>>>,
    notifications: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}

impl Filesystem for DeferredFs {
    fn read(
        &mut self,
        request: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        _size: u32,
        _flags: i32,
        _owner: Option<u64>,
        reply: ReplyData,
    ) {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let token = crate::current_read_request_interrupt().expect("read context installed");
        assert_eq!(token.unique(), request.unique());
        let notifications = Arc::clone(&self.notifications);
        request.on_interrupt(move || {
            notifications.fetch_add(1, Ordering::SeqCst);
        });
        *self.token.lock().unwrap() = Some(token);
        *self.reply.lock().unwrap() = Some(reply);
    }

    fn write(
        &mut self,
        _request: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        assert!(crate::current_read_request_interrupt().is_none());
        self.writes.fetch_add(1, Ordering::SeqCst);
        reply.written(u32::try_from(data.len()).unwrap());
    }
}

fn session() -> (Session<DeferredFs>, Arc<Wire>) {
    let fd = std::fs::File::open("/dev/null").unwrap();
    let mut session = Session::from_fd(DeferredFs::default(), fd.into(), SessionACL::All);
    session.initialized = true;
    (session, Arc::new(Wire::default()))
}

fn packet(opcode: u32, unique: u64, payload: &[u8]) -> AlignedData<[u8; 256]> {
    let mut bytes = AlignedData([0_u8; 256]);
    let header = std::mem::size_of::<abi::fuse_in_header>();
    let len = header + payload.len();
    bytes[0..4].copy_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
    bytes[4..8].copy_from_slice(&opcode.to_ne_bytes());
    bytes[8..16].copy_from_slice(&unique.to_ne_bytes());
    bytes[16..24].copy_from_slice(&1_u64.to_ne_bytes());
    bytes[header..len].copy_from_slice(payload);
    bytes
}

fn dispatch(session: &mut Session<DeferredFs>, wire: &Arc<Wire>, bytes: &[u8]) {
    let len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let sender: Arc<dyn ReplySender> = wire.clone();
    let request = Request::new_with_sender(sender, &bytes[..len]).expect("valid wire request");
    session.dispatch_request(&request);
}

fn read_packet(unique: u64) -> AlignedData<[u8; 256]> {
    let mut payload = [0_u8; std::mem::size_of::<abi::fuse_read_in>()];
    payload[16..20].copy_from_slice(&8_u32.to_ne_bytes());
    packet(15, unique, &payload) // FUSE_READ
}

fn interrupt_packet(unique: u64, target: u64) -> AlignedData<[u8; 256]> {
    packet(36, unique, &target.to_ne_bytes()) // FUSE_INTERRUPT
}

fn reply_header(bytes: &[u8]) -> (u64, i32) {
    (
        u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        i32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
    )
}

#[test]
fn deferred_reply_retains_tracking_and_interrupt_has_no_success_ack() {
    let (mut session, wire) = session();
    dispatch(&mut session, &wire, &read_packet(7)[..]);
    assert!(crate::current_read_request_interrupt().is_none());
    assert!(wire.replies.lock().unwrap().is_empty());
    dispatch(&mut session, &wire, &interrupt_packet(101, 7)[..]);
    dispatch(&mut session, &wire, &interrupt_packet(102, 7)[..]);
    assert_eq!(session.filesystem.notifications.load(Ordering::SeqCst), 1);
    assert!(wire.replies.lock().unwrap().is_empty());
    session
        .filesystem
        .reply
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .error(EINTR);
    assert_eq!(reply_header(&wire.replies.lock().unwrap()[0]), (7, -EINTR));
    assert!(!session.interrupts.interrupt(7));
    dispatch(&mut session, &wire, &interrupt_packet(103, 7)[..]);
    assert_eq!(reply_header(&wire.replies.lock().unwrap()[1]), (103, -EAGAIN));
}

#[test]
fn early_interrupt_requests_retry_and_then_targets_the_original() {
    let (mut session, wire) = session();
    dispatch(&mut session, &wire, &interrupt_packet(100, 7)[..]);
    assert_eq!(reply_header(&wire.replies.lock().unwrap()[0]), (100, -EAGAIN));
    dispatch(&mut session, &wire, &read_packet(7)[..]);
    dispatch(&mut session, &wire, &interrupt_packet(101, 7)[..]);
    assert_eq!(session.filesystem.notifications.load(Ordering::SeqCst), 1);
    // The callback may ignore cancellation and return its actual result.
    session
        .filesystem
        .reply
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .data(b"ok");
    let replies = wire.replies.lock().unwrap();
    assert_eq!(replies.len(), 2);
    assert_eq!(reply_header(&replies[1]), (7, 0));
    assert_eq!(&replies[1][16..], b"ok");
}

#[test]
fn abandoned_or_failed_original_replies_release_registration() {
    for fail_send in [false, true] {
        let (mut session, wire) = session();
        dispatch(&mut session, &wire, &read_packet(7)[..]);
        wire.fail.store(fail_send, Ordering::Release);
        drop(session.filesystem.reply.lock().unwrap().take());
        assert!(!session.interrupts.interrupt(7));
        // The mock still holds a token; completion, not its destruction,
        // removed the lookup. A retained handle must not keep it cancellable.
        assert!(session.filesystem.token.lock().unwrap().is_some());
        if !fail_send {
            assert_eq!(reply_header(&wire.replies.lock().unwrap()[0]), (7, -libc::EIO));
        }
    }
}

#[test]
fn interrupt_bypasses_both_kinds_of_dispatch_barrier() {
    for serialized in [false, true] {
        let (mut session, wire) = session();
        dispatch(&mut session, &wire, &read_packet(7)[..]);
        let gate = Arc::new(DispatchGate::new(2));
        let lock = Arc::new(Mutex::new(()));
        session.dispatch_gate = Some(Arc::clone(&gate));
        if serialized {
            session.dispatch_lock = Some(Arc::clone(&lock));
        }
        let mut worker = session.worker_clone(1);
        let exclusive = gate.exclusive();
        let serial = lock.lock().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker_wire = Arc::clone(&wire);
        let worker = std::thread::spawn(move || {
            dispatch(&mut worker, &worker_wire, &interrupt_packet(100, 7)[..]);
            done_tx.send(()).unwrap();
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(2));
        // Release before joining/asserting so a regression reports a failure
        // rather than leaving a permanently stuck test worker.
        drop(serial);
        drop(exclusive);
        worker.join().unwrap();
        completed.expect("interrupt must run while the original's barriers are held");
        assert_eq!(session.filesystem.notifications.load(Ordering::SeqCst), 1);
        session
            .filesystem
            .reply
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .error(EINTR);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn ring_clone_and_classic_control_path_share_request_registration() {
    let (session, wire) = session();
    let mut ring = session.ring_worker_clone();
    let mut control = session.worker_clone(0);
    dispatch(&mut ring, &wire, &read_packet(7)[..]);
    dispatch(&mut control, &wire, &interrupt_packet(100, 7)[..]);
    assert_eq!(session.filesystem.notifications.load(Ordering::SeqCst), 1);
    session
        .filesystem
        .reply
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .error(EINTR);
    assert!(!ring.interrupts.interrupt(7));
}

#[test]
fn completed_mutation_result_is_not_rewritten_as_interrupted() {
    let (mut session, wire) = session();
    let mut payload = vec![0_u8; std::mem::size_of::<abi::fuse_write_in>()];
    payload[16..20].copy_from_slice(&3_u32.to_ne_bytes());
    payload.extend_from_slice(b"abc");
    let bytes = packet(16, 9, &payload);
    let len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let sender: Arc<dyn ReplySender> = wire.clone();
    let request = Request::new_with_sender(sender, &bytes[..len]).unwrap();
    assert!(request.register_interrupt(&session.interrupts));
    assert!(session.interrupts.interrupt(9));
    // Even an interrupt received before the callback must not opt a write
    // into the read-only context bridge.
    session.dispatch_request(&request);
    dispatch(&mut session, &wire, &interrupt_packet(100, 9)[..]);
    let replies = wire.replies.lock().unwrap();
    assert_eq!(session.filesystem.writes.load(Ordering::SeqCst), 1);
    assert_eq!(reply_header(&replies[0]), (9, 0));
    assert_eq!(u32::from_ne_bytes(replies[0][16..20].try_into().unwrap()), 3);
    assert_eq!(reply_header(&replies[1]), (100, -EAGAIN));
}

#[test]
fn no_reply_forget_does_not_leave_an_outstanding_registration() {
    let (mut session, wire) = session();
    dispatch(&mut session, &wire, &packet(2, 17, &1_u64.to_ne_bytes())[..]);
    assert!(!session.interrupts.interrupt(17));
    assert!(wire.replies.lock().unwrap().is_empty());
}

#[test]
fn duplicate_wire_request_does_not_execute_the_handler_twice() {
    let (mut session, wire) = session();
    dispatch(&mut session, &wire, &read_packet(7)[..]);
    dispatch(&mut session, &wire, &read_packet(7)[..]);
    assert_eq!(session.filesystem.reads.load(Ordering::SeqCst), 1);
    dispatch(&mut session, &wire, &interrupt_packet(100, 7)[..]);
    assert_eq!(session.filesystem.notifications.load(Ordering::SeqCst), 1);
    session
        .filesystem
        .reply
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .error(EINTR);
    assert_eq!(wire.replies.lock().unwrap().len(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn per_core_receiver_dispatches_interrupt_without_enqueuing_it() {
    let (socket, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let mut session = Session::from_fd(DeferredFs::default(), socket.into(), SessionACL::All);
    session.initialized = true;
    let scheduler = Arc::new(PerCoreScheduler::new(1));
    session.per_core_scheduler = Some(Arc::clone(&scheduler));
    let wire = Arc::new(Wire::default());
    dispatch(&mut session, &wire, &read_packet(7)[..]);
    let bytes = interrupt_packet(100, 7);
    let len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap()) as usize;
    peer.send(&bytes[..len]).unwrap();
    let mut buffer = AlignedData([0_u8; 1024]);
    assert!(session.dispatch_next_per_core(&mut buffer[..]).unwrap());
    assert_eq!(session.filesystem.notifications.load(Ordering::SeqCst), 1);
    assert!(scheduler.pop_local(0).is_none());
    session
        .filesystem
        .reply
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .error(EINTR);
}
