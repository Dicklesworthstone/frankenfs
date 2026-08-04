//! Linux FUSE-over-io_uring transport.
//!
//! The kernel interface is hybrid: INIT, interrupts, and notifications keep
//! using `/dev/fuse`, while normal requests are delivered through one io_uring
//! queue per possible CPU.  Every queue entry owns stable header and payload
//! buffers until the kernel completes the command.

use io_uring::{IoUring, opcode, squeue, types};
use libc::{EAGAIN, EINTR, ENOTCONN};
use log::warn;
use std::io::{self, IoSlice};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(feature = "abi-7-40")]
use std::os::fd::BorrowedFd;

use crate::Filesystem;
use crate::channel::ChannelSender;
use crate::ll::fuse_abi as abi;
#[cfg(feature = "abi-7-40")]
use crate::passthrough::BackingId;
use crate::reply::ReplySender;
use crate::request::Request;
use crate::session::{Session, SessionUnmounter};

const FUSE_URING_HEADER_SIZE: usize = 128;
const FUSE_URING_OP_HEADER_SIZE: usize = 128;
const FUSE_URING_RING_ENTRY_OFFSET: usize = FUSE_URING_HEADER_SIZE + FUSE_URING_OP_HEADER_SIZE;
const FUSE_URING_RING_ENTRY_SIZE: usize = 32;
const FUSE_URING_COMMIT_ID_OFFSET: usize = FUSE_URING_RING_ENTRY_OFFSET + 8;
const FUSE_URING_PAYLOAD_SIZE_OFFSET: usize = FUSE_URING_RING_ENTRY_OFFSET + 16;
const FUSE_URING_HEADERS_SIZE: usize = FUSE_URING_RING_ENTRY_OFFSET + FUSE_URING_RING_ENTRY_SIZE;
const FUSE_IO_URING_CMD_REGISTER: u32 = 1;
const FUSE_IO_URING_CMD_COMMIT_AND_FETCH: u32 = 2;
const EVENT_TOKEN: u64 = u64::MAX;

#[derive(Debug)]
struct PageAlignedBuffer {
    storage: Vec<u8>,
    offset: usize,
    len: usize,
}

impl PageAlignedBuffer {
    fn new(len: usize) -> Self {
        let page_size = page_size::get();
        let storage = vec![0; len + page_size];
        let remainder = storage.as_ptr() as usize % page_size;
        let offset = if remainder == 0 {
            0
        } else {
            page_size - remainder
        };
        Self {
            storage,
            offset,
            len,
        }
    }
}

impl Deref for PageAlignedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.storage[self.offset..self.offset + self.len]
    }
}

impl DerefMut for PageAlignedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.storage[self.offset..self.offset + self.len]
    }
}

#[derive(Debug)]
struct RingBuffers {
    headers: PageAlignedBuffer,
    payload: PageAlignedBuffer,
}

impl RingBuffers {
    fn new(payload_size: usize) -> Self {
        Self {
            headers: PageAlignedBuffer::new(FUSE_URING_HEADERS_SIZE),
            payload: PageAlignedBuffer::new(payload_size),
        }
    }
}

struct RingSlot {
    buffers: Mutex<RingBuffers>,
    iovecs: Box<[libc::iovec; 2]>,
}

// SAFETY: the raw pointers in `iovecs` point into the two Vec allocations in
// `buffers`, whose allocations never move. The state machine accesses those
// buffers only after a CQE transfers ownership from the kernel and before the
// next SQE transfers it back. `buffers` serializes userspace access.
unsafe impl Send for RingSlot {}
// SAFETY: see the `Send` proof above; shared userspace access is mutex-guarded.
unsafe impl Sync for RingSlot {}

impl RingSlot {
    fn new(payload_size: usize) -> Self {
        let mut buffers = RingBuffers::new(payload_size);
        let iovecs = Box::new([
            libc::iovec {
                iov_base: buffers.headers.as_mut_ptr().cast(),
                iov_len: buffers.headers.len(),
            },
            libc::iovec {
                iov_base: buffers.payload.as_mut_ptr().cast(),
                iov_len: buffers.payload.len(),
            },
        ]);
        Self {
            buffers: Mutex::new(buffers),
            iovecs,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum PendingCommand {
    Register,
    Commit(u64),
}

#[derive(Debug)]
struct Commit {
    slot: usize,
    commit_id: u64,
}

#[derive(Clone)]
struct EventFd(Arc<OwnedFd>);

impl EventFd {
    fn new() -> io::Result<Self> {
        // SAFETY: `eventfd` returns a new owned descriptor on success.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ownership of the newly-created descriptor transfers here.
        Ok(Self(Arc::new(unsafe { OwnedFd::from_raw_fd(fd) })))
    }

    fn signal(&self) -> io::Result<()> {
        let value = 1_u64.to_ne_bytes();
        // SAFETY: the pointer names all eight bytes of `value`; eventfd accepts
        // exactly one u64 and does not retain the pointer.
        let rc = unsafe {
            libc::write(
                self.0.as_ref().as_raw_fd(),
                value.as_ptr().cast(),
                value.len(),
            )
        };
        if rc == value.len() as isize {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(EAGAIN) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn drain(&self) -> io::Result<()> {
        let mut value = [0_u8; 8];
        loop {
            // SAFETY: the pointer names the writable eight-byte array and the
            // kernel does not retain it after `read` returns.
            let rc = unsafe {
                libc::read(
                    self.0.as_ref().as_raw_fd(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            if rc == value.len() as isize {
                continue;
            }
            if rc == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(EAGAIN) {
                return Ok(());
            }
            return Err(error);
        }
    }

    fn raw_fd(&self) -> i32 {
        self.0.as_ref().as_raw_fd()
    }
}

#[derive(Clone)]
struct RingReplySender {
    slot_index: usize,
    slot: Arc<RingSlot>,
    commit_id: u64,
    commits: Sender<Commit>,
    eventfd: EventFd,
    classic: ChannelSender,
}

impl ReplySender for RingReplySender {
    fn send(&self, data: &[IoSlice<'_>]) -> io::Result<()> {
        {
            let mut buffers = self
                .slot
                .buffers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            write_reply(&mut buffers, data)?;
        }
        self.commits
            .send(Commit {
                slot: self.slot_index,
                commit_id: self.commit_id,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "io_uring queue stopped"))?;
        self.eventfd.signal()
    }

    #[cfg(feature = "abi-7-40")]
    fn open_backing(&self, fd: BorrowedFd<'_>) -> io::Result<BackingId> {
        self.classic.open_backing(fd)
    }
}

fn write_reply(buffers: &mut RingBuffers, data: &[IoSlice<'_>]) -> io::Result<()> {
    let Some(header) = data.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FUSE reply has no output header",
        ));
    };
    let out_header_size = std::mem::size_of::<abi::fuse_out_header>();
    if header.len() != out_header_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "FUSE output header is {} bytes, expected {out_header_size}",
                header.len()
            ),
        ));
    }

    let payload_size = data[1..].iter().try_fold(0_usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "FUSE reply size overflow"))
    })?;
    if payload_size > buffers.payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "FUSE reply payload is {payload_size} bytes, ring capacity is {}",
                buffers.payload.len()
            ),
        ));
    }

    buffers.headers[..out_header_size].copy_from_slice(header);
    let mut offset = 0;
    for part in &data[1..] {
        let end = offset + part.len();
        buffers.payload[offset..end].copy_from_slice(part);
        offset = end;
    }
    buffers.headers[FUSE_URING_PAYLOAD_SIZE_OFFSET..FUSE_URING_PAYLOAD_SIZE_OFFSET + 4]
        .copy_from_slice(&(payload_size as u32).to_ne_bytes());
    Ok(())
}

fn assemble_request(slot: &RingSlot) -> io::Result<(Vec<u8>, u64)> {
    let buffers = slot
        .buffers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let input_header_size = std::mem::size_of::<abi::fuse_in_header>();
    let request_size = read_u32(&buffers.headers, 0)? as usize;
    let commit_id = read_u64(&buffers.headers, FUSE_URING_COMMIT_ID_OFFSET)?;
    let payload_size = read_u32(&buffers.headers, FUSE_URING_PAYLOAD_SIZE_OFFSET)? as usize;

    if commit_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FUSE io_uring request has commit_id=0",
        ));
    }
    if payload_size > buffers.payload.len() || request_size < input_header_size + payload_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FUSE io_uring request sizes are inconsistent",
        ));
    }
    let operation_header_size = request_size - input_header_size - payload_size;
    if operation_header_size > FUSE_URING_OP_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("FUSE operation header is {operation_header_size} bytes"),
        ));
    }

    let mut request = Vec::with_capacity(request_size);
    request.extend_from_slice(&buffers.headers[..input_header_size]);
    request.extend_from_slice(
        &buffers.headers[FUSE_URING_HEADER_SIZE..FUSE_URING_HEADER_SIZE + operation_header_size],
    );
    request.extend_from_slice(&buffers.payload[..payload_size]);
    if request.len() != request_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "assembled FUSE request length mismatch",
        ));
    }
    Ok((request, commit_id))
}

fn read_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "short ring header"))?
        .try_into()
        .expect("slice length checked");
    Ok(u32::from_ne_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "short ring header"))?
        .try_into()
        .expect("slice length checked");
    Ok(u64::from_ne_bytes(raw))
}

fn possible_cpu_count() -> io::Result<usize> {
    // SAFETY: `sysconf` has no pointer arguments and `_SC_NPROCESSORS_CONF`
    // returns a scalar count.
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
    if count <= 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(count).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "possible CPU count does not fit usize",
        )
    })
}

fn command_bytes(qid: u16, commit_id: u64) -> [u8; 80] {
    let mut command = [0_u8; 80];
    command[8..16].copy_from_slice(&commit_id.to_ne_bytes());
    command[16..18].copy_from_slice(&qid.to_ne_bytes());
    command
}

fn set_entry_len(entry: &mut squeue::Entry128, len: u32) {
    // `io-uring` intentionally exposes the FUSE command's `addr` but not the
    // adjacent SQE `len`. The UAPI fixes `len` at byte offset 24 in both 64-
    // and 128-byte SQEs. Entry128 is repr(C), and its first 64 bytes are the
    // kernel `io_uring_sqe` (asserted by the dependency's own layout tests).
    // SAFETY: `entry` is uniquely borrowed, the target four bytes are within
    // the first 64 bytes, and no SQ reference exists until after this returns.
    unsafe {
        (entry as *mut squeue::Entry128)
            .cast::<u8>()
            .add(24)
            .cast::<u32>()
            .write_unaligned(len);
    }
}

fn make_command(
    fuse_fd: i32,
    qid: u16,
    slot: usize,
    command: PendingCommand,
    iovecs: Option<*const libc::iovec>,
) -> squeue::Entry128 {
    let (opcode, commit_id) = match command {
        PendingCommand::Register => (FUSE_IO_URING_CMD_REGISTER, 0),
        PendingCommand::Commit(commit_id) => (FUSE_IO_URING_CMD_COMMIT_AND_FETCH, commit_id),
    };
    let mut builder =
        opcode::UringCmd80::new(types::Fd(fuse_fd), opcode).cmd(command_bytes(qid, commit_id));
    if let Some(iovecs) = iovecs {
        builder = builder.addr(Some(iovecs as u64));
    }
    let mut entry = builder.build().user_data(slot as u64);
    if iovecs.is_some() {
        set_entry_len(&mut entry, 2);
    }
    entry
}

fn push(ring: &mut IoUring<squeue::Entry128>, entry: &squeue::Entry128) -> io::Result<()> {
    let mut submission = ring.submission();
    // SAFETY: all pointers referenced by the SQE name Arc-owned RingSlot
    // allocations that remain alive until after the ring is dropped.
    unsafe { submission.push(entry) }
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "io_uring SQ is full"))
}

fn push_event_poll(ring: &mut IoUring<squeue::Entry128>, eventfd: &EventFd) -> io::Result<()> {
    let entry = squeue::Entry128::from(
        opcode::PollAdd::new(types::Fd(eventfd.raw_fd()), libc::POLLIN as u32)
            .build()
            .user_data(EVENT_TOKEN),
    );
    push(ring, &entry)
}

fn drain_commits(
    ring: &mut IoUring<squeue::Entry128>,
    receiver: &Receiver<Commit>,
    fuse_fd: i32,
    qid: u16,
    pending: &mut [PendingCommand],
) -> io::Result<usize> {
    let mut count = 0;
    while let Ok(commit) = receiver.try_recv() {
        let command = PendingCommand::Commit(commit.commit_id);
        pending[commit.slot] = command;
        push(
            ring,
            &make_command(fuse_fd, qid, commit.slot, command, None),
        )?;
        count += 1;
    }
    Ok(count)
}

fn run_queue<FS: Filesystem + Clone + Send>(
    mut session: Session<FS>,
    qid: usize,
    queue_depth: usize,
    payload_size: usize,
    startup: Sender<Result<(), String>>,
) -> io::Result<()> {
    let started = (|| -> io::Result<_> {
        let qid = u16::try_from(qid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "FUSE qid exceeds u16"))?;
        let eventfd = EventFd::new()?;
        let slots = (0..queue_depth)
            .map(|_| Arc::new(RingSlot::new(payload_size)))
            .collect::<Vec<_>>();
        let ring_entries = (queue_depth + 1).next_power_of_two() as u32;
        let mut builder = IoUring::<squeue::Entry128>::builder();
        builder.setup_cqsize(ring_entries * 2).setup_submit_all();
        let mut ring = builder.build(ring_entries)?;
        let fuse_fd = session.as_fd().as_raw_fd();
        let (commit_sender, commit_receiver) = mpsc::channel();
        let pending = vec![PendingCommand::Register; queue_depth];

        for (slot_index, slot) in slots.iter().enumerate() {
            push(
                &mut ring,
                &make_command(
                    fuse_fd,
                    qid,
                    slot_index,
                    PendingCommand::Register,
                    Some(slot.iovecs.as_ptr()),
                ),
            )?;
        }
        push_event_poll(&mut ring, &eventfd)?;
        ring.submit()?;
        Ok((
            qid,
            eventfd,
            slots,
            ring,
            commit_sender,
            commit_receiver,
            pending,
            fuse_fd,
        ))
    })();

    let (qid, eventfd, slots, mut ring, commit_sender, commit_receiver, mut pending, fuse_fd) =
        match started {
            Ok(started) => {
                let _ = startup.send(Ok(()));
                started
            }
            Err(error) => {
                let _ = startup.send(Err(error.to_string()));
                return Err(error);
            }
        };

    loop {
        if drain_commits(&mut ring, &commit_receiver, fuse_fd, qid, &mut pending)? > 0 {
            ring.submit()?;
        }

        match ring.submit_and_wait(1) {
            Ok(_) => {}
            Err(error) if error.raw_os_error() == Some(EINTR) => continue,
            Err(error) => return Err(error),
        }

        let completions = ring
            .completion()
            .map(|entry| (entry.user_data(), entry.result()))
            .collect::<Vec<_>>();
        for (token, result) in completions {
            if token == EVENT_TOKEN {
                if result < 0 {
                    return Err(io::Error::from_raw_os_error(-result));
                }
                eventfd.drain()?;
                push_event_poll(&mut ring, &eventfd)?;
                continue;
            }

            let slot_index = usize::try_from(token).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid io_uring user_data")
            })?;
            let Some(slot) = slots.get(slot_index) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "io_uring completion names an unknown slot",
                ));
            };
            if result == -ENOTCONN {
                return Ok(());
            }
            if result == -EAGAIN || result == -EINTR {
                let command = pending[slot_index];
                let iovecs =
                    matches!(command, PendingCommand::Register).then_some(slot.iovecs.as_ptr());
                push(
                    &mut ring,
                    &make_command(fuse_fd, qid, slot_index, command, iovecs),
                )?;
                continue;
            }
            if result != 0 {
                return Err(io::Error::from_raw_os_error(-result));
            }

            let (request_bytes, commit_id) = assemble_request(slot)?;
            let sender = RingReplySender {
                slot_index,
                slot: Arc::clone(slot),
                commit_id,
                commits: commit_sender.clone(),
                eventfd: eventfd.clone(),
                classic: session.ch.sender(),
            };
            let request =
                Request::new_with_sender(Arc::new(sender), &request_bytes).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid io_uring FUSE request")
                })?;
            session.dispatch_ring_request(&request);
        }
    }
}

pub(crate) fn run_hybrid<FS: Filesystem + Clone + Send>(
    session: &mut Session<FS>,
    queue_depth: usize,
    payload_size: u32,
    classic_buffer: &mut [u8],
) -> io::Result<()> {
    if queue_depth == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FUSE io_uring queue depth must be non-zero",
        ));
    }
    let queue_count = possible_cpu_count()?;
    if queue_count > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "FUSE io_uring possible CPU count exceeds the UAPI qid width",
        ));
    }

    let (startup_sender, startup_receiver) = mpsc::channel();
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(queue_count);
        for qid in 0..queue_count {
            let worker = session.ring_worker_clone();
            let startup = startup_sender.clone();
            let mut unmounter: SessionUnmounter = session.unmount_callable();
            handles.push(scope.spawn(move || {
                let result = run_queue(worker, qid, queue_depth, payload_size as usize, startup);
                if let Err(error) = &result {
                    warn!("FUSE io_uring queue {qid} stopped: {error}");
                    let _ = unmounter.unmount();
                }
                result
            }));
        }
        drop(startup_sender);

        let mut startup_error = None;
        for _ in 0..queue_count {
            match startup_receiver.recv() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    startup_error.get_or_insert(error);
                }
                Err(_) => {
                    startup_error.get_or_insert_with(|| "io_uring startup channel closed".into());
                }
            };
        }

        let classic_result = if let Some(error) = startup_error {
            session.unmount();
            Err(io::Error::other(error))
        } else {
            session.run_classic_loop(classic_buffer)
        };

        let mut worker_error = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) if error.raw_os_error() == Some(ENOTCONN) => {}
                Ok(Err(error)) => {
                    worker_error.get_or_insert(error);
                }
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
        classic_result?;
        if let Some(error) = worker_error {
            return Err(error);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_split_request_without_padding() {
        let slot = RingSlot::new(64);
        {
            let mut buffers = slot.buffers.lock().unwrap();
            let input_header_size = std::mem::size_of::<abi::fuse_in_header>();
            let operation = [0x11_u8; 16];
            let payload = b"name\0";
            let request_size = input_header_size + operation.len() + payload.len();
            buffers.headers[..4].copy_from_slice(&(request_size as u32).to_ne_bytes());
            buffers.headers[FUSE_URING_HEADER_SIZE..FUSE_URING_HEADER_SIZE + operation.len()]
                .copy_from_slice(&operation);
            buffers.headers[FUSE_URING_COMMIT_ID_OFFSET..FUSE_URING_COMMIT_ID_OFFSET + 8]
                .copy_from_slice(&77_u64.to_ne_bytes());
            buffers.headers[FUSE_URING_PAYLOAD_SIZE_OFFSET..FUSE_URING_PAYLOAD_SIZE_OFFSET + 4]
                .copy_from_slice(&(payload.len() as u32).to_ne_bytes());
            buffers.payload[..payload.len()].copy_from_slice(payload);
        }

        let (request, commit_id) = assemble_request(&slot).unwrap();
        assert_eq!(commit_id, 77);
        assert_eq!(
            &request[std::mem::size_of::<abi::fuse_in_header>()
                ..std::mem::size_of::<abi::fuse_in_header>() + 16],
            &[0x11; 16]
        );
        assert!(request.ends_with(b"name\0"));
    }

    #[test]
    fn reply_payload_is_contiguous_and_counted() {
        let mut buffers = RingBuffers::new(32);
        let header = [0x22_u8; 16];
        let left = [1_u8, 2, 3];
        let right = [4_u8, 5];
        write_reply(
            &mut buffers,
            &[
                IoSlice::new(&header),
                IoSlice::new(&left),
                IoSlice::new(&right),
            ],
        )
        .unwrap();
        assert_eq!(&buffers.headers[..16], &header);
        assert_eq!(&buffers.payload[..5], &[1, 2, 3, 4, 5]);
        assert_eq!(
            read_u32(&buffers.headers, FUSE_URING_PAYLOAD_SIZE_OFFSET).unwrap(),
            5
        );
    }

    #[test]
    fn command_layout_matches_fuse_uapi() {
        let bytes = command_bytes(513, 0x0102_0304_0506_0708);
        assert_eq!(
            u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
            0x0102_0304_0506_0708
        );
        assert_eq!(u16::from_ne_bytes(bytes[16..18].try_into().unwrap()), 513);
    }

    #[test]
    fn ring_buffers_are_page_aligned() {
        let slot = RingSlot::new(128 * 1024);
        let buffers = slot.buffers.lock().unwrap();
        let page_size = page_size::get();
        assert_eq!(buffers.headers.as_ptr() as usize % page_size, 0);
        assert_eq!(buffers.payload.as_ptr() as usize % page_size, 0);
    }
}
