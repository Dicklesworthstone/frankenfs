use super::{COPY_FILE_RANGE_CHUNK_BYTES, FsOps, InodeAttr, ReaddirPage, RequestScope};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_mvcc::MvccStore;
use ffs_types::{BlockNumber, InodeNumber};
use std::ffi::OsStr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const SOURCE: InodeNumber = InodeNumber(100);
const DESTINATION: InodeNumber = InodeNumber(101);
const SOURCE_OFFSET: usize = 7;
const DESTINATION_OFFSET: usize = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Read(usize),
    Write(usize),
    CancelAfterRead(usize),
    CancelAfterWrite(usize),
}

// Empty scopes publish successful writes immediately, like native NTFS/ZFS.
// Transaction scopes retain staged writes, including partial failed writes,
// until the caller decides whether to publish or abort the whole request.
struct CopyFs {
    source: Vec<u8>,
    destination: Mutex<Vec<u8>>,
    reads: AtomicUsize,
    writes: AtomicUsize,
    fault: Fault,
    write_limit: Option<usize>,
}

impl CopyFs {
    fn new(fault: Fault) -> Self {
        let chunk = COPY_FILE_RANGE_CHUNK_BYTES as usize;
        Self {
            source: (0..2 * chunk + 91).map(|i| (i % 251) as u8).collect(),
            destination: Mutex::new(vec![0xa7; 3 * chunk + 128]),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            fault,
            write_limit: None,
        }
    }

    fn copy(&self, cx: &Cx, completed: usize, length: usize) -> Result<u64> {
        self.copy_with_scope(cx, &mut RequestScope::empty(), completed, length)
    }

    fn copy_with_scope(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        completed: usize,
        length: usize,
    ) -> Result<u64> {
        self.copy_file_range(
            cx,
            scope,
            SOURCE,
            (SOURCE_OFFSET + completed) as u64,
            DESTINATION,
            (DESTINATION_OFFSET + completed) as u64,
            length as u64,
        )
    }

    fn assert_prefix(&self, completed: usize) {
        let destination = self.destination.lock().unwrap();
        assert_eq!(
            &destination[DESTINATION_OFFSET..DESTINATION_OFFSET + completed],
            &self.source[SOURCE_OFFSET..SOURCE_OFFSET + completed]
        );
        assert!(
            destination[..DESTINATION_OFFSET]
                .iter()
                .all(|&byte| byte == 0xa7)
        );
        assert!(
            destination[DESTINATION_OFFSET + completed..]
                .iter()
                .all(|&byte| byte == 0xa7)
        );
    }
}

impl FsOps for CopyFs {
    fn getattr(&self, _cx: &Cx, _scope: &mut RequestScope, _ino: InodeNumber) -> Result<InodeAttr> {
        unreachable!("the streaming fallback uses read and write")
    }

    fn lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> Result<InodeAttr> {
        unreachable!("the streaming fallback uses read and write")
    }

    fn readdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
    ) -> Result<ReaddirPage> {
        unreachable!("the streaming fallback uses read and write")
    }

    fn readlink(&self, _cx: &Cx, _scope: &mut RequestScope, _ino: InodeNumber) -> Result<Vec<u8>> {
        unreachable!("the streaming fallback uses read and write")
    }

    fn read(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>> {
        assert_eq!(ino, SOURCE);
        let call = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fault == Fault::Read(call) {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EIO)));
        }
        let start = usize::try_from(offset).unwrap().min(self.source.len());
        let end = start.saturating_add(size as usize).min(self.source.len());
        let bytes = self.source[start..end].to_vec();
        if self.fault == Fault::CancelAfterRead(call) {
            cx.set_cancel_requested(true);
        }
        Ok(bytes)
    }

    fn write(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> Result<u32> {
        assert_eq!(ino, DESTINATION);
        let call = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fault == Fault::Write(call) {
            if let Some(tx) = &mut scope.tx {
                // A staged ext4 write can fail after adding blocks to the
                // caller's transaction. Publishing its earlier successful
                // chunk must not accidentally publish this partial tail.
                tx.stage_write(BlockNumber(offset), data[..data.len().min(17)].to_vec());
            }
            return Err(FfsError::NoSpace);
        }
        let amount = self.write_limit.unwrap_or(data.len()).min(data.len());
        let start = usize::try_from(offset).unwrap();
        if let Some(tx) = &mut scope.tx {
            tx.stage_write(BlockNumber(offset), data[..amount].to_vec());
        } else {
            self.destination.lock().unwrap()[start..start + amount]
                .copy_from_slice(&data[..amount]);
        }
        if self.fault == Fault::CancelAfterWrite(call) {
            cx.set_cancel_requested(true);
        }
        Ok(u32::try_from(amount).unwrap())
    }
}

#[test]
fn copy_reports_completed_chunks_before_later_io_errors_and_can_resume() {
    let chunk = COPY_FILE_RANGE_CHUNK_BYTES as usize;
    let length = 2 * chunk + 37;
    for fault in [Fault::Read(2), Fault::Write(2)] {
        let cx = Cx::for_testing();
        let fs = CopyFs::new(fault);
        assert_eq!(fs.copy(&cx, 0, length).unwrap(), chunk as u64, "{fault:?}");
        fs.assert_prefix(chunk);

        // The returned offset is sufficient to resume after either source I/O
        // failure or destination ENOSPC; the failed call made no extra write.
        assert_eq!(
            fs.copy(&cx, chunk, length - chunk).unwrap(),
            (length - chunk) as u64,
            "{fault:?}"
        );
        fs.assert_prefix(length);
    }
}

#[test]
fn copy_preserves_errors_before_any_progress() {
    for (fault, errno) in [(Fault::Read(1), libc::EIO), (Fault::Write(1), libc::ENOSPC)] {
        let cx = Cx::for_testing();
        let fs = CopyFs::new(fault);
        assert_eq!(fs.copy(&cx, 0, 64).unwrap_err().to_errno(), errno);
        fs.assert_prefix(0);
    }
}

#[test]
fn copy_observes_cancellation_before_io_and_between_read_and_write() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let fs = CopyFs::new(Fault::None);
    assert!(matches!(fs.copy(&cx, 0, 64), Err(FfsError::Cancelled)));
    assert_eq!(fs.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    fs.assert_prefix(0);

    let cx = Cx::for_testing();
    let fs = CopyFs::new(Fault::CancelAfterRead(1));
    assert!(matches!(fs.copy(&cx, 0, 64), Err(FfsError::Cancelled)));
    assert_eq!(fs.reads.load(Ordering::SeqCst), 1);
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    fs.assert_prefix(0);
}

#[test]
fn copy_reports_committed_prefix_when_cancelled_mid_transfer() {
    let chunk = COPY_FILE_RANGE_CHUNK_BYTES as usize;
    for (fault, reads) in [
        (Fault::CancelAfterWrite(1), 1),
        (Fault::CancelAfterRead(2), 2),
    ] {
        let cx = Cx::for_testing();
        let fs = CopyFs::new(fault);
        assert_eq!(fs.copy(&cx, 0, 2 * chunk).unwrap(), chunk as u64);
        assert_eq!(fs.reads.load(Ordering::SeqCst), reads);
        assert_eq!(fs.writes.load(Ordering::SeqCst), 1);
        fs.assert_prefix(chunk);
    }
}

#[test]
fn copy_preserves_short_writes_eof_and_zero_length_behavior() {
    let cx = Cx::for_testing();
    let mut fs = CopyFs::new(Fault::None);
    fs.write_limit = Some(13);
    assert_eq!(fs.copy(&cx, 0, 64).unwrap(), 13);
    assert_eq!(fs.reads.load(Ordering::SeqCst), 1);
    assert_eq!(fs.writes.load(Ordering::SeqCst), 1);
    fs.assert_prefix(13);

    let fs = CopyFs::new(Fault::None);
    let available = fs.source.len() - SOURCE_OFFSET;
    assert_eq!(fs.copy(&cx, 0, available + 100).unwrap(), available as u64);
    fs.assert_prefix(available);

    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let fs = CopyFs::new(Fault::None);
    assert_eq!(fs.copy(&cx, 0, 0).unwrap(), 0);
    assert_eq!(fs.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    fs.assert_prefix(0);
}

#[test]
fn copy_rejects_partial_failed_staging_in_a_transaction() {
    let cx = Cx::for_testing();
    let chunk = COPY_FILE_RANGE_CHUNK_BYTES as usize;
    let fs = CopyFs::new(Fault::Write(2));
    let mut store = MvccStore::new();
    let mut scope = RequestScope::with_transaction(store.begin());
    let first = BlockNumber(DESTINATION_OFFSET as u64);
    let second = BlockNumber((DESTINATION_OFFSET + chunk) as u64);

    assert!(matches!(
        fs.copy_with_scope(&cx, &mut scope, 0, 2 * chunk),
        Err(FfsError::NoSpace)
    ));
    assert_eq!(fs.reads.load(Ordering::SeqCst), 2);
    assert_eq!(fs.writes.load(Ordering::SeqCst), 2);
    assert_eq!(scope.pending_write_count(), 2);
    let tx = scope.tx.as_ref().unwrap();
    assert_eq!(
        tx.staged_write(first).unwrap(),
        &fs.source[SOURCE_OFFSET..SOURCE_OFFSET + chunk]
    );
    assert_eq!(
        tx.staged_write(second).unwrap(),
        &fs.source[SOURCE_OFFSET + chunk..SOURCE_OFFSET + chunk + 17]
    );
    fs.assert_prefix(0);

    // The enclosing request must abort after this error, dropping both the
    // successful first chunk and the failed second chunk's partial staging.
    drop(scope);
    let snapshot = store.current_snapshot();
    assert!(store.read_visible(first, snapshot).is_none());
    assert!(store.read_visible(second, snapshot).is_none());
}

#[test]
fn copy_propagates_later_read_errors_and_cancellation_in_a_transaction() {
    let chunk = COPY_FILE_RANGE_CHUNK_BYTES as usize;
    for (fault, errno, reads) in [
        (Fault::Read(2), libc::EIO, 2),
        (Fault::CancelAfterWrite(1), libc::EINTR, 1),
        (Fault::CancelAfterRead(2), libc::EINTR, 2),
    ] {
        let cx = Cx::for_testing();
        let fs = CopyFs::new(fault);
        let mut store = MvccStore::new();
        let mut scope = RequestScope::with_transaction(store.begin());
        assert_eq!(
            fs.copy_with_scope(&cx, &mut scope, 0, 2 * chunk)
                .unwrap_err()
                .to_errno(),
            errno,
            "{fault:?}"
        );
        assert_eq!(fs.reads.load(Ordering::SeqCst), reads, "{fault:?}");
        assert_eq!(fs.writes.load(Ordering::SeqCst), 1, "{fault:?}");
        assert_eq!(scope.pending_write_count(), 1, "{fault:?}");
        assert_eq!(
            scope
                .tx
                .as_ref()
                .unwrap()
                .staged_write(BlockNumber(DESTINATION_OFFSET as u64))
                .unwrap(),
            &fs.source[SOURCE_OFFSET..SOURCE_OFFSET + chunk],
            "{fault:?}"
        );
        fs.assert_prefix(0);
    }
}
