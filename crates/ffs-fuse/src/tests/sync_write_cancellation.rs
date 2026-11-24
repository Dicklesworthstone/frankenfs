//! A committed WRITE must finish its O_SYNC/O_DSYNC continuation before replying.

use super::*;

#[derive(Default)]
struct SyncWriteState {
    request_cx: Option<Cx>,
    published: Vec<u8>,
    flushed: Vec<u8>,
    writes: usize,
    flushes: Vec<bool>,
}

struct SyncWriteFs {
    inner: MutationRecordingFs,
    state: Arc<Mutex<SyncWriteState>>,
    cancel_before_write: bool,
    fsync_errno: Option<i32>,
}

impl FsOps for SyncWriteFs {
    fn getattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        self.inner.getattr(cx, scope, ino)
    }

    fn lookup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        self.inner.lookup(cx, scope, parent, name)
    }

    fn readdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        self.inner.readdir(cx, scope, ino, offset)
    }

    fn read(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        self.inner.read(cx, scope, ino, offset, size)
    }

    fn readlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        self.inner.readlink(cx, scope, ino)
    }

    fn begin_request_scope(&self, cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
        // Match native backends' default admission checkpoint, including the
        // separate Fsync scope opened after the Write scope has ended.
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.inner.begin_request_scope(cx, op)
    }

    fn write(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> ffs_error::Result<u32> {
        self.state.lock().unwrap().request_cx = Some(cx.clone());
        if self.cancel_before_write {
            cx.set_cancel_requested(true);
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let written = self.inner.write(cx, scope, ino, offset, data)?;
        {
            let mut state = self.state.lock().unwrap();
            // Model an immediate native publication; a duplicate call is
            // observable in both the payload and the publication count.
            state.published.extend_from_slice(data);
            state.writes += 1;
        }
        cx.set_cancel_requested(true);
        Ok(written)
    }

    fn fsync(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        datasync: bool,
    ) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut state = self.state.lock().unwrap();
        state.flushes.push(datasync);
        if let Some(errno) = self.fsync_errno {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(errno)));
        }
        state.flushed = state.published.clone();
        drop(state);
        self.inner.fsync(cx, scope, ino, fh, datasync)
    }
}

fn fixture(
    cancel_before_write: bool,
    fsync_errno: Option<i32>,
) -> (FrankenFuse, Arc<Mutex<SyncWriteState>>) {
    let state = Arc::new(Mutex::new(SyncWriteState::default()));
    let fs = SyncWriteFs {
        inner: MutationRecordingFs::new(Arc::new(Mutex::new(Vec::new()))),
        state: Arc::clone(&state),
        cancel_before_write,
        fsync_errno,
    };
    let fuse = FrankenFuse::with_options(
        Box::new(fs),
        &MountOptions {
            read_only: false,
            ..MountOptions::default()
        },
    );
    (fuse, state)
}

fn assert_cancellation_remains_pending(state: &SyncWriteState) {
    assert!(
        state.request_cx.as_ref().unwrap().checkpoint().is_err(),
        "the continuation must neither clear cancellation nor leak its mask"
    );
}

#[test]
fn sync_write_finishes_durability_after_committed_write_requests_cancellation() {
    for (flags, datasync) in [(libc::O_SYNC, false), (libc::O_DSYNC, true)] {
        let (fuse, state) = fixture(false, None);
        let written = fuse
            .dispatch_write_with_intent(42, 0, b"accepted", WriteIntent::from_fuse(9001, 0, flags))
            .expect("a committed synchronous write must finish its durability continuation");
        assert_eq!(written, 8);
        let state = state.lock().unwrap();
        assert_eq!(state.writes, 1);
        assert_eq!(state.published, b"accepted");
        assert_eq!(state.flushed, b"accepted");
        assert_eq!(state.flushes, [datasync]);
        assert_cancellation_remains_pending(&state);
    }
}

#[test]
fn sync_write_preserves_real_fsync_failure_after_late_cancellation() {
    for (flags, datasync) in [(libc::O_SYNC, false), (libc::O_DSYNC, true)] {
        let (fuse, state) = fixture(false, Some(libc::EIO));
        let error = fuse
            .dispatch_write_with_intent(42, 0, b"accepted", WriteIntent::from_fuse(9001, 0, flags))
            .expect_err("a real durability failure must reach the caller");
        assert!(matches!(
            error,
            MutationDispatchError::Operation { error, offset: Some(0) }
                if error.to_errno() == libc::EIO
        ));
        let state = state.lock().unwrap();
        assert_eq!(state.writes, 1);
        assert_eq!(state.published, b"accepted");
        assert_eq!(state.flushed, b"");
        assert_eq!(state.flushes, [datasync]);
        assert_cancellation_remains_pending(&state);
    }
}

#[test]
fn sync_write_still_observes_cancellation_before_native_publication() {
    for flags in [libc::O_SYNC, libc::O_DSYNC] {
        let (fuse, state) = fixture(true, None);
        let error = fuse
            .dispatch_write_with_intent(42, 0, b"rejected", WriteIntent::from_fuse(9001, 0, flags))
            .expect_err("the write itself must remain cancellable");
        assert!(matches!(
            error,
            MutationDispatchError::Operation {
                error: FfsError::Cancelled,
                offset: Some(0),
            }
        ));
        let state = state.lock().unwrap();
        assert_eq!(state.writes, 0);
        assert_eq!(state.published, b"");
        assert_eq!(state.flushed, b"");
        assert_eq!(state.flushes, [] as [bool; 0]);
        assert_cancellation_remains_pending(&state);
    }
}
