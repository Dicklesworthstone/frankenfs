// Included in the adapter's test module to exercise the actual reply helpers
// with the existing request recorder and wire-level ReplySender.

#[derive(Default)]
struct StatefulLifecycleState {
    handles: BTreeMap<u64, InodeNumber>,
    create_flags: Vec<i32>,
}

struct StatefulLifecycleFs {
    inner: MutationRecordingFs,
    lifetime: Arc<Mutex<StatefulLifecycleState>>,
    fail_end: Option<RequestOp>,
    fail_commit: bool,
}

#[allow(clippy::too_many_arguments)]
impl FsOps for StatefulLifecycleFs {
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

    fn requires_stateful_open(&self) -> bool {
        true
    }

    fn open(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        flags: i32,
    ) -> ffs_error::Result<(u64, u32)> {
        let reply = self.inner.open(cx, scope, ino, flags)?;
        let mut lifetime = self.lifetime.lock().unwrap();
        assert!(lifetime.handles.insert(reply.0, ino).is_none());
        Ok(reply)
    }

    fn create_open(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
        flags: i32,
    ) -> ffs_error::Result<(InodeAttr, u64, u32)> {
        let attr = self.inner.create(cx, scope, parent, name, mode, uid, gid)?;
        let mut lifetime = self.lifetime.lock().unwrap();
        lifetime.create_flags.push(flags);
        assert!(lifetime.handles.insert(9002, attr.ino).is_none());
        Ok((attr, 9002, fuse_consts::FOPEN_DIRECT_IO))
    }

    fn release(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        request: ReleaseRequest,
    ) -> ffs_error::Result<()> {
        // A cancelled OPEN/CREATE must not also cancel its required cleanup.
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut lifetime = self.lifetime.lock().unwrap();
        if lifetime.handles.get(&request.fh) != Some(&request.ino) {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EBADF)));
        }
        lifetime.handles.remove(&request.fh);
        drop(lifetime);
        self.inner.release(cx, scope, request)
    }

    fn end_request_scope(
        &self,
        cx: &Cx,
        op: RequestOp,
        scope: RequestScope,
    ) -> ffs_error::Result<()> {
        if self.fail_end == Some(op) {
            cx.cancel_with(asupersync::types::CancelKind::User, Some("scope after open"));
            return Err(FfsError::Cancelled);
        }
        self.inner.end_request_scope(cx, op, scope)
    }

    fn commit_request_scope(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
    ) -> ffs_error::Result<ffs_types::CommitSeq> {
        if self.fail_commit {
            cx.cancel_with(asupersync::types::CancelKind::User, Some("create scope commit"));
            return Err(FfsError::Cancelled);
        }
        self.inner.commit_request_scope(cx, scope)
    }
}

struct StatefulLifecycleHarness {
    fuse: FrankenFuse,
    calls: Arc<Mutex<Vec<MutationCall>>>,
    lifetime: Arc<Mutex<StatefulLifecycleState>>,
}

impl StatefulLifecycleHarness {
    fn new(fail_end: Option<RequestOp>, fail_commit: bool) -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let lifetime = Arc::new(Mutex::new(StatefulLifecycleState::default()));
        let backend = StatefulLifecycleFs {
            inner: MutationRecordingFs::new(Arc::clone(&calls)),
            lifetime: Arc::clone(&lifetime),
            fail_end,
            fail_commit,
        };
        Self {
            fuse: FrankenFuse::with_options(
                Box::new(backend),
                &MountOptions {
                    read_only: false,
                    ..MountOptions::default()
                },
            ),
            calls,
            lifetime,
        }
    }
}

fn wire_open_result(sender: &RecordingSender) -> (u64, u32) {
    assert_eq!(sender.errno(), None);
    let bytes = sender.bytes();
    assert!(bytes.len() >= 32);
    // Both OPEN and CREATE end with the native 16-byte fuse_open_out.
    let open = &bytes[bytes.len() - 16..];
    (
        u64::from_ne_bytes(open[..8].try_into().unwrap()),
        u32::from_ne_bytes(open[8..12].try_into().unwrap()),
    )
}

#[test]
fn stateful_open_reaches_backend_and_releases_the_wire_handle() {
    let harness = StatefulLifecycleHarness::new(None, false);
    assert!(
        !harness.fuse.zero_message_open_enabled(),
        "INIT and OPEN must both opt this backend out of zero-message OPEN"
    );
    let sender = RecordingSender::default();
    let flags = libc::O_RDWR | libc::O_APPEND;
    harness.fuse.open_impl(
        44,
        flags,
        <ReplyOpen as fuser::Reply>::new(1, sender.clone()),
    );
    let (fh, open_flags) = wire_open_result(&sender);
    assert_eq!((fh, open_flags), (9001, fuse_consts::FOPEN_KEEP_CACHE));
    assert_eq!(
        harness.lifetime.lock().unwrap().handles.get(&fh),
        Some(&InodeNumber(44))
    );
    harness
        .fuse
        .release_for_fuzzing(44, fh, flags, None, false)
        .unwrap();
    assert!(harness.lifetime.lock().unwrap().handles.is_empty());
    assert_eq!(
        harness.calls.lock().unwrap().as_slice(),
        &[
            MutationCall::Open {
                ino: InodeNumber(44),
                flags,
            },
            MutationCall::Release {
                ino: InodeNumber(44),
                fh,
                flags,
                lock_owner: None,
                flush: false,
            },
        ]
    );
}

#[test]
fn create_open_retains_stateless_reply_and_zero_message_defaults() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let fuse = FrankenFuse::with_options(
        Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
        &MountOptions {
            read_only: false,
            ..MountOptions::default()
        },
    );
    assert_eq!(
        fuse.zero_message_open_enabled(),
        zero_message_open_measurement_enabled()
    );
    let sender = RecordingSender::default();
    fuse.create_impl(
        2,
        OsStr::new("legacy"),
        0o640,
        0,
        libc::O_CREAT | libc::O_RDWR,
        1001,
        1002,
        <ReplyCreate as fuser::Reply>::new(2, sender.clone()),
    );
    assert_eq!(wire_open_result(&sender), (0, 0));
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[MutationCall::Create {
            parent: InodeNumber(2),
            name: "legacy".to_owned(),
            mode: 0o640,
            uid: 1001,
            gid: 1002,
        }]
    );
}

#[test]
fn stateful_create_returns_its_backend_handle_flags_and_release_lifetime() {
    let harness = StatefulLifecycleHarness::new(None, false);
    let sender = RecordingSender::default();
    let flags = libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_TRUNC;
    harness.fuse.create_impl(
        2,
        OsStr::new("stateful"),
        0o600,
        0,
        flags,
        1001,
        1002,
        <ReplyCreate as fuser::Reply>::new(3, sender.clone()),
    );
    let (fh, open_flags) = wire_open_result(&sender);
    assert_eq!((fh, open_flags), (9002, fuse_consts::FOPEN_DIRECT_IO));
    {
        let lifetime = harness.lifetime.lock().unwrap();
        assert_eq!(lifetime.create_flags, [flags]);
        assert_eq!(lifetime.handles.get(&fh), Some(&InodeNumber(303)));
    }
    assert_eq!(harness.fuse.inner.lookup_refcounts.count(303), 1);
    harness
        .fuse
        .release_for_fuzzing(303, fh, flags, None, false)
        .unwrap();
    assert!(harness.lifetime.lock().unwrap().handles.is_empty());
    assert!(matches!(
        harness.calls.lock().unwrap().last(),
        Some(MutationCall::Release { fh: 9002, .. })
    ));
}

#[test]
fn stateful_scope_failures_release_handles_the_kernel_never_received() {
    for (operation, fail_commit) in [
        (RequestOp::Open, false),
        (RequestOp::Create, false),
        (RequestOp::Create, true),
    ] {
        let harness =
            StatefulLifecycleHarness::new((!fail_commit).then_some(operation), fail_commit);
        let sender = RecordingSender::default();
        let expected_handle = if operation == RequestOp::Open {
            harness.fuse.open_impl(
                44,
                libc::O_RDWR,
                <ReplyOpen as fuser::Reply>::new(4, sender.clone()),
            );
            9001
        } else {
            harness.fuse.create_impl(
                2,
                OsStr::new("cancelled"),
                0o600,
                0,
                libc::O_RDWR,
                0,
                0,
                <ReplyCreate as fuser::Reply>::new(5, sender.clone()),
            );
            9002
        };
        assert_eq!(sender.errno(), Some(FfsError::Cancelled.to_errno()));
        assert!(
            harness.lifetime.lock().unwrap().handles.is_empty(),
            "{operation:?} leaked a backend handle after its reply failed"
        );
        assert_eq!(harness.fuse.inner.lookup_refcounts.count(303), 0);
        assert!(matches!(
            harness.calls.lock().unwrap().last(),
            Some(MutationCall::Release { fh, .. }) if *fh == expected_handle
        ));
    }
}
