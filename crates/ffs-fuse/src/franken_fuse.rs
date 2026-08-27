impl FrankenFuse {
    fn with_inner(
        ops: Box<dyn FsOps>,
        options: &MountOptions,
        mountpoint: Option<&Path>,
        backpressure: Option<Arc<BackpressureGate>>,
    ) -> Self {
        let thread_count = options.resolved_thread_count();
        if backpressure.is_some() {
            info!(thread_count, "FrankenFuse initialized with backpressure");
        } else {
            info!(thread_count, "FrankenFuse initialized");
        }
        Self {
            inner: Arc::new(FuseInner {
                ops: Arc::from(ops),
                metrics: Arc::new(AtomicMetrics::new()),
                thread_count,
                worker_dispatch: options.worker_threads > 0,
                parallel_dirops: options.worker_threads > 1,
                read_only: options.read_only,
                count_memoized_requests: count_memoized_requests_from_env(),
                mountpoint: mountpoint.map(Path::to_path_buf),
                kernel_notifier: Mutex::new(None),
                ioctl_trace: options.ioctl_trace_path.clone().map(IoctlTraceProbe::new),
                backpressure,
                access_predictor: AccessPredictor::default(),
                readahead: ReadaheadManager::new(MAX_PENDING_READAHEAD_ENTRIES),
                readonly_xattr_cache: ReadonlyXattrCache::default(),
                readdirplus_attr_memo: ReaddirplusAttrMemo::from_env(),
                // `from_env`, not `default`: this is the one production mount, and
                // the FFS_FUSE_CAPABILITY_MEMO switch has to reach it for the
                // comparator to A/B the memo from a single ELF (bd-2pq73).
                missing_capability_xattr: LastMissingCapabilityXattr::from_env(),
                inode_locks: Arc::new(FuseInodeLocks::default()),
                // bd-2i2ez: `from_env`, not `default` — this is the one
                // production mount, and `FFS_FUSE_WRITEBACK_BATCH` has to reach
                // it for the comparator to A/B the batch from a single ELF.
                writeback: WritebackBatch::from_env(),
                // bd-q0xnl: starts false and is armed at `init` from the env, the
                // same as the crate's other two `FuseInner` constructors. This one
                // was missed when the field landed, which broke every build of
                // ffs-fuse and everything downstream of it (ffs-cli, and so the
                // mounted instruments).
                zero_message_opendir: std::sync::atomic::AtomicBool::new(false),
            }),
            final_flush_errno: Arc::new(std::sync::atomic::AtomicI32::new(0)),
        }
    }

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
        Self::with_inner(ops, options, None, None)
    }

    fn with_mount_config(
        ops: Box<dyn FsOps>,
        mountpoint: Option<&Path>,
        config: &MountConfig,
    ) -> Self {
        Self::with_inner(
            ops,
            &config.options,
            mountpoint,
            config.backpressure.clone(),
        )
    }

    /// Create a FUSE adapter with an attached backpressure gate.
    #[must_use]
    pub fn with_backpressure(
        ops: Box<dyn FsOps>,
        options: &MountOptions,
        gate: BackpressureGate,
    ) -> Self {
        Self::with_inner(ops, options, None, Some(Arc::new(gate)))
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

    fn shared_handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            final_flush_errno: Arc::clone(&self.final_flush_errno),
        }
    }

    /// Record the failure that `fuser` cannot return from `Filesystem::destroy`.
    ///
    /// The blocking mount owner checks this once `Session::run` returns. Keeping
    /// the native errno makes a final ENOSPC distinguishable from generic I/O
    /// failure to the CLI and its caller.
    fn record_final_flush_failure(&self, error: &FfsError) {
        self.final_flush_errno
            .store(error.to_errno(), std::sync::atomic::Ordering::Release);
    }

    fn final_flush_result(&self) -> Result<(), FuseError> {
        let errno = self
            .final_flush_errno
            .load(std::sync::atomic::Ordering::Acquire);
        if errno == 0 {
            return Ok(());
        }
        Err(FuseError::Io(std::io::Error::from_raw_os_error(errno)))
    }

    fn install_kernel_notifier(&self, notifier: fuser::Notifier) {
        // bd-7s0p7: the notifier is handed to a dedicated thread rather than
        // stored for the dispatch thread to use. See `KernelNotifyQueue`.
        let queue = KernelNotifyQueue::spawn(notifier);
        let mut guard = match self.inner.kernel_notifier.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("FUSE kernel notifier slot poisoned, recovering");
                poisoned.into_inner()
            }
        };
        *guard = Some(queue);
    }

    fn kernel_notifier(&self) -> Option<KernelNotifyQueue> {
        match self.inner.kernel_notifier.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                warn!("FUSE kernel notifier slot poisoned, recovering");
                poisoned.into_inner().clone()
            }
        }
    }

    fn notify_entry_invalidation(&self, parent: u64, name: &OsStr) {
        // An entry invalidation names a parent/name, not the inode displaced by
        // a rename-over or removed by unlink. Drop every pending READDIRPLUS
        // hand-off before the notifier early-return so this boundary is also
        // correct in unit tests and before a live mount installs its notifier.
        self.inner.invalidate_readdirplus_entries();
        let Some(notifier) = self.kernel_notifier() else {
            return;
        };
        // bd-avg6f: default ON. Off only to MEASURE what bd-yu6jz's per-mutation
        // notification costs; the readdirplus hand-off above is dropped either
        // way, so the knob isolates the KERNEL notification and nothing else.
        if !crate::entry_invalidation_enabled() {
            return;
        }
        // Queued, never issued here: this runs inside the request handler, and
        // the caller's syscall still holds the parent directory's inode lock
        // that `fuse_reverse_inval_entry` needs (bd-7s0p7).
        notifier.entry(parent, name);
    }

    /// A successful create-like operation only needs to evict a negative dentry
    /// when this mount previously installed that exact negative lookup reply.
    fn notify_created_entry_invalidation(&self, parent: u64, name: &OsStr) {
        self.inner.invalidate_readdirplus_entries();
        let Some(notifier) = self.kernel_notifier() else {
            return;
        };
        if !crate::entry_invalidation_enabled() || !notifier.take_negative_entry(parent, name) {
            return;
        }
        notifier.entry(parent, name);
    }

    /// Drop a cached inode's attributes after a successful mutation.
    ///
    /// Positive entry and attribute TTLs are valid only while the metadata is
    /// unchanged. The kernel can keep a prior reply for up to `ATTR_TTL`, so a
    /// committed mutation must actively evict it rather than waiting for that
    /// timeout to elapse.
    fn notify_inode_invalidation(&self, ino: u64) {
        // READDIRPLUS may have prepared attributes for the next GETATTR before
        // this mutation committed. Clear that userspace hand-off regardless of
        // whether a live kernel notifier has been installed; the kernel cache
        // and our own hand-off must have the same mutation boundary.
        self.inner
            .invalidate_readdirplus_attrs(InodeNumber(ino));
        let Some(notifier) = self.kernel_notifier() else {
            return;
        };
        // Queued for the same reason as the entry case (bd-7s0p7): this is a
        // request-handler context, and `fuse_reverse_inval_inode` takes a lock
        // the caller has not released yet.
        notifier.inode(ino);
    }

    /// Execute the internal ioctl dispatcher without a live kernel mount.
    ///
    /// This is a narrow hook for fuzz/integration harnesses that need to drive
    /// the real ioctl argument parser and backend routing from userspace.
    /// The return shape intentionally mirrors the kernel contract:
    /// successful commands yield the raw reply payload, failed commands yield
    /// the errno that would be sent back through FUSE.
    #[doc(hidden)]
    pub fn dispatch_ioctl_for_fuzzing(
        &self,
        caller_pid: u32,
        ino: u64,
        fh: u64,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
    ) -> std::result::Result<Vec<u8>, c_int> {
        match self.dispatch_ioctl(caller_pid, ino, fh, cmd, in_data, out_size) {
            IoctlResult::Data(data) => Ok(data),
            IoctlResult::Error(errno) => Err(errno),
        }
    }

    /// Execute open without a live kernel mount.
    #[doc(hidden)]
    pub fn open_for_fuzzing(&self, ino: u64, flags: i32) -> std::result::Result<(u64, u32), c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Open, |cx, scope| {
            self.inner.ops.open(cx, scope, InodeNumber(ino), flags)
        })
        .map(|(fh, open_flags)| (fh, Self::kernel_open_flags(flags, open_flags)))
        .map_err(|error| error.to_errno())
    }

    /// Execute read without a live kernel mount.
    #[doc(hidden)]
    pub fn read_for_fuzzing(
        &self,
        ino: u64,
        offset: i64,
        size: u32,
    ) -> std::result::Result<Vec<u8>, c_int> {
        let byte_offset = u64::try_from(offset).map_err(|_| libc::EINVAL)?;
        let cx = Self::cx_for_request();
        let data = self
            .read_with_readahead(&cx, InodeNumber(ino), byte_offset, size)
            .map_err(|error| error.to_errno())?;
        self.inner
            .metrics
            .record_bytes_read(u64::try_from(data.len()).unwrap_or(u64::MAX));
        Ok(data)
    }

    /// Execute write without a live kernel mount.
    #[doc(hidden)]
    pub fn write_for_fuzzing(
        &self,
        ino: u64,
        offset: i64,
        data: &[u8],
    ) -> std::result::Result<u32, c_int> {
        self.dispatch_write(ino, offset, data)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute copy-file-range without a live kernel mount.
    #[doc(hidden)]
    pub fn copy_file_range_for_fuzzing(
        &self,
        ino_in: u64,
        offset_in: i64,
        ino_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
    ) -> std::result::Result<u32, c_int> {
        self.dispatch_copy_file_range(ino_in, offset_in, ino_out, offset_out, len, flags)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute flush without a live kernel mount.
    #[doc(hidden)]
    pub fn flush_for_fuzzing(
        &self,
        ino: u64,
        fh: u64,
        lock_owner: u64,
    ) -> std::result::Result<(), c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Flush, |cx, scope| {
            self.inner
                .ops
                .flush(cx, scope, InodeNumber(ino), fh, lock_owner)
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute fsync without a live kernel mount.
    #[doc(hidden)]
    pub fn fsync_for_fuzzing(
        &self,
        ino: u64,
        fh: u64,
        datasync: bool,
    ) -> std::result::Result<(), c_int> {
        if self.inner.read_only {
            return Err(libc::EROFS);
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Fsync) {
            return Err(errno);
        }
        self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
            self.inner
                .ops
                .fsync(cx, scope, InodeNumber(ino), fh, datasync)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute release without a live kernel mount.
    #[doc(hidden)]
    pub fn release_for_fuzzing(
        &self,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
    ) -> std::result::Result<(), c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Release, |cx, scope| {
            self.inner.ops.release(
                cx,
                scope,
                ReleaseRequest {
                    ino: InodeNumber(ino),
                    fh,
                    flags,
                    lock_owner,
                    flush,
                },
            )
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute lookup with raw path-component bytes and return the backend
    /// result without a live kernel mount.
    #[doc(hidden)]
    pub fn lookup_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
    ) -> std::result::Result<InodeAttr, c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Lookup, |cx, scope| {
            self.inner.ops.lookup(cx, scope, InodeNumber(parent), name)
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute getattr without a live kernel mount.
    #[doc(hidden)]
    pub fn getattr_for_fuzzing(&self, ino: u64) -> std::result::Result<InodeAttr, c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Getattr, |cx, scope| {
            self.inner.ops.getattr(cx, scope, InodeNumber(ino))
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute statfs without a live kernel mount.
    #[doc(hidden)]
    pub fn statfs_for_fuzzing(&self, ino: u64) -> std::result::Result<FsStat, c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Statfs, |cx, scope| {
            self.inner.ops.statfs(cx, scope, InodeNumber(ino))
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute readdir and force the same raw-byte name conversion the live
    /// FUSE path performs before replying.
    #[doc(hidden)]
    pub fn readdir_for_fuzzing(
        &self,
        ino: u64,
        offset: u64,
    ) -> std::result::Result<Vec<FfsDirEntry>, c_int> {
        let cx = Self::cx_for_request();
        let entries = self
            .with_request_scope(&cx, RequestOp::Readdir, |cx, scope| {
                self.inner.ops.readdir(cx, scope, InodeNumber(ino), offset)
            })
            .map_err(|error| error.to_errno())?;

        for entry in &entries {
            #[cfg(unix)]
            let _ = OsStr::from_bytes(&entry.name);
            #[cfg(not(unix))]
            let _ = entry.name_str();
        }

        Ok(entries.to_vec())
    }

    /// Execute readlink without a live mount.
    #[doc(hidden)]
    pub fn readlink_for_fuzzing(&self, ino: u64) -> std::result::Result<Vec<u8>, c_int> {
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Readlink, |cx, scope| {
            self.inner.ops.readlink(cx, scope, InodeNumber(ino))
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute create with raw path-component bytes without a live kernel
    /// mount.
    #[doc(hidden)]
    pub fn create_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        if self.inner.read_only {
            return Err(libc::EROFS);
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Create) {
            return Err(errno);
        }

        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.with_request_scope(&cx, RequestOp::Create, |cx, scope| {
            let attr =
                self.inner
                    .ops
                    .create(cx, scope, InodeNumber(parent), name, mode, uid, gid)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        })
        .map_err(|error| error.to_errno())
    }

    /// Execute setattr without a live kernel mount.
    #[doc(hidden)]
    pub fn setattr_for_fuzzing(
        &self,
        ino: u64,
        attrs: &SetAttrRequest,
    ) -> std::result::Result<InodeAttr, c_int> {
        self.setattr_for_fuzzing_as(ino, attrs, 0)
    }

    /// Execute setattr as a specific caller without a live kernel mount.
    #[doc(hidden)]
    pub fn setattr_for_fuzzing_as(
        &self,
        ino: u64,
        attrs: &SetAttrRequest,
        caller_uid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        if self.inner.read_only {
            return Err(libc::EROFS);
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Setattr) {
            return Err(errno);
        }

        self.dispatch_setattr(&cx, ino, attrs, caller_uid)
            .map_err(|error| error.to_errno())
    }

    fn dispatch_setattr(
        &self,
        cx: &Cx,
        ino: u64,
        attrs: &SetAttrRequest,
        caller_uid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        self.with_request_scope(cx, RequestOp::Setattr, |cx, scope| {
            self.authorize_setattr_owner_change(cx, scope, InodeNumber(ino), attrs, caller_uid)?;
            let attr = self.inner.ops.setattr(cx, scope, InodeNumber(ino), attrs)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        })
    }

    fn authorize_setattr_owner_change(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
        caller_uid: u32,
    ) -> ffs_error::Result<()> {
        if caller_uid == 0 || (attrs.uid.is_none() && attrs.gid.is_none()) {
            return Ok(());
        }

        let current = self.inner.ops.getattr(cx, scope, ino)?;
        let uid_unchanged = attrs.uid.is_none_or(|uid| uid == current.uid);
        let gid_unchanged = attrs.gid.is_none_or(|gid| gid == current.gid);
        if uid_unchanged && gid_unchanged {
            return Ok(());
        }

        Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EPERM)))
    }

    /// Execute mkdir with raw path-component bytes without a live kernel mount.
    #[doc(hidden)]
    pub fn mkdir_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.dispatch_mkdir(parent, name, mode, uid, gid)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute rmdir with raw path-component bytes without a live kernel mount.
    #[doc(hidden)]
    pub fn rmdir_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
    ) -> std::result::Result<(), c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.dispatch_rmdir(parent, name)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute unlink with raw path-component bytes without a live kernel mount.
    #[doc(hidden)]
    pub fn unlink_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
    ) -> std::result::Result<(), c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.dispatch_unlink(parent, name)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute mknod without a live kernel mount.
    ///
    /// Regular files route through `FsOps::create`, supported special nodes
    /// route through `FsOps::mknod`, and unsupported node types fail with
    /// `EOPNOTSUPP`.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn mknod_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        mode: u32,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        self.dispatch_mknod(parent, name, mode, rdev, uid, gid)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute rename with raw path-component bytes without a live kernel
    /// mount.
    #[doc(hidden)]
    pub fn rename_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        newparent: u64,
        newname_bytes: &[u8],
    ) -> std::result::Result<(), c_int> {
        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        #[cfg(not(unix))]
        let owned_newname = OsString::from(String::from_utf8_lossy(newname_bytes).into_owned());
        #[cfg(unix)]
        let new_name = OsStr::from_bytes(newname_bytes);
        #[cfg(not(unix))]
        let new_name = owned_newname.as_os_str();

        self.dispatch_rename(parent, name, newparent, new_name, 0)
            .map_err(|error| match error {
                MutationDispatchError::Errno(errno) => errno,
                MutationDispatchError::Operation { error, .. } => error.to_errno(),
            })
    }

    /// Execute symlink with raw path/name bytes without a live kernel mount.
    #[doc(hidden)]
    pub fn symlink_for_fuzzing(
        &self,
        parent: u64,
        name_bytes: &[u8],
        target_bytes: &[u8],
        uid: u32,
        gid: u32,
    ) -> std::result::Result<InodeAttr, c_int> {
        if self.inner.read_only {
            return Err(libc::EROFS);
        }
        let cx = Self::cx_for_request();
        if let Some(errno) = self.backpressure_errno(&cx, RequestOp::Symlink) {
            return Err(errno);
        }

        #[cfg(not(unix))]
        let owned_name = OsString::from(String::from_utf8_lossy(name_bytes).into_owned());
        #[cfg(unix)]
        let name = OsStr::from_bytes(name_bytes);
        #[cfg(not(unix))]
        let name = owned_name.as_os_str();

        #[cfg(unix)]
        let target = PathBuf::from(OsString::from_vec(target_bytes.to_vec()));
        #[cfg(not(unix))]
        let target = PathBuf::from(String::from_utf8_lossy(target_bytes).into_owned());

        self.with_request_scope(&cx, RequestOp::Symlink, |cx, scope| {
            let attr =
                self.inner
                    .ops
                    .symlink(cx, scope, InodeNumber(parent), name, &target, uid, gid)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        })
        .map_err(|error| error.to_errno())
    }

    fn backpressure_errno(&self, cx: &Cx, op: RequestOp) -> Option<c_int> {
        match self.should_shed_with_cx(cx, op) {
            Ok(false) => None,
            Ok(true) => Some(libc::EBUSY),
            Err(error) => Some(error.to_errno()),
        }
    }

    /// Check backpressure for an operation. Returns `true` if the operation
    /// should be rejected (shed).
    fn should_shed_with_cx(&self, cx: &Cx, op: RequestOp) -> ffs_error::Result<bool> {
        let Some(gate) = self.inner.backpressure.as_ref() else {
            return Ok(false);
        };

        match gate.check(op) {
            BackpressureDecision::Proceed => Ok(false),
            BackpressureDecision::Throttle => {
                self.inner.metrics.record_throttled();
                trace!(
                    ?op,
                    delay_ms = BACKPRESSURE_THROTTLE_DELAY.as_millis(),
                    "backpressure: throttling request"
                );
                Self::sleep_with_cx_budget(cx, BACKPRESSURE_THROTTLE_DELAY)?;
                Ok(false)
            }
            BackpressureDecision::Shed => {
                self.inner.metrics.record_shed();
                Ok(true)
            }
        }
    }

    fn sleep_with_cx_budget(cx: &Cx, delay: Duration) -> ffs_error::Result<()> {
        if delay.is_zero() {
            return Ok(());
        }

        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let budget = cx.budget();
        let now = cx.now();
        if budget.is_past_deadline(now)
            || budget
                .remaining_time(now)
                .is_some_and(|remaining| remaining <= delay)
        {
            return Err(FfsError::Cancelled);
        }
        let mut remaining = delay;
        while !remaining.is_zero() {
            let slice = remaining.min(BACKPRESSURE_SLEEP_CHECK_INTERVAL);
            let budget = cx.budget();
            let now = cx.now();
            if budget.is_past_deadline(now)
                || budget
                    .remaining_time(now)
                    .is_some_and(|remaining| remaining <= slice)
            {
                return Err(FfsError::Cancelled);
            }
            std::thread::sleep(slice);
            remaining = remaining.saturating_sub(slice);
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        }

        Ok(())
    }

    #[cfg(test)]
    fn should_shed(&self, op: RequestOp) -> bool {
        let cx = Self::cx_for_request();
        self.should_shed_with_cx(&cx, op).unwrap_or(true)
    }

    fn acquire_mutation_inode_guards(&self, inodes: &[InodeNumber]) -> FuseInodeGuards {
        self.inner.inode_locks.acquire(inodes)
    }

    fn try_acquire_mutation_inode_guards(&self, inodes: &[InodeNumber]) -> Option<FuseInodeGuards> {
        self.inner.inode_locks.try_acquire(inodes)
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

    /// Reply to `LOOKUP` with a protocol negative entry, not merely `ENOENT`.
    ///
    /// Linux caches a `fuse_entry_out` whose node id is zero for `entry_valid`.
    /// `ReplyEntry::error(ENOENT)` deliberately carries no such validity, so it
    /// makes every repeated miss cross FUSE again. The remaining attribute
    /// fields are ignored for a zero node id.
    fn reply_negative_entry(reply: ReplyEntry) {
        let negative = FileAttr {
            ino: 0,
            size: 0,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 0,
            flags: 0,
        };
        reply.entry(&NEGATIVE_ENTRY_TTL, &negative, 0);
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

    fn parse_setxattr_mode(flags: i32, position: u32) -> Result<XattrSetMode, c_int> {
        if position != 0 {
            return Err(libc::EINVAL);
        }

        let known = XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE;
        if flags & !known != 0 {
            return Err(libc::EINVAL);
        }

        let create = flags & XATTR_FLAG_CREATE != 0;
        let replace = flags & XATTR_FLAG_REPLACE != 0;
        if create && replace {
            return Err(libc::EINVAL);
        }

        if create {
            Ok(XattrSetMode::Create)
        } else if replace {
            Ok(XattrSetMode::Replace)
        } else {
            Ok(XattrSetMode::Set)
        }
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

    fn parse_fiemap_request(in_data: &[u8]) -> Result<(u64, u64, u32, u32), c_int> {
        if in_data.len() < FIEMAP_HEADER_SIZE {
            return Err(libc::EINVAL);
        }

        let fm_start = u64::from_ne_bytes(
            in_data[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let fm_length = u64::from_ne_bytes(
            in_data[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let fm_flags = u32::from_ne_bytes(
            in_data[FIEMAP_FLAGS_OFFSET..FIEMAP_FLAGS_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let fm_extent_count = u32::from_ne_bytes(
            in_data[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );

        Ok((fm_start, fm_length, fm_flags, fm_extent_count))
    }

    fn parse_move_ext_request(in_data: &[u8]) -> Result<(u32, u64, u64, u64), c_int> {
        if in_data.len() < MOVE_EXT_SIZE {
            return Err(libc::EINVAL);
        }

        let reserved = u32::from_ne_bytes(
            in_data[MOVE_EXT_RESERVED_OFFSET..MOVE_EXT_RESERVED_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        if reserved != 0 {
            return Err(libc::EINVAL);
        }

        let donor_fd = i32::from_ne_bytes(
            in_data[MOVE_EXT_DONOR_FD_OFFSET..MOVE_EXT_DONOR_FD_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        if donor_fd < 0 {
            return Err(libc::EBADF);
        }
        let orig_start = u64::from_ne_bytes(
            in_data[MOVE_EXT_ORIG_START_OFFSET..MOVE_EXT_ORIG_START_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let donor_start = u64::from_ne_bytes(
            in_data[MOVE_EXT_DONOR_START_OFFSET..MOVE_EXT_DONOR_START_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let len = u64::from_ne_bytes(
            in_data[MOVE_EXT_LEN_OFFSET..MOVE_EXT_LEN_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );

        if orig_start.checked_add(len).is_none() || donor_start.checked_add(len).is_none() {
            return Err(libc::EINVAL);
        }

        Ok((
            u32::try_from(donor_fd).map_err(|_| libc::EBADF)?,
            orig_start,
            donor_start,
            len,
        ))
    }

    fn parse_u32_ioctl_arg(in_data: &[u8]) -> Result<u32, c_int> {
        if in_data.len() < std::mem::size_of::<u32>() {
            return Err(libc::EINVAL);
        }
        let mut bytes = [0_u8; std::mem::size_of::<u32>()];
        bytes.copy_from_slice(&in_data[..std::mem::size_of::<u32>()]);
        Ok(u32::from_ne_bytes(bytes))
    }

    fn parse_btrfs_tree_search_key(in_data: &[u8]) -> Result<BtrfsTreeSearchKey, c_int> {
        if in_data.len() < BTRFS_TREE_SEARCH_KEY_SIZE {
            return Err(libc::EINVAL);
        }

        let read_u64 = |offset: usize| -> u64 {
            u64::from_ne_bytes(
                in_data[offset..offset + 8]
                    .try_into()
                    .expect("validated btrfs search key u64 field"),
            )
        };
        let read_u32 = |offset: usize| -> u32 {
            u32::from_ne_bytes(
                in_data[offset..offset + 4]
                    .try_into()
                    .expect("validated btrfs search key u32 field"),
            )
        };

        Ok(BtrfsTreeSearchKey {
            tree_id: read_u64(0),
            min_objectid: read_u64(8),
            max_objectid: read_u64(16),
            min_offset: read_u64(24),
            max_offset: read_u64(32),
            min_transid: read_u64(40),
            max_transid: read_u64(48),
            min_type: read_u32(56),
            max_type: read_u32(60),
            nr_items: read_u32(BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET),
        })
    }

    fn parse_inode_flags(in_data: &[u8]) -> Result<u32, c_int> {
        Self::parse_u32_ioctl_arg(in_data)
    }

    fn parse_fs_label_request(in_data: &[u8]) -> Result<Vec<u8>, c_int> {
        let parse_window = &in_data[..in_data.len().min(FSLABEL_MAX)];
        let Some(nul_pos) = parse_window.iter().position(|&byte| byte == 0) else {
            return Err(libc::EINVAL);
        };
        Ok(parse_window[..nul_pos].to_vec())
    }

    fn clamp_fiemap_extent_count(requested: u32, out_size: u32) -> usize {
        let max_extents_by_count = usize::try_from(requested).unwrap_or(usize::MAX);
        let max_extents_by_size = if usize::try_from(out_size).unwrap_or(0) > FIEMAP_HEADER_SIZE {
            (usize::try_from(out_size).unwrap_or(0) - FIEMAP_HEADER_SIZE) / FIEMAP_EXTENT_SIZE
        } else {
            0
        };
        max_extents_by_count.min(max_extents_by_size)
    }

    /// Serialise an [`FsxattrInfo`] into the 28-byte `struct fsxattr`
    /// payload returned by `FS_IOC_FSGETXATTR`. Layout per
    /// `<uapi/linux/fs.h>`: `xflags | extsize | nextents | projid |
    /// cowextsize | 8 bytes pad`. The Linux FUSE driver does no byte-swapping
    /// on ioctl payloads, so the FS daemon must match host byte order.
    /// Parse the 24-byte `struct fstrim_range` from FITRIM input.
    /// Layout: u64 start + u64 len + u64 minlen, host-native.
    fn parse_fstrim_range(buf: &[u8]) -> Result<(u64, u64, u64), i32> {
        if buf.len() < FITRIM_SIZE as usize {
            return Err(libc::EINVAL);
        }
        let start = u64::from_ne_bytes(buf[0..8].try_into().map_err(|_| libc::EINVAL)?);
        let len = u64::from_ne_bytes(buf[8..16].try_into().map_err(|_| libc::EINVAL)?);
        let min_len = u64::from_ne_bytes(buf[16..24].try_into().map_err(|_| libc::EINVAL)?);
        Ok((start, len, min_len))
    }

    /// Serialise the FITRIM response: the kernel writes the
    /// bytes-discarded count back into `fstrim_range.len` while
    /// leaving start + minlen unchanged.
    fn encode_fstrim_response(start: u64, bytes_discarded: u64, min_len: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FITRIM_SIZE as usize);
        buf.extend_from_slice(&start.to_ne_bytes());
        buf.extend_from_slice(&bytes_discarded.to_ne_bytes());
        buf.extend_from_slice(&min_len.to_ne_bytes());
        debug_assert_eq!(buf.len(), FITRIM_SIZE as usize);
        buf
    }

    /// Serialise the FS UUID into the 17-byte `struct fsuuid2`
    /// payload returned by `FS_IOC_GETFSUUID`. Layout per
    /// `<uapi/linux/fs.h>`: `u8 len` (always 16 for ext4 + btrfs) +
    /// `u8 uuid[16]`. The kernel copies the struct verbatim into
    /// userspace so byte order is host-native (the UUID itself is an
    /// opaque 16-byte token).
    fn encode_fsuuid_response(uuid: &[u8; 16]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FS_IOC_GETFSUUID_SIZE as usize);
        buf.push(16); // fsuuid2.len
        buf.extend_from_slice(uuid);
        debug_assert_eq!(buf.len(), FS_IOC_GETFSUUID_SIZE as usize);
        buf
    }

    /// Serialise a sysfs path into the 129-byte `struct fs_sysfs_path`
    /// payload returned by `FS_IOC_GETFSSYSFSPATH`. Layout per
    /// `<uapi/linux/fs.h>`: `u8 len` + `u8 name[128]`. `name` is
    /// zero-padded; `len` records the actual byte count. An empty path
    /// (the FUSE-backend default) encodes to `len = 0` followed by 128
    /// NUL bytes — userspace probes treat that as "no sysfs visibility"
    /// and skip silently. Returns `Err(EINVAL)` if the backend hands us
    /// a path longer than the 128-byte field can hold; the dispatcher
    /// turns that into a userspace EINVAL per the ioctl contract.
    fn encode_fs_sysfs_path_response(path: &[u8]) -> Result<Vec<u8>, i32> {
        if path.len() > FS_IOC_GETFSSYSFSPATH_NAME_MAX {
            return Err(libc::EINVAL);
        }
        let mut buf = vec![0_u8; FS_IOC_GETFSSYSFSPATH_SIZE as usize];
        // Cast is safe: bounds-checked against NAME_MAX (128) above.
        #[expect(clippy::cast_possible_truncation)]
        {
            buf[0] = path.len() as u8; // len byte
        }
        buf[1..=path.len()].copy_from_slice(path);
        // bytes [1 + path.len() .. 129] stay zero (NUL-padded name field).
        debug_assert_eq!(buf.len(), FS_IOC_GETFSSYSFSPATH_SIZE as usize);
        Ok(buf)
    }

    /// Parse the 28-byte `struct fsxattr` payload that userspace passes
    /// through `FS_IOC_FSSETXATTR`. Returns `EINVAL` if the buffer is
    /// the wrong length — callers must surface that errno verbatim per
    /// the Linux ioctl contract.
    fn parse_fsxattr_request(buf: &[u8]) -> Result<FsxattrInfo, i32> {
        if buf.len() < FS_IOC_FSSETXATTR_SIZE {
            return Err(libc::EINVAL);
        }
        let xflags = u32::from_ne_bytes(buf[0..4].try_into().map_err(|_| libc::EINVAL)?);
        let extsize = u32::from_ne_bytes(buf[4..8].try_into().map_err(|_| libc::EINVAL)?);
        // fsx_nextents (bytes 8..12) is read-only on the SET path and
        // must be ignored — kernel zeroes it on its own copy.
        let proj = u32::from_ne_bytes(buf[12..16].try_into().map_err(|_| libc::EINVAL)?);
        let cowextsize = u32::from_ne_bytes(buf[16..20].try_into().map_err(|_| libc::EINVAL)?);
        // fsx_pad[8] (bytes 20..28) is reserved; tolerate non-zero
        // padding to match the kernel which silently zeroes it.
        Ok(FsxattrInfo {
            xflags,
            extsize,
            nextents: 0,
            projid: proj,
            cowextsize,
        })
    }

    fn encode_fsxattr_response(fsx: &FsxattrInfo) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FS_IOC_FSGETXATTR_SIZE as usize);
        buf.extend_from_slice(&fsx.xflags.to_ne_bytes());
        buf.extend_from_slice(&fsx.extsize.to_ne_bytes());
        buf.extend_from_slice(&fsx.nextents.to_ne_bytes());
        buf.extend_from_slice(&fsx.projid.to_ne_bytes());
        buf.extend_from_slice(&fsx.cowextsize.to_ne_bytes());
        buf.extend_from_slice(&[0_u8; 8]); // fsx_pad[8]
        debug_assert_eq!(buf.len(), FS_IOC_FSGETXATTR_SIZE as usize);
        buf
    }

    fn encode_fiemap_response(
        fm_start: u64,
        fm_length: u64,
        requested_extent_count: u32,
        extents: &[FiemapExtent],
        out_size: u32,
    ) -> Vec<u8> {
        let returned_extents = extents
            .iter()
            .take(Self::clamp_fiemap_extent_count(
                requested_extent_count,
                out_size,
            ))
            .collect::<Vec<_>>();
        let mapped_count = u32::try_from(returned_extents.len()).unwrap_or(u32::MAX);

        let response_size = FIEMAP_HEADER_SIZE + returned_extents.len() * FIEMAP_EXTENT_SIZE;
        let mut response = vec![0_u8; response_size];

        response[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8]
            .copy_from_slice(&fm_start.to_ne_bytes());
        response[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
            .copy_from_slice(&fm_length.to_ne_bytes());
        response[FIEMAP_MAPPED_EXTENTS_OFFSET..FIEMAP_MAPPED_EXTENTS_OFFSET + 4]
            .copy_from_slice(&mapped_count.to_ne_bytes());
        response[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
            .copy_from_slice(&requested_extent_count.to_ne_bytes());

        for (i, ext) in returned_extents.iter().enumerate() {
            let off = FIEMAP_HEADER_SIZE + i * FIEMAP_EXTENT_SIZE;
            response[off..off + 8].copy_from_slice(&ext.logical.to_ne_bytes());
            response[off + 8..off + 16].copy_from_slice(&ext.physical.to_ne_bytes());
            response[off + 16..off + 24].copy_from_slice(&ext.length.to_ne_bytes());
            response[off + 40..off + 44].copy_from_slice(&ext.flags.to_ne_bytes());
        }

        response
    }

    fn encode_move_ext_response(
        donor_fd: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
        moved_len: u64,
    ) -> Vec<u8> {
        let mut response = vec![0_u8; MOVE_EXT_SIZE];
        response[MOVE_EXT_DONOR_FD_OFFSET..MOVE_EXT_DONOR_FD_OFFSET + 4]
            .copy_from_slice(&donor_fd.to_ne_bytes());
        response[MOVE_EXT_ORIG_START_OFFSET..MOVE_EXT_ORIG_START_OFFSET + 8]
            .copy_from_slice(&orig_start.to_ne_bytes());
        response[MOVE_EXT_DONOR_START_OFFSET..MOVE_EXT_DONOR_START_OFFSET + 8]
            .copy_from_slice(&donor_start.to_ne_bytes());
        response[MOVE_EXT_LEN_OFFSET..MOVE_EXT_LEN_OFFSET + 8].copy_from_slice(&len.to_ne_bytes());
        response[MOVE_EXT_MOVED_LEN_OFFSET..MOVE_EXT_MOVED_LEN_OFFSET + 8]
            .copy_from_slice(&moved_len.to_ne_bytes());
        response
    }

    fn validate_move_ext_range(
        blksize: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> Result<(), c_int> {
        let blocks_per_page = (MOVE_EXT_PAGE_SIZE_BYTES / u64::from(blksize.max(1))).max(1);
        if orig_start % blocks_per_page != donor_start % blocks_per_page {
            return Err(libc::EINVAL);
        }

        let orig_end = orig_start.checked_add(len).ok_or(libc::EINVAL)?;
        let donor_end = donor_start.checked_add(len).ok_or(libc::EINVAL)?;
        if orig_start >= EXT4_MOVE_EXT_MAX_BLOCKS
            || donor_start >= EXT4_MOVE_EXT_MAX_BLOCKS
            || len > EXT4_MOVE_EXT_MAX_BLOCKS
            || orig_end >= EXT4_MOVE_EXT_MAX_BLOCKS
            || donor_end >= EXT4_MOVE_EXT_MAX_BLOCKS
        {
            return Err(libc::EINVAL);
        }

        Ok(())
    }

    fn validate_move_ext_source(attr: &InodeAttr, flags: u32) -> Result<(), c_int> {
        if attr.kind != FfsFileType::RegularFile {
            return Err(libc::EINVAL);
        }
        if attr.size == 0 {
            return Err(libc::EINVAL);
        }
        if flags & EXT4_EXTENTS_FL == 0 {
            return Err(libc::EOPNOTSUPP);
        }
        Ok(())
    }

    fn move_ext_operation_id(
        ino: u64,
        donor_fd: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> String {
        format!("fuse-move-ext-{ino}-{donor_fd}-{orig_start}-{donor_start}-{len}")
    }

    fn classify_move_ext_error(error: &FfsError) -> &'static str {
        match error {
            FfsError::ReadOnly => "read_only",
            FfsError::UnsupportedFeature(_) => "unsupported_feature",
            FfsError::InvalidGeometry(_) | FfsError::Format(_) | FfsError::Parse(_) => {
                "invalid_request"
            }
            FfsError::NotFound(_) => "not_found",
            FfsError::Io(io_error) => match io_error.raw_os_error() {
                Some(libc::EBADF) => "bad_donor_fd",
                Some(libc::EINVAL) => "invalid_request",
                Some(libc::EPERM) => "permission_denied",
                Some(libc::EROFS) => "read_only",
                Some(libc::EOPNOTSUPP) => "unsupported_feature",
                Some(libc::ENOTTY) => "unsupported_ioctl",
                _ => "io_error",
            },
            _ => "operation_failed",
        }
    }

    fn move_ext_success_log_record(
        ctx: MoveExtLogContext<'_>,
        moved_len: u64,
    ) -> MoveExtLogRecord<'_> {
        MoveExtLogRecord {
            target: "ffs::ioctl",
            operation_id: ctx.operation_id,
            scenario_id: MOVE_EXT_SCENARIO_ID,
            outcome: "applied",
            error_class: MOVE_EXT_SUCCESS_ERROR_CLASS,
            ino: ctx.ino,
            donor_ino: ctx.donor_ino.map(|ino| ino.0),
            donor_fd: ctx.donor_fd,
            orig_start: ctx.orig_start,
            donor_start: ctx.donor_start,
            len: ctx.len,
            moved_len: Some(moved_len),
            errno: None,
        }
    }

    fn move_ext_error_log_record<'a>(
        ctx: MoveExtLogContext<'a>,
        error: &FfsError,
    ) -> MoveExtLogRecord<'a> {
        let error_class = Self::classify_move_ext_error(error);
        let outcome = match error.to_errno() {
            libc::EBADF
            | libc::EINVAL
            | libc::EPERM
            | libc::EROFS
            | libc::EOPNOTSUPP
            | libc::ENOTTY => "rejected",
            _ => "failed",
        };
        MoveExtLogRecord {
            target: "ffs::ioctl",
            operation_id: ctx.operation_id,
            scenario_id: MOVE_EXT_SCENARIO_ID,
            outcome,
            error_class,
            ino: ctx.ino,
            donor_ino: ctx.donor_ino.map(|ino| ino.0),
            donor_fd: ctx.donor_fd,
            orig_start: ctx.orig_start,
            donor_start: ctx.donor_start,
            len: ctx.len,
            moved_len: None,
            errno: Some(error.to_errno()),
        }
    }

    fn log_move_ext_success(ctx: MoveExtLogContext<'_>, moved_len: u64) {
        let record = Self::move_ext_success_log_record(ctx, moved_len);
        let logged_moved_len = record.moved_len.unwrap_or(0);
        info!(
            target: "ffs::ioctl",
            operation_id = record.operation_id,
            scenario_id = record.scenario_id,
            outcome = record.outcome,
            error_class = record.error_class,
            ino = record.ino,
            donor_ino = record.donor_ino,
            donor_fd = record.donor_fd,
            orig_start = record.orig_start,
            donor_start = record.donor_start,
            len = record.len,
            moved_len = logged_moved_len,
            "ext4 move_ext completed"
        );
    }

    fn log_move_ext_error(ctx: MoveExtLogContext<'_>, error: &FfsError) {
        let record = Self::move_ext_error_log_record(ctx, error);
        let logged_errno = record.errno.unwrap_or(libc::EIO);
        warn!(
            target: "ffs::ioctl",
            operation_id = record.operation_id,
            scenario_id = record.scenario_id,
            outcome = record.outcome,
            error_class = record.error_class,
            ino = record.ino,
            donor_ino = record.donor_ino,
            donor_fd = record.donor_fd,
            orig_start = record.orig_start,
            donor_start = record.donor_start,
            len = record.len,
            errno = logged_errno,
            error = %error,
            "ext4 move_ext rejected"
        );
    }

    fn resolve_move_ext_donor(
        &self,
        caller_pid: u32,
        donor_fd: u32,
    ) -> ffs_error::Result<InodeNumber> {
        let proc_fd_path = PathBuf::from(format!("/proc/{caller_pid}/fd/{donor_fd}"));
        let donor_file = std::fs::File::open(&proc_fd_path)
            .map_err(|_| FfsError::Io(std::io::Error::from_raw_os_error(libc::EBADF)))?;
        let donor_meta = donor_file
            .metadata()
            .map_err(|_| FfsError::Io(std::io::Error::from_raw_os_error(libc::EBADF)))?;

        if let Some(mountpoint) = self.inner.mountpoint.as_ref() {
            let mount_meta = std::fs::metadata(mountpoint)
                .map_err(|_| FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL)))?;
            if donor_meta.dev() != mount_meta.dev() {
                return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                    libc::EINVAL,
                )));
            }
        }

        Ok(InodeNumber(donor_meta.ino()))
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_ioctl(
        &self,
        caller_pid: u32,
        ino: u64,
        fh: u64,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
    ) -> IoctlResult {
        let cmd = match cmd {
            BTRFS_IOC_CLONE => FICLONE,
            BTRFS_IOC_CLONE_RANGE => FICLONERANGE,
            other => other,
        };
        match cmd {
            FS_IOC_FIEMAP => {
                let (fm_start, fm_length, fm_flags, fm_extent_count) =
                    match Self::parse_fiemap_request(in_data) {
                        Ok(request) => request,
                        Err(errno) => return IoctlResult::Error(errno),
                    };
                if fm_flags & !FIEMAP_SUPPORTED_FLAGS != 0 {
                    return IoctlResult::Error(libc::EBADR);
                }

                if out_size < u32::try_from(FIEMAP_HEADER_SIZE).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }

                let cx = Self::cx_for_request();
                if fm_flags & FIEMAP_FLAG_SYNC != 0 && !self.inner.read_only {
                    match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
                        self.inner
                            .ops
                            .fsync(cx, scope, InodeNumber(ino), fh, false)?;
                        self.inner.ops.commit_request_scope(scope)?;
                        Ok(())
                    }) {
                        Ok(()) => {}
                        Err(error) => return IoctlResult::Error(error.to_errno()),
                    }
                }
                let extents =
                    match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                        self.inner
                            .ops
                            .fiemap(cx, scope, InodeNumber(ino), fm_start, fm_length)
                    }) {
                        Ok(exts) => exts,
                        Err(error) => return IoctlResult::Error(error.to_errno()),
                    };

                IoctlResult::Data(Self::encode_fiemap_response(
                    fm_start,
                    fm_length,
                    fm_extent_count,
                    &extents,
                    out_size,
                ))
            }
            EXT4_IOC_GETFLAGS => {
                if out_size < u32::try_from(std::mem::size_of::<u32>()).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_inode_flags(cx, scope, InodeNumber(ino))
                }) {
                    Ok(flags) => IoctlResult::Data(flags.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_GETSTATE => {
                // _IOR with a 4-byte payload: validate the user buffer
                // can hold the u32 reply, route through FsOps under
                // an IoctlRead scope, and encode the host-native u32
                // back to userspace. The kernel never returns an
                // error for a valid inode here, but we propagate
                // backend errors (e.g. ENOENT) the same way.
                if out_size < EXT4_IOC_GETSTATE_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_inode_state(cx, scope, InodeNumber(ino))
                }) {
                    Ok(state) => IoctlResult::Data(state.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            cmd if cmd == EXT4_IOC_GETVERSION || cmd == FS_IOC_GETVERSION => {
                if out_size < u32::try_from(std::mem::size_of::<u32>()).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_inode_generation(cx, scope, InodeNumber(ino))
                }) {
                    Ok(generation) => IoctlResult::Data(generation.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FIBMAP => {
                if out_size < FIBMAP_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let logical = match Self::parse_u32_ioctl_arg(in_data) {
                    Ok(value) => u64::from(value),
                    Err(errno) => return IoctlResult::Error(errno),
                };
                let cx = Self::cx_for_request();
                let (block_size, extents) =
                    match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                        let stats = self.inner.ops.statfs(cx, scope, InodeNumber(ino))?;
                        let block_size = u64::from(stats.block_size);
                        if block_size == 0 {
                            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                                libc::EINVAL,
                            )));
                        }
                        let extents = self.inner.ops.fiemap(
                            cx,
                            scope,
                            InodeNumber(ino),
                            logical.saturating_mul(block_size),
                            block_size,
                        )?;
                        Ok((block_size, extents))
                    }) {
                        Ok(result) => result,
                        Err(error) => return IoctlResult::Error(error.to_errno()),
                    };
                let req_byte = logical.saturating_mul(block_size);
                // Hole / sparse range -> 0 per fs/ext4/inode.c::ext4_get_block.
                let physical_block = extents
                    .into_iter()
                    .find(|e| {
                        // The first extent that actually covers the
                        // queried logical block (fiemap may return an
                        // extent that starts later if the query falls
                        // in a hole).
                        e.logical <= req_byte && req_byte < e.logical.saturating_add(e.length)
                    })
                    .map_or(0_u64, |e| {
                        if e.flags & FIEMAP_EXTENT_UNWRITTEN != 0 {
                            return 0;
                        }
                        let offset_into = req_byte - e.logical;
                        e.physical.saturating_add(offset_into) / block_size
                    });
                let physical_u32 = u32::try_from(physical_block).unwrap_or(u32::MAX);
                IoctlResult::Data(physical_u32.to_ne_bytes().to_vec())
            }
            FITRIM => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if out_size < FITRIM_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let (start, len, min_len) = match Self::parse_fstrim_range(in_data) {
                    Ok(parsed) => parsed,
                    Err(errno) => return IoctlResult::Error(errno),
                };
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.trim_range(cx, scope, start, len, min_len)
                }) {
                    Ok(bytes_discarded) => IoctlResult::Data(Self::encode_fstrim_response(
                        start,
                        bytes_discarded,
                        min_len,
                    )),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_GETFSUUID => {
                if out_size < FS_IOC_GETFSUUID_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                match self.inner.ops.fs_uuid() {
                    Ok(uuid) => IoctlResult::Data(Self::encode_fsuuid_response(&uuid)),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_GETFSSYSFSPATH => {
                if out_size < FS_IOC_GETFSSYSFSPATH_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                match self.inner.ops.fs_sysfs_path() {
                    Ok(path) => match Self::encode_fs_sysfs_path_response(&path) {
                        Ok(buf) => IoctlResult::Data(buf),
                        Err(errno) => IoctlResult::Error(errno),
                    },
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_FSGETXATTR => {
                if out_size < FS_IOC_FSGETXATTR_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_inode_fsxattr(cx, scope, InodeNumber(ino))
                }) {
                    Ok(fsx) => IoctlResult::Data(Self::encode_fsxattr_response(&fsx)),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_FSSETXATTR => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let fsx = match Self::parse_fsxattr_request(in_data) {
                    Ok(fsx) => fsx,
                    Err(errno) => return IoctlResult::Error(errno),
                };
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .set_inode_fsxattr(cx, scope, InodeNumber(ino), fsx)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_PRECACHE_EXTENTS => {
                // _IO with no payload: ignore in_data / out_size and
                // run the precache walk under a read scope. ext4 always
                // returns 0 for valid inodes (the per-inode precache is
                // a best-effort hint), so propagate backend errors but
                // keep success as an empty Data reply.
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.precache_extents(cx, scope, InodeNumber(ino))
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_CLEAR_ES_CACHE => {
                // _IO with no payload: same dispatch shape as
                // EXT4_IOC_PRECACHE_EXTENTS. ext4_clear_inode_es is
                // always a successful no-op for a valid inode in the
                // kernel; we mirror that contract by routing through
                // FsOps::clear_extent_status_cache and propagating only
                // backend errors (e.g. ENOENT for a bogus inode).
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .clear_extent_status_cache(cx, scope, InodeNumber(ino))
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            cmd if cmd == EXT4_IOC_SETVERSION || cmd == FS_IOC_SETVERSION => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let generation = match Self::parse_u32_ioctl_arg(in_data) {
                    Ok(generation) => generation,
                    Err(errno) => return IoctlResult::Error(errno),
                };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .set_inode_generation(cx, scope, InodeNumber(ino), generation)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_GET_ENCRYPTION_POLICY => {
                // Linux exposes the legacy v1 fscrypt getter as an `_IOW` ioctl,
                // so real mounted-path requests often arrive with a caller buffer
                // in `in_data` and `out_size == 0`. Unit tests that bypass the
                // kernel still use the simpler `out_size` form, so accept either
                // request shape as long as one side advertises a full v1 policy
                // buffer. Note that restricted FUSE still cannot return success
                // data for this ioctl shape: the kernel advertises zero output
                // bytes and converts any non-empty reply into `EIO`.
                let advertised_len =
                    usize::max(in_data.len(), usize::try_from(out_size).unwrap_or(0));
                if advertised_len < FSCRYPT_POLICY_V1_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_encryption_policy_v1(cx, scope, InodeNumber(ino))
                }) {
                    Ok(policy) => IoctlResult::Data(policy.to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_GET_ENCRYPTION_POLICY_EX => {
                // The _EX ioctl uses a struct fscrypt_get_policy_ex_arg:
                //   policy_size: u64 (in/out)
                //   policy: union { v1: [u8; 12], v2: [u8; 24] }
                // Input: caller sets policy_size to buffer capacity
                // Output: kernel sets policy_size to actual size
                //
                // Real mounted requests carry the caller's policy capacity in
                // the `policy_size` field. Direct unit tests that bypass the
                // kernel use `out_size`, so accept either advertised capacity.
                let advertised_by_in_data = if in_data.len() >= FSCRYPT_POLICY_EX_HEADER_SIZE {
                    let mut raw_size = [0_u8; FSCRYPT_POLICY_EX_HEADER_SIZE];
                    raw_size.copy_from_slice(&in_data[..FSCRYPT_POLICY_EX_HEADER_SIZE]);
                    usize::try_from(u64::from_ne_bytes(raw_size))
                        .ok()
                        .and_then(|policy_size| {
                            policy_size.checked_add(FSCRYPT_POLICY_EX_HEADER_SIZE)
                        })
                        .unwrap_or(usize::MAX)
                } else {
                    in_data.len()
                };
                let advertised_len = if in_data.len() >= FSCRYPT_POLICY_EX_HEADER_SIZE {
                    advertised_by_in_data
                } else {
                    usize::try_from(out_size).unwrap_or(0)
                };

                // We must check the caller's advertised capacity against the
                // actual policy size returned by the backend, not just the v1
                // minimum, to avoid returning more bytes than the caller can
                // accept for v2 policies.
                let min_out_size = FSCRYPT_POLICY_EX_HEADER_SIZE + FSCRYPT_POLICY_V1_SIZE;
                if advertised_len < min_out_size {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_encryption_policy_ex(cx, scope, InodeNumber(ino))
                }) {
                    Ok((version, policy)) => {
                        let required_size = FSCRYPT_POLICY_EX_HEADER_SIZE + policy.len();
                        if advertised_len < required_size {
                            // Caller buffer too small for the actual policy version.
                            return IoctlResult::Error(libc::EOVERFLOW);
                        }
                        let policy_size = policy.len() as u64;
                        let mut buf = vec![0_u8; required_size];
                        buf[..8].copy_from_slice(&policy_size.to_ne_bytes());
                        buf[8..8 + policy.len()].copy_from_slice(&policy);
                        if version == 0 {
                            // v1 policy: version byte is already 0 in position 8
                        } else {
                            // v2 policy: set version byte at position 8
                            buf[8] = version;
                        }
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_SETFLAGS => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let flags = match Self::parse_inode_flags(in_data) {
                    Ok(flags) => flags,
                    Err(errno) => return IoctlResult::Error(errno),
                };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .set_inode_flags(cx, scope, InodeNumber(ino), flags)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_MOVE_EXT => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if out_size < u32::try_from(MOVE_EXT_SIZE).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let (donor_fd, orig_start, donor_start, len) =
                    match Self::parse_move_ext_request(in_data) {
                        Ok(request) => request,
                        Err(errno) => return IoctlResult::Error(errno),
                    };
                let operation_id =
                    Self::move_ext_operation_id(ino, donor_fd, orig_start, donor_start, len);
                let log_ctx = MoveExtLogContext {
                    operation_id: &operation_id,
                    ino,
                    donor_ino: None,
                    donor_fd,
                    orig_start,
                    donor_start,
                    len,
                };

                let cx = Self::cx_for_request();
                let mut donor_ino = None;
                let mut donor_registered = false;
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    let attr = self.inner.ops.getattr(cx, scope, InodeNumber(ino))?;
                    let flags = self
                        .inner
                        .ops
                        .get_inode_flags(cx, scope, InodeNumber(ino))?;
                    Self::validate_move_ext_source(&attr, flags)
                        .map_err(|errno| FfsError::Io(std::io::Error::from_raw_os_error(errno)))?;
                    Self::validate_move_ext_range(attr.blksize, orig_start, donor_start, len)
                        .map_err(|_| FfsError::InvalidGeometry("invalid move_ext range".into()))?;
                    let resolved_donor = self.resolve_move_ext_donor(caller_pid, donor_fd)?;
                    donor_ino = Some(resolved_donor);
                    self.inner
                        .ops
                        .register_move_ext_donor_fd(donor_fd, resolved_donor)?;
                    donor_registered = true;
                    let moved_len = self.inner.ops.move_ext(
                        cx,
                        scope,
                        InodeNumber(ino),
                        donor_fd,
                        orig_start,
                        donor_start,
                        len,
                    )?;
                    self.inner.ops.unregister_move_ext_donor_fd(donor_fd);
                    donor_registered = false;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(moved_len)
                }) {
                    Ok(moved_len) => {
                        let mut success_ctx = log_ctx;
                        success_ctx.donor_ino = donor_ino;
                        Self::log_move_ext_success(success_ctx, moved_len);
                        IoctlResult::Data(Self::encode_move_ext_response(
                            donor_fd,
                            orig_start,
                            donor_start,
                            len,
                            moved_len,
                        ))
                    }
                    Err(error) => {
                        if donor_registered {
                            self.inner.ops.unregister_move_ext_donor_fd(donor_fd);
                        }
                        let mut error_ctx = log_ctx;
                        error_ctx.donor_ino = donor_ino;
                        Self::log_move_ext_error(error_ctx, &error);
                        IoctlResult::Error(error.to_errno())
                    }
                }
            }
            EXT4_IOC_GROUP_EXTEND => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_group_extend(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_RESIZE_FS => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_resize_fs(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_GROUP_ADD => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 16 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_group_add(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_ALLOC_DA_BLKS => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_alloc_da_blks(cx, scope, ino)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_MIGRATE => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_migrate(cx, scope, ino)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_SWAP_BOOT => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.ext4_swap_boot(cx, scope, ino)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FS_IOC_SHUTDOWN => {
                if in_data.len() < 4 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.fs_shutdown(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FIFREEZE => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.fs_freeze(cx, scope)
                }) {
                    Ok(level) => {
                        let mut buf = [0u8; 4];
                        buf.copy_from_slice(&level.to_ne_bytes());
                        IoctlResult::Data(buf.to_vec())
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FITHAW => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.fs_thaw(cx, scope)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FIGETBSZ => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_block_size(cx, scope)
                }) {
                    Ok(bsz) => {
                        let mut buf = [0u8; 4];
                        // FIGETBSZ returns i32; block sizes are always small (<= 65536)
                        #[expect(clippy::cast_possible_wrap)]
                        let bsz_i32 = bsz as i32;
                        buf.copy_from_slice(&bsz_i32.to_ne_bytes());
                        IoctlResult::Data(buf.to_vec())
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            cmd if cmd == FS_IOC_GETFSLABEL || cmd == BTRFS_IOC_GET_FSLABEL => {
                if out_size < FSLABEL_MAX_U32 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                debug_assert_eq!(BTRFS_FSLABEL_SIZE, FSLABEL_MAX_U32);
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_fs_label(cx, scope)
                }) {
                    Ok(label) => {
                        let mut buf = vec![0_u8; FSLABEL_MAX];
                        let copy_len = label.len().min(FSLABEL_MAX);
                        buf[..copy_len].copy_from_slice(&label[..copy_len]);
                        if copy_len < FSLABEL_MAX {
                            buf[copy_len] = 0;
                        }
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            cmd if cmd == FS_IOC_SETFSLABEL || cmd == BTRFS_IOC_SET_FSLABEL => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let label = match Self::parse_fs_label_request(in_data) {
                    Ok(label) => label,
                    Err(errno) => return IoctlResult::Error(errno),
                };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.set_fs_label(cx, scope, &label)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_FS_INFO => {
                // Reject if the caller's out buffer can't hold the full 1024-byte
                // `btrfs_ioctl_fs_info_args` struct — the kernel would truncate
                // it and hand back garbage padding, so fail deterministically.
                if out_size < BTRFS_IOC_FS_INFO_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_fs_info(cx, scope)
                }) {
                    Ok(payload) => {
                        // Backend contract: exactly 1024 bytes.  Be defensive
                        // — pad/truncate to that width so a single backend
                        // bug can't corrupt the kernel reply buffer.
                        let mut buf = vec![0_u8; BTRFS_IOC_FS_INFO_SIZE as usize];
                        let copy_len = payload.len().min(buf.len());
                        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEV_INFO => {
                // `_IOWR`: the caller's in_data carries `devid` + `uuid` lookup
                // keys (24 bytes are enough — offsets 0x00..0x08 + 0x08..0x18),
                // and the caller's out buffer must be able to hold the full
                // 4096-byte struct reply.  Any smaller shape is rejected
                // deterministically rather than silently truncated.
                if in_data.len() < 24 || out_size < BTRFS_IOC_DEV_INFO_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let mut raw_devid = [0_u8; 8];
                raw_devid.copy_from_slice(&in_data[0..8]);
                let devid_in = u64::from_ne_bytes(raw_devid);
                let mut uuid_in = [0_u8; 16];
                uuid_in.copy_from_slice(&in_data[8..24]);

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_btrfs_dev_info(cx, scope, devid_in, uuid_in)
                }) {
                    Ok(payload) => {
                        let mut buf = vec![0_u8; BTRFS_IOC_DEV_INFO_SIZE as usize];
                        let copy_len = payload.len().min(buf.len());
                        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_TREE_SEARCH => {
                if out_size < BTRFS_TREE_SEARCH_ARGS_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let search_key = match Self::parse_btrfs_tree_search_key(in_data) {
                    Ok(search_key) => search_key,
                    Err(errno) => return IoctlResult::Error(errno),
                };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_tree_search(cx, scope, search_key)
                }) {
                    Ok((nr_items, payload)) => {
                        let mut buf = vec![0_u8; BTRFS_TREE_SEARCH_ARGS_SIZE as usize];
                        buf[..BTRFS_TREE_SEARCH_KEY_SIZE]
                            .copy_from_slice(&in_data[..BTRFS_TREE_SEARCH_KEY_SIZE]);
                        buf[BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET
                            ..BTRFS_TREE_SEARCH_NR_ITEMS_OFFSET + 4]
                            .copy_from_slice(&nr_items.to_ne_bytes());

                        let tail_start = BTRFS_TREE_SEARCH_KEY_SIZE;
                        let copy_len = payload.len().min(buf.len() - tail_start);
                        buf[tail_start..tail_start + copy_len]
                            .copy_from_slice(&payload[..copy_len]);
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_INO_LOOKUP => {
                // Require full 4096-byte buffer for input and output.
                if in_data.len() < BTRFS_INO_LOOKUP_ARGS_SIZE as usize
                    || out_size < BTRFS_INO_LOOKUP_ARGS_SIZE
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                // Parse input: treeid (u64 at offset 0), objectid (u64 at offset 8).
                let mut raw_treeid = [0_u8; 8];
                raw_treeid.copy_from_slice(&in_data[0..8]);
                let treeid = u64::from_ne_bytes(raw_treeid);
                let mut raw_objectid = [0_u8; 8];
                raw_objectid.copy_from_slice(&in_data[8..16]);
                let objectid = u64::from_ne_bytes(raw_objectid);

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_ino_lookup(cx, scope, treeid, objectid)
                }) {
                    Ok((resolved_treeid, path)) => {
                        // Build output: treeid (8 bytes) + objectid (8 bytes) + name[4080].
                        let mut buf = vec![0_u8; BTRFS_INO_LOOKUP_ARGS_SIZE as usize];
                        buf[0..8].copy_from_slice(&resolved_treeid.to_ne_bytes());
                        buf[8..16].copy_from_slice(&objectid.to_ne_bytes());
                        let path_len = path.len().min(4080);
                        buf[16..16 + path_len].copy_from_slice(&path[..path_len]);
                        IoctlResult::Data(buf)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEFAULT_SUBVOL => {
                if in_data.len() < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let mut raw = [0_u8; 8];
                raw.copy_from_slice(&in_data[0..8]);
                let treeid = u64::from_ne_bytes(raw);
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_set_default_subvol(cx, scope, treeid)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SUBVOL_GETFLAGS => {
                if out_size < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_subvol_flags(cx, scope, InodeNumber(ino))
                }) {
                    Ok(flags) => IoctlResult::Data(flags.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SUBVOL_SETFLAGS => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 8 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let mut raw = [0_u8; 8];
                raw.copy_from_slice(&in_data[0..8]);
                let flags = u64::from_ne_bytes(raw);

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .set_subvol_flags(cx, scope, InodeNumber(ino), flags)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SYNC => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
                    self.inner.ops.sync_fs(cx, scope)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_TRANS_START => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_start_transaction(cx, scope)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_TRANS_END => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_end_transaction(cx, scope)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_START_SYNC => {
                if out_size < BTRFS_SYNC_TRANSID_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
                    self.inner.ops.btrfs_start_sync(cx, scope)
                }) {
                    Ok(transid) => IoctlResult::Data(transid.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_WAIT_SYNC => {
                if in_data.len() < BTRFS_SYNC_TRANSID_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let mut raw = [0_u8; 8];
                raw.copy_from_slice(&in_data[0..8]);
                let transid = u64::from_ne_bytes(raw);
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
                    self.inner.ops.btrfs_wait_sync(cx, scope, transid)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_FEATURES => {
                if out_size < BTRFS_FEATURE_FLAGS_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_features(cx, scope)
                }) {
                    Ok(flags) => IoctlResult::Data(flags),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SET_FEATURES => {
                if in_data.len() < BTRFS_SET_FEATURES_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.set_btrfs_features(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_SUPPORTED_FEATURES => {
                if out_size < BTRFS_SUPPORTED_FEATURE_FLAGS_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_supported_features(cx, scope)
                }) {
                    Ok(flags) => IoctlResult::Data(flags),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SPACE_INFO => {
                // Input: 16-byte header with space_slots (number of entries caller can receive)
                // Output: header (space_slots ignored, total_spaces set) + array of space_info
                if in_data.len() < BTRFS_SPACE_ARGS_HEADER_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let space_slots = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_space_info(cx, scope, space_slots)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_INO_PATHS => {
                // Input: 56-byte struct with inum, size, reserved, fspath pointer
                // For now, return EOPNOTSUPP as implementing backref resolution is complex
                if in_data.len() < BTRFS_INO_PATH_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let inum = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_ino_paths(cx, scope, inum)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_LOGICAL_INO => {
                // Input: 56-byte struct with logical addr, size, reserved, flags, inodes pointer
                // For now, return EOPNOTSUPP as implementing logical-to-inode is complex
                if in_data.len() < BTRFS_LOGICAL_INO_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let logical = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_btrfs_logical_ino(cx, scope, logical)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_LOGICAL_INO_V2 => {
                // V2 adds flags field at offset 32 for BTRFS_LOGICAL_INO_ARGS_IGNORE_OFFSET
                if in_data.len() < BTRFS_LOGICAL_INO_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let logical = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_btrfs_logical_ino_v2(cx, scope, logical, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SCRUB => {
                // Input: 1024-byte struct with devid, start, end, flags, progress
                if in_data.len() < BTRFS_SCRUB_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let devid = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_scrub_start(cx, scope, devid)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SCRUB_CANCEL => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_scrub_cancel(cx, scope)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SCRUB_PROGRESS => {
                // Input: 1024-byte struct with devid to query
                if in_data.len() < BTRFS_SCRUB_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let devid = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_scrub_progress(cx, scope, devid)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QUOTA_RESCAN_WAIT => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_wait_quota_rescan(cx, scope)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QUOTA_RESCAN_STATUS => {
                if out_size < BTRFS_QUOTA_RESCAN_ARGS_SIZE {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_quota_rescan_status(cx, scope)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QUOTA_RESCAN => {
                if in_data.len() < BTRFS_QUOTA_RESCAN_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let flags = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_start_quota_rescan(cx, scope, flags)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QUOTA_CTL => {
                if in_data.len() < BTRFS_QUOTA_CTL_ARGS_SIZE as usize
                    || out_size < BTRFS_QUOTA_CTL_ARGS_SIZE
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cmd = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let status = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_quota_control(cx, scope, cmd, status)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QGROUP_ASSIGN => {
                if in_data.len() < BTRFS_QGROUP_ASSIGN_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let assign = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let src = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let dst = u64::from_le_bytes(in_data[16..24].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_assign_qgroup(cx, scope, assign, src, dst)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QGROUP_CREATE => {
                if in_data.len() < BTRFS_QGROUP_CREATE_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let create = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let qgroupid = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_create_qgroup(cx, scope, create, qgroupid)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_QGROUP_LIMIT => {
                if in_data.len() < BTRFS_QGROUP_LIMIT_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let limit = BtrfsQgroupLimitRequest {
                    qgroupid: u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8])),
                    flags: u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8])),
                    max_rfer: u64::from_le_bytes(in_data[16..24].try_into().unwrap_or([0; 8])),
                    max_excl: u64::from_le_bytes(in_data[24..32].try_into().unwrap_or([0; 8])),
                    rsv_rfer: u64::from_le_bytes(in_data[32..40].try_into().unwrap_or([0; 8])),
                    rsv_excl: u64::from_le_bytes(in_data[40..48].try_into().unwrap_or([0; 8])),
                };
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_limit_qgroup(cx, scope, limit)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEFRAG_RANGE => {
                // Input: 48-byte struct with start, len, flags, extent_thresh, compress_type
                if in_data.len() < BTRFS_DEFRAG_RANGE_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let start = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let len = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_defrag_range(cx, scope, fh, start, len)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SNAP_CREATE_V2 => {
                // Input: 4096-byte vol_args_v2 with fd, transid, flags, name
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_snap_create(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SNAP_DESTROY => {
                // Input: 4096-byte vol_args with name
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_snap_destroy(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SNAP_DESTROY_V2 => {
                // Input: 4096-byte vol_args_v2 with subvolid field
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_snap_destroy_v2(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_ENCODED_READ => {
                // Input: 64-byte encoded_io_args with iovec info
                if in_data.len() < BTRFS_ENCODED_IO_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_encoded_read(cx, scope, ino, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_ENCODED_WRITE => {
                // Write is unsupported on read-only filesystem
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_encoded_write(cx, scope, ino, in_data)
                }) {
                    Ok(len) => {
                        let mut out = vec![0u8; 8];
                        out[0..8].copy_from_slice(&(len as u64).to_le_bytes());
                        IoctlResult::Data(out)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_RESIZE => {
                // Resize requires write access
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_resize(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEV_REPLACE => {
                // Input: 2600-byte dev_replace_args with cmd + status
                if in_data.len() < BTRFS_DEV_REPLACE_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_dev_replace(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_DEFRAG => {
                // v1 defrag requires write access
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_defrag(cx, scope, ino)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SCAN_DEV => {
                // Device scanning - not applicable in FUSE context
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_scan_dev(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_FORGET_DEV => {
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_forget_dev(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SEND => {
                // Send requires implementing the full btrfs send stream protocol
                if in_data.len() < BTRFS_SEND_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_send(cx, scope, in_data, caller_pid)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SET_RECEIVED_SUBVOL => {
                // Set received UUID requires write access
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < BTRFS_RECEIVED_SUBVOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_set_received_subvol(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_FILE_EXTENT_SAME => {
                // Dedupe requires write access
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < BTRFS_SAME_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_file_extent_same(cx, scope, ino, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_SUBVOL_CREATE_V2 => {
                // Input: 4096-byte vol_args_v2 with flags and name
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_subvol_create(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_RM_DEV_V2 => {
                // Input: 4096-byte vol_args_v2 with flags and name/devid.
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_rm_dev_v2(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_ADD_DEV => {
                // Input: 4096-byte vol_args with device path.
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_add_dev(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_RM_DEV => {
                // Input: 4096-byte vol_args with device path.
                if in_data.len() < BTRFS_VOL_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner.ops.btrfs_rm_dev(cx, scope, in_data)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FICLONE => {
                // Reflink: writes dst's extent tree, so a read-only mount must
                // reject with EROFS. Input: 4-byte source fd.
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < 4 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let src_fd = i32::from_le_bytes(in_data[0..4].try_into().unwrap_or([0; 4]));
                let Ok(src_fd) = u32::try_from(src_fd) else {
                    return IoctlResult::Error(libc::EBADF);
                };
                let cx = Self::cx_for_request();
                // Resolve the caller's source fd to a same-device inode (reuses
                // the move_ext donor resolver), then share its extents into the
                // ioctl target (`ino`). bd-vh8p9.
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    let src_ino = self.resolve_move_ext_donor(caller_pid, src_fd)?;
                    self.inner
                        .ops
                        .clone_file(cx, scope, InodeNumber(ino), src_ino)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            FICLONERANGE => {
                // Input: 32-byte file_clone_range struct. Writes dst, so RO
                // mounts reject with EROFS.
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if in_data.len() < FILE_CLONE_RANGE_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let src_fd = i64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let src_offset = u64::from_le_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let src_length = u64::from_le_bytes(in_data[16..24].try_into().unwrap_or([0; 8]));
                let dest_offset = u64::from_le_bytes(in_data[24..32].try_into().unwrap_or([0; 8]));
                let Ok(src_fd) = u32::try_from(src_fd) else {
                    return IoctlResult::Error(libc::EBADF);
                };
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    let src_ino = self.resolve_move_ext_donor(caller_pid, src_fd)?;
                    self.inner.ops.clone_file_range(
                        cx,
                        scope,
                        InodeNumber(ino),
                        src_ino,
                        src_offset,
                        src_length,
                        dest_offset,
                    )?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_BALANCE_V2 => {
                // Input: 1024-byte balance_args with filters
                if in_data.len() < BTRFS_BALANCE_ARGS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_balance_start(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_BALANCE_CTL => {
                // Input: 4-byte int (1=pause, 2=cancel, 3=resume)
                if in_data.len() < 4 {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cmd = i32::from_le_bytes(in_data[0..4].try_into().unwrap_or([0; 4]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_balance_ctl(cx, scope, cmd)
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_BALANCE_PROGRESS => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_balance_progress(cx, scope)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_DEV_STATS => {
                // Input: 1032-byte struct with devid
                if in_data.len() < BTRFS_DEV_STATS_SIZE as usize {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let devid = u64::from_le_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_get_dev_stats(cx, scope, devid)
                }) {
                    Ok(mut data) => {
                        data.resize(BTRFS_DEV_STATS_SIZE as usize, 0);
                        IoctlResult::Data(data)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_SUBVOL_INFO => {
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_get_subvol_info(cx, scope, InodeNumber(ino))
                }) {
                    Ok(mut data) => {
                        data.resize(BTRFS_SUBVOL_INFO_SIZE as usize, 0);
                        IoctlResult::Data(data)
                    }
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_TREE_SEARCH_V2 => {
                if in_data.len() < BTRFS_TREE_SEARCH_V2_HEADER_SIZE
                    || out_size < BTRFS_TREE_SEARCH_V2_HEADER_SIZE_U32
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_tree_search_v2(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_INO_LOOKUP_USER => {
                if in_data.len() < BTRFS_INO_LOOKUP_USER_SIZE as usize
                    || out_size < BTRFS_INO_LOOKUP_USER_SIZE
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let dirid = u64::from_ne_bytes(in_data[0..8].try_into().unwrap_or([0; 8]));
                let treeid = u64::from_ne_bytes(in_data[8..16].try_into().unwrap_or([0; 8]));
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .btrfs_ino_lookup_user(cx, scope, treeid, dirid)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            BTRFS_IOC_GET_SUBVOL_ROOTREF => {
                if in_data.len() < BTRFS_SUBVOL_ROOTREF_SIZE as usize
                    || out_size < BTRFS_SUBVOL_ROOTREF_SIZE
                {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.btrfs_get_subvol_rootref(cx, scope, in_data)
                }) {
                    Ok(data) => IoctlResult::Data(data),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            _ => IoctlResult::Error(libc::ENOTTY),
        }
    }

    fn record_ioctl_probe(&self, ino: u64, cmd: u32, in_len: usize, out_size: u32) {
        let Some(trace) = self.inner.ioctl_trace.as_ref() else {
            return;
        };
        // Non-blocking enqueue onto the writer thread's bounded channel.
        // Backpressure is recorded inside the probe and surfaced on shutdown.
        trace.record(ino, cmd, in_len, out_size);
    }

    /// Commit any outstanding writeback batch (bd-2i2ez).
    ///
    /// THE VISIBILITY INVARIANT LIVES HERE. Staged writes are in an uncommitted
    /// MVCC transaction and are invisible through a fresh scope, so every
    /// non-WRITE request commits the batch before it runs. A missed call site
    /// here does not fail loudly — it serves a stale read — which is why the
    /// call is in the single funnel every handler already goes through rather
    /// than sprinkled across the handlers that happen to observe.
    ///
    /// Failure to commit is propagated: the batch holds writes whose `write()`
    /// already returned success, and swallowing the error would lose them
    /// silently. The batch is taken out of the slot before the commit is
    /// attempted, so a failed commit does not leave a poisoned scope behind for
    /// the next request to retry forever.
    fn flush_writeback_batch(&self, cx: &Cx) -> ffs_error::Result<()> {
        if !self.inner.writeback.has_outstanding() {
            return Ok(());
        }
        let taken = {
            let mut slot = self.inner.writeback.lock();
            let taken = slot.take();
            self.inner.writeback.set_outstanding(false);
            taken
        };
        let Some((pending, scope)) = taken else {
            return Ok(());
        };
        let staged = pending.staged;
        let seq = self.inner.ops.commit_writeback_batch_scope(cx, scope)?;
        trace!(
            target: "ffs::fuse::writeback",
            ino = pending.ino,
            staged,
            commit_seq = seq.0,
            "writeback_batch_committed"
        );
        Ok(())
    }

    fn with_request_scope<T, F>(&self, cx: &Cx, op: RequestOp, f: F) -> ffs_error::Result<T>
    where
        F: FnOnce(&Cx, &mut RequestScope) -> ffs_error::Result<T>,
    {
        // Per-opcode census (see crate::OP_COUNTS). This is the one choke point every
        // request passes through -- the getxattr memo used to return BEFORE it, which is
        // why requests_total once read 22 for 6,001 stats, fixed in bdd0fd1b.
        crate::OP_COUNTS[op.as_index()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // bd-2i2ez: everything that is not a WRITE observes, so it commits the
        // outstanding batch first. `has_outstanding` makes this one relaxed load
        // when batching is off or nothing is staged.
        if op != RequestOp::Write {
            self.flush_writeback_batch(cx)?;
        }
        // Only read the clock when something will read the counter (bd-xfe7z).
        let started = crate::dispatch_timing_enabled().then(Instant::now);
        let result = match self.inner.ops.begin_request_scope(cx, op) {
            Ok(mut scope) => {
                let op_result = f(cx, &mut scope);
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
            Err(e) => {
                self.inner.metrics.record_err();
                Err(e)
            }
        };
        self.inner
            .metrics
            .record_dispatch_duration(op, started.map(|started| started.elapsed()));
        result
    }

    fn dispatch_opendir(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<(u64, u32)> {
        self.with_request_scope(cx, RequestOp::Opendir, |cx, scope| {
            let attr = self.inner.ops.getattr(cx, scope, ino)?;
            Self::validate_opendir_attr(&attr)?;
            Ok((0, 0))
        })
    }

    fn validate_opendir_attr(attr: &InodeAttr) -> ffs_error::Result<()> {
        if attr.kind == FfsFileType::Directory {
            Ok(())
        } else {
            Err(FfsError::NotDirectory)
        }
    }

    fn enforce_mutation_guards(
        &self,
        cx: &Cx,
        op: RequestOp,
        ino_for_logging: u64,
    ) -> Result<(), MutationDispatchError> {
        if self.inner.read_only {
            return Err(MutationDispatchError::Errno(libc::EROFS));
        }
        if let Some(errno) = self.backpressure_errno(cx, op) {
            warn!(
                ino = ino_for_logging,
                ?op,
                "backpressure: shedding mutation request"
            );
            return Err(MutationDispatchError::Errno(errno));
        }
        Ok(())
    }

    fn dispatch_mkdir(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttr, MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Mkdir, parent)?;
        {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
            self.with_request_scope(&cx, RequestOp::Mkdir, |cx, scope| {
                let attr =
                    self.inner
                        .ops
                        .mkdir(cx, scope, InodeNumber(parent), name, mode, uid, gid)?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(attr)
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })
    }

    fn dispatch_rmdir(&self, parent: u64, name: &OsStr) -> Result<(), MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Rmdir, parent)?;
        let result = {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
            self.with_request_scope(&cx, RequestOp::Rmdir, |cx, scope| {
                self.inner.ops.rmdir(cx, scope, InodeNumber(parent), name)?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(())
            })
        };
        result.map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })?;
        Ok(())
    }

    fn dispatch_unlink(&self, parent: u64, name: &OsStr) -> Result<(), MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Unlink, parent)?;
        let result = {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
            self.with_request_scope(&cx, RequestOp::Unlink, |cx, scope| {
                self.inner
                    .ops
                    .unlink(cx, scope, InodeNumber(parent), name)?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(())
            })
        };
        result.map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })?;
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn dispatch_mknod(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u32,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttr, MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Create, parent)?;

        let s_ifmt = mode & libc::S_IFMT;
        // Regular files keep the legacy `create` fast path so we avoid
        // mode-bit churn for the common case. Char/block devices,
        // FIFOs, and Unix-domain sockets route through ops.mknod which
        // sets up the device-type inode shape (no extents, rdev in
        // i_block for char/block). overlayfs whiteouts land here as
        // S_IFCHR + rdev = makedev(0,0) = 0.
        if rdev == 0 && s_ifmt == libc::S_IFREG {
            return {
                let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
                self.with_request_scope(&cx, RequestOp::Create, |cx, scope| {
                    let attr = self.inner.ops.create(
                        cx,
                        scope,
                        InodeNumber(parent),
                        name,
                        (mode & 0o7777) as u16,
                        uid,
                        gid,
                    )?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(attr)
                })
            }
            .map_err(|error| MutationDispatchError::Operation {
                error,
                offset: None,
            });
        }
        let supported_type = matches!(
            s_ifmt,
            libc::S_IFCHR | libc::S_IFBLK | libc::S_IFIFO | libc::S_IFSOCK
        );
        if !supported_type {
            return Err(MutationDispatchError::Errno(libc::EOPNOTSUPP));
        }

        // Build the full ext4-flavoured 16-bit mode (file-type bits +
        // permission bits). Truncation is bounded by S_IFMT being
        // the high 4 bits of mode and 0o7777 capping the lower 12.
        let full_mode = u16::try_from(s_ifmt | (mode & 0o7777))
            .map_err(|_| MutationDispatchError::Errno(libc::EINVAL))?;

        {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(parent)]);
            self.with_request_scope(&cx, RequestOp::Create, |cx, scope| {
                let attr = self.inner.ops.mknod(
                    cx,
                    scope,
                    InodeNumber(parent),
                    name,
                    full_mode,
                    rdev,
                    uid,
                    gid,
                )?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(attr)
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })
    }

    fn dispatch_rename(
        &self,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
    ) -> Result<(), MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Rename, parent)?;
        let result = {
            let _inode_guards =
                self.acquire_mutation_inode_guards(&[InodeNumber(parent), InodeNumber(newparent)]);
            self.with_request_scope(&cx, RequestOp::Rename, |cx, scope| {
                self.inner.ops.rename2(
                    cx,
                    scope,
                    InodeNumber(parent),
                    name,
                    InodeNumber(newparent),
                    newname,
                    flags,
                )?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(())
            })
        };
        result.map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })?;
        Ok(())
    }

    fn dispatch_write(
        &self,
        ino: u64,
        offset: i64,
        data: &[u8],
    ) -> Result<u32, MutationDispatchError> {
        self.dispatch_write_with_intent(ino, offset, data, WriteIntent::default())
    }

    fn dispatch_write_with_intent(
        &self,
        ino: u64,
        offset: i64,
        data: &[u8],
        intent: WriteIntent,
    ) -> Result<u32, MutationDispatchError> {
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Write, ino)?;
        if let Some(errno) = intent.unsupported_errno() {
            return Err(MutationDispatchError::Errno(errno));
        }
        let byte_offset =
            u64::try_from(offset).map_err(|_| MutationDispatchError::Errno(libc::EINVAL))?;
        let mut operation_offset = byte_offset;
        // bd-2i2ez: a plain WRITE stages into the outstanding batch instead of
        // committing. Excluded deliberately: O_SYNC/O_DSYNC writes, whose whole
        // contract is to be durable on return, and which therefore keep the
        // per-request commit.
        if self.inner.writeback.enabled && intent.sync_mode().is_none() {
            return self.dispatch_batched_write(&cx, ino, byte_offset, data, intent);
        }
        let (written, _commit_seq) = {
            let _inode_guards = if intent.nowait() {
                self.try_acquire_mutation_inode_guards(&[InodeNumber(ino)])
                    .ok_or(MutationDispatchError::Errno(libc::EAGAIN))?
            } else {
                self.acquire_mutation_inode_guards(&[InodeNumber(ino)])
            };
            self.with_request_scope(&cx, RequestOp::Write, |cx, scope| {
                let write_offset = if intent.append_to_eof() {
                    self.inner.ops.getattr(cx, scope, InodeNumber(ino))?.size
                } else {
                    byte_offset
                };
                operation_offset = write_offset;
                let bytes =
                    self.inner
                        .ops
                        .write(cx, scope, InodeNumber(ino), write_offset, data)?;
                let seq = self.inner.ops.commit_request_scope(scope)?;
                self.inner.readahead.invalidate_inode(InodeNumber(ino));
                if let Some(sync_mode) = intent.sync_mode() {
                    self.inner.ops.fsync(
                        cx,
                        scope,
                        InodeNumber(ino),
                        intent.fh,
                        sync_mode.datasync(),
                    )?;
                }
                Ok((bytes, seq))
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: Some(operation_offset),
        })?;
        // Update writeback barrier if enabled.
        Ok(written)
    }

    /// Stage one WRITE into the outstanding writeback batch (bd-2i2ez).
    ///
    /// The amortization this bead is about: 64 sequential writes to one file
    /// currently pay 64 full MVCC commits — SSI validate, WAL append, snapshot
    /// bump, version insert — where kernel ext4 accumulates the same bytes into
    /// one journal transaction and pays once at the fsync.
    ///
    /// The `getattr` for an append lands in the SAME scope as the staged writes,
    /// so an appending writer sees its own staged size. That is read-your-writes
    /// for the one observation this path makes; every OTHER observer is handled
    /// by `flush_writeback_batch` committing before non-write requests.
    fn dispatch_batched_write(
        &self,
        cx: &Cx,
        ino: u64,
        byte_offset: u64,
        data: &[u8],
        intent: WriteIntent,
    ) -> Result<u32, MutationDispatchError> {
        let mut operation_offset = byte_offset;
        let outcome = {
            let _inode_guards = if intent.nowait() {
                self.try_acquire_mutation_inode_guards(&[InodeNumber(ino)])
                    .ok_or(MutationDispatchError::Errno(libc::EAGAIN))?
            } else {
                self.acquire_mutation_inode_guards(&[InodeNumber(ino)])
            };
            // A batch belongs to exactly one inode. Writing to a different one
            // commits the old batch rather than mixing two files' staged writes
            // into a transaction that a single fsync would then publish together.
            let flush_other = {
                let slot = self.inner.writeback.lock();
                slot.as_ref().is_some_and(|(pending, _)| pending.ino != ino)
            };
            if flush_other {
                self.flush_writeback_batch(cx)
                    .map_err(|error| MutationDispatchError::Operation {
                        error,
                        offset: Some(byte_offset),
                    })?;
            }

            let mut slot = self.inner.writeback.lock();
            if slot.is_none() {
                let scope = self.inner.ops.begin_writeback_batch_scope(cx).map_err(
                    |error| MutationDispatchError::Operation {
                        error,
                        offset: Some(byte_offset),
                    },
                )?;
                *slot = Some((PendingWriteback { ino, staged: 0 }, scope));
                self.inner.writeback.set_outstanding(true);
            }
            let (pending, scope) = slot
                .as_mut()
                .expect("the batch slot was just populated for this inode");

            let staged = (|| -> ffs_error::Result<u32> {
                let write_offset = if intent.append_to_eof() {
                    self.inner.ops.getattr(cx, scope, InodeNumber(ino))?.size
                } else {
                    byte_offset
                };
                operation_offset = write_offset;
                self.inner
                    .ops
                    .write(cx, scope, InodeNumber(ino), write_offset, data)
            })();

            match staged {
                Ok(bytes) => {
                    pending.staged += 1;
                    let full = pending.staged >= self.inner.writeback.max_staged_writes;
                    drop(slot);
                    self.inner.readahead.invalidate_inode(InodeNumber(ino));
                    // Bounded dirty state: a writer that never fsyncs must not
                    // pin an unbounded transaction.
                    if full {
                        self.flush_writeback_batch(cx).map_err(|error| {
                            MutationDispatchError::Operation {
                                error,
                                offset: Some(operation_offset),
                            }
                        })?;
                    }
                    Ok(bytes)
                }
                Err(error) => {
                    // The staged write failed, so the transaction may hold a
                    // partial mutation. Drop the whole batch rather than let a
                    // later fsync publish it: the writes it carries have already
                    // been reported as successful, so this is the one place the
                    // batch can legitimately be abandoned, and it is reported.
                    let abandoned = slot.take();
                    self.inner.writeback.set_outstanding(false);
                    drop(slot);
                    if let Some((pending, scope)) = abandoned {
                        warn!(
                            target: "ffs::fuse::writeback",
                            ino = pending.ino,
                            staged = pending.staged,
                            error = %error,
                            "writeback batch abandoned after a staged write failed; \
                             its earlier writes are lost and were never fsync'd"
                        );
                        let _ = self.inner.ops.abort_writeback_batch_scope(cx, scope);
                    }
                    Err(MutationDispatchError::Operation {
                        error,
                        offset: Some(operation_offset),
                    })
                }
            }
        };
        outcome
    }

    fn kernel_open_flags(request_flags: i32, backend_open_flags: u32) -> u32 {
        let direct_io_requested = request_flags & libc::O_DIRECT != 0;
        let direct_io_forced = backend_open_flags & fuse_consts::FOPEN_DIRECT_IO != 0;
        if direct_io_requested || direct_io_forced {
            backend_open_flags
        } else {
            backend_open_flags | fuse_consts::FOPEN_KEEP_CACHE
        }
    }

    fn dispatch_copy_file_range(
        &self,
        ino_in: u64,
        offset_in: i64,
        ino_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
    ) -> Result<u32, MutationDispatchError> {
        if flags != 0 {
            return Err(MutationDispatchError::Errno(libc::EINVAL));
        }
        let src_offset =
            u64::try_from(offset_in).map_err(|_| MutationDispatchError::Errno(libc::EINVAL))?;
        let dst_offset =
            u64::try_from(offset_out).map_err(|_| MutationDispatchError::Errno(libc::EINVAL))?;
        if len == 0 {
            return Ok(0);
        }
        let cx = Self::cx_for_request();
        self.enforce_mutation_guards(&cx, RequestOp::Write, ino_out)?;
        let copy_len = len.min(u64::from(u32::MAX));
        let copied = {
            let _inode_guards =
                self.acquire_mutation_inode_guards(&[InodeNumber(ino_in), InodeNumber(ino_out)]);
            self.with_request_scope(&cx, RequestOp::Write, |cx, scope| {
                let copied = self.inner.ops.copy_file_range(
                    cx,
                    scope,
                    InodeNumber(ino_in),
                    src_offset,
                    InodeNumber(ino_out),
                    dst_offset,
                    copy_len,
                )?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(copied)
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: Some(dst_offset),
        })?;
        if copied > 0 {
            self.inner.readahead.invalidate_inode(InodeNumber(ino_out));
        }
        Ok(u32::try_from(copied).unwrap_or(u32::MAX))
    }

    fn dispatch_setxattr(
        &self,
        cx: &Cx,
        ino: u64,
        name: &str,
        value: &[u8],
        flags: i32,
        position: u32,
    ) -> Result<XattrSetMode, MutationDispatchError> {
        self.enforce_mutation_guards(cx, RequestOp::Setxattr, ino)?;
        let mode =
            Self::parse_setxattr_mode(flags, position).map_err(MutationDispatchError::Errno)?;
        {
            let _inode_guards = self.acquire_mutation_inode_guards(&[InodeNumber(ino)]);
            self.with_request_scope(cx, RequestOp::Setxattr, |cx, scope| {
                self.inner
                    .ops
                    .setxattr(cx, scope, InodeNumber(ino), name, value, mode)?;
                self.inner.ops.commit_request_scope(scope)?;
                Ok(())
            })
        }
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })?;
        Ok(mode)
    }

    fn read_with_readahead(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        byte_offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        let requested_len = usize::try_from(size).unwrap_or(usize::MAX);
        self.with_request_scope(cx, RequestOp::Read, |cx, scope| {
            let mut served = self
                .inner
                .readahead
                .take(ino, byte_offset, requested_len)
                .map_or_else(Vec::new, |prefetched| {
                    trace!(
                        target: "ffs::fuse::io",
                        event = "readahead_hit",
                        ino = ino.0,
                        offset = byte_offset,
                        bytes = prefetched.len()
                    );
                    prefetched
                });

            if served.len() < requested_len {
                let remaining_req =
                    size.saturating_sub(u32::try_from(served.len()).unwrap_or(u32::MAX));
                let next_offset =
                    byte_offset.saturating_add(u64::try_from(served.len()).unwrap_or(u64::MAX));
                let fetch_size =
                    self.inner
                        .access_predictor
                        .fetch_size(ino, next_offset, remaining_req);

                let mut fetched = self
                    .inner
                    .ops
                    .read(cx, scope, ino, next_offset, fetch_size)?;
                let fetched_served_len = (requested_len - served.len()).min(fetched.len());
                let tail = fetched.split_off(fetched_served_len);

                served.append(&mut fetched);

                if !tail.is_empty() {
                    let consumed = u64::try_from(fetched_served_len).unwrap_or(u64::MAX);
                    let prefetch_offset = next_offset.saturating_add(consumed);
                    let prefetch_bytes = tail.len();
                    self.inner.readahead.insert(ino, prefetch_offset, tail);
                    debug!(
                        target: "ffs::fuse::io",
                        event = "readahead_queued",
                        ino = ino.0,
                        offset = prefetch_offset,
                        bytes = prefetch_bytes
                    );
                }
            }

            self.inner.access_predictor.record_read(
                ino,
                byte_offset,
                u32::try_from(served.len()).unwrap_or(u32::MAX),
            );

            Ok(served)
        })
    }
}
