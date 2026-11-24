//! COPY must apply the caller's privilege policy before exposing copied bytes.

use super::*;

const SOURCE: InodeNumber = InodeNumber(1);
const DESTINATION: InodeNumber = InodeNumber(2);
const UNPRIVILEGED: (u32, u32, u32) = (1000, 1000, u32::MAX);

#[derive(Debug, Clone, PartialEq, Eq)]
enum CopyEvent {
    Begin,
    Getattr(InodeNumber),
    SetMode(u16),
    RemoveCapability,
    Read,
    Write { mode: u16, capability: bool },
    Commit,
    End,
}

struct CopyState {
    mode: u16,
    capability: bool,
    source_kind: FfsFileType,
    destination_kind: FfsFileType,
    source_bytes: Vec<u8>,
    destination_bytes: Vec<u8>,
    mode_error: Option<i32>,
    capability_error: Option<i32>,
    events: Vec<CopyEvent>,
    locks: Option<Arc<FuseInodeLocks>>,
    active_destination_lock: Option<Arc<FuseInodeLock>>,
}

impl Default for CopyState {
    fn default() -> Self {
        Self {
            mode: 0o6666,
            capability: true,
            source_kind: FfsFileType::RegularFile,
            destination_kind: FfsFileType::RegularFile,
            source_bytes: b"new-data".to_vec(),
            destination_bytes: b"old-data".to_vec(),
            mode_error: None,
            capability_error: None,
            events: Vec::new(),
            locks: None,
            active_destination_lock: None,
        }
    }
}

impl CopyState {
    fn attr(&self, ino: InodeNumber) -> ffs_error::Result<InodeAttr> {
        let (kind, mode, size) = match ino {
            SOURCE => (self.source_kind, 0o644, self.source_bytes.len()),
            DESTINATION => (
                self.destination_kind,
                self.mode,
                self.destination_bytes.len(),
            ),
            _ => return Err(FfsError::NotFound("copy fixture inode".into())),
        };
        let mut attr = test_inode_attr(ino.0, kind, mode);
        attr.size = size as u64;
        Ok(attr)
    }

    fn assert_continuous_inode_guards(&mut self) {
        let locks = self.locks.as_ref().unwrap();
        assert!(locks.try_acquire(&[SOURCE]).is_none());
        assert!(locks.try_acquire(&[DESTINATION]).is_none());
        let current = Arc::clone(&locks.table.lock().unwrap().get(&DESTINATION).unwrap().lock);
        if let Some(previous) = &self.active_destination_lock {
            // Releasing the last guard evicts this slot. Reacquiring after
            // killpriv would have a new identity and allow a racing chmod.
            assert!(Arc::ptr_eq(previous, &current));
        } else {
            self.active_destination_lock = Some(current);
        }
    }
}

struct CopyPrivilegeFs(Arc<Mutex<CopyState>>);

impl FsOps for CopyPrivilegeFs {
    fn getattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        let mut state = self.0.lock().unwrap();
        state.events.push(CopyEvent::Getattr(ino));
        state.attr(ino)
    }

    fn lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::NotFound("copy fixture name".into()))
    }

    fn readdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        Ok(ReaddirPage::new(Vec::new()))
    }

    fn readlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::NotFound("copy fixture link".into()))
    }

    fn read(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        assert_eq!(ino, SOURCE);
        let mut state = self.0.lock().unwrap();
        state.assert_continuous_inode_guards();
        state.events.push(CopyEvent::Read);
        let start = usize::try_from(offset)
            .unwrap()
            .min(state.source_bytes.len());
        let end = (start + size as usize).min(state.source_bytes.len());
        Ok(state.source_bytes[start..end].to_vec())
    }

    fn write(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        bytes: &[u8],
    ) -> ffs_error::Result<u32> {
        assert_eq!(ino, DESTINATION);
        let mut state = self.0.lock().unwrap();
        state.assert_continuous_inode_guards();
        let mode = state.mode;
        let capability = state.capability;
        state.events.push(CopyEvent::Write { mode, capability });
        let start = usize::try_from(offset).unwrap();
        let end = start + bytes.len();
        if state.destination_bytes.len() < end {
            state.destination_bytes.resize(end, 0);
        }
        state.destination_bytes[start..end].copy_from_slice(bytes);
        Ok(u32::try_from(bytes.len()).unwrap())
    }

    fn setattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> ffs_error::Result<InodeAttr> {
        assert_eq!(ino, DESTINATION);
        let mut state = self.0.lock().unwrap();
        state.assert_continuous_inode_guards();
        let mode = attrs.mode.unwrap();
        state.events.push(CopyEvent::SetMode(mode));
        if let Some(errno) = state.mode_error {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(errno)));
        }
        state.mode = mode;
        state.attr(ino)
    }

    fn removexattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<bool> {
        assert_eq!((ino, name), (DESTINATION, SECURITY_CAPABILITY_XATTR));
        let mut state = self.0.lock().unwrap();
        state.assert_continuous_inode_guards();
        state.events.push(CopyEvent::RemoveCapability);
        if let Some(errno) = state.capability_error {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(errno)));
        }
        Ok(std::mem::take(&mut state.capability))
    }

    fn begin_request_scope(&self, _cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
        assert_eq!(op, RequestOp::Write);
        self.0.lock().unwrap().events.push(CopyEvent::Begin);
        Ok(RequestScope::empty())
    }

    fn commit_request_scope(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<CommitSeq> {
        let mut state = self.0.lock().unwrap();
        state.assert_continuous_inode_guards();
        state.events.push(CopyEvent::Commit);
        Ok(CommitSeq(1))
    }

    fn end_request_scope(
        &self,
        _cx: &Cx,
        op: RequestOp,
        _scope: RequestScope,
    ) -> ffs_error::Result<()> {
        assert_eq!(op, RequestOp::Write);
        self.0.lock().unwrap().events.push(CopyEvent::End);
        Ok(())
    }
}

fn copy_fixture(state: CopyState, read_only: bool) -> (FrankenFuse, Arc<Mutex<CopyState>>) {
    let state = Arc::new(Mutex::new(state));
    let fuse = FrankenFuse::with_options(
        Box::new(CopyPrivilegeFs(Arc::clone(&state))),
        &MountOptions {
            read_only,
            ..MountOptions::default()
        },
    );
    state.lock().unwrap().locks = Some(Arc::clone(&fuse.inner.inode_locks));
    (fuse, state)
}

fn copy_errno(error: MutationDispatchError) -> i32 {
    match error {
        MutationDispatchError::Errno(errno) => errno,
        MutationDispatchError::Operation { error, .. } => error.to_errno(),
    }
}

#[test]
fn copy_killpriv_applies_group_and_fsetid_policy_under_one_guard_and_scope() {
    // An unreadable /proc status uses the existing conservative identity
    // fallback: nonroot lacks CAP_FSETID, root retains it.
    for (mode, caller, expected_mode) in [
        (0o6666, UNPRIVILEGED, 0o2666),
        (0o6666, (2000, 2000, u32::MAX), 0o0666),
        (0o6676, UNPRIVILEGED, 0o0676),
        (0o6755, (0, 2000, u32::MAX), 0o6755),
        (0o0644, UNPRIVILEGED, 0o0644),
    ] {
        let (fuse, state) = copy_fixture(
            CopyState {
                mode,
                ..CopyState::default()
            },
            false,
        );
        assert_eq!(
            fuse.dispatch_copy_file_range_with_caller(1, 0, 2, 0, 4, 0, Some(caller))
                .unwrap(),
            4
        );
        let state = state.lock().unwrap();
        assert_eq!(state.destination_bytes, b"new-data");
        assert_eq!(state.mode, expected_mode);
        assert!(
            !state.capability,
            "CAP_FSETID never preserves file capabilities"
        );
        let mut expected = vec![
            CopyEvent::Begin,
            CopyEvent::Getattr(SOURCE),
            CopyEvent::Getattr(DESTINATION),
        ];
        if mode != expected_mode {
            expected.push(CopyEvent::SetMode(expected_mode));
        }
        expected.extend([
            CopyEvent::RemoveCapability,
            CopyEvent::Read,
            CopyEvent::Write {
                mode: expected_mode,
                capability: false,
            },
            CopyEvent::Commit,
            CopyEvent::End,
        ]);
        assert_eq!(state.events, expected);
    }
}

#[test]
fn copy_killpriv_accepts_absence_and_aborts_data_on_privilege_errors() {
    for (mode_error, capability_error, capability, caller, expected_errno) in [
        (None, None, false, UNPRIVILEGED, None),
        (None, Some(libc::ENODATA), false, UNPRIVILEGED, None),
        (Some(libc::EIO), None, true, UNPRIVILEGED, Some(libc::EIO)),
        (
            None,
            Some(libc::EOPNOTSUPP),
            true,
            UNPRIVILEGED,
            Some(libc::EOPNOTSUPP),
        ),
        (
            None,
            Some(libc::EPERM),
            true,
            (0, 1000, u32::MAX),
            Some(libc::EPERM),
        ),
    ] {
        let (fuse, state) = copy_fixture(
            CopyState {
                capability,
                mode_error,
                capability_error,
                ..CopyState::default()
            },
            false,
        );
        let result = fuse.dispatch_copy_file_range_with_caller(1, 0, 2, 0, 4, 0, Some(caller));
        let state = state.lock().unwrap();
        if let Some(errno) = expected_errno {
            assert_eq!(copy_errno(result.unwrap_err()), errno);
            assert_eq!(state.destination_bytes, b"old-data");
            assert!(!state.events.iter().any(|event| matches!(
                event,
                CopyEvent::Read | CopyEvent::Write { .. } | CopyEvent::Commit
            )));
            assert_eq!(state.capability, capability);
            if mode_error.is_some() || caller.0 == 0 {
                assert_eq!(state.mode, 0o6666);
            }
        } else {
            assert_eq!(result.unwrap(), 4);
            assert_eq!(state.destination_bytes, b"new-data");
            assert_eq!(state.mode, 0o2666);
        }
    }
}

#[test]
fn copy_killpriv_validates_ranges_and_zero_length_before_backend_changes() {
    for (source, source_offset, destination, destination_offset, len, flags, read_only, errno) in [
        (1, 0, 2, 0, 4, 1, false, Some(libc::EINVAL)),
        (1, -1, 2, 0, 4, 0, false, Some(libc::EINVAL)),
        (1, 0, 2, -1, 4, 0, false, Some(libc::EINVAL)),
        (1, 0, 1, 2, 4, 0, false, Some(libc::EINVAL)),
        (1, i64::MAX, 2, 0, 2, 0, false, Some(libc::EINVAL)),
        (1, 0, 2, i64::MAX, 2, 0, false, Some(libc::EINVAL)),
        (1, 0, 2, 0, 4, 0, true, Some(libc::EROFS)),
        (1, 0, 2, 0, 0, 0, false, None),
        (1, 0, 1, 0, 0, 0, true, None),
    ] {
        let (fuse, state) = copy_fixture(CopyState::default(), read_only);
        let result = fuse.dispatch_copy_file_range_with_caller(
            source,
            source_offset,
            destination,
            destination_offset,
            len,
            flags,
            Some(UNPRIVILEGED),
        );
        if let Some(errno) = errno {
            assert_eq!(copy_errno(result.unwrap_err()), errno);
        } else {
            assert_eq!(result.unwrap(), 0);
        }
        let state = state.lock().unwrap();
        assert_eq!(state.events, [] as [CopyEvent; 0]);
        assert_eq!((state.mode, state.capability), (0o6666, true));
        assert_eq!(state.destination_bytes, b"old-data");
    }
}

#[test]
fn copy_killpriv_checks_file_types_and_source_eof_before_privilege_changes() {
    for (source_kind, destination_kind, offset, expected_errno) in [
        (
            FfsFileType::Directory,
            FfsFileType::RegularFile,
            0,
            Some(libc::EISDIR),
        ),
        (
            FfsFileType::RegularFile,
            FfsFileType::Directory,
            0,
            Some(libc::EISDIR),
        ),
        (
            FfsFileType::Symlink,
            FfsFileType::RegularFile,
            0,
            Some(libc::EINVAL),
        ),
        (
            FfsFileType::RegularFile,
            FfsFileType::Socket,
            0,
            Some(libc::EINVAL),
        ),
        (FfsFileType::RegularFile, FfsFileType::RegularFile, 8, None),
        (FfsFileType::RegularFile, FfsFileType::RegularFile, 32, None),
    ] {
        let (fuse, state) = copy_fixture(
            CopyState {
                source_kind,
                destination_kind,
                ..CopyState::default()
            },
            false,
        );
        let result =
            fuse.dispatch_copy_file_range_with_caller(1, offset, 2, 0, 4, 0, Some(UNPRIVILEGED));
        if let Some(errno) = expected_errno {
            assert_eq!(copy_errno(result.unwrap_err()), errno);
        } else {
            assert_eq!(result.unwrap(), 0);
        }
        let state = state.lock().unwrap();
        assert_eq!(
            state.events,
            [
                CopyEvent::Begin,
                CopyEvent::Getattr(SOURCE),
                CopyEvent::Getattr(DESTINATION),
                CopyEvent::End
            ]
        );
        assert_eq!((state.mode, state.capability), (0o6666, true));
        assert_eq!(state.destination_bytes, b"old-data");
    }
}

#[test]
fn copy_killpriv_clamps_large_requests_to_readable_source_bytes() {
    let (fuse, state) = copy_fixture(CopyState::default(), false);
    assert_eq!(
        fuse.dispatch_copy_file_range_with_caller(1, 0, 2, 0, u64::MAX, 0, Some(UNPRIVILEGED))
            .unwrap(),
        8
    );
    let state = state.lock().unwrap();
    assert_eq!(state.destination_bytes, b"new-data");
    assert_eq!((state.mode, state.capability), (0o2666, false));
}
