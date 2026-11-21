//! Serialized publication of native NTFS transactions into the mounted view.
//!
//! The transaction engine owns native allocation and WAL ordering. This layer
//! retains its exclusive device, refreshes the reader only after a committed
//! outcome, and refuses further requests when publication becomes uncertain.

use super::{
    Cache, Cx, FfsError, FileType, InodeAttr, InodeNumber, Mutex, NtfsFs, NtfsReference,
    NtfsTransactionEngine, OsStr, ROOT, Result, SetAttrRequest, SystemTime, TICKS_PER_SECOND,
    UNIX_EPOCH, UNIX_FILETIME, checkpoint, is_ads_ino, parse_ads_component, reference, unsupported,
};
use crate::transaction::NtfsEaSetMode;
use crate::transaction::{DEFAULT_NTFS_FILETIME, NtfsTxOutcome, validate_ntfs_component_utf16};
use ffs_core::vfs::XattrSetMode;
use ffs_ondisk::ntfs::ea::{MAX_EA_NAME_BYTES, NtfsEa};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static RETAINED_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn invalid_argument() -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL))
}

fn system_time_to_filetime(time: SystemTime) -> Result<u64> {
    let ticks = match time.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let sub = u64::from(d.subsec_nanos() / 100);
            d.as_secs()
                .checked_mul(TICKS_PER_SECOND)
                .and_then(|s| s.checked_add(sub))
                .and_then(|t| UNIX_FILETIME.checked_add(t))
        }
        Err(e) => {
            let d = e.duration();
            let sub_ticks = u64::from(d.subsec_nanos().div_ceil(100));
            d.as_secs()
                .checked_mul(TICKS_PER_SECOND)
                .and_then(|s| s.checked_add(sub_ticks))
                .and_then(|t| UNIX_FILETIME.checked_sub(t))
        }
    }
    .ok_or_else(|| unsupported("SystemTime cannot be represented as NTFS FILETIME"))?;
    if ticks > i64::MAX as u64 {
        return Err(unsupported("SystemTime exceeds signed NTFS FILETIME range"));
    }
    Ok(ticks)
}

impl NtfsFs {
    /// Adopt an explicitly admitted native writer for filesystem operations.
    ///
    /// The writer keeps its exclusive backing capability for this object's
    /// entire lifetime. Ordinary `new`/`new_recovered` constructors remain
    /// read-only. Native transforms not admitted by the writer stay refused.
    pub fn from_engine(cx: &Cx, engine: NtfsTransactionEngine, uid: u32, gid: u32) -> Result<Self> {
        if engine.requires_recovery() {
            return Err(unsupported(
                "NTFS writer requires recovery before filesystem admission",
            ));
        }
        engine.check_clean_consistency(cx)?;
        let volume = engine.volume_view(cx)?;
        let mut fs = Self::new(cx, volume, uid, gid)?;
        fs.writer = Some(Mutex::new(engine));
        // Construction populated attributes using read-only permissions.
        *fs.cache()? = Cache::default();
        Ok(fs)
    }

    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.writer.is_some()
    }

    /// Return the most recently committed native [`crate::transaction::NtfsDurableToken`],
    /// performing zero backing I/O.
    pub fn last_durable_token(&self) -> Result<Option<crate::transaction::NtfsDurableToken>> {
        self.last_token
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| FfsError::Io(std::io::Error::other("NTFS durable-token lock poisoned")))
    }

    /// Return the admitted [`crate::transaction::NtfsStorageIdentity`] when writable.
    pub fn writable_storage_identity(
        &self,
    ) -> Result<Option<crate::transaction::NtfsStorageIdentity>> {
        let Some(writer) = self.writer.as_ref() else {
            return Ok(None);
        };
        let guard = writer
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NTFS writer poisoned")))?;
        Ok(Some(guard.storage_identity().clone()))
    }

    pub(super) fn ensure_writable(&self) -> Result<()> {
        if self.is_writable() {
            Ok(())
        } else {
            Err(FfsError::ReadOnly)
        }
    }

    fn writer(&self) -> Result<std::sync::MutexGuard<'_, NtfsTransactionEngine>> {
        self.writer
            .as_ref()
            .ok_or(FfsError::ReadOnly)?
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NTFS writer poisoned")))
    }

    fn transact<T>(
        &self,
        cx: &Cx,
        operation: impl FnOnce(&mut NtfsTransactionEngine) -> NtfsTxOutcome<T>,
    ) -> Result<T> {
        checkpoint(cx)?;
        let mut engine = self.writer()?;
        engine.backing_device().begin_durability_commit(cx)?;
        self.health.mark_dirty();
        match operation(&mut engine) {
            NtfsTxOutcome::NotCommitted(error) => {
                engine.backing_device().abort_durability_commit();
                // A pre-commit failure can still leave native recovery work.
                // Only a refusal before journal publication permits reuse.
                if engine.requires_recovery() {
                    self.health.fail();
                } else {
                    self.health.mark_clean();
                }
                Err(error)
            }
            NtfsTxOutcome::Uncertain { reason, .. } => {
                engine.backing_device().abort_durability_commit();
                self.health.fail();
                Err(reason)
            }
            NtfsTxOutcome::Committed { value, token } => {
                if !token.matches_engine(&engine) {
                    engine.backing_device().abort_durability_commit();
                    self.health.fail();
                    return Err(super::corrupt(
                        0,
                        "NTFS commit token changed storage identity",
                    ));
                }
                engine.backing_device().complete_durability_commit();
                // The durable token settles the outcome. Finish publishing
                // through the caller's authority even if cancellation arrived
                // after the journal commit; otherwise a successful mutation
                // would be reported as failed and poison the live mount.
                cx.masked(|| {
                    *self.last_token.lock().map_err(|_| {
                        FfsError::Io(std::io::Error::other("NTFS durable-token lock poisoned"))
                    })? = Some(token);
                    let view = Arc::new(engine.volume_view(cx)?);
                    *self.live_volume.write().map_err(|_| {
                        FfsError::Io(std::io::Error::other("NTFS live volume poisoned"))
                    })? = Some(view);
                    *self.cache()? = Cache::default();
                    self.health.mark_clean();
                    Ok(value)
                })
            }
        }
    }

    fn component(&self, parent: InodeNumber, name: &OsStr) -> Result<Vec<u16>> {
        let text = name
            .to_str()
            .ok_or_else(|| unsupported("NTFS mutation requires lossless UTF-8"))?;
        if text.len() > 255 {
            return Err(FfsError::NameTooLong);
        }
        if parse_ads_component(text)?.is_some() {
            return Err(unsupported(
                "native alternate-stream namespace mutation is not admitted",
            ));
        }
        let units: Vec<_> = text.encode_utf16().collect();
        validate_ntfs_component_utf16(&units)?;
        if parent == ROOT && self.is_hidden_root_folded_name(&self.fold_units(&units))? {
            return Err(FfsError::PermissionDenied);
        }
        Ok(units)
    }

    fn ads_mutation_component(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<Option<(Vec<u16>, Vec<u16>)>> {
        let text = name
            .to_str()
            .ok_or_else(|| unsupported("NTFS mutation requires lossless UTF-8"))?;
        if !text.contains(':') {
            return Ok(None);
        }
        // A literal native colon name takes precedence over the host ADS
        // projection. Never reinterpret its removal as another file's stream.
        let directory = self.record(cx, parent)?;
        if !directory.is_directory() {
            return Err(FfsError::NotDirectory);
        }
        let units: Vec<_> = text.encode_utf16().collect();
        let volume = self.active_volume()?;
        if units.len() <= 255
            && volume
                .lookup_indexed_entry(cx, &directory, &units, &self.upcase)?
                .is_some()
        {
            return Err(unsupported(
                "mutation of literal native colon filenames is not admitted",
            ));
        }
        parse_ads_component(text)
    }

    fn directory_reference(&self, cx: &Cx, ino: InodeNumber) -> Result<NtfsReference> {
        if self.describe(cx, ino)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        Ok(reference(&self.record(cx, ino)?))
    }

    fn data_target(&self, cx: &Cx, ino: InodeNumber) -> Result<(NtfsReference, Vec<u16>)> {
        let attr = self.describe(cx, ino)?;
        if attr.kind == FileType::Directory {
            return Err(FfsError::IsDirectory);
        }
        if attr.kind != FileType::RegularFile {
            return Err(unsupported(
                "NTFS native mutation requires an ordinary file",
            ));
        }
        if attr.perm & 0o222 == 0 {
            return Err(FfsError::PermissionDenied);
        }
        if is_ads_ino(ino) {
            self.ads_target(ino)
        } else {
            Ok((reference(&self.record(cx, ino)?), Vec::new()))
        }
    }

    pub(super) fn open_locked(&self, cx: &Cx, ino: InodeNumber, flags: i32) -> Result<(u64, u32)> {
        let access = flags & libc::O_ACCMODE;
        if ![libc::O_RDONLY, libc::O_WRONLY, libc::O_RDWR].contains(&access) {
            return Err(invalid_argument());
        }
        let writing = access != libc::O_RDONLY || flags & (libc::O_TRUNC | libc::O_CREAT) != 0;
        if writing {
            self.ensure_writable()?;
            self.data_target(cx, ino)?;
        } else if self.describe(cx, ino)?.kind == FileType::Directory {
            return Err(FfsError::IsDirectory);
        }
        // Validate the data interpretation before returning a usable handle.
        self.stream(cx, ino)?;
        if !self.is_writable() {
            return Ok((0, 0));
        }
        let fh = self.register_open(ino, flags)?;
        if flags & libc::O_TRUNC != 0 {
            let result = self.setattr_locked(
                cx,
                ino,
                &SetAttrRequest {
                    size: Some(0),
                    ..SetAttrRequest::default()
                },
            );
            if let Err(error) = result {
                self.release_open(ino, fh)?;
                return Err(error);
            }
        }
        Ok((fh, 0))
    }

    /// Validate an open request on an immutable NTFS reader without instantiating
    /// writable truncation or transaction code paths.
    pub fn open_read_only(&self, cx: &Cx, ino: InodeNumber, flags: i32) -> Result<(u64, u32)> {
        let _op = self.operation(cx, false)?;
        let access = flags & libc::O_ACCMODE;
        if ![libc::O_RDONLY, libc::O_WRONLY, libc::O_RDWR].contains(&access) {
            return Err(invalid_argument());
        }
        if access != libc::O_RDONLY || flags & (libc::O_TRUNC | libc::O_CREAT) != 0 {
            return Err(FfsError::ReadOnly);
        }
        if self.describe(cx, ino)?.kind == FileType::Directory {
            return Err(FfsError::IsDirectory);
        }
        self.stream(cx, ino)?;
        Ok((0, 0))
    }

    /// Validate `fsync` on an immutable NTFS reader without instantiating writer sync paths.
    pub fn fsync_read_only(&self, cx: &Cx, ino: InodeNumber) -> Result<()> {
        let _op = self.operation(cx, false)?;
        if is_ads_ino(ino) {
            self.describe(cx, ino)?;
        } else {
            self.record(cx, ino)?;
        }
        checkpoint(cx)
    }

    /// Validate `fsyncdir` on an immutable NTFS reader without instantiating writer sync paths.
    pub fn fsyncdir_read_only(&self, cx: &Cx, ino: InodeNumber) -> Result<()> {
        let _op = self.operation(cx, false)?;
        if self.describe(cx, ino)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        checkpoint(cx)
    }

    fn check_create_mode(mode: u16, directory: bool) -> Result<bool> {
        // Linux FUSE passes file-type bits (e.g. S_IFREG = 0o100000) in `mode`
        // while direct FsOps callers pass permission bits only (`ftype == 0`).
        let ftype = u32::from(mode) & libc::S_IFMT;
        let expected_ftype = if directory {
            libc::S_IFDIR
        } else {
            libc::S_IFREG
        };
        if ftype != 0 && ftype != expected_ftype {
            return Err(unsupported(
                "requested file type does not match NTFS create operation",
            ));
        }
        let perm = mode & 0o7777;
        // NTFS's host projection supports writable (0o644/0o755) and read-only
        // (0o444/0o555 via FILE_ATTRIBUTE_READONLY); never claim a more
        // restrictive Unix mode succeeded while exposing broader access.
        let read_only = (perm & 0o222) == 0;
        let projected = match (directory, read_only) {
            (true, false) => 0o755,
            (true, true) => 0o555,
            (false, false) => 0o644,
            (false, true) => 0o444,
        };
        if perm & 0o7000 != 0 || projected & !perm & 0o777 != 0 {
            return Err(unsupported(
                "requested mode cannot be represented by the NTFS host projection",
            ));
        }
        Ok(read_only)
    }

    pub(super) fn create_open_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        flags: i32,
    ) -> Result<(InodeAttr, u64, u32)> {
        let access = flags & libc::O_ACCMODE;
        if ![libc::O_RDONLY, libc::O_WRONLY, libc::O_RDWR].contains(&access) {
            return Err(invalid_argument());
        }
        let read_only = Self::check_create_mode(mode, false)?;
        if read_only && access != libc::O_RDONLY {
            return Err(FfsError::PermissionDenied);
        }
        self.check_open_capacity()?;
        let attr = self.create_locked(cx, parent, name, mode)?;
        let fh = cx.masked(|| self.register_open(attr.ino, flags))?;
        Ok((attr, fh, 0))
    }

    pub(super) fn create_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
    ) -> Result<InodeAttr> {
        self.ensure_writable()?;
        let read_only = Self::check_create_mode(mode, false)?;
        if let Some((base, stream)) = self.ads_mutation_component(cx, parent, name)? {
            if read_only {
                return Err(unsupported(
                    "NTFS alternate streams inherit read-only state from their base file",
                ));
            }
            let base_name = String::from_utf16(&base)
                .map_err(|_| unsupported("NTFS stream base name is not lossless UTF-8"))?;
            let base_attr = self.lookup_indexed(cx, parent, OsStr::new(&base_name))?;
            let (target, _) = self.data_target(cx, base_attr.ino)?;
            self.check_ads_registration(target, &stream)?;
            self.transact(cx, |engine| engine.create_stream(cx, target, &stream, &[]))?;
            return cx.masked(|| {
                let ino = self.register_ads(target, &stream)?;
                self.describe(cx, ino)
            });
        }
        let name = self.component(parent, name)?;
        let parent = self.directory_reference(cx, parent)?;
        let target = if read_only {
            self.transact(cx, |engine| {
                engine.create_entry_at(cx, parent, &name, false, true, &[], DEFAULT_NTFS_FILETIME)
            })?
        } else {
            self.transact(cx, |engine| engine.create_file_at(cx, parent, &name, &[]))?
        };
        cx.masked(|| self.describe(cx, self.inode(target)?))
    }

    pub(super) fn mkdir_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
    ) -> Result<InodeAttr> {
        self.ensure_writable()?;
        let read_only = Self::check_create_mode(mode, true)?;
        let name = self.component(parent, name)?;
        let parent = self.directory_reference(cx, parent)?;
        let target = if read_only {
            self.transact(cx, |engine| {
                engine.create_entry_at(cx, parent, &name, true, true, &[], DEFAULT_NTFS_FILETIME)
            })?
        } else {
            self.transact(cx, |engine| engine.mkdir_at(cx, parent, &name))?
        };
        cx.masked(|| self.describe(cx, self.inode(target)?))
    }

    pub(super) fn write_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> Result<u32> {
        self.ensure_writable()?;
        let size = u32::try_from(data.len()).map_err(|_| invalid_argument())?;
        let (target, stream) = self.data_target(cx, ino)?;
        self.transact(cx, |engine| {
            engine.write_stream_range(cx, target, &stream, offset, data)
        })?;
        Ok(size)
    }

    fn user_ea_name(name: &str) -> Result<()> {
        if name.len() > MAX_EA_NAME_BYTES {
            return Err(FfsError::NameTooLong);
        }
        let suffix = name
            .strip_prefix("user.")
            .ok_or_else(|| unsupported("only native NTFS user.* EAs are exposed as host xattrs"))?;
        if suffix.is_empty() || name.as_bytes().contains(&0) {
            return Err(invalid_argument());
        }
        Ok(())
    }

    pub(super) fn setxattr_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        name: &str,
        value: &[u8],
        mode: XattrSetMode,
    ) -> Result<()> {
        self.ensure_writable()?;
        Self::user_ea_name(name)?;
        if value.len() > usize::from(u16::MAX) {
            return Err(FfsError::RequestRejected {
                errno: libc::E2BIG,
                detail: "native NTFS EA value is too large".into(),
            });
        }
        if is_ads_ino(ino) {
            self.describe(cx, ino)?;
            return Err(unsupported(
                "NTFS EAs belong to FILE records, not DATA streams",
            ));
        }
        let record = self.record(cx, ino)?;
        let flags = self
            .active_volume()?
            .extended_attributes(cx, &record)?
            .find(name.as_bytes())
            .map_or(0, |entry| entry.flags);
        let entry = NtfsEa {
            name: name.as_bytes().to_vec(),
            flags,
            value: value.to_vec(),
        };
        let mode = match mode {
            XattrSetMode::Set => NtfsEaSetMode::Set,
            XattrSetMode::Create => NtfsEaSetMode::Create,
            XattrSetMode::Replace => NtfsEaSetMode::Replace,
        };
        let now = system_time_to_filetime(SystemTime::now())?;
        self.transact(cx, |engine| {
            engine.set_extended_attribute(cx, reference(&record), &entry, mode, now)
        })
    }

    pub(super) fn removexattr_locked(&self, cx: &Cx, ino: InodeNumber, name: &str) -> Result<bool> {
        self.ensure_writable()?;
        if name.len() > MAX_EA_NAME_BYTES {
            return Err(FfsError::NameTooLong);
        }
        if is_ads_ino(ino) {
            self.describe(cx, ino)?;
            return Ok(false);
        }
        let record = self.record(cx, ino)?;
        if !name.starts_with("user.") {
            // Kernel privilege removal probes security.capability on writes.
            // This frontend does not expose that native namespace as a host
            // capability, and must not reinterpret or remove unrelated EAs.
            return Ok(false);
        }
        Self::user_ea_name(name)?;
        if self
            .active_volume()?
            .extended_attributes(cx, &record)?
            .find(name.as_bytes())
            .is_none()
        {
            return Ok(false);
        }
        let now = system_time_to_filetime(SystemTime::now())?;
        self.transact(cx, |engine| {
            engine.remove_extended_attribute(cx, reference(&record), name.as_bytes(), now)
        })?;
        Ok(true)
    }

    pub(super) fn setattr_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> Result<InodeAttr> {
        self.ensure_writable()?;
        let current = self.describe(cx, ino)?;
        // Refuse unsupported ownership changes before mutating anything.
        if attrs.uid.is_some_and(|uid| uid != current.uid)
            || attrs.gid.is_some_and(|gid| gid != current.gid)
        {
            return Err(unsupported(
                "native NTFS ownership mutation is not admitted",
            ));
        }
        if is_ads_ino(ino) {
            if attrs.mode.is_some_and(|mode| {
                let ftype = u32::from(mode) & libc::S_IFMT;
                (ftype != 0 && ftype != libc::S_IFREG) || (mode & 0o7777) != current.perm
            }) || attrs.atime.is_some_and(|atime| atime != current.atime)
                || attrs.mtime.is_some_and(|mtime| mtime != current.mtime)
            {
                return Err(unsupported(
                    "native NTFS alternate-stream mode and timestamp mutation is not admitted",
                ));
            }
            if let Some(size) = attrs.size {
                let (target, stream) = self.data_target(cx, ino)?;
                self.transact(cx, |engine| {
                    engine.truncate_stream(cx, target, &stream, size)
                })?;
                return cx.masked(|| self.describe(cx, ino));
            }
            return Ok(current);
        }

        let mut new_read_only = match attrs.mode {
            Some(raw_mode) => {
                // Linux FUSE FUSE_SETATTR supplies file-type bits (e.g. S_IFREG | 0o444)
                // whereas direct FsOps callers pass permission bits (`ftype == 0`).
                let ftype = u32::from(raw_mode) & libc::S_IFMT;
                let perm = raw_mode & 0o7777;
                match current.kind {
                    FileType::Directory if ftype == 0 || ftype == libc::S_IFDIR => {
                        if perm == current.perm {
                            None
                        } else if ino != ROOT && matches!(perm, 0o555 | 0o755) {
                            Some(perm == 0o555)
                        } else {
                            return Err(unsupported(
                                "requested mode cannot be represented by the NTFS host projection",
                            ));
                        }
                    }
                    FileType::RegularFile if ftype == 0 || ftype == libc::S_IFREG => {
                        if perm == current.perm {
                            None
                        } else if matches!(perm, 0o444 | 0o644) {
                            Some(perm == 0o444)
                        } else {
                            return Err(unsupported(
                                "requested mode cannot be represented by the NTFS host projection",
                            ));
                        }
                    }
                    _ => {
                        return Err(unsupported(
                            "requested mode cannot be represented by the NTFS host projection",
                        ));
                    }
                }
            }
            None => None,
        };
        let mtime_ft = match attrs.mtime {
            Some(mtime) if mtime != current.mtime => Some(system_time_to_filetime(mtime)?),
            _ => None,
        };
        let atime_ft = match attrs.atime {
            Some(atime) if atime != current.atime => Some(system_time_to_filetime(atime)?),
            _ => None,
        };
        if attrs.size.is_some() {
            if current.kind == FileType::Directory {
                return Err(FfsError::IsDirectory);
            }
            if current.kind != FileType::RegularFile {
                return Err(unsupported(
                    "NTFS native mutation requires an ordinary file",
                ));
            }
            if (current.perm & 0o222 == 0) && new_read_only != Some(false) {
                return Err(FfsError::PermissionDenied);
            }
        }

        if attrs.size.is_none()
            && new_read_only.is_none()
            && mtime_ft.is_none()
            && atime_ft.is_none()
        {
            return Ok(current);
        }
        if attrs.size.is_some() && (current.perm & 0o222 == 0) && new_read_only == Some(false) {
            let base_ref = reference(&self.record(cx, ino)?);
            self.transact(cx, |engine| {
                engine.set_metadata_at(cx, base_ref, Some(false), None, None, DEFAULT_NTFS_FILETIME)
            })?;
            new_read_only = None;
        }
        if let Some(size) = attrs.size {
            let (target, stream) = self.data_target(cx, ino)?;
            self.transact(cx, |engine| {
                engine.truncate_stream(cx, target, &stream, size)
            })?;
        }
        if new_read_only.is_some() || mtime_ft.is_some() || atime_ft.is_some() {
            let base_ref = reference(&self.record(cx, ino)?);
            let now_ft = mtime_ft.or(atime_ft).unwrap_or(DEFAULT_NTFS_FILETIME);
            self.transact(cx, |engine| {
                engine.set_metadata_at(cx, base_ref, new_read_only, atime_ft, mtime_ft, now_ft)
            })?;
        }
        cx.masked(|| self.describe(cx, ino))
    }

    pub(super) fn touch_atime_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        _now: SystemTime,
        _strict: bool,
    ) -> Result<bool> {
        // Automatic host atime is not a native transaction in this profile.
        // Validate the inode, but do not fabricate a persisted timestamp.
        self.describe(cx, ino)?;
        Ok(false)
    }

    pub(super) fn settle_ads_target_before_mutation(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<()> {
        if !self.is_writable() {
            return Ok(());
        }
        let Ok(Some((base, stream))) = self.ads_mutation_component(cx, parent, name) else {
            return Ok(());
        };
        let Ok(attr) = self.lookup_ads_component(cx, parent, &base, &stream) else {
            return Ok(());
        };
        self.wait_for_inflight_ads_release(cx, attr.ino)
    }

    pub(super) fn unlink_locked(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> Result<()> {
        self.ensure_writable()?;
        if let Some((base, stream)) = self.ads_mutation_component(cx, parent, name)? {
            let attr = self.lookup_ads_component(cx, parent, &base, &stream)?;
            let (target, exact_name) = self.data_target(cx, attr.ino)?;
            if self.has_open_handle(attr.ino)? {
                return Err(FfsError::RequestRejected {
                    errno: libc::EBUSY,
                    detail: "removing an open NTFS stream requires native stream retention".into(),
                });
            }
            self.transact(cx, |engine| engine.remove_stream(cx, target, &exact_name))?;
            self.retire_ads(attr.ino)?;
            return Ok(());
        }
        let name = self.component(parent, name)?;
        let parent = self.directory_reference(cx, parent)?;
        let target = self.writer()?.lookup_reference(cx, parent, &name)?;
        let ino = self.inode(target)?;
        let attr = self.describe(cx, ino)?;
        if attr.kind == FileType::Directory {
            return Err(FfsError::IsDirectory);
        }
        if attr.nlink == 1 && self.pinned(ino)? {
            self.retain_unlinked(cx, parent, &name, target, ino)?;
        } else {
            self.transact(cx, |engine| engine.unlink_at(cx, parent, &name, target))?;
            if attr.nlink == 1 {
                self.retire_ads_for_base(ino)?;
            }
        }
        Ok(())
    }

    fn retain_unlinked(
        &self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
        target: NtfsReference,
        ino: InodeNumber,
    ) -> Result<()> {
        // A native rename keeps the open FILE and its allocation journaled.
        // Only this live mount's exact retained names are hidden. A crash can
        // leave an ordinary recoverable native file; never delete a preexisting
        // name on reopen merely because it resembles this prefix.
        for _ in 0..16 {
            let sequence = RETAINED_SEQUENCE
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| FfsError::NoSpace)?;
            let retained: Vec<u16> = format!(".ffs-unlinked-{:016x}-{sequence:016x}", ino.0)
                .encode_utf16()
                .collect();
            self.check_retained_file(ino, &retained)?;
            let outcome = self.transact(cx, |engine| {
                engine.rename_at(cx, parent, name, self.root, &retained, target, true)
            });
            match outcome {
                Ok(_) => {
                    if let Err(error) = self.register_retained_file(ino, retained) {
                        self.health.fail();
                        return Err(error);
                    }
                    *self.cache()? = Cache::default();
                    return Ok(());
                }
                Err(FfsError::Exists) => {}
                Err(error) => return Err(error),
            }
        }
        Err(FfsError::NoSpace)
    }

    pub(super) fn rmdir_locked(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> Result<()> {
        self.ensure_writable()?;
        let name = self.component(parent, name)?;
        let parent = self.directory_reference(cx, parent)?;
        let target = self.writer()?.lookup_reference(cx, parent, &name)?;
        let ino = self.inode(target)?;
        if self.describe(cx, ino)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        self.transact(cx, |engine| engine.unlink_at(cx, parent, &name, target))?;
        Ok(())
    }

    pub(super) fn link_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<InodeAttr> {
        self.ensure_writable()?;
        let attr = self.describe(cx, ino)?;
        if is_ads_ino(ino) || attr.kind != FileType::RegularFile {
            return Err(FfsError::PermissionDenied);
        }
        // Retained names are owned by final-unlink cleanup. Resurrection would
        // need to retire that hidden name in the same native transaction.
        if attr.nlink == 0 || self.is_retained_file(ino)? {
            return Err(unsupported(
                "linking an unlinked NTFS handle is not admitted",
            ));
        }
        let name = self.component(parent, name)?;
        let parent = self.directory_reference(cx, parent)?;
        let target = reference(&self.record(cx, ino)?);
        self.transact(cx, |engine| engine.link_at(cx, target, parent, &name))?;
        cx.masked(|| self.describe(cx, ino))
    }

    pub(super) fn rename_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
        no_replace: bool,
    ) -> Result<()> {
        self.ensure_writable()?;
        let src_ads = self.ads_mutation_component(cx, parent, name)?;
        let dst_ads = self.ads_mutation_component(cx, new_parent, new_name)?;
        if src_ads.is_some() || dst_ads.is_some() {
            let (Some((src_base, src_stream)), Some((dst_base, dst_stream))) = (src_ads, dst_ads)
            else {
                return Err(unsupported(
                    "NTFS alternate data streams cannot be renamed across files and streams",
                ));
            };
            if parent != new_parent {
                return Err(unsupported(
                    "NTFS alternate data streams can only be renamed within the same base file",
                ));
            }
            let src_base_str = String::from_utf16(&src_base)
                .map_err(|_| unsupported("NTFS stream base name is not lossless UTF-8"))?;
            let dst_base_str = String::from_utf16(&dst_base)
                .map_err(|_| unsupported("NTFS stream base name is not lossless UTF-8"))?;
            let src_base_attr = self.lookup_indexed(cx, parent, OsStr::new(&src_base_str))?;
            let dst_base_attr = self.lookup_indexed(cx, new_parent, OsStr::new(&dst_base_str))?;
            if src_base_attr.ino != dst_base_attr.ino {
                return Err(unsupported(
                    "NTFS alternate data streams can only be renamed within the same base file",
                ));
            }
            let src_ads_attr = self.lookup_ads_component(cx, parent, &src_base, &src_stream)?;
            let (base_ref, exact_old_stream) = self.data_target(cx, src_ads_attr.ino)?;
            let replaced_ads =
                match self.lookup_ads_component(cx, new_parent, &dst_base, &dst_stream) {
                    Ok(dst_ads_attr) => {
                        if dst_ads_attr.ino == src_ads_attr.ino {
                            if exact_old_stream == dst_stream {
                                return Ok(());
                            }
                            if no_replace {
                                return Err(FfsError::Exists);
                            }
                            None
                        } else {
                            if no_replace {
                                return Err(FfsError::Exists);
                            }
                            if self.has_open_handle(dst_ads_attr.ino)? {
                                return Err(FfsError::RequestRejected {
                                errno: libc::EBUSY,
                                detail:
                                    "replacing an open NTFS stream requires native stream retention"
                                        .into(),
                            });
                            }
                            Some(dst_ads_attr.ino)
                        }
                    }
                    Err(FfsError::NotFound(_)) => None,
                    Err(error) => return Err(error),
                };
            self.transact(cx, |engine| {
                engine.rename_stream_at(
                    cx,
                    base_ref,
                    &exact_old_stream,
                    &dst_stream,
                    no_replace,
                    DEFAULT_NTFS_FILETIME,
                )
            })?;
            return cx.masked(|| {
                if let Some(victim_ads) = replaced_ads {
                    self.retire_ads(victim_ads)?;
                }
                self.rename_ads_identity(src_ads_attr.ino, &dst_stream)?;
                Ok(())
            });
        }

        let name = self.component(parent, name)?;
        let new_name = self.component(new_parent, new_name)?;
        let parent = self.directory_reference(cx, parent)?;
        let new_parent = self.directory_reference(cx, new_parent)?;
        let (target, dst_lookup) = {
            let engine = self.writer()?;
            let target = engine.lookup_reference(cx, parent, &name)?;
            let dst_lookup = engine.lookup_reference(cx, new_parent, &new_name);
            (target, dst_lookup)
        };
        let destination_ref = match dst_lookup {
            Ok(destination) if destination != target => Some(destination),
            Ok(_) | Err(FfsError::NotFound(_)) => None,
            Err(error) => return Err(error),
        };
        if let Some(destination) = destination_ref {
            let ino = self.inode(destination)?;
            let dst_attr = self.describe(cx, ino)?;
            if dst_attr.kind == FileType::Directory {
                let _ = self.transact(cx, |engine| {
                    engine.rename_at(cx, parent, &name, new_parent, &new_name, target, no_replace)
                })?;
                return Ok(());
            }
            if self.pinned(ino)? {
                if no_replace {
                    return Err(FfsError::Exists);
                }
                if self.has_pinned_ads(ino)? {
                    return Err(unsupported(
                        "rename over an open NTFS destination requires atomic retention",
                    ));
                }
                if dst_attr.nlink == 1 {
                    for _ in 0..16 {
                        let sequence = RETAINED_SEQUENCE
                            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                            .map_err(|_| FfsError::NoSpace)?;
                        let retained: Vec<u16> =
                            format!(".ffs-unlinked-{:016x}-{sequence:016x}", ino.0)
                                .encode_utf16()
                                .collect();
                        self.check_retained_file(ino, &retained)?;
                        let outcome = self.transact(cx, |engine| {
                            engine.rename_entry_at(
                                cx,
                                parent,
                                &name,
                                new_parent,
                                &new_name,
                                false,
                                Some(retained.as_slice()),
                                DEFAULT_NTFS_FILETIME,
                            )
                        });
                        match outcome {
                            Ok(res) => {
                                if res.overwritten_retained_as_orphan
                                    && let Err(error) = self.register_retained_file(ino, retained)
                                {
                                    self.health.fail();
                                    return Err(error);
                                }
                                *self.cache()? = Cache::default();
                                return Ok(());
                            }
                            Err(FfsError::Exists) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    return Err(FfsError::NoSpace);
                }
            }
            let final_destination = (dst_attr.nlink == 1).then_some((destination, ino));
            let outcome = self.transact(cx, |engine| {
                engine.rename_at(cx, parent, &name, new_parent, &new_name, target, no_replace)
            })?;
            if let Some((reference, ino)) = final_destination
                && outcome.replaced == Some(reference)
            {
                self.retire_ads_for_base(ino)?;
            }
            return Ok(());
        }

        let _ = self.transact(cx, |engine| {
            engine.rename_at(cx, parent, &name, new_parent, &new_name, target, no_replace)
        })?;
        Ok(())
    }

    pub(super) fn reap_retained_inode_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        force: bool,
    ) -> Result<bool> {
        let ino = if is_ads_ino(ino) {
            self.inode(self.ads_target(ino)?.0)?
        } else {
            ino
        };
        let Some(name) = self.retained_file_name(ino)? else {
            return Ok(false);
        };
        if !force && self.pinned(ino)? {
            return Ok(false);
        }
        let target = reference(&self.record(cx, ino)?);
        self.transact(cx, |engine| engine.unlink_at(cx, self.root, &name, target))?;
        if let Err(error) = self.forget_retained_file(ino) {
            self.health.fail();
            return Err(error);
        }
        Ok(true)
    }

    pub(super) fn reap_all_retained_locked(&self, cx: &Cx) -> Result<()> {
        for (ino, _) in self.retained_files()? {
            self.reap_retained_inode_locked(cx, ino, true)?;
        }
        Ok(())
    }

    pub(super) fn sync_device_locked(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        let mut engine = self.writer()?;
        self.health.mark_dirty();
        engine.sync_device(cx)?;
        self.health.mark_clean();
        Ok(())
    }
}
