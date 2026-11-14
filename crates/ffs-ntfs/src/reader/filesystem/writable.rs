//! Serialized publication of native NTFS transactions into the mounted view.
//!
//! The transaction engine owns native allocation and WAL ordering. This layer
//! retains its exclusive device, refreshes the reader only after a committed
//! outcome, and refuses further requests when publication becomes uncertain.

use super::{
    Cache, Cx, FfsError, FileType, InodeAttr, InodeNumber, Mutex, NtfsFs, NtfsReference,
    NtfsTransactionEngine, OsStr, ROOT, Result, SetAttrRequest, SystemTime, checkpoint, is_ads_ino,
    parse_ads_component, reference, unsupported,
};
use crate::transaction::{NtfsTxOutcome, validate_ntfs_component_utf16};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static RETAINED_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn invalid_argument() -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(libc::EINVAL))
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
        self.health.mark_dirty();
        match operation(&mut engine) {
            NtfsTxOutcome::NotCommitted(error) => {
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
                self.health.fail();
                Err(reason)
            }
            NtfsTxOutcome::Committed { value, token } => {
                if !token.matches_engine(&engine) {
                    self.health.fail();
                    return Err(super::corrupt(
                        0,
                        "NTFS commit token changed storage identity",
                    ));
                }
                // The durable token settles the outcome. Finish publishing
                // through the caller's authority even if cancellation arrived
                // after the journal commit; otherwise a successful mutation
                // would be reported as failed and poison the live mount.
                cx.masked(|| {
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

    fn check_create_mode(mode: u16, directory: bool) -> Result<()> {
        // NTFS's host projection is fixed; never claim a more restrictive Unix
        // mode succeeded while exposing broader access than the caller asked.
        let projected = if directory { 0o755 } else { 0o644 };
        if mode & 0o7000 != 0 || projected & !mode & 0o777 != 0 {
            return Err(unsupported(
                "requested mode cannot be represented by the NTFS host projection",
            ));
        }
        Ok(())
    }

    pub(super) fn create_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
    ) -> Result<InodeAttr> {
        self.ensure_writable()?;
        Self::check_create_mode(mode, false)?;
        let name = self.component(parent, name)?;
        let parent = self.directory_reference(cx, parent)?;
        let target = self.transact(cx, |engine| engine.create_file_at(cx, parent, &name, &[]))?;
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
        Self::check_create_mode(mode, true)?;
        let name = self.component(parent, name)?;
        let parent = self.directory_reference(cx, parent)?;
        let target = self.transact(cx, |engine| engine.mkdir_at(cx, parent, &name))?;
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

    pub(super) fn setattr_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> Result<InodeAttr> {
        self.ensure_writable()?;
        let current = self.describe(cx, ino)?;
        // Refuse unsupported parts of a compound request before truncating.
        if attrs.mode.is_some_and(|mode| mode != current.perm)
            || attrs.uid.is_some_and(|uid| uid != current.uid)
            || attrs.gid.is_some_and(|gid| gid != current.gid)
            || attrs.atime.is_some_and(|atime| atime != current.atime)
            || attrs.mtime.is_some_and(|mtime| mtime != current.mtime)
        {
            return Err(unsupported(
                "native NTFS ownership, mode and timestamp mutation is not admitted",
            ));
        }
        if let Some(size) = attrs.size {
            let (target, stream) = self.data_target(cx, ino)?;
            self.transact(cx, |engine| {
                engine.truncate_stream(cx, target, &stream, size)
            })?;
            return cx.masked(|| self.describe(cx, ino));
        }
        Ok(current)
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

    pub(super) fn unlink_locked(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> Result<()> {
        self.ensure_writable()?;
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
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
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
        self.describe(cx, ino)?;
        self.directory_reference(cx, parent)?;
        self.component(parent, name)?;
        Err(unsupported(
            "native NTFS hard-link creation is not admitted",
        ))
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
        let name = self.component(parent, name)?;
        let new_name = self.component(new_parent, new_name)?;
        let parent = self.directory_reference(cx, parent)?;
        let new_parent = self.directory_reference(cx, new_parent)?;
        let engine = self.writer()?;
        let target = engine.lookup_reference(cx, parent, &name)?;
        match engine.lookup_reference(cx, new_parent, &new_name) {
            Ok(destination)
                if destination != target && self.pinned(self.inode(destination)?)? =>
            {
                return Err(if no_replace {
                    FfsError::Exists
                } else {
                    unsupported("rename over an open NTFS destination requires atomic retention")
                });
            }
            Ok(_) | Err(FfsError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        drop(engine);
        self.transact(cx, |engine| {
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
