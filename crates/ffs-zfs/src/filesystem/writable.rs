//! Native TXG ownership, mount identity publication, and open-handle admission.

use super::{
    CTL_FLAG, Cx, FfsError, Identity, InodeAttr, InodeNumber, MAX_NODES, Metadata, ROOT, Result,
    State, SystemTime, Timestamp, UNIX_EPOCH, ViewState, ZfsFs, checkpoint, corrupt, unsupported,
};
use crate::{ZfsDurableToken, ZfsTransactionEngine, ZfsTxOutcome, ZfsUnlinkedObject};
use ffs_core::vfs::ReleaseRequest;
use ffs_ondisk::zfs_zpl::Kind;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::Mutex;

const MAX_OPEN_HANDLES: usize = 65_536;
const MAX_COOKIE_REVISION: u32 = (1 << 31) - 1;

pub(super) fn errno(code: i32) -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(code))
}

pub(super) fn native_timestamp(time: SystemTime) -> Result<Timestamp> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => Ok(Timestamp {
            seconds: i64::try_from(elapsed.as_secs()).map_err(|_| errno(libc::EOVERFLOW))?,
            nanos: elapsed.subsec_nanos(),
        }),
        Err(before) => {
            let elapsed = before.duration();
            let seconds = i128::from(elapsed.as_secs());
            let nanos = elapsed.subsec_nanos();
            Ok(Timestamp {
                seconds: i64::try_from(-seconds - i128::from(nanos != 0))
                    .map_err(|_| errno(libc::EOVERFLOW))?,
                nanos: if nanos == 0 { 0 } else { 1_000_000_000 - nanos },
            })
        }
    }
}

/// Mount-level policy options for [`ZfsFs::with_writer_options`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZfsMountWriteOptions {
    /// Authorize `FsOps::setattr` mode (`chmod`) and ownership (`chown`) updates,
    /// rebuilding trivial NFSv4 DACLs and updating per-owner quota accounting.
    pub allow_mode_and_owner_setattr: bool,
}

pub(super) struct MutableView {
    pub(super) objects: BTreeMap<u64, InodeNumber>,
    pub(super) next_ino: u64,
    revision: u32,
}

pub(super) struct WriterState {
    pub(super) engine: ZfsTransactionEngine,
    pub(super) dataset: Vec<Vec<u8>>,
    pub(super) allow_mode_and_owner_setattr: bool,
    last_token: Option<ZfsDurableToken>,
    refresh_needed: bool,
    handles: BTreeMap<u64, InodeNumber>,
    counts: BTreeMap<InodeNumber, u64>,
    orphans: BTreeMap<InodeNumber, ZfsUnlinkedObject>,
    next_handle: u64,
}

impl ZfsFs {
    /// Consume an already admitted, exclusively owned pool writer and expose one
    /// head dataset through `FsOps`. Every successful mutation is a full native
    /// TXG commit. The existing immutable constructor never grants write authority.
    ///
    /// Native mode bits and numeric owner IDs are exposed; this does not implement
    /// native ACL evaluation. The mount frontend must retain its permission policy.
    /// Open regular files survive final unlink in the native unlinked set. A
    /// fresh owner drains pending regular-file reclamation before exposing the
    /// mount. Snapshot and control-directory operations remain read-only.
    pub fn with_writer(
        cx: &Cx,
        engine: ZfsTransactionEngine,
        dataset_components: Vec<Vec<u8>>,
    ) -> Result<Self> {
        Self::with_writer_options(
            cx,
            engine,
            dataset_components,
            ZfsMountWriteOptions::default(),
        )
    }

    /// Consume an already admitted, exclusively owned pool writer with explicit
    /// mount-level write policy options (such as enabling `chmod`/`chown` via `FsOps::setattr`).
    pub fn with_writer_options(
        cx: &Cx,
        mut engine: ZfsTransactionEngine,
        dataset_components: Vec<Vec<u8>>,
        options: ZfsMountWriteOptions,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if engine.requires_recovery() {
            return Err(errno(libc::EIO));
        }
        // Preflight the complete native queue and mount view before beginning
        // recovery writes. Unsupported host identities must refuse the mount
        // without modifying even an otherwise reclaimable orphan.
        let pending = engine.pending_unlinks(cx, &dataset_components)?;
        let mut objects = engine.open_read_objects(cx)?;
        let properties =
            objects.properties(cx, &dataset_components, None, &["readonly".to_owned()])?;
        match properties
            .values
            .first()
            .and_then(|property| property.value.as_ref())
        {
            Some(crate::reader::dmu::properties::PropertyValue::Number(0)) => {}
            Some(crate::reader::dmu::properties::PropertyValue::Number(1)) => {
                return Err(FfsError::ReadOnly);
            }
            _ => {
                return Err(corrupt(
                    "missing or invalid effective ZFS readonly property",
                ));
            }
        }
        let view = objects.zpl(cx, &dataset_components)?;
        if !(4..=5).contains(&view.version) {
            return Err(unsupported("native ZPL mount writes require ZPL v4/v5"));
        }
        let mut head = ViewState::new(cx, view, ROOT, ROOT, 0)?;
        let (root, _) = head.metadata(cx, ROOT)?;
        let uid = u32::try_from(root.uid).map_err(|_| errno(libc::EOVERFLOW))?;
        let gid = u32::try_from(root.gid).map_err(|_| errno(libc::EOVERFLOW))?;
        // The engine is moved into its only mount owner, so persisted orphans
        // have no live handles in this new mount lifetime. Reclamation changes
        // the native object-set root even though visible directory entries and
        // their already admitted identities stay unchanged.
        let mut last_token = None;
        for identity in pending {
            let (_, token) = engine
                .reap_unlinked_file(cx, &dataset_components, identity)
                .into_result()?;
            last_token = Some(token);
        }
        if last_token.is_some() {
            let mut objects = engine.open_read_objects(cx)?;
            let view = objects.zpl(cx, &dataset_components)?;
            if view.root != head.view.root || view.dataset_guid != head.view.dataset_guid {
                return Err(corrupt("reclaimed ZPL dataset identity changed"));
            }
            head.view = view;
        }
        let next_ino = head.nodes.last_key_value().map_or(2, |(ino, _)| ino.0 + 1);
        head.mutable = Some(MutableView {
            objects: head
                .nodes
                .iter()
                .map(|(&ino, id)| (id.object, ino))
                .collect(),
            next_ino,
            revision: 1,
        });
        // The initial directory was validated before mutable cookies existed.
        head.clear_directory_cache();
        Ok(Self {
            state: Mutex::new(State {
                head,
                snapshot_dir: None,
                snap_idx_by_guid: BTreeMap::new(),
                snap_name_by_idx: BTreeMap::new(),
                next_snap_idx: 1,
                snapshots: BTreeMap::new(),
                writer: Some(WriterState {
                    engine,
                    dataset: dataset_components,
                    allow_mode_and_owner_setattr: options.allow_mode_and_owner_setattr,
                    last_token,
                    refresh_needed: false,
                    handles: BTreeMap::new(),
                    counts: BTreeMap::new(),
                    orphans: BTreeMap::new(),
                    next_handle: 1,
                }),
                recovery_required: false,
            }),
            uid,
            gid,
        })
    }

    /// Create an atomic snapshot of this mounted dataset and immediately refresh `.zfs/snapshot`.
    pub fn create_snapshot(&self, cx: &Cx, snap_name: &[u8]) -> Result<u64> {
        let mut state = self.state(cx)?;
        let timestamp = native_timestamp(SystemTime::now())?;
        let obj = state
            .mutate(|engine, dataset| engine.create_snapshot(cx, dataset, snap_name, timestamp))?;
        state.publish_committed(|state| {
            state.refresh_head(cx)?;
            state.invalidate_snapshots_locked(cx)?;
            Ok(obj)
        })
    }

    /// Destroy (or defer-destroy) a snapshot on this mounted dataset and immediately prune `.zfs/snapshot`.
    pub fn destroy_snapshot(&self, cx: &Cx, snap_name: &[u8], defer: bool) -> Result<u64> {
        let mut state = self.state(cx)?;
        let obj = state
            .mutate(|engine, dataset| engine.destroy_snapshot(cx, dataset, snap_name, defer))?;
        state.publish_committed(|state| {
            state.refresh_head(cx)?;
            state.invalidate_snapshots_locked(cx)?;
            Ok(obj)
        })
    }

    /// Rename a snapshot on this mounted dataset and immediately refresh `.zfs/snapshot`.
    pub fn rename_snapshot(
        &self,
        cx: &Cx,
        old_snap_name: &[u8],
        new_snap_name: &[u8],
    ) -> Result<u64> {
        let mut state = self.state(cx)?;
        let obj = state.mutate(|engine, dataset| {
            engine.rename_snapshot(cx, dataset, old_snap_name, new_snap_name)
        })?;
        state.publish_committed(|state| {
            state.refresh_head(cx)?;
            state.invalidate_snapshots_locked(cx)?;
            Ok(obj)
        })
    }

    /// Explicitly invalidate and reload `.zfs/snapshot` entries from the committed dataset root.
    pub fn invalidate_snapshots(&self, cx: &Cx) -> Result<()> {
        let mut state = self.state(cx)?;
        state.invalidate_snapshots_locked(cx)
    }

    /// The most recent known durable result, even when later request delivery or
    /// view refresh failed. Reading this token performs no I/O or recovery.
    pub fn last_durable_token(&self) -> Result<Option<ZfsDurableToken>> {
        let state = self.state.lock().map_err(|_| errno(libc::EIO))?;
        Ok(state
            .writer
            .as_ref()
            .and_then(|writer| writer.last_token.clone()))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn create_with_handle(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
        flags: Option<i32>,
    ) -> Result<(InodeAttr, u64, u32)> {
        let mut state = self.state(cx)?;
        let parent_object = state.writable_parent(cx, parent, name.as_bytes())?;
        let (mode, gid) = state.creation_mode_gid(cx, parent, mode & 0o7777, gid, false)?;
        state.reserve_identity()?;
        let handle = if let Some(flags) = flags {
            if flags & libc::O_ACCMODE == libc::O_ACCMODE {
                return Err(errno(libc::EINVAL));
            }
            if flags & libc::O_DIRECTORY != 0 {
                return Err(FfsError::NotDirectory);
            }
            // Reserve capacity before committing a namespace entry. The state
            // lock covers creation, identity publication, and the lifetime pin.
            Some(state.next_open_handle()?)
        } else {
            None
        };
        let timestamp = native_timestamp(SystemTime::now())?;
        let object = state.mutate(|engine, dataset| {
            engine.create_file(
                cx,
                dataset,
                parent_object,
                name.as_bytes(),
                mode,
                u64::from(uid),
                u64::from(gid),
                timestamp,
                crate::ZfsDataChecksum::default(),
            )
        })?;
        let attr = state.publish_committed(|state| {
            state.refresh_head(cx)?;
            let ino = state.head.remember_object(cx, object)?;
            self.attributes(cx, state, ino)
        })?;
        if let Some(handle) = handle {
            state.publish_open_handle(attr.ino, handle);
        }
        Ok((attr, handle.unwrap_or(0), 0))
    }

    pub(super) fn remove_entry(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        directory: bool,
    ) -> Result<()> {
        let mut state = self.state(cx)?;
        let parent_object = state.writable_parent(cx, parent, name.as_bytes())?;
        let ino = state.child(cx, parent, name.as_bytes())?;
        let metadata = state.head.metadata(cx, ino)?.0;
        if (metadata.kind == Kind::Directory) != directory {
            return Err(if directory {
                FfsError::NotDirectory
            } else {
                FfsError::IsDirectory
            });
        }
        if directory {
            state.reject_pinned_reclamation(ino)?;
        }
        let retained =
            (!directory && metadata.links <= 1 && state.has_open_handles(ino)).then(|| {
                ZfsUnlinkedObject {
                    object: state.head.nodes[&ino].object,
                    generation: metadata.generation,
                }
            });
        let timestamp = native_timestamp(SystemTime::now())?;
        state.mutate(|engine, dataset| {
            if let Some(identity) = retained {
                engine.unlink_open_file(
                    cx,
                    dataset,
                    parent_object,
                    name.as_bytes(),
                    identity,
                    timestamp,
                )
            } else {
                engine.unlink_entry(
                    cx,
                    dataset,
                    parent_object,
                    name.as_bytes(),
                    directory,
                    timestamp,
                )
            }
        })?;
        if let Some(identity) = retained {
            state.remember_unlinked(ino, identity);
        }
        Ok(())
    }
}

impl ViewState {
    pub(super) fn cookie_base(&self) -> u64 {
        self.mutable
            .as_ref()
            .map_or(0, |view| u64::from(view.revision) << 32)
    }

    pub(super) fn validate_cookie(&self, cookie: u64) -> Result<()> {
        if self.mutable.is_some() && cookie != 0 && cookie >> 32 != self.cookie_base() >> 32 {
            return Err(errno(libc::ESTALE));
        }
        Ok(())
    }

    fn clear_directory_cache(&mut self) {
        self.directories.clear();
        self.directory_bytes = 0;
    }

    pub(super) fn stage_identity(
        &self,
        identity: Identity,
        pending: &mut BTreeMap<InodeNumber, Identity>,
        pending_objects: &mut BTreeMap<u64, InodeNumber>,
        next_ino: &mut u64,
    ) -> Result<InodeNumber> {
        let target = if let Some(mutable) = &self.mutable {
            if identity.object == 0 || identity.object >= (1 << 48) - 1 {
                return Err(corrupt("invalid ZPL mount object number"));
            }
            let mapped = pending_objects
                .get(&identity.object)
                .or_else(|| mutable.objects.get(&identity.object))
                .copied();
            let current = mapped.filter(|ino| {
                self.nodes
                    .get(ino)
                    .or_else(|| pending.get(ino))
                    .is_some_and(|old| old.generation == identity.generation)
            });
            if let Some(ino) = current {
                ino
            } else {
                if identity.object == self.view.root {
                    return Err(corrupt(
                        "ZPL root generation changed during native mutation",
                    ));
                }
                if *next_ino >= CTL_FLAG {
                    return Err(errno(libc::EOVERFLOW));
                }
                let ino = InodeNumber(*next_ino);
                *next_ino += 1;
                pending_objects.insert(identity.object, ino);
                ino
            }
        } else {
            self.inode(identity.object)?
        };
        if let Some(previous) = self.nodes.get(&target).or_else(|| pending.get(&target)) {
            if previous.object != identity.object
                || previous.generation != identity.generation
                || previous.kind != identity.kind
                || (self.mutable.is_none()
                    && previous.directory_parent != identity.directory_parent)
            {
                return Err(corrupt(
                    "ZPL mount object has conflicting native identities",
                ));
            }
        } else {
            pending.insert(target, identity);
            if self.nodes.len() + pending.len() > MAX_NODES {
                return Err(unsupported("ZPL mount exceeds 131072 object identities"));
            }
        }
        Ok(target)
    }

    pub(super) fn remember_object(&mut self, cx: &Cx, object: u64) -> Result<InodeNumber> {
        let (metadata, _) = self.view.stat(cx, object)?;
        let identity = Identity::from_metadata(object, &metadata);
        let mut pending = BTreeMap::new();
        let mut pending_objects = BTreeMap::new();
        let mut next_ino = self.mutable.as_ref().map_or(0, |view| view.next_ino);
        let ino =
            self.stage_identity(identity, &mut pending, &mut pending_objects, &mut next_ino)?;
        checkpoint(cx)?;
        self.nodes.extend(pending);
        if let Some(mutable) = &mut self.mutable {
            mutable.objects.extend(pending_objects);
            mutable.next_ino = next_ino;
        }
        Ok(ino)
    }
}

impl State {
    pub(super) fn refresh_head(&mut self, cx: &Cx) -> Result<()> {
        let Some(writer) = &mut self.writer else {
            return Ok(());
        };
        if !writer.refresh_needed {
            return Ok(());
        }
        let refreshed = writer
            .engine
            .open_read_objects(cx)
            .and_then(|mut objects| objects.zpl(cx, &writer.dataset));
        let view = match refreshed {
            Ok(view) => view,
            Err(error) => {
                // Cancellation cannot roll back a durable TXG. Leave refresh
                // pending so a fresh request can publish that exact new root.
                if !matches!(error, FfsError::Cancelled) {
                    self.recovery_required = true;
                }
                return Err(error);
            }
        };
        if view.root != self.head.view.root || view.dataset_guid != self.head.view.dataset_guid {
            self.recovery_required = true;
            return Err(corrupt("committed ZPL dataset identity changed"));
        }
        self.head.view = view;
        self.head.clear_directory_cache();
        writer.refresh_needed = false;
        Ok(())
    }

    pub(super) fn writable_metadata(&mut self, cx: &Cx, ino: InodeNumber) -> Result<Metadata> {
        if self.writer.is_none() || ino.0 & CTL_FLAG != 0 {
            return Err(FfsError::ReadOnly);
        }
        self.head.metadata(cx, ino).map(|(metadata, _)| metadata)
    }

    pub(super) fn writable_parent(
        &mut self,
        cx: &Cx,
        parent: InodeNumber,
        name: &[u8],
    ) -> Result<u64> {
        let metadata = self.writable_metadata(cx, parent)?;
        if metadata.kind != Kind::Directory {
            return Err(FfsError::NotDirectory);
        }
        if name.len() > 255 {
            return Err(FfsError::NameTooLong);
        }
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&0)
            || name.contains(&b'/')
        {
            return Err(FfsError::Format("invalid ZPL mount path component".into()));
        }
        if parent == ROOT && name == b".zfs" {
            return Err(FfsError::PermissionDenied);
        }
        Ok(self.head.nodes[&parent].object)
    }

    pub(super) fn creation_mode_gid(
        &mut self,
        cx: &Cx,
        parent: InodeNumber,
        mode: u16,
        gid: u32,
        directory: bool,
    ) -> Result<(u16, u32)> {
        let metadata = self.writable_metadata(cx, parent)?;
        if metadata.mode & 0o2000 == 0 {
            return Ok((mode, gid));
        }
        // A setgid directory passes its group to every new child and passes
        // the setgid bit to new subdirectories. Validate host representability
        // before a native TXG can commit an entry whose attributes cannot reply.
        let inherited_gid = u32::try_from(metadata.gid).map_err(|_| errno(libc::EOVERFLOW))?;
        let inherited_mode = if directory { mode | 0o2000 } else { mode };
        Ok((inherited_mode, inherited_gid))
    }

    pub(super) fn admit_data_mutation(
        &mut self,
        cx: &Cx,
        ino: InodeNumber,
        metadata: &Metadata,
    ) -> Result<()> {
        // Some transport paths drop privileges after SETATTR, while streaming
        // copy reaches WRITE directly. This profile cannot atomically clear
        // set-ID bits or native capabilities, so refuse before any native data
        // mutation.
        if metadata.mode & 0o6000 != 0 {
            return Err(unsupported(
                "native ZPL data mutation cannot clear set-ID permissions",
            ));
        }
        let object = self.head.nodes[&ino].object;
        if self.head.view.has_file_capabilities(cx, object)? {
            return Err(unsupported(
                "native ZPL data mutation cannot clear file capabilities",
            ));
        }
        Ok(())
    }

    pub(super) fn child(
        &mut self,
        cx: &Cx,
        parent: InodeNumber,
        name: &[u8],
    ) -> Result<InodeNumber> {
        let rows = self.head.directory(cx, parent)?;
        let position = rows[2..]
            .binary_search_by(|entry| entry.name.as_slice().cmp(name))
            .map_err(|_| FfsError::NotFound("ZPL mount path component".into()))?;
        Ok(rows[position + 2].ino)
    }

    pub(super) fn reserve_identity(&self) -> Result<()> {
        if self.head.nodes.len() >= MAX_NODES {
            return Err(unsupported("ZPL mount exceeds 131072 object identities"));
        }
        if self
            .head
            .mutable
            .as_ref()
            .is_some_and(|view| view.next_ino >= CTL_FLAG)
        {
            return Err(errno(libc::EOVERFLOW));
        }
        Ok(())
    }

    pub(super) fn mutate(
        &mut self,
        operation: impl FnOnce(&mut ZfsTransactionEngine, &[Vec<u8>]) -> ZfsTxOutcome<u64>,
    ) -> Result<u64> {
        let view = self.head.mutable.as_mut().ok_or(FfsError::ReadOnly)?;
        if view.revision == MAX_COOKIE_REVISION {
            return Err(errno(libc::EOVERFLOW));
        }
        let writer = self.writer.as_mut().ok_or(FfsError::ReadOnly)?;
        match operation(&mut writer.engine, &writer.dataset) {
            ZfsTxOutcome::Committed { value, token } => {
                writer.last_token = Some(token);
                writer.refresh_needed = true;
                view.revision += 1;
                Ok(value)
            }
            ZfsTxOutcome::NotCommitted(error) => Err(error),
            ZfsTxOutcome::Uncertain { reason, .. } => {
                self.recovery_required = true;
                Err(reason)
            }
        }
    }

    pub(super) fn reject_pinned_reclamation(&self, ino: InodeNumber) -> Result<()> {
        self.writer.as_ref().ok_or(FfsError::ReadOnly)?;
        // FUSE OPEN and CREATE both hold real backend handles for this writer.
        // LOOKUP references alone must not prevent ordinary closed-file unlink;
        // the generation registry prevents them from naming a reused object.
        if self.has_open_handles(ino) {
            return Err(errno(libc::EBUSY));
        }
        Ok(())
    }

    pub(super) fn has_open_handles(&self, ino: InodeNumber) -> bool {
        self.writer
            .as_ref()
            .is_some_and(|writer| writer.counts.contains_key(&ino))
    }

    pub(super) fn remember_unlinked(&mut self, ino: InodeNumber, identity: ZfsUnlinkedObject) {
        if let Some(writer) = &mut self.writer {
            writer.orphans.insert(ino, identity);
        }
    }

    pub(super) fn reap_closed_orphan(&mut self, cx: &Cx, ino: InodeNumber) -> Result<bool> {
        if self.has_open_handles(ino) {
            return Ok(false);
        }
        let Some(identity) = self
            .writer
            .as_ref()
            .and_then(|writer| writer.orphans.get(&ino))
            .copied()
        else {
            return Ok(false);
        };
        self.mutate(|engine, dataset| engine.reap_unlinked_file(cx, dataset, identity))?;
        if let Some(writer) = &mut self.writer {
            writer.orphans.remove(&ino);
        }
        Ok(true)
    }

    pub(super) fn reap_closed_orphans(&mut self, cx: &Cx) -> Result<()> {
        let pending: Vec<_> = self
            .writer
            .as_ref()
            .map_or_else(Vec::new, |writer| writer.orphans.keys().copied().collect());
        for ino in pending {
            self.reap_closed_orphan(cx, ino)?;
        }
        Ok(())
    }

    pub(super) fn publish_committed<T>(
        &mut self,
        publish: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let result = publish(self);
        if let Err(error) = &result
            && !matches!(error, FfsError::Cancelled)
        {
            // Native persistence already succeeded. An unreadable result must
            // not fall back to the predecessor view or continue mutating it.
            self.recovery_required = true;
        }
        result
    }

    pub(super) fn next_open_handle(&self) -> Result<u64> {
        let writer = self.writer.as_ref().ok_or(FfsError::ReadOnly)?;
        if writer.handles.len() >= MAX_OPEN_HANDLES || writer.next_handle == u64::MAX {
            return Err(errno(libc::EMFILE));
        }
        Ok(writer.next_handle)
    }

    pub(super) fn publish_open_handle(&mut self, ino: InodeNumber, handle: u64) {
        if let Some(writer) = &mut self.writer {
            writer.handles.insert(handle, ino);
            *writer.counts.entry(ino).or_default() += 1;
            writer.next_handle += 1;
        }
    }

    pub(super) fn release_open_handle(&mut self, request: ReleaseRequest) -> Result<()> {
        let Some(writer) = &mut self.writer else {
            return Ok(());
        };
        if writer.handles.get(&request.fh) != Some(&request.ino) {
            return Err(errno(libc::EBADF));
        }
        let count = writer
            .counts
            .get_mut(&request.ino)
            .ok_or_else(|| errno(libc::EIO))?;
        *count = count.checked_sub(1).ok_or_else(|| errno(libc::EIO))?;
        if *count == 0 {
            writer.counts.remove(&request.ino);
        }
        writer.handles.remove(&request.fh);
        Ok(())
    }

    pub(super) fn validate_handle(&self, ino: InodeNumber, fh: u64) -> Result<()> {
        if fh != 0
            && self
                .writer
                .as_ref()
                .is_some_and(|writer| writer.handles.get(&fh) != Some(&ino))
        {
            return Err(errno(libc::EBADF));
        }
        Ok(())
    }

    pub(super) fn sync(&self, cx: &Cx) -> Result<()> {
        if let Some(writer) = &self.writer {
            writer.engine.sync_devices(cx)?;
        }
        checkpoint(cx)
    }
}
