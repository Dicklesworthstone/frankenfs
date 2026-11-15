//! Native writable [`FsOps`](ffs_core::FsOps) implementation, Alternate Data
//! Stream (`file:stream`) operations, open-handle orphan retention, and ARIES
//! `$LogFile`-backed durability for [`super::NtfsFs`].

use super::health::MountHealth;
use super::lifetime::{
    NtfsLifetime, RetainedNtfsFile, RetainedNtfsStream, is_ads_ino, parse_ads_component,
};
use super::{
    Cache, Cx, DATA, FfsError, FileType, InodeAttr, InodeNumber, NtfsFileRecord, NtfsFs,
    NtfsReference, NtfsVolume, OsStr, ROOT, Result, Stream, TICKS_PER_SECOND, UNIX_FILETIME,
    checkpoint, corrupt, filetime, reference, unsupported,
};
use crate::transaction::{
    NtfsStageHook, NtfsTransactionEngine, NtfsTxOutcome, NtfsWriteOptions,
    validate_ntfs_component_utf16,
};
use ffs_core::SetAttrRequest;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const FILE_ATTR_READONLY: u32 = 0x0000_0001;

fn errno(code: i32) -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(code))
}

pub(super) fn system_time_to_filetime(time: SystemTime) -> Result<u64> {
    if let Ok(after) = time.duration_since(UNIX_EPOCH) {
        let secs_ticks = after
            .as_secs()
            .checked_mul(TICKS_PER_SECOND)
            .ok_or_else(|| errno(libc::EINVAL))?;
        let sub_ticks = u64::from(after.subsec_nanos() / 100);
        let ticks = UNIX_FILETIME
            .checked_add(secs_ticks)
            .and_then(|v| v.checked_add(sub_ticks))
            .filter(|&v| i64::try_from(v).is_ok())
            .ok_or_else(|| errno(libc::EINVAL))?;
        Ok(ticks)
    } else {
        let before = UNIX_EPOCH
            .duration_since(time)
            .map_err(|_| errno(libc::EINVAL))?;
        let secs_ticks = before
            .as_secs()
            .checked_mul(TICKS_PER_SECOND)
            .ok_or_else(|| errno(libc::EINVAL))?;
        let sub_ticks = u64::from(before.subsec_nanos().div_ceil(100));
        let delta = secs_ticks
            .checked_add(sub_ticks)
            .filter(|&d| d <= UNIX_FILETIME)
            .ok_or_else(|| errno(libc::EINVAL))?;
        Ok(UNIX_FILETIME - delta)
    }
}

pub(super) fn now_filetime_ticks() -> u64 {
    system_time_to_filetime(SystemTime::now()).unwrap_or(UNIX_FILETIME)
}

impl NtfsFs {
    /// Construct a writable [`NtfsFs`] backed by an admitted [`NtfsTransactionEngine`].
    pub fn new_writable(
        cx: &Cx,
        engine: NtfsTransactionEngine,
        uid: u32,
        gid: u32,
        indexed_lookup: bool,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let initial_volume = engine.volume_view(cx)?;
        let live_snapshot = Arc::new(engine.volume_view(cx)?);
        let root_record = live_snapshot.record(cx, 5, None)?;
        if !root_record.is_directory() {
            return Err(corrupt(0, "NTFS root is not a directory"));
        }
        let upcase = engine.upcase().to_vec();
        let fs = Self {
            root: reference(&root_record),
            volume: initial_volume,
            live_volume: RwLock::new(Some(live_snapshot)),
            writer: Some(Mutex::new(engine)),
            operations: RwLock::new(()),
            health: MountHealth::new(),
            lifetime: Mutex::new(NtfsLifetime::default()),
            upcase,
            uid,
            gid,
            indexed_lookup,
            cache: Mutex::new(Cache::default()),
        };
        if fs.describe(cx, ROOT)?.kind != FileType::Directory {
            return Err(corrupt(0, "NTFS mount root is a reparse object"));
        }
        if indexed_lookup {
            fs.active_volume()?
                .admit_indexed_directory(cx, &root_record, &fs.upcase)?;
        } else {
            fs.directory(cx, ROOT)?;
        }
        checkpoint(cx)?;
        Ok(fs)
    }

    /// Open an offline regular-file NTFS 3.1 image for native writable [`FsOps`](ffs_core::FsOps).
    #[allow(clippy::too_many_arguments)]
    pub fn open_writable(
        cx: &Cx,
        path: &Path,
        base: u64,
        length: Option<u64>,
        options: NtfsWriteOptions,
        uid: u32,
        gid: u32,
        indexed_lookup: bool,
    ) -> Result<Self> {
        let engine = NtfsTransactionEngine::open(cx, path, base, length, options)?;
        Self::new_writable(cx, engine, uid, gid, indexed_lookup)
    }

    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.writer.is_some()
    }

    /// Verify clean structural consistency (`$Bitmap`, `$MFT` bitmap, `$I30` indexes,
    /// `$Secure`, clean `$LogFile`, and clean `$Volume` flags) on this mount.
    pub fn check_clean_consistency(&self, cx: &Cx) -> Result<()> {
        let _op = self.operation(cx, false)?;
        if let Some(writer) = &self.writer {
            let guard = writer
                .lock()
                .map_err(|_| FfsError::Io(std::io::Error::other("NTFS writer lock poisoned")))?;
            guard.check_clean_consistency(cx)
        } else {
            let vol = self.active_volume()?;
            let rep =
                vol.check_allocations(cx, super::super::allocation::AllocationLimits::default())?;
            if !rep.is_consistent() {
                return Err(corrupt(0, "NTFS read-only allocation check failed"));
            }
            Ok(())
        }
    }

    /// Install or clear a persistence-stage hook on the underlying [`NtfsTransactionEngine`]
    /// for deterministic fault-injection tests.
    pub fn set_stage_hook_for_testing(&self, hook: Option<NtfsStageHook>) -> Result<()> {
        let writer = self.writer.as_ref().ok_or(FfsError::ReadOnly)?;
        let mut guard = writer
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NTFS writer lock poisoned")))?;
        guard.set_stage_hook(hook);
        Ok(())
    }

    pub(super) fn ensure_writable(&self) -> Result<()> {
        if !self.is_writable() {
            return Err(FfsError::ReadOnly);
        }
        Ok(())
    }

    fn writer_lock(&self) -> Result<MutexGuard<'_, NtfsTransactionEngine>> {
        let writer = self.writer.as_ref().ok_or(FfsError::ReadOnly)?;
        writer
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NTFS writer lock poisoned")))
    }

    pub(super) fn invalidate_all_caches(&self) -> Result<()> {
        let mut cache = self.cache()?;
        cache.attributes.clear();
        cache.streams.clear();
        cache.directories.clear();
        cache.directory_bytes = 0;
        cache.statistics = None;
        Ok(())
    }

    fn refresh_live_volume_from_engine(
        &self,
        cx: &Cx,
        engine: &NtfsTransactionEngine,
    ) -> Result<()> {
        let fresh = Arc::new(engine.volume_view(cx)?);
        let mut guard = self
            .live_volume
            .write()
            .map_err(|_| FfsError::Io(std::io::Error::other("NTFS live volume RwLock poisoned")))?;
        *guard = Some(fresh);
        drop(guard);
        self.invalidate_all_caches()
    }

    pub(super) fn with_engine_tx<T>(
        &self,
        cx: &Cx,
        f: impl FnOnce(&mut NtfsTransactionEngine) -> NtfsTxOutcome<T>,
    ) -> Result<T> {
        let mut engine = self.writer_lock()?;
        match f(&mut engine) {
            NtfsTxOutcome::NotCommitted(err) => Err(err),
            NtfsTxOutcome::Uncertain { reason, .. } => {
                self.health.latch_failed();
                Err(reason)
            }
            NtfsTxOutcome::Committed { value, .. } => {
                self.health.bump_epoch();
                let refresh = self.refresh_live_volume_from_engine(cx, &engine);
                drop(engine);
                refresh?;
                Ok(value)
            }
        }
    }

    pub(super) fn sync_device_locked(&self, cx: &Cx) -> Result<()> {
        if !self.is_writable() {
            return checkpoint(cx);
        }
        let mut engine = self.writer_lock()?;
        self.health.bump_epoch();
        engine.sync_device(cx)
    }

    fn read_standard_flags_and_times(
        cx: &Cx,
        vol: &NtfsVolume,
        record: &NtfsFileRecord,
    ) -> Result<(u32, [SystemTime; 4])> {
        let catalog = vol.attributes(cx, record)?;
        let standard = catalog.select(&vol.geometry, 0x10, &[])?;
        if !standard.resident() || !matches!(standard.size, 48 | 72) {
            return Err(corrupt(0, "invalid resident NTFS STANDARD_INFORMATION"));
        }
        let raw = vol.read(cx, &standard, 0, 72)?;
        let flags = u32::from_le_bytes(
            raw.get(32..36)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| corrupt(0, "truncated NTFS file attributes"))?,
        );
        let parse_t = |off: usize| -> Result<SystemTime> {
            let slice = raw
                .get(off..off + 8)
                .ok_or_else(|| corrupt(0, "short NTFS timestamp"))?;
            let ticks = u64::from_le_bytes(
                slice
                    .try_into()
                    .map_err(|_| corrupt(0, "short NTFS timestamp"))?,
            );
            filetime(ticks)
        };
        Ok((
            flags,
            [parse_t(0)?, parse_t(8)?, parse_t(16)?, parse_t(24)?],
        ))
    }

    /// Select a named `$DATA` stream on `record` matching `target_folded` (exact UTF-16 first,
    /// then `$UpCase`-folded unique match), returning `(exact_stored_name, Stream)`.
    fn select_named_stream_on_record(
        &self,
        cx: &Cx,
        vol: &NtfsVolume,
        record: &NtfsFileRecord,
        preferred_exact: &[u16],
        target_folded: &[u16],
    ) -> Result<(Vec<u16>, Stream)> {
        let catalog = vol.attributes(cx, record)?;
        let all = catalog.all()?;
        let mut exact_found: Option<Vec<u16>> = None;
        let mut folded_matches: Vec<Vec<u16>> = Vec::new();
        let mut seen_names: BTreeSet<Vec<u16>> = BTreeSet::new();
        for attr in &all {
            if attr.kind != DATA || attr.name.is_empty() {
                continue;
            }
            if !seen_names.insert(attr.name.clone()) {
                continue;
            }
            if !preferred_exact.is_empty() && attr.name.as_slice() == preferred_exact {
                exact_found = Some(attr.name.clone());
                break;
            }
            if self.fold_units(&attr.name) == target_folded {
                folded_matches.push(attr.name.clone());
            }
        }
        let chosen_name = if let Some(exact) = exact_found {
            exact
        } else {
            match folded_matches.len() {
                0 => return Err(FfsError::NotFound("NTFS alternate data stream".into())),
                1 => folded_matches.swap_remove(0),
                _ => return Err(corrupt(0, "ambiguous folded NTFS alternate data stream")),
            }
        };
        let stream = vol.data_from_catalog(cx, record, &catalog, &chosen_name)?;
        Ok((chosen_name, stream))
    }

    pub(super) fn describe_ads_uncached(&self, cx: &Cx, ads_ino: InodeNumber) -> Result<InodeAttr> {
        let (binding, retained_stream) = {
            let state = self.lifetime_lock()?;
            let b = state
                .ads
                .get(ads_ino)
                .ok_or_else(|| FfsError::NotFound(format!("NTFS ADS inode {}", ads_ino.0)))?;
            let ret = state.retained_streams.get(&ads_ino).cloned();
            (b, ret)
        };
        let vol = self.active_volume()?;
        let base_record = self.record_by_ref(cx, &vol, binding.base_ref, true)?;
        if base_record.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        let (flags, [created_at, modified_at, changed_at, accessed_at]) =
            Self::read_standard_flags_and_times(cx, &vol, &base_record)?;
        if flags & 0x4000 != 0 {
            return Err(unsupported("NTFS encrypted file is not mounted"));
        }
        let (_, stream) = if let Some(ref ret) = retained_stream {
            self.select_named_stream_on_record(
                cx,
                &vol,
                &base_record,
                &ret.orphan_stream_utf16,
                &ret.folded_orphan_stream,
            )?
        } else {
            if self.is_hidden_ads_folded_name(binding.base_ref, &binding.folded_stream)? {
                return Err(FfsError::NotFound("NTFS alternate data stream".into()));
            }
            self.select_named_stream_on_record(
                cx,
                &vol,
                &base_record,
                &binding.stream_utf16,
                &binding.folded_stream,
            )?
        };
        let base_ino = self.inode(binding.base_ref)?;
        let nlink = u32::from(!(retained_stream.is_some() || self.is_retained_file(base_ino)?));
        let blocks = if stream.resident() {
            0
        } else {
            stream.allocated.div_ceil(512)
        };
        let perm = if !self.is_writable() || (flags & FILE_ATTR_READONLY != 0) {
            0o444
        } else {
            0o644
        };
        Ok(InodeAttr {
            ino: ads_ino,
            size: stream.size,
            blocks,
            crtime: created_at,
            mtime: modified_at,
            ctime: changed_at,
            atime: accessed_at,
            kind: FileType::RegularFile,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: vol.geometry.cluster_bytes(),
            generation: u64::from(base_record.sequence),
        })
    }

    pub(super) fn ads_stream_uncached(&self, cx: &Cx, ads_ino: InodeNumber) -> Result<Stream> {
        let (binding, retained_stream) = {
            let state = self.lifetime_lock()?;
            let b = state
                .ads
                .get(ads_ino)
                .ok_or_else(|| FfsError::NotFound(format!("NTFS ADS inode {}", ads_ino.0)))?;
            let ret = state.retained_streams.get(&ads_ino).cloned();
            (b, ret)
        };
        let vol = self.active_volume()?;
        let base_record = self.record_by_ref(cx, &vol, binding.base_ref, true)?;
        if base_record.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        let (flags, _) = Self::read_standard_flags_and_times(cx, &vol, &base_record)?;
        if flags & 0x4000 != 0 {
            return Err(unsupported("NTFS encrypted file is not mounted"));
        }
        let (_, stream) = if let Some(ref ret) = retained_stream {
            self.select_named_stream_on_record(
                cx,
                &vol,
                &base_record,
                &ret.orphan_stream_utf16,
                &ret.folded_orphan_stream,
            )?
        } else {
            if self.is_hidden_ads_folded_name(binding.base_ref, &binding.folded_stream)? {
                return Err(FfsError::NotFound("NTFS alternate data stream".into()));
            }
            self.select_named_stream_on_record(
                cx,
                &vol,
                &base_record,
                &binding.stream_utf16,
                &binding.folded_stream,
            )?
        };
        Ok(stream)
    }

    /// Resolve a visible child entry in `parent` by UTF-16 component name (without `:`).
    pub(super) fn resolve_visible_base_in_parent(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        base_utf16: &[u16],
    ) -> Result<(InodeNumber, NtfsReference)> {
        if parent == ROOT && self.is_hidden_root_folded_name(&self.fold_units(base_utf16))? {
            return Err(FfsError::NotFound("NTFS name".into()));
        }
        let target_ino = if self.indexed_lookup {
            let vol = self.active_volume()?;
            let dir_rec = self.record(cx, parent)?;
            let entry = vol
                .lookup_indexed_entry(cx, &dir_rec, base_utf16, &self.upcase)?
                .ok_or_else(|| FfsError::NotFound("NTFS name".into()))?;
            if parent == ROOT
                && self.is_hidden_root_folded_name(&self.fold_units(&entry.filename.name))?
            {
                return Err(FfsError::NotFound("NTFS name".into()));
            }
            self.inode(entry.reference)?
        } else {
            let snapshot = self.directory(cx, parent)?;
            if let Ok(idx) = snapshot
                .exact
                .binary_search_by(|(k, _)| k.as_slice().cmp(base_utf16))
            {
                snapshot.exact[idx].1
            } else {
                let folded = self.fold_units(base_utf16);
                let idx = snapshot
                    .folded
                    .binary_search_by(|(k, _)| k.cmp(&folded))
                    .map_err(|_| FfsError::NotFound("NTFS name".into()))?;
                snapshot.folded[idx]
                    .1
                    .ok_or_else(|| corrupt(0, "ambiguous NTFS folded mount name"))?
            }
        };
        let rec = self.record(cx, target_ino)?;
        Ok((target_ino, reference(&rec)))
    }

    pub(super) fn lookup_ads_component(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        base_utf16: &[u16],
        stream_utf16: &[u16],
    ) -> Result<InodeAttr> {
        let (base_ino, base_ref) = self.resolve_visible_base_in_parent(cx, parent, base_utf16)?;
        let base_attr = self.describe(cx, base_ino)?;
        if base_attr.kind == FileType::Directory {
            return Err(FfsError::IsDirectory);
        }
        if base_attr.kind != FileType::RegularFile {
            return Err(unsupported(
                "NTFS alternate data streams are supported on regular files only",
            ));
        }
        let folded_stream = self.fold_units(stream_utf16);
        if self.is_hidden_ads_folded_name(base_ref, &folded_stream)? {
            return Err(FfsError::NotFound("NTFS alternate data stream".into()));
        }
        let vol = self.active_volume()?;
        let record_obj = self.record_by_ref(cx, &vol, base_ref, true)?;
        let (stored_name, _) = self.select_named_stream_on_record(
            cx,
            &vol,
            &record_obj,
            stream_utf16,
            &folded_stream,
        )?;
        let ads_ino =
            self.lifetime_lock()?
                .ads
                .resolve_or_insert(base_ref, folded_stream, stored_name)?;
        self.describe(cx, ads_ino)
    }

    fn require_unreserved_root_component(
        &self,
        parent: InodeNumber,
        units: &[u16],
        err_on_hit: FfsError,
    ) -> Result<()> {
        if parent == ROOT && self.is_hidden_root_folded_name(&self.fold_units(units))? {
            return Err(err_on_hit);
        }
        Ok(())
    }

    fn allocate_root_orphan_name(&self, cx: &Cx) -> Result<(Vec<u16>, Vec<u16>)> {
        let vol = self.active_volume()?;
        let root_rec = vol.record(cx, 5, None)?;
        let existing = vol.list_directory(cx, &root_rec)?;
        let mut occupied: BTreeSet<Vec<u16>> = existing
            .into_iter()
            .map(|e| self.fold_units(&e.filename.name))
            .collect();
        {
            let state = self.lifetime_lock()?;
            state.ensure_retention_capacity()?;
            for ret in state.retained_files.values() {
                occupied.insert(ret.folded_orphan.clone());
            }
        }
        for _ in 0..=occupied.len() + 16 {
            checkpoint(cx)?;
            let id = {
                let mut state = self.lifetime_lock()?;
                state.next_orphan_id = state.next_orphan_id.wrapping_add(1);
                state.next_orphan_id
            };
            let cand_str = format!("__ffs_ntfs_orphan_{id:016x}");
            let cand_utf16: Vec<u16> = cand_str.encode_utf16().collect();
            let folded = self.fold_units(&cand_utf16);
            if !occupied.contains(&folded) {
                return Ok((cand_utf16, folded));
            }
        }
        Err(errno(libc::ENOSPC))
    }

    fn allocate_ads_orphan_name(
        &self,
        cx: &Cx,
        base_ref: NtfsReference,
    ) -> Result<(Vec<u16>, Vec<u16>)> {
        let vol = self.active_volume()?;
        let record_obj = self.record_by_ref(cx, &vol, base_ref, true)?;
        let catalog = vol.attributes(cx, &record_obj)?;
        let mut occupied: BTreeSet<Vec<u16>> = BTreeSet::new();
        for attr in catalog.all()? {
            if attr.kind == DATA && !attr.name.is_empty() {
                occupied.insert(self.fold_units(&attr.name));
            }
        }
        {
            let state = self.lifetime_lock()?;
            state.ensure_retention_capacity()?;
            for ret in state.retained_streams.values() {
                if ret.base_ref == base_ref {
                    occupied.insert(ret.folded_orphan_stream.clone());
                }
            }
        }
        for _ in 0..=occupied.len() + 16 {
            checkpoint(cx)?;
            let id = {
                let mut state = self.lifetime_lock()?;
                state.next_orphan_id = state.next_orphan_id.wrapping_add(1);
                state.next_orphan_id
            };
            let cand_str = format!("__ffs_ads_orphan_{id:016x}");
            let cand_utf16: Vec<u16> = cand_str.encode_utf16().collect();
            let folded = self.fold_units(&cand_utf16);
            if !occupied.contains(&folded) {
                return Ok((cand_utf16, folded));
            }
        }
        Err(errno(libc::ENOSPC))
    }

    fn count_visible_links_on_record(&self, cx: &Cx, target_ref: NtfsReference) -> Result<u32> {
        let vol = self.active_volume()?;
        let rec = self.record_by_ref(cx, &vol, target_ref, true)?;
        let cat = vol.attributes(cx, &rec)?;
        super::super::namespace::host_link_count(cx, &cat.all()?)
    }

    fn is_record_readonly(&self, cx: &Cx, target_ref: NtfsReference) -> Result<bool> {
        let vol = self.active_volume()?;
        let rec = self.record_by_ref(cx, &vol, target_ref, true)?;
        let (flags, _) = Self::read_standard_flags_and_times(cx, &vol, &rec)?;
        Ok(flags & FILE_ATTR_READONLY != 0)
    }

    fn parse_plain_child_name(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<(NtfsReference, Vec<u16>)> {
        let parent_attr = self.describe(cx, parent)?;
        if parent_attr.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        let parent_rec = self.record(cx, parent)?;
        let s = name
            .to_str()
            .ok_or_else(|| unsupported("NTFS requires lossless UTF-8 component names"))?;
        if s.len() > 255 {
            return Err(FfsError::NameTooLong);
        }
        let units: Vec<u16> = s.encode_utf16().collect();
        validate_ntfs_component_utf16(&units)?;
        Ok((reference(&parent_rec), units))
    }

    pub(super) fn open_locked(&self, cx: &Cx, ino: InodeNumber, flags: i32) -> Result<(u64, u32)> {
        checkpoint(cx)?;
        let wants_write = flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_TRUNC | libc::O_CREAT) != 0;
        if wants_write && !self.is_writable() {
            return Err(FfsError::ReadOnly);
        }
        let attr = self.describe(cx, ino)?;
        if attr.kind == FileType::Directory {
            return Err(FfsError::IsDirectory);
        }
        if attr.kind == FileType::Symlink {
            return Err(errno(libc::ELOOP));
        }
        if wants_write && (attr.perm & 0o222) == 0 {
            return Err(FfsError::PermissionDenied);
        }
        self.stream(cx, ino)?;
        if !self.is_writable() {
            return Ok((0, 0));
        }
        let reservation = self.reserve_open(ino)?;
        if flags & libc::O_TRUNC != 0 {
            let now = now_filetime_ticks();
            if is_ads_ino(ino) {
                let (base_ref, stream_utf16) = self.resolve_ads_target_for_mutation(ino)?;
                self.with_engine_tx(cx, |eng| {
                    eng.truncate_stream_at(cx, base_ref, &stream_utf16, 0, now)
                })?;
            } else {
                let target_ref = reference(&self.record(cx, ino)?);
                self.with_engine_tx(cx, |eng| {
                    eng.truncate_stream_at(cx, target_ref, &[], 0, now)
                })?;
            }
        }
        Ok((reservation.accept(), 0))
    }

    fn resolve_ads_target_for_mutation(
        &self,
        ads_ino: InodeNumber,
    ) -> Result<(NtfsReference, Vec<u16>)> {
        let state = self.lifetime_lock()?;
        let binding = state
            .ads
            .get(ads_ino)
            .ok_or_else(|| FfsError::NotFound(format!("NTFS ADS inode {}", ads_ino.0)))?;
        if let Some(ret) = state.retained_streams.get(&ads_ino) {
            Ok((ret.base_ref, ret.orphan_stream_utf16.clone()))
        } else {
            Ok((binding.base_ref, binding.stream_utf16))
        }
    }

    pub(super) fn create_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
    ) -> Result<InodeAttr> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        if self.describe(cx, parent)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        let name_str = name
            .to_str()
            .ok_or_else(|| unsupported("NTFS create requires lossless UTF-8"))?;
        let now = now_filetime_ticks();

        if let Some((base_utf16, stream_utf16)) = parse_ads_component(name_str)? {
            if (mode & 0o222) == 0 {
                return Err(unsupported(
                    "NTFS alternate data stream permissions are inherited from the base file",
                ));
            }
            let (base_ino, base_ref) =
                self.resolve_visible_base_in_parent(cx, parent, &base_utf16)?;
            let base_attr = self.describe(cx, base_ino)?;
            if base_attr.kind == FileType::Directory {
                return Err(FfsError::IsDirectory);
            }
            if base_attr.kind != FileType::RegularFile {
                return Err(unsupported(
                    "NTFS alternate data streams are supported on regular files only",
                ));
            }
            if (base_attr.perm & 0o222) == 0 {
                return Err(FfsError::PermissionDenied);
            }
            let folded_stream = self.fold_units(&stream_utf16);
            if self.is_hidden_ads_folded_name(base_ref, &folded_stream)? {
                return Err(FfsError::Exists);
            }
            // Verify stream does not already exist (`create` is exclusive creation).
            {
                let vol = self.active_volume()?;
                let rec = self.record_by_ref(cx, &vol, base_ref, true)?;
                if self
                    .select_named_stream_on_record(cx, &vol, &rec, &stream_utf16, &folded_stream)
                    .is_ok()
                {
                    return Err(FfsError::Exists);
                }
            }
            self.with_engine_tx(cx, |eng| {
                eng.write_stream_at(cx, base_ref, &stream_utf16, 0, &[], true, now)
            })?;
            let ads_ino = self.lifetime_lock()?.ads.resolve_or_insert(
                base_ref,
                folded_stream,
                stream_utf16,
            )?;
            return self.describe(cx, ads_ino);
        }

        let (parent_ref, units) = self.parse_plain_child_name(cx, parent, name)?;
        self.require_unreserved_root_component(parent, &units, FfsError::Exists)?;
        let read_only = (mode & 0o222) == 0;
        let created_ref = self.with_engine_tx(cx, |eng| {
            eng.create_entry_at(cx, parent_ref, &units, false, read_only, &[], now)
        })?;
        let ino = self.inode(created_ref)?;
        self.describe(cx, ino)
    }

    pub(super) fn mkdir_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
    ) -> Result<InodeAttr> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        if self.describe(cx, parent)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        let (parent_ref, units) = self.parse_plain_child_name(cx, parent, name)?;
        self.require_unreserved_root_component(parent, &units, FfsError::Exists)?;
        let read_only = (mode & 0o222) == 0;
        let now = now_filetime_ticks();
        let created_ref = self.with_engine_tx(cx, |eng| {
            eng.create_entry_at(cx, parent_ref, &units, true, read_only, &[], now)
        })?;
        let ino = self.inode(created_ref)?;
        self.describe(cx, ino)
    }

    pub(super) fn write_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> Result<u32> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        let written = u32::try_from(data.len()).map_err(|_| errno(libc::EINVAL))?;
        let attr = self.describe(cx, ino)?;
        if attr.kind == FileType::Directory {
            return Err(FfsError::IsDirectory);
        }
        if attr.kind != FileType::RegularFile {
            return Err(unsupported("NTFS write requires a regular file or ADS"));
        }
        if (attr.perm & 0o222) == 0 {
            return Err(FfsError::PermissionDenied);
        }
        let now = now_filetime_ticks();
        if is_ads_ino(ino) {
            let (base_ref, stream_utf16) = self.resolve_ads_target_for_mutation(ino)?;
            self.with_engine_tx(cx, |eng| {
                eng.write_stream_at(cx, base_ref, &stream_utf16, offset, data, false, now)
            })?;
        } else {
            let target_ref = reference(&self.record(cx, ino)?);
            self.with_engine_tx(cx, |eng| {
                eng.write_stream_at(cx, target_ref, &[], offset, data, false, now)
            })?;
        }
        Ok(written)
    }

    pub(super) fn setattr_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> Result<InodeAttr> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        if attrs.uid.is_some_and(|u| u != self.uid) || attrs.gid.is_some_and(|g| g != self.gid) {
            return Err(FfsError::PermissionDenied);
        }
        let current = self.describe(cx, ino)?;
        if attrs.size.is_some() && current.kind == FileType::Directory {
            return Err(FfsError::IsDirectory);
        }
        if current.kind == FileType::Symlink {
            return Err(unsupported("NTFS symlink setattr is not supported"));
        }
        if let Some(sz) = attrs.size
            && i64::try_from(sz).is_err()
        {
            return Err(errno(libc::EFBIG));
        }
        let atime_ticks = attrs.atime.map(system_time_to_filetime).transpose()?;
        let mtime_ticks = attrs.mtime.map(system_time_to_filetime).transpose()?;

        let read_only = if ino == ROOT {
            if attrs.mode.is_some_and(|m| m != 0o755) {
                return Err(unsupported("NTFS root directory mode is fixed to 0o755"));
            }
            None
        } else if is_ads_ino(ino) {
            if let Some(m) = attrs.mode
                && m != current.perm
            {
                return Err(unsupported(
                    "NTFS alternate data stream permissions are inherited from the base file",
                ));
            }
            None
        } else if let Some(mode) = attrs.mode {
            let (writable_perm, readonly_perm) = if current.kind == FileType::Directory {
                (0o755, 0o555)
            } else {
                (0o644, 0o444)
            };
            if mode == writable_perm {
                Some(false)
            } else if mode == readonly_perm {
                Some(true)
            } else {
                return Err(unsupported(
                    "NTFS mode must match the native read-only-bit projection",
                ));
            }
        } else {
            None
        };

        if attrs.size.is_some() && (current.perm & 0o222) == 0 && read_only != Some(false) {
            return Err(FfsError::PermissionDenied);
        }

        let now = now_filetime_ticks();
        if is_ads_ino(ino) {
            let (base_ref, stream_utf16) = self.resolve_ads_target_for_mutation(ino)?;
            if let Some(new_size) = attrs.size {
                self.with_engine_tx(cx, |eng| {
                    eng.truncate_stream_at(cx, base_ref, &stream_utf16, new_size, now)
                })?;
            }
            if atime_ticks.is_some() || mtime_ticks.is_some() {
                self.with_engine_tx(cx, |eng| {
                    eng.set_metadata_at(cx, base_ref, None, atime_ticks, mtime_ticks, now)
                })?;
            }
            return self.describe(cx, ino);
        }

        let target_ref = reference(&self.record(cx, ino)?);
        if read_only == Some(false) && attrs.size.is_some() && (current.perm & 0o222) == 0 {
            // Clear READONLY first if caller simultaneously clears READONLY and truncates.
            self.with_engine_tx(cx, |eng| {
                eng.set_metadata_at(cx, target_ref, Some(false), None, None, now)
            })?;
        }
        if let Some(new_size) = attrs.size {
            self.with_engine_tx(cx, |eng| {
                eng.truncate_stream_at(cx, target_ref, &[], new_size, now)
            })?;
        }
        if read_only.is_some() || atime_ticks.is_some() || mtime_ticks.is_some() {
            self.with_engine_tx(cx, |eng| {
                eng.set_metadata_at(cx, target_ref, read_only, atime_ticks, mtime_ticks, now)
            })?;
        }
        self.describe(cx, ino)
    }

    pub(super) fn touch_atime_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        now_time: SystemTime,
        strict: bool,
    ) -> Result<bool> {
        checkpoint(cx)?;
        if !self.is_writable() {
            return Ok(false);
        }
        let current = self.describe(cx, ino)?;
        if current.kind == FileType::Symlink {
            return Ok(false);
        }
        if !strict {
            let newer_than_modify = current.atime > current.mtime && current.atime > current.ctime;
            let fresh_within_day = now_time
                .duration_since(current.atime)
                .is_ok_and(|d| d.as_secs() < 86_400);
            if newer_than_modify && fresh_within_day {
                return Ok(false);
            }
        }
        let atime_ticks = system_time_to_filetime(now_time)?;
        let target_ref = if is_ads_ino(ino) {
            self.resolve_ads_target_for_mutation(ino)?.0
        } else {
            reference(&self.record(cx, ino)?)
        };
        let mft_ticks = current
            .ctime
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|_| system_time_to_filetime(current.ctime).ok())
            .unwrap_or(atime_ticks);
        self.with_engine_tx(cx, |eng| {
            eng.set_metadata_at(cx, target_ref, None, Some(atime_ticks), None, mft_ticks)
        })?;
        Ok(true)
    }

    pub(super) fn link_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> Result<InodeAttr> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        if is_ads_ino(ino) {
            return Err(unsupported(
                "NTFS alternate data streams cannot be hard-linked independently",
            ));
        }
        if self.is_retained_file(ino)? {
            return Err(FfsError::NotFound(format!("NTFS unlinked inode {}", ino.0)));
        }
        let target_attr = self.describe(cx, ino)?;
        if target_attr.kind == FileType::Directory {
            return Err(FfsError::PermissionDenied);
        }
        if target_attr.kind != FileType::RegularFile {
            return Err(unsupported("NTFS hard links require regular files"));
        }
        if self.describe(cx, new_parent)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        let (new_parent_ref, new_units) = self.parse_plain_child_name(cx, new_parent, new_name)?;
        self.require_unreserved_root_component(new_parent, &new_units, FfsError::Exists)?;
        let target_ref = reference(&self.record(cx, ino)?);
        let now = now_filetime_ticks();
        self.with_engine_tx(cx, |eng| {
            eng.link_entry_at(cx, target_ref, new_parent_ref, &new_units, now)
        })?;
        self.describe(cx, ino)
    }

    pub(super) fn unlink_locked(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> Result<()> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        if self.describe(cx, parent)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        let name_str = name
            .to_str()
            .ok_or_else(|| unsupported("NTFS unlink requires lossless UTF-8"))?;
        let now = now_filetime_ticks();

        // Check for ADS `file:stream` unlink when no plain entry matches (plain entries cannot contain `:`).
        if let Some((base_utf16, stream_utf16)) = parse_ads_component(name_str)? {
            let (base_ino, base_ref) =
                self.resolve_visible_base_in_parent(cx, parent, &base_utf16)?;
            let base_attr = self.describe(cx, base_ino)?;
            if base_attr.kind == FileType::Directory {
                return Err(FfsError::IsDirectory);
            }
            if (base_attr.perm & 0o222) == 0 {
                return Err(FfsError::PermissionDenied);
            }
            let folded_stream = self.fold_units(&stream_utf16);
            if self.is_hidden_ads_folded_name(base_ref, &folded_stream)? {
                return Err(FfsError::NotFound("NTFS alternate data stream".into()));
            }
            // Verify stream exists and find/assign its ADS inode if pinned.
            let existing_ads_ino = {
                let vol = self.active_volume()?;
                let record_obj = self.record_by_ref(cx, &vol, base_ref, true)?;
                let _ = self.select_named_stream_on_record(
                    cx,
                    &vol,
                    &record_obj,
                    &stream_utf16,
                    &folded_stream,
                )?;
                self.lifetime_lock()?.ads.find_ino(base_ref, &folded_stream)
            };
            if let Some(ads_ino) = existing_ads_ino
                && self.pinned(ads_ino)?
            {
                let (orphan_utf16, folded_orphan) = self.allocate_ads_orphan_name(cx, base_ref)?;
                self.with_engine_tx(cx, |eng| {
                    eng.rename_stream_at(cx, base_ref, &stream_utf16, &orphan_utf16, now)
                })?;
                let mut state = self.lifetime_lock()?;
                state
                    .ads
                    .rebind_stream(ads_ino, folded_orphan.clone(), orphan_utf16.clone());
                state.retained_streams.insert(
                    ads_ino,
                    RetainedNtfsStream {
                        base_ref,
                        orphan_stream_utf16: orphan_utf16,
                        folded_orphan_stream: folded_orphan,
                    },
                );
                return Ok(());
            }
            self.with_engine_tx(cx, |eng| {
                eng.unlink_stream_at(cx, base_ref, &stream_utf16, now)
            })?;
            if let Some(ads_ino) = existing_ads_ino {
                self.lifetime_lock()?.ads.remove_ino(ads_ino);
            }
            return Ok(());
        }

        let (parent_ref, units) = self.parse_plain_child_name(cx, parent, name)?;
        self.require_unreserved_root_component(
            parent,
            &units,
            FfsError::NotFound("NTFS name".into()),
        )?;
        let (target_ino, target_ref) = self.resolve_visible_base_in_parent(cx, parent, &units)?;
        let target_attr = self.describe(cx, target_ino)?;
        if target_attr.kind == FileType::Directory {
            return Err(FfsError::IsDirectory);
        }

        let visible_links = self.count_visible_links_on_record(cx, target_ref)?;
        if visible_links <= 1 && self.is_base_or_ads_pinned(target_ino, target_ref)? {
            let (orphan_utf16, folded_orphan) = self.allocate_root_orphan_name(cx)?;
            self.with_engine_tx(cx, |eng| {
                eng.rename_entry_at(
                    cx,
                    parent_ref,
                    &units,
                    self.root,
                    &orphan_utf16,
                    true,
                    None,
                    now,
                )
            })?;
            self.lifetime_lock()?.retained_files.insert(
                target_ino,
                RetainedNtfsFile {
                    base_ref: target_ref,
                    orphan_utf16,
                    folded_orphan,
                },
            );
            self.invalidate_all_caches()?;
            return Ok(());
        }

        let (_, rem) = self.with_engine_tx(cx, |eng| {
            eng.unlink_entry_at(cx, parent_ref, &units, Some(false), now)
        })?;
        if rem == 0 {
            self.lifetime_lock()?.ads.remove_all_for_base(target_ref);
        }
        Ok(())
    }

    pub(super) fn rmdir_locked(&self, cx: &Cx, parent: InodeNumber, name: &OsStr) -> Result<()> {
        checkpoint(cx)?;
        self.ensure_writable()?;
        if self.describe(cx, parent)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        let (parent_ref, units) = self.parse_plain_child_name(cx, parent, name)?;
        self.require_unreserved_root_component(
            parent,
            &units,
            FfsError::NotFound("NTFS directory".into()),
        )?;
        let (dir_ino, _) = self.resolve_visible_base_in_parent(cx, parent, &units)?;
        let now = now_filetime_ticks();
        self.with_engine_tx(cx, |eng| {
            eng.unlink_entry_at(cx, parent_ref, &units, Some(true), now)
        })?;
        self.lifetime_lock()?.cookies.remove(&dir_ino);
        Ok(())
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
        checkpoint(cx)?;
        self.ensure_writable()?;
        if self.describe(cx, parent)?.kind != FileType::Directory
            || self.describe(cx, new_parent)?.kind != FileType::Directory
        {
            return Err(FfsError::NotDirectory);
        }
        let old_str = name
            .to_str()
            .ok_or_else(|| unsupported("NTFS rename requires lossless UTF-8"))?;
        let new_str = new_name
            .to_str()
            .ok_or_else(|| unsupported("NTFS rename requires lossless UTF-8"))?;
        let old_ads = parse_ads_component(old_str)?;
        let new_ads = parse_ads_component(new_str)?;
        let now = now_filetime_ticks();

        match (old_ads, new_ads) {
            (Some((old_base, old_stream)), Some((new_base, new_stream))) => {
                let (src_base_ino, src_base_ref) =
                    self.resolve_visible_base_in_parent(cx, parent, &old_base)?;
                let (_, dst_base_ref) =
                    self.resolve_visible_base_in_parent(cx, new_parent, &new_base)?;
                if src_base_ref != dst_base_ref {
                    return Err(errno(libc::EXDEV));
                }
                if (self.describe(cx, src_base_ino)?.perm & 0o222) == 0 {
                    return Err(FfsError::PermissionDenied);
                }
                let old_folded = self.fold_units(&old_stream);
                let new_folded = self.fold_units(&new_stream);
                if self.is_hidden_ads_folded_name(src_base_ref, &old_folded)? {
                    return Err(FfsError::NotFound("NTFS alternate data stream".into()));
                }
                if self.is_hidden_ads_folded_name(src_base_ref, &new_folded)? {
                    return Err(FfsError::Exists);
                }
                let dst_exists = {
                    let vol = self.active_volume()?;
                    let rec = self.record_by_ref(cx, &vol, src_base_ref, true)?;
                    self.select_named_stream_on_record(cx, &vol, &rec, &new_stream, &new_folded)
                        .is_ok()
                };
                if old_folded != new_folded && dst_exists {
                    if no_replace {
                        return Err(FfsError::Exists);
                    }
                    let dst_ads_ino = self
                        .lifetime_lock()?
                        .ads
                        .find_ino(src_base_ref, &new_folded);
                    if let Some(d_ino) = dst_ads_ino
                        && self.pinned(d_ino)?
                    {
                        let (orph_u16, orph_fold) =
                            self.allocate_ads_orphan_name(cx, src_base_ref)?;
                        self.with_engine_tx(cx, |eng| {
                            eng.rename_stream_at(cx, src_base_ref, &new_stream, &orph_u16, now)
                        })?;
                        let mut st = self.lifetime_lock()?;
                        st.ads
                            .rebind_stream(d_ino, orph_fold.clone(), orph_u16.clone());
                        st.retained_streams.insert(
                            d_ino,
                            RetainedNtfsStream {
                                base_ref: src_base_ref,
                                orphan_stream_utf16: orph_u16,
                                folded_orphan_stream: orph_fold,
                            },
                        );
                    } else {
                        self.with_engine_tx(cx, |eng| {
                            eng.unlink_stream_at(cx, src_base_ref, &new_stream, now)
                        })?;
                        if let Some(d_ino) = dst_ads_ino {
                            self.lifetime_lock()?.ads.remove_ino(d_ino);
                        }
                    }
                }
                let src_ads_ino = self
                    .lifetime_lock()?
                    .ads
                    .find_ino(src_base_ref, &old_folded);
                self.with_engine_tx(cx, |eng| {
                    eng.rename_stream_at(cx, src_base_ref, &old_stream, &new_stream, now)
                })?;
                if let Some(s_ino) = src_ads_ino {
                    self.lifetime_lock()?
                        .ads
                        .rebind_stream(s_ino, new_folded, new_stream);
                }
                return Ok(());
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(errno(libc::EINVAL));
            }
            (None, None) => {}
        }

        let (src_parent_ref, src_units) = self.parse_plain_child_name(cx, parent, name)?;
        let (dst_parent_ref, dst_units) = self.parse_plain_child_name(cx, new_parent, new_name)?;
        self.require_unreserved_root_component(
            parent,
            &src_units,
            FfsError::NotFound("NTFS rename source".into()),
        )?;
        self.require_unreserved_root_component(new_parent, &dst_units, FfsError::Exists)?;

        let (_, src_ref) = self.resolve_visible_base_in_parent(cx, parent, &src_units)?;
        let dst_resolved = match self.resolve_visible_base_in_parent(cx, new_parent, &dst_units) {
            Ok(pair) => Some(pair),
            Err(FfsError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };

        let mut pending_orphan: Option<(InodeNumber, NtfsReference, Vec<u16>, Vec<u16>)> = None;
        if let Some((dst_ino, dst_ref)) = dst_resolved
            && dst_ref != src_ref
        {
            if no_replace {
                return Err(FfsError::Exists);
            }
            let dst_attr = self.describe(cx, dst_ino)?;
            if dst_attr.kind == FileType::RegularFile {
                let dst_links = self.count_visible_links_on_record(cx, dst_ref)?;
                if dst_links <= 1 && self.is_base_or_ads_pinned(dst_ino, dst_ref)? {
                    let (orphan_u16, orphan_fold) = self.allocate_root_orphan_name(cx)?;
                    pending_orphan = Some((dst_ino, dst_ref, orphan_u16, orphan_fold));
                }
            }
        }

        let orphan_arg = pending_orphan
            .as_ref()
            .map(|(_, _, u16s, _)| u16s.as_slice());
        let outcome = self.with_engine_tx(cx, |eng| {
            eng.rename_entry_at(
                cx,
                src_parent_ref,
                &src_units,
                dst_parent_ref,
                &dst_units,
                no_replace,
                orphan_arg,
                now,
            )
        })?;

        if outcome.overwritten_retained_as_orphan
            && let Some((dst_ino, dst_ref, orphan_utf16, folded_orphan)) = pending_orphan
        {
            self.lifetime_lock()?.retained_files.insert(
                dst_ino,
                RetainedNtfsFile {
                    base_ref: dst_ref,
                    orphan_utf16,
                    folded_orphan,
                },
            );
            self.invalidate_all_caches()?;
        } else if let Some(over_ref) = outcome.overwritten_reference
            && outcome.overwritten_remaining_links == 0
        {
            let over_ino = self.inode(over_ref)?;
            let mut st = self.lifetime_lock()?;
            st.ads.remove_all_for_base(over_ref);
            st.cookies.remove(&over_ino);
        }
        Ok(())
    }

    pub(super) fn reap_retained_inode_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        destroying: bool,
    ) -> Result<bool> {
        checkpoint(cx)?;
        if !self.is_writable() {
            return Ok(false);
        }
        let mut reclaimed_any = false;
        let now = now_filetime_ticks();

        if is_ads_ino(ino) {
            let (ret_stream, maybe_base_ref) = {
                let st = self.lifetime_lock()?;
                (
                    st.retained_streams.get(&ino).cloned(),
                    st.ads.get(ino).map(|b| b.base_ref),
                )
            };
            if let Some(ret) = ret_stream
                && (destroying || !self.pinned(ino)?)
            {
                if self.is_record_readonly(cx, ret.base_ref).unwrap_or(false) {
                    let _ = self.with_engine_tx(cx, |eng| {
                        eng.set_metadata_at(cx, ret.base_ref, Some(false), None, None, now)
                    });
                }
                match self.with_engine_tx(cx, |eng| {
                    eng.unlink_stream_at(cx, ret.base_ref, &ret.orphan_stream_utf16, now)
                }) {
                    Ok(()) | Err(FfsError::NotFound(_)) => {}
                    Err(e) => return Err(e),
                }
                let mut st = self.lifetime_lock()?;
                st.retained_streams.remove(&ino);
                st.ads.remove_ino(ino);
                reclaimed_any = true;
            }
            if let Some(base_ref) = maybe_base_ref {
                let base_ino = self.inode(base_ref)?;
                if self.reap_retained_file_only_locked(cx, base_ino, destroying, now)? {
                    reclaimed_any = true;
                }
            }
            return Ok(reclaimed_any);
        }

        self.reap_retained_file_only_locked(cx, ino, destroying, now)
    }

    fn reap_retained_file_only_locked(
        &self,
        cx: &Cx,
        base_ino: InodeNumber,
        destroying: bool,
        now: u64,
    ) -> Result<bool> {
        let Some(ret) = self.lifetime_lock()?.retained_files.get(&base_ino).cloned() else {
            return Ok(false);
        };
        if !destroying && self.is_base_or_ads_pinned(base_ino, ret.base_ref)? {
            return Ok(false);
        }
        if self.is_record_readonly(cx, ret.base_ref).unwrap_or(false) {
            self.with_engine_tx(cx, |eng| {
                eng.set_metadata_at(cx, ret.base_ref, Some(false), None, None, now)
            })?;
        }
        self.with_engine_tx(cx, |eng| {
            eng.unlink_entry_at(cx, self.root, &ret.orphan_utf16, Some(false), now)
        })?;
        {
            let mut st = self.lifetime_lock()?;
            st.retained_files.remove(&base_ino);
            let ads_inos = st.ads.inodes_for_base(ret.base_ref);
            for a_ino in ads_inos {
                st.retained_streams.remove(&a_ino);
                st.ads.remove_ino(a_ino);
            }
        }
        self.invalidate_all_caches()?;
        Ok(true)
    }

    pub(super) fn reap_all_retained_locked(&self, cx: &Cx) -> Result<()> {
        let (stream_inos, file_inos): (Vec<InodeNumber>, Vec<InodeNumber>) = {
            let st = self.lifetime_lock()?;
            (
                st.retained_streams.keys().copied().collect(),
                st.retained_files.keys().copied().collect(),
            )
        };
        for s_ino in stream_inos {
            checkpoint(cx)?;
            self.reap_retained_inode_locked(cx, s_ino, true)?;
        }
        for f_ino in file_inos {
            checkpoint(cx)?;
            self.reap_retained_inode_locked(cx, f_ino, true)?;
        }
        Ok(())
    }
}
