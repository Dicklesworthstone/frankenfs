//! Mount-lifetime open-handle tracking, root/ADS orphan retention, compound
//! Alternate Data Stream (`file:stream`) inode registry, and monotonic `readdir`
//! cookie assignment for [`super::NtfsFs`].

use super::{DirEntry, FfsError, InodeNumber, NtfsFs, NtfsReference, Result};
use crate::transaction::{validate_ntfs_component_utf16, validate_ntfs_stream_name_utf16};
use ffs_core::vfs::OpenHandleOracle;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

/// Bit 61 distinguishes compound ADS (`file:stream`) VFS inodes from regular
/// MFT `(sequence << 32 | record) + 2` inodes (`< 1 << 49`), while staying
/// strictly inside signed 64-bit `ino_t` (`< 1 << 63`).
pub(super) const ADS_INO_BIT: u64 = 1_u64 << 61;
const MAX_ADS_ID: u64 = (1_u64 << 60) - 1;
const MAX_ADS_NODES: usize = 65_536;
const MAX_HANDLES: usize = 65_536;
const MAX_RETAINED: usize = 4_096;
const MAX_COOKIE: u64 = (1_u64 << 63) - 1;

#[inline]
pub(super) const fn is_ads_ino(ino: InodeNumber) -> bool {
    (ino.0 & ADS_INO_BIT) != 0
}

/// Parse `"base:stream"` into validated `(base_utf16, stream_utf16)` when `name`
/// contains `':'`. Returns `Ok(None)` when `name` has no colon.
pub(super) fn parse_ads_component(name: &str) -> Result<Option<(Vec<u16>, Vec<u16>)>> {
    let Some((base, stream)) = name.split_once(':') else {
        return Ok(None);
    };
    if base.is_empty()
        || stream.is_empty()
        || stream.contains(':')
        || matches!(base, "." | "..")
        || base.contains(['/', '\\', '\0'])
        || stream.contains(['/', '\\', '\0'])
    {
        return Err(FfsError::Format(
            "invalid NTFS alternate data stream component".into(),
        ));
    }
    if base.len() > 255 {
        return Err(FfsError::NameTooLong);
    }
    let base_utf16: Vec<u16> = base.encode_utf16().collect();
    let stream_utf16: Vec<u16> = stream.encode_utf16().collect();
    validate_ntfs_component_utf16(&base_utf16)?;
    validate_ntfs_stream_name_utf16(&stream_utf16)?;
    Ok(Some((base_utf16, stream_utf16)))
}

fn errno(value: i32) -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(value))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdsBinding {
    pub(super) base_ref: NtfsReference,
    pub(super) folded_stream: Vec<u16>,
    pub(super) stream_utf16: Vec<u16>,
}

#[derive(Default)]
pub(super) struct AdsRegistry {
    by_ino: BTreeMap<InodeNumber, AdsBinding>,
    by_key: BTreeMap<(u64, u16, Vec<u16>), InodeNumber>,
    next_id: u64,
}

impl AdsRegistry {
    pub(super) fn resolve_or_insert(
        &mut self,
        base_ref: NtfsReference,
        folded_stream: Vec<u16>,
        stream_utf16: Vec<u16>,
    ) -> Result<InodeNumber> {
        let key = (base_ref.record, base_ref.sequence, folded_stream.clone());
        if let Some(&existing) = self.by_key.get(&key) {
            if let Some(binding) = self.by_ino.get_mut(&existing) {
                binding.stream_utf16 = stream_utf16;
            }
            return Ok(existing);
        }
        if self.by_ino.len() >= MAX_ADS_NODES {
            return Err(errno(libc::ENOMEM));
        }
        let next = self
            .next_id
            .checked_add(1)
            .filter(|&id| id <= MAX_ADS_ID)
            .ok_or_else(|| errno(libc::EOVERFLOW))?;
        self.next_id = next;
        let ino = InodeNumber(ADS_INO_BIT | next);
        self.by_key.insert(key, ino);
        self.by_ino.insert(
            ino,
            AdsBinding {
                base_ref,
                folded_stream,
                stream_utf16,
            },
        );
        Ok(ino)
    }

    pub(super) fn get(&self, ino: InodeNumber) -> Option<AdsBinding> {
        self.by_ino.get(&ino).cloned()
    }

    pub(super) fn find_ino(
        &self,
        base_ref: NtfsReference,
        folded_stream: &[u16],
    ) -> Option<InodeNumber> {
        self.by_key
            .get(&(base_ref.record, base_ref.sequence, folded_stream.to_vec()))
            .copied()
    }

    pub(super) fn inodes_for_base(&self, base_ref: NtfsReference) -> Vec<InodeNumber> {
        self.by_ino
            .iter()
            .filter_map(|(&ino, b)| (b.base_ref == base_ref).then_some(ino))
            .collect()
    }

    pub(super) fn rebind_stream(
        &mut self,
        ino: InodeNumber,
        new_folded: Vec<u16>,
        new_stream_utf16: Vec<u16>,
    ) {
        if let Some(binding) = self.by_ino.get_mut(&ino) {
            let old_key = (
                binding.base_ref.record,
                binding.base_ref.sequence,
                binding.folded_stream.clone(),
            );
            self.by_key.remove(&old_key);
            binding.folded_stream.clone_from(&new_folded);
            binding.stream_utf16 = new_stream_utf16;
            let new_key = (
                binding.base_ref.record,
                binding.base_ref.sequence,
                new_folded,
            );
            self.by_key.insert(new_key, ino);
        }
    }

    pub(super) fn remove_ino(&mut self, ino: InodeNumber) {
        if let Some(removed) = self.by_ino.remove(&ino) {
            self.by_key.remove(&(
                removed.base_ref.record,
                removed.base_ref.sequence,
                removed.folded_stream,
            ));
        }
    }

    pub(super) fn remove_all_for_base(&mut self, base_ref: NtfsReference) {
        let doomed = self.inodes_for_base(base_ref);
        for ino in doomed {
            self.remove_ino(ino);
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct RetainedNtfsFile {
    pub(super) base_ref: NtfsReference,
    pub(super) orphan_utf16: Vec<u16>,
    pub(super) folded_orphan: Vec<u16>,
}

#[derive(Debug, Clone)]
pub(super) struct RetainedNtfsStream {
    pub(super) base_ref: NtfsReference,
    pub(super) orphan_stream_utf16: Vec<u16>,
    pub(super) folded_orphan_stream: Vec<u16>,
}

pub(super) struct DirCookieState {
    next_cookie: u64,
    by_key: BTreeMap<(InodeNumber, Vec<u8>), u64>,
}

impl Default for DirCookieState {
    fn default() -> Self {
        Self {
            next_cookie: 3,
            by_key: BTreeMap::new(),
        }
    }
}

impl DirCookieState {
    fn assign(&mut self, rows: &mut [DirEntry]) -> Result<()> {
        if rows.len() <= 2 {
            self.by_key.clear();
            return Ok(());
        }
        let mut live_keys = BTreeSet::new();
        for entry in &mut rows[2..] {
            let key = (entry.ino, entry.name.clone());
            live_keys.insert(key.clone());
            if let Some(&cookie) = self.by_key.get(&key) {
                entry.offset = cookie;
            } else {
                if self.next_cookie > MAX_COOKIE {
                    return Err(errno(libc::EOVERFLOW));
                }
                let cookie = self.next_cookie;
                self.next_cookie += 1;
                self.by_key.insert(key, cookie);
                entry.offset = cookie;
            }
        }
        self.by_key.retain(|k, _| live_keys.contains(k));
        rows[2..].sort_by_key(|entry| entry.offset);
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct NtfsLifetime {
    pub(super) oracle: Option<OpenHandleOracle>,
    pub(super) handles: BTreeMap<u64, InodeNumber>,
    pub(super) counts: BTreeMap<InodeNumber, u64>,
    pub(super) next_handle: u64,
    pub(super) next_orphan_id: u64,
    pub(super) retained_files: BTreeMap<InodeNumber, RetainedNtfsFile>,
    pub(super) retained_streams: BTreeMap<InodeNumber, RetainedNtfsStream>,
    pub(super) ads: AdsRegistry,
    pub(super) cookies: BTreeMap<InodeNumber, DirCookieState>,
}

impl NtfsLifetime {
    pub(super) fn ensure_retention_capacity(&self) -> Result<()> {
        if self.retained_files.len() + self.retained_streams.len() >= MAX_RETAINED {
            return Err(errno(libc::ENOSPC));
        }
        Ok(())
    }

    fn remove_handle(&mut self, handle: u64, ino: InodeNumber) -> Result<()> {
        if self.handles.get(&handle) != Some(&ino) {
            return Err(errno(libc::EBADF));
        }
        let count = self
            .counts
            .get_mut(&ino)
            .ok_or_else(|| FfsError::Io(std::io::Error::other("NTFS handle count missing")))?;
        *count = count
            .checked_sub(1)
            .ok_or_else(|| FfsError::Io(std::io::Error::other("NTFS handle count underflow")))?;
        if *count == 0 {
            self.counts.remove(&ino);
        }
        self.handles.remove(&handle);
        Ok(())
    }
}

pub(super) struct OpenReservation<'a> {
    lifetime: &'a Mutex<NtfsLifetime>,
    handle: u64,
    ino: InodeNumber,
    accepted: bool,
}

impl OpenReservation<'_> {
    pub(super) fn accept(mut self) -> u64 {
        self.accepted = true;
        self.handle
    }
}

impl Drop for OpenReservation<'_> {
    fn drop(&mut self) {
        if !self.accepted
            && let Ok(mut state) = self.lifetime.lock()
        {
            let _ = state.remove_handle(self.handle, self.ino);
        }
    }
}

impl NtfsFs {
    pub(super) fn lifetime_lock(&self) -> Result<MutexGuard<'_, NtfsLifetime>> {
        self.lifetime
            .lock()
            .map_err(|_| FfsError::Io(std::io::Error::other("NTFS lifetime registry poisoned")))
    }

    pub(super) fn install_lifetime_oracle(&self, oracle: OpenHandleOracle) {
        if let Ok(mut state) = self.lifetime.lock()
            && state.oracle.is_none()
        {
            state.oracle = Some(oracle);
        }
    }

    pub(super) fn reserve_open(&self, ino: InodeNumber) -> Result<OpenReservation<'_>> {
        let mut state = self.lifetime_lock()?;
        if state.handles.len() >= MAX_HANDLES {
            return Err(errno(libc::EMFILE));
        }
        let handle = state
            .next_handle
            .checked_add(1)
            .ok_or_else(|| errno(libc::EOVERFLOW))?;
        let count = state
            .counts
            .get(&ino)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| errno(libc::EOVERFLOW))?;
        state.handles.insert(handle, ino);
        state.counts.insert(ino, count);
        state.next_handle = handle;
        Ok(OpenReservation {
            lifetime: &self.lifetime,
            handle,
            ino,
            accepted: false,
        })
    }

    pub(super) fn release_open(&self, ino: InodeNumber, handle: u64) -> Result<()> {
        if handle == 0 {
            return Ok(());
        }
        self.lifetime_lock()?.remove_handle(handle, ino)
    }

    pub(super) fn pinned(&self, ino: InodeNumber) -> Result<bool> {
        let (own, oracle) = {
            let state = self.lifetime_lock()?;
            (
                state.counts.get(&ino).copied().unwrap_or(0),
                state.oracle.clone(),
            )
        };
        Ok(own != 0 || oracle.is_some_and(|oracle| oracle(ino) != 0))
    }

    pub(super) fn is_base_or_ads_pinned(
        &self,
        base_ino: InodeNumber,
        base_ref: NtfsReference,
    ) -> Result<bool> {
        if self.pinned(base_ino)? {
            return Ok(true);
        }
        let ads_inos = self.lifetime_lock()?.ads.inodes_for_base(base_ref);
        for ads_ino in ads_inos {
            if self.pinned(ads_ino)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn is_retained_file(&self, ino: InodeNumber) -> Result<bool> {
        Ok(self.lifetime_lock()?.retained_files.contains_key(&ino))
    }

    pub(super) fn fold_units(&self, units: &[u16]) -> Vec<u16> {
        units.iter().map(|&u| self.upcase[usize::from(u)]).collect()
    }

    pub(super) fn is_hidden_root_folded_name(&self, folded: &[u16]) -> Result<bool> {
        let state = self.lifetime_lock()?;
        Ok(state
            .retained_files
            .values()
            .any(|r| r.folded_orphan == folded))
    }

    pub(super) fn is_hidden_ads_folded_name(
        &self,
        base_ref: NtfsReference,
        folded_stream: &[u16],
    ) -> Result<bool> {
        let state = self.lifetime_lock()?;
        Ok(state
            .retained_streams
            .values()
            .any(|r| r.base_ref == base_ref && r.folded_orphan_stream == folded_stream))
    }

    pub(super) fn assign_dir_cookies(
        &self,
        dir_ino: InodeNumber,
        rows: &mut [DirEntry],
    ) -> Result<()> {
        let mut state = self.lifetime_lock()?;
        state.cookies.entry(dir_ino).or_default().assign(rows)
    }
}
