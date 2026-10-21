//! Mount-lifetime retention using ordinary native short-name recovery records.
//!
//! Unlink hides a collision-checked, same-slot native rename from this mount,
//! rather than freeing clusters still pinned by an open handle or the transport.
//! The record keeps exact EOF, metadata and allocation durable, so all existing
//! positioned I/O, truncate, allocation, copy and fsync paths continue to work.
//! No checker exception, synthetic FAT, temporary payload copy or dirty-admission
//! bypass is needed. Last release/FORGET reclaims through the native unlink path.
//!
//! This is a deliberately bounded retention profile, not full POSIX parity:
//! each retained file still occupies its native directory slot, and prevents
//! removing that physical parent while retained. A crash can leave Fxxxxxxx.DEL
//! records, including an intermediate exchanged namespace after interrupted
//! rename-overwrite; interruption during a name rewrite can also leave lost
//! allocation requiring the existing native recovery/salvage tools. Pinned
//! overwrite retains exchange's conservative read-only-attribute admission.
//! On a fresh mount completed recovery records are ORDINARY recoverable files;
//! never infer ownership or delete a pre-existing file from its name. Runtime
//! visibility comes only from this mount's registry. No crash atomicity claimed.

use super::{
    Directory, Entry, FatFs, FfsError, InodeNumber, OsStr, Result, checkpoint, map_mutation_error,
    rename_in_volume, set_attr_in_volume, unlink_in_volume,
};
use asupersync::Cx;
use ffs_core::vfs::OpenHandleOracle;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

const MAX_HANDLES: usize = 65_536;
const MAX_RETAINED: usize = 4_096;

#[derive(Clone, Copy)]
struct Retained {
    slot: u64,
    visible_to_handles: bool,
}

#[derive(Default)]
pub(super) struct Lifetime {
    oracle: Option<OpenHandleOracle>,
    handles: BTreeMap<u64, InodeNumber>,
    counts: BTreeMap<InodeNumber, u64>,
    retained: BTreeMap<InodeNumber, Retained>,
    next_handle: u64,
    next_name: u32,
}

fn locked(lifetime: &Mutex<Lifetime>) -> Result<MutexGuard<'_, Lifetime>> {
    lifetime
        .lock()
        .map_err(|_| FfsError::Io(std::io::Error::other("FAT lifetime registry poisoned")))
}

fn errno(value: i32) -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(value))
}

impl Lifetime {
    fn remove_handle(&mut self, handle: u64, ino: InodeNumber) -> Result<()> {
        if self.handles.get(&handle) != Some(&ino) {
            return Err(errno(libc::EBADF));
        }
        let count = self
            .counts
            .get_mut(&ino)
            .ok_or_else(|| FfsError::Io(std::io::Error::other("FAT handle count missing")))?;
        *count = count
            .checked_sub(1)
            .ok_or_else(|| FfsError::Io(std::io::Error::other("FAT handle count underflow")))?;
        if *count == 0 {
            self.counts.remove(&ino);
        }
        self.handles.remove(&handle);
        Ok(())
    }
}

/// Reserve before O_TRUNC or other backing writes. A failed open drops only its
/// registry reservation, never performs filesystem I/O in a destructor.
pub(super) struct OpenReservation<'a> {
    lifetime: &'a Mutex<Lifetime>,
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
            // A mismatched internal reservation must fail closed, not silently
            // permit reclamation. Such a mismatch leaves the remaining pins.
            let _ = state.remove_handle(self.handle, self.ino);
        }
    }
}

/// Preallocate the bounded registry entry before native namespace mutation.
/// Readers cannot observe a pending reservation: the caller owns the writer gate.
struct RetentionReservation<'a> {
    lifetime: &'a Mutex<Lifetime>,
    ino: InodeNumber,
    accepted: bool,
}

impl RetentionReservation<'_> {
    fn publish(mut self, slot: u64) -> Result<()> {
        let mut state = locked(self.lifetime)?;
        let record = state.retained.get_mut(&self.ino).ok_or_else(|| {
            FfsError::Io(std::io::Error::other("FAT retention reservation missing"))
        })?;
        if record.slot != slot || record.visible_to_handles {
            return Err(FfsError::Corruption {
                block: slot / 512,
                detail: "native retention moved or reused its reserved slot".into(),
            });
        }
        record.visible_to_handles = true;
        self.accepted = true;
        Ok(())
    }
}

impl Drop for RetentionReservation<'_> {
    fn drop(&mut self) {
        if !self.accepted
            && let Ok(mut state) = self.lifetime.lock()
        {
            state.retained.remove(&self.ino);
        }
    }
}

impl FatFs {
    pub(super) fn install_lifetime_oracle(&self, oracle: OpenHandleOracle) {
        // Installation is a once-per-mount transport hook. Replacing a live
        // oracle with one returning zero could release another caller's pins.
        // Poison is not recovered: subsequent operations report the error.
        if let Ok(mut state) = self.lifetime.lock()
            && state.oracle.is_none()
        {
            state.oracle = Some(oracle);
        }
    }

    pub(super) fn reserve_open(&self, ino: InodeNumber) -> Result<OpenReservation<'_>> {
        let mut state = locked(&self.lifetime)?;
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
        // A transport may CREATE without calling backend open, returning the
        // stateless handle zero. Its oracle/FORGET hook still owns that lifetime.
        if handle == 0 {
            return Ok(());
        }
        locked(&self.lifetime)?.remove_handle(handle, ino)
    }

    pub(super) fn pinned(&self, ino: InodeNumber) -> Result<bool> {
        let (own, oracle) = {
            let state = locked(&self.lifetime)?;
            (
                state.counts.get(&ino).copied().unwrap_or(0),
                state.oracle.clone(),
            )
        };
        // No registry/namespace mutex is held while invoking transport code.
        Ok(own != 0 || oracle.is_some_and(|oracle| oracle(ino) != 0))
    }

    pub(super) fn retained(&self, ino: InodeNumber) -> Result<bool> {
        Ok(locked(&self.lifetime)?
            .retained
            .get(&ino)
            .is_some_and(|record| record.visible_to_handles))
    }

    pub(super) fn visible_lookup(
        &self,
        cx: &Cx,
        directory: Directory,
        name: &str,
    ) -> Result<Entry> {
        let entry = self.volume.lookup(cx, directory, name)?;
        if locked(&self.lifetime)?
            .retained
            .values()
            .any(|record| record.visible_to_handles && record.slot == entry.offset)
        {
            return Err(FfsError::NotFound(name.to_owned()));
        }
        checkpoint(cx)?;
        Ok(entry)
    }

    pub(super) fn require_unreserved_target(&self, slot: u64) -> Result<()> {
        // Invisible is NOT free. Otherwise rename to a guessed recovery name
        // would let the native writer overwrite and free a still-open object.
        if locked(&self.lifetime)?
            .retained
            .values()
            .any(|record| record.visible_to_handles && record.slot == slot)
        {
            return Err(FfsError::Exists);
        }
        Ok(())
    }

    pub(super) fn visible_entries(&self, mut entries: Vec<Entry>) -> Result<Vec<Entry>> {
        let state = locked(&self.lifetime)?;
        let hidden: BTreeSet<_> = state
            .retained
            .values()
            .filter(|record| record.visible_to_handles)
            .map(|record| record.slot)
            .collect();
        entries.retain(|entry| !hidden.contains(&entry.offset));
        Ok(entries)
    }

    fn reserve_retention(&self, ino: InodeNumber, slot: u64) -> Result<RetentionReservation<'_>> {
        let mut state = locked(&self.lifetime)?;
        if state.retained.len() >= MAX_RETAINED {
            return Err(errno(libc::ENOSPC));
        }
        if state.retained.contains_key(&ino)
            || state.retained.values().any(|record| record.slot == slot)
        {
            return Err(FfsError::Corruption {
                block: slot / 512,
                detail: "FAT retention identity or slot already registered".into(),
            });
        }
        state.retained.insert(
            ino,
            Retained {
                slot,
                visible_to_handles: false,
            },
        );
        Ok(RetentionReservation {
            lifetime: &self.lifetime,
            ino,
            accepted: false,
        })
    }

    fn recovery_name(&self, cx: &Cx, parent: InodeNumber) -> Result<String> {
        let directory = self.node(cx, parent)?.directory()?;
        let entries = self.volume.list(cx, directory)?;
        let page = self.volume.oem_code_page();
        let mut keys = BTreeSet::new();
        let mut conservative = BTreeSet::new();
        for entry in &entries {
            checkpoint(cx)?;
            let name = entry.name()?;
            let alias = entry.short_alias().ok_or_else(|| {
                FfsError::UnsupportedFeature(
                    "retention requires representable native aliases".into(),
                )
            })?;
            for value in [name, alias] {
                keys.insert(page.name_key(&value));
                conservative.insert(value.to_uppercase().to_lowercase());
            }
        }
        // Every existing object reserves at most a display name and an alias.
        // Bound the search by that set, not an unbounded collision retry loop.
        for _ in 0..=2 * entries.len() {
            checkpoint(cx)?;
            let serial = {
                let mut state = locked(&self.lifetime)?;
                let serial = state.next_name & 0x0FFF_FFFF;
                state.next_name = serial + 1;
                serial
            };
            let name = format!("F{serial:07X}.DEL");
            if !keys.contains(&page.name_key(&name))
                && !conservative.contains(&name.to_uppercase().to_lowercase())
            {
                return self
                    .child_path(parent, OsStr::new(&name))
                    .map(|(path, _)| path);
            }
        }
        Err(errno(libc::ENOSPC))
    }

    /// The supplied source is already resolved through the visible namespace.
    /// Ordinary unlink policy (including native read-only attributes) applies.
    pub(super) fn retain_unlink_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        path: &str,
        entry: &Entry,
        ino: InodeNumber,
    ) -> Result<()> {
        unlink_in_volume(cx, &self.volume, path, true).map_err(map_mutation_error)?;
        let recovery = self.recovery_name(cx, parent)?;
        rename_in_volume(cx, &self.volume, path, &recovery, true).map_err(map_mutation_error)?;
        let reservation = self.reserve_retention(ino, entry.offset)?;
        rename_in_volume(cx, &self.volume, path, &recovery, false).map_err(map_mutation_error)?;
        let node = self.refresh_node_from_path(cx, ino, &recovery)?;
        let slot = node.entry.ok_or(FfsError::IsDirectory)?.offset;
        reservation.publish(slot)?;
        checkpoint(cx)
    }

    /// A pinned overwrite target must not be freed or disappear on a later
    /// deterministic refusal. Preflight both native steps, then exchange the
    /// objects and retain the displaced target in the source's old footprint.
    /// This works without spare source/destination slots or copying payloads.
    pub(super) fn replace_pinned_locked(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
        target_ino: InodeNumber,
    ) -> Result<()> {
        let (from, _) = self.child_path(parent, name)?;
        let (to, _) = self.child_path(new_parent, new_name)?;
        rename_in_volume(cx, &self.volume, &from, &to, true).map_err(map_mutation_error)?;
        self.volume
            .rename_exchange(cx, &from, &to, true)
            .map_err(map_mutation_error)?;
        let recovery = self.recovery_name(cx, parent)?;
        rename_in_volume(cx, &self.volume, &from, &recovery, true).map_err(map_mutation_error)?;
        let source = self
            .volume
            .resolve(cx, &from)?
            .ok_or(FfsError::IsDirectory)?;
        let reservation = self.reserve_retention(target_ino, source.offset)?;
        self.exchange_locked(cx, parent, name, new_parent, new_name)?;
        // Do not recurse through public rename/unlink: this operation retains
        // one writer guard and has already reserved the displaced object's ID.
        rename_in_volume(cx, &self.volume, &from, &recovery, false).map_err(map_mutation_error)?;
        let node = self.refresh_node_from_path(cx, target_ino, &recovery)?;
        reservation.publish(node.entry.ok_or(FfsError::IsDirectory)?.offset)?;
        checkpoint(cx)
    }

    /// Called under the operation writer gate by RELEASE, FORGET or destroy.
    /// Never infer a reclaimable record from a filename, even after remount.
    pub(super) fn reap_retained_locked(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        destroying: bool,
    ) -> Result<bool> {
        checkpoint(cx)?;
        if !self.retained(ino)? || (!destroying && self.pinned(ino)?) {
            return Ok(false);
        }
        self.ensure_writable()?;
        let path = self.path_for_inode(ino)?;
        let node = self.node(cx, ino)?;
        let entry = node.entry.as_ref().ok_or(FfsError::IsDirectory)?;
        let expected = locked(&self.lifetime)?
            .retained
            .get(&ino)
            .copied()
            .ok_or_else(|| FfsError::NotFound(format!("FAT retained inode {}", ino.0)))?;
        let actual = self
            .volume
            .resolve(cx, &path)?
            .ok_or(FfsError::IsDirectory)?;
        if entry.offset != expected.slot
            || actual.offset != expected.slot
            || actual.native != entry.native
            || actual.native.is_directory()
        {
            return Err(FfsError::Corruption {
                block: expected.slot / 512,
                detail: "retained FAT record changed before final reclamation".into(),
            });
        }
        // chmod through a held inode can set DOS read-only AFTER unlink.
        // Last-close reclamation is not a new user unlink permission decision.
        if actual.native.attributes & 1 != 0 {
            set_attr_in_volume(cx, &self.volume, &path, Some(false), None, None)
                .map_err(map_mutation_error)?;
            self.refresh_node_from_path(cx, ino, &path)?;
        }
        unlink_in_volume(cx, &self.volume, &path, false).map_err(map_mutation_error)?;
        {
            let mut state = self.state()?;
            if state.slot_to_ino.get(&expected.slot) != Some(&ino) {
                return Err(FfsError::Corruption {
                    block: expected.slot / 512,
                    detail: "FAT retained inode mapping changed during finalization".into(),
                });
            }
            state.slot_to_ino.remove(&expected.slot);
            Self::invalidate_cached_chain(&mut state, ino);
            state.nodes.remove(&ino);
            state.free_clusters = None;
        }
        locked(&self.lifetime)?.retained.remove(&ino);
        checkpoint(cx)?;
        Ok(true)
    }

    pub(super) fn reap_all_retained_locked(&self, cx: &Cx) -> Result<()> {
        let ids: Vec<_> = locked(&self.lifetime)?
            .retained
            .iter()
            .filter_map(|(&ino, record)| record.visible_to_handles.then_some(ino))
            .collect();
        for ino in ids {
            checkpoint(cx)?;
            self.reap_retained_locked(cx, ino, true)?;
        }
        Ok(())
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
