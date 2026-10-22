//! Bounded allocation evidence for read-only FsOps, separate from writable maps.
//!
//! Cache immutable sparse indexes, never borrowed readers or per-request cursors.
//! The operation gate is acquired by FsOps before entering these helpers. No
//! namespace/cache mutex is held while the native reader touches the device.
//!
//! Retained anchor Vec capacity is capped at 2 MiB and 1024 entries. Arc/map
//! headers, allocator overhead and in-flight requests are separate; eviction
//! does not revoke an index already held by a request. FAT windows and seek
//! cursors are request-local. This is not a whole-process memory limit.
//! FIEMAP walks physical runs without a temporary complete cluster map. Its
//! result still grows with the number of intersecting extents requested; the
//! complete chain is checked even for empty queries or matches near the head.

use super::{Entry, FatFs, FfsError, InodeNumber, MAX_CACHED_CHAINS, Result, checkpoint};
use super::{
    FIEMAP_EXTENT_LAST, FIEMAP_EXTENT_NOT_ALIGNED, FIEMAP_EXTENT_UNWRITTEN,
    FiemapExtent, fiemap_corrupt,
};
use crate::reader::FileIndex;
use asupersync::Cx;
use std::collections::BTreeMap;
use std::sync::MutexGuard;

const MAX_INDEX_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct IndexCache {
    entries: BTreeMap<InodeNumber, FileIndex>,
    retained_bytes: usize,
    byte_limit: usize,
    entry_limit: usize,
}

impl Default for IndexCache {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            retained_bytes: 0,
            byte_limit: MAX_INDEX_BYTES,
            entry_limit: MAX_CACHED_CHAINS,
        }
    }
}

impl IndexCache {
    fn get(&self, ino: InodeNumber, entry: &Entry) -> Result<Option<FileIndex>> {
        let Some(index) = self.entries.get(&ino) else {
            return Ok(None);
        };
        if !index.matches(entry) {
            return Err(FfsError::Corruption {
                block: entry.offset / 512,
                detail: "immutable FAT allocation identity changed".into(),
            });
        }
        Ok(Some(index.clone()))
    }

    fn insert(&mut self, ino: InodeNumber, entry: &Entry, index: FileIndex) -> Result<FileIndex> {
        // Concurrent cold readers may have validated the same file. Retain one
        // allocation and charge it once; neither thread owns shared seek state.
        if let Some(existing) = self.get(ino, entry)? {
            return Ok(existing);
        }
        let bytes = index.storage_bytes();
        if bytes > self.byte_limit || self.entry_limit == 0 {
            return Ok(index);
        }
        while self.retained_bytes > self.byte_limit - bytes
            || self.entries.len() >= self.entry_limit
        {
            let Some((_, previous)) = self.entries.pop_first() else {
                return Err(FfsError::Io(std::io::Error::other(
                    "FAT immutable index cache accounting is inconsistent",
                )));
            };
            self.retained_bytes = self
                .retained_bytes
                .checked_sub(previous.storage_bytes())
                .ok_or_else(|| {
                    FfsError::Io(std::io::Error::other("FAT immutable cache accounting underflow"))
                })?;
        }
        self.retained_bytes += bytes;
        self.entries.insert(ino, index.clone());
        Ok(index)
    }
}

impl FatFs {
    /// Enumerate selected-volume extents with constant traversal storage, apart
    /// from bounded FAT windows and the requested result. Do not consult cached
    /// anchors: every chain link, including an unrequested tail, is revalidated.
    /// The operation gate is held by the FsOps caller; no cache lock spans I/O.
    pub(super) fn readonly_fiemap(
        &self,
        cx: &Cx,
        entry: &Entry,
        start: u64,
        length: u64,
    ) -> Result<Vec<FiemapExtent>> {
        checkpoint(cx)?;
        if self.writable {
            return Err(FfsError::UnsupportedFeature(
                "immutable FAT extent traversal is unavailable on writable mounts".into(),
            ));
        }
        let mut result = Vec::new();
        let query_end = start.saturating_add(length);
        let size = u64::from(entry.native.size);
        let cluster_bytes = u64::from(self.volume.geometry.cluster_bytes());
        self.volume.visit_file_runs(cx, entry, |logical, physical, run_length, last| {
            let run_end = logical
                .checked_add(run_length)
                .ok_or_else(|| fiemap_corrupt(logical, "FAT extent end overflow"))?;
            let initialized_end = size.clamp(logical, run_end);
            // Match the existing materialized mapper exactly: retain complete
            // intersecting extents, split at EOF, and describe real allocated
            // slack/preallocation as UNWRITTEN rather than readable file bytes.
            for (at, delta, count, mut flags) in [
                (logical, 0, initialized_end - logical, 0),
                (
                    initialized_end,
                    initialized_end - logical,
                    run_end - initialized_end,
                    FIEMAP_EXTENT_UNWRITTEN,
                ),
            ] {
                checkpoint(cx)?;
                let end = at + count; // Bounded by the checked run_end above.
                if count == 0 || length == 0 || at >= query_end || end <= start {
                    continue;
                }
                let position = physical + delta; // Checked by visit_file_runs.
                if last && end == run_end {
                    flags |= FIEMAP_EXTENT_LAST;
                }
                if !at.is_multiple_of(cluster_bytes)
                    || !position.is_multiple_of(cluster_bytes)
                    || !count.is_multiple_of(cluster_bytes)
                {
                    flags |= FIEMAP_EXTENT_NOT_ALIGNED;
                }
                result.try_reserve(1)
                    .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
                result.push(FiemapExtent {
                    logical: at,
                    physical: position,
                    length: count,
                    flags,
                });
            }
            Ok(())
        })?;
        // Nothing escapes on a late FAT error, visitor failure or cancellation.
        checkpoint(cx)?;
        Ok(result)
    }

    fn immutable_cache(&self) -> Result<MutexGuard<'_, IndexCache>> {
        self.immutable_indexes.lock().map_err(|_| {
            FfsError::Io(std::io::Error::other("FAT immutable index cache poisoned"))
        })
    }

    pub(super) fn readonly_index(&self, cx: &Cx, ino: InodeNumber, entry: &Entry) -> Result<FileIndex> {
        checkpoint(cx)?;
        // Refuse accidental use by mutation paths, rather than adding a second
        // invalidation protocol which could retain old allocation after reuse.
        if self.writable {
            return Err(FfsError::UnsupportedFeature(
                "immutable FAT indexes are unavailable on writable mounts".into(),
            ));
        }
        let cached = self.immutable_cache()?.get(ino, entry)?;
        if let Some(index) = cached {
            checkpoint(cx)?;
            return Ok(index);
        }
        let index = self.volume.index_file(cx, entry)?;
        checkpoint(cx)?;
        let index = self.immutable_cache()?.insert(ino, entry, index)?;
        checkpoint(cx)?;
        Ok(index)
    }

    pub(super) fn file_allocation(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        entry: &Entry,
    ) -> Result<(u64, usize)> {
        if self.writable {
            let chain = self.chain(cx, ino, entry)?;
            Ok((u64::from(chain.size), chain.clusters.len()))
        } else {
            let index = self.readonly_index(cx, ino, entry)?;
            Ok((index.len_bytes(), index.allocated_clusters()))
        }
    }
}

#[cfg(test)]
mod extents_tests;

// Test-only observations exercise actual FsOps calls without exporting cache
// state as public API or relaxing any production bound/admission rule.
#[cfg(test)]
impl FatFs {
    pub(crate) fn immutable_cache_usage(&self) -> (usize, usize, usize) {
        let (entries, bytes) = {
            let cache = self.immutable_cache().unwrap();
            (cache.entries.len(), cache.retained_bytes)
        };
        (entries, bytes, self.state().unwrap().chains.len())
    }

    pub(crate) fn limit_immutable_cache(&self, bytes: usize, entries: usize) {
        let mut cache = self.immutable_cache().unwrap();
        assert!(cache.entries.is_empty());
        cache.byte_limit = bytes;
        cache.entry_limit = entries;
    }
}
