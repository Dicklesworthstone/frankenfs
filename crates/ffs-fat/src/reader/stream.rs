//! Bounded indexes for immutable-file reads. This is not sparse-file storage.
//!
//! Validate every allocation link (including preallocation) before reading data,
//! but retain only every 256th cluster. Random seeks walk at most 255 links from
//! an anchor; sequential requests reuse a cursor and bounded selected-FAT caches.

use super::{
    Cx, Entry, FatTable, FatVolume, FfsError, MAX_CHAIN_CLUSTERS, MAX_READ_BYTES,
    MAX_READ_RUN_BYTES, Result, allocate, checkpoint, corrupt,
};
use std::sync::Arc;

const ANCHOR_STRIDE: usize = 256;

/// Owned validation evidence for the immutable adapter's mount-local cache.
/// Only the owning volume may reuse it, and never across native mutation.
/// The type is only re-exported within this crate; public callers cannot supply
/// one to bypass validation.
#[derive(Clone)]
pub struct FileIndex {
    anchors: Arc<Vec<u32>>,
    allocated: usize,
    size: u32,
    report_offset: u64,
    first_cluster: u32,
}

impl FileIndex {
    #[must_use]
    pub(crate) fn len_bytes(&self) -> u64 {
        u64::from(self.size)
    }

    #[must_use]
    pub(crate) fn allocated_clusters(&self) -> usize {
        self.allocated
    }

    #[must_use]
    pub(crate) fn storage_bytes(&self) -> usize {
        self.anchors.capacity() * std::mem::size_of::<u32>()
    }

    #[must_use]
    pub(crate) fn matches(&self, entry: &Entry) -> bool {
        !entry.native.is_directory()
            && entry.offset == self.report_offset
            && entry.native.first_cluster == self.first_cluster
            && entry.native.size == self.size
    }
}

/// Read-only file access tied to one immutable volume and verified chain.
///
/// Keep the backing and native metadata unchanged for this reader's ENTIRE
/// lifetime, including between calls. A shared Rust borrow/advisory file lock
/// does not exclude a native mutation through another handle. Drop this reader
/// before mutation; it is not a snapshot or a mounted mutable-cache substitute.
/// Construction scans the complete chain. It does not check global ownership.
/// No method writes or synchronizes the backing device.
pub struct FileReader<'a> {
    volume: &'a FatVolume,
    table: FatTable<'a>,
    anchors: Arc<Vec<u32>>,
    allocated: usize,
    size: u32,
    report_offset: u64,
    cursor: Option<(usize, u32)>,
}

impl FatVolume {
    /// Walk complete physical runs without retaining the cluster map. The
    /// visitor's output is provisional until this method succeeds: a corrupt
    /// tail, short chain or cancellation must discard ALL accumulated extents.
    /// No payload is read. Keep the volume immutable or hold its operation gate.
    pub(crate) fn visit_file_runs(
        &self,
        cx: &Cx,
        entry: &Entry,
        mut visit: impl FnMut(u64, u64, u64, bool) -> Result<()>,
    ) -> Result<()> {
        checkpoint(cx)?;
        if entry.native.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());
        let required = u64::from(entry.native.size).div_ceil(cluster_bytes);
        let mut emit = |index: usize, first: u32, count: usize, last: bool| {
            checkpoint(cx)?;
            let logical = (index as u64)
                .checked_mul(cluster_bytes)
                .ok_or_else(|| corrupt(entry.offset, "FAT run logical offset overflow"))?;
            let physical = self.cluster_offset(first)?;
            let length = (count as u64)
                .checked_mul(cluster_bytes)
                .ok_or_else(|| corrupt(entry.offset, "FAT run length overflow"))?;
            if physical
                .checked_add(length)
                .is_none_or(|end| end > self.geometry.volume_bytes())
            {
                return Err(corrupt(entry.offset, "FAT run exceeds selected volume"));
            }
            visit(logical, physical, length, last)?;
            checkpoint(cx)
        };
        let mut run: Option<(usize, u32, u32, usize)> = None;
        self.walk_chain(
            cx,
            entry.native.first_cluster,
            required,
            entry.offset,
            MAX_CHAIN_CLUSTERS,
            |index, cluster| {
                if let Some((_, _, previous, count)) = run.as_mut()
                    && previous.checked_add(1) == Some(cluster)
                {
                    *previous = cluster;
                    *count += 1;
                    return Ok(());
                }
                if let Some((start, first, _, count)) = run.take() {
                    emit(start, first, count, false)?;
                }
                run = Some((index, cluster, cluster, 1));
                Ok(())
            },
        )?;
        // LAST is only announced after complete native chain validation, even
        // when logical EOF is zero or precedes reachable preallocation.
        if let Some((start, first, _, count)) = run {
            emit(start, first, count, true)?;
        }
        checkpoint(cx)
    }

    /// Validate a regular file and prepare a bounded random/sequential reader.
    /// Uses the same native link validation and work limit as `file_chain`,
    /// without retaining a vector entry for every allocated cluster.
    pub fn open_file_reader(&self, cx: &Cx, entry: &Entry) -> Result<FileReader<'_>> {
        let index = self.index_file(cx, entry)?;
        Ok(self.reader_from_index(&index))
    }

    /// Build completely before insertion into the immutable mount cache. No
    /// provisional anchors or failed validation are reusable evidence.
    pub(crate) fn index_file(&self, cx: &Cx, entry: &Entry) -> Result<FileIndex> {
        checkpoint(cx)?;
        if entry.native.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        let required =
            u64::from(entry.native.size).div_ceil(u64::from(self.geometry.cluster_bytes()));
        let limit = MAX_CHAIN_CLUSTERS.min(self.geometry.cluster_count() as usize);
        let max_anchors = limit.div_ceil(ANCHOR_STRIDE);
        let mut anchors = Vec::new();
        let allocated = self.walk_chain(
            cx,
            entry.native.first_cluster,
            required,
            entry.offset,
            limit,
            |index, cluster| {
                if index.is_multiple_of(ANCHOR_STRIDE) {
                    if anchors.len() == anchors.capacity() {
                        let additional = anchors.len().max(16).min(max_anchors - anchors.len());
                        anchors.try_reserve_exact(additional).map_err(|error| {
                            FfsError::Format(format!("FAT seek-index allocation failed: {error}"))
                        })?;
                    }
                    anchors.push(cluster);
                }
                Ok(())
            },
        )?;
        checkpoint(cx)?;
        Ok(FileIndex {
            anchors: Arc::new(anchors),
            allocated,
            size: entry.native.size,
            report_offset: entry.offset,
            first_cluster: entry.native.first_cluster,
        })
    }

    /// Caller pairs this internal index with its originating immutable volume.
    /// Request-local FAT windows and cursor prevent concurrent reads sharing
    /// mutable seek state or holding the mount cache lock during device I/O.
    #[must_use]
    pub(crate) fn reader_from_index(&self, index: &FileIndex) -> FileReader<'_> {
        FileReader {
            volume: self,
            // Validation caches are deliberately not used to answer the first
            // demand read. Subsequent cache lifetime is this immutable reader.
            table: FatTable::new(self),
            anchors: Arc::clone(&index.anchors),
            allocated: index.allocated,
            size: index.size,
            report_offset: index.report_offset,
            cursor: None,
        }
    }
}

impl FileReader<'_> {
    /// Logical EOF; never includes final-cluster slack or preallocation.
    #[must_use]
    pub fn len_bytes(&self) -> u64 {
        u64::from(self.size)
    }

    /// Complete verified allocation, including reachable clusters beyond EOF.
    #[must_use]
    pub fn allocated_clusters(&self) -> usize {
        self.allocated
    }

    /// Retained anchor-vector capacity in bytes, excluding the two bounded FAT
    /// windows, returned payload buffers, object headers and allocator overhead.
    #[must_use]
    pub fn index_storage_bytes(&self) -> usize {
        self.anchors.capacity() * std::mem::size_of::<u32>()
    }

    fn cluster_at(&mut self, cx: &Cx, index: usize) -> Result<u32> {
        checkpoint(cx)?;
        if index >= self.allocated {
            return Err(corrupt(
                self.report_offset,
                "FAT seek exceeds verified allocation",
            ));
        }
        let anchor_index = index / ANCHOR_STRIDE;
        let base = anchor_index * ANCHOR_STRIDE;
        let first = *self
            .anchors
            .get(anchor_index)
            .ok_or_else(|| corrupt(self.report_offset, "FAT seek anchor is absent"))?;
        let (mut position, mut cluster) = self
            .cursor
            .filter(|(position, _)| *position >= base && *position <= index)
            .unwrap_or((base, first));
        while position < index {
            checkpoint(cx)?;
            cluster = self
                .table
                .next(cx, cluster)?
                .ok_or_else(|| corrupt(self.report_offset, "FAT chain changed after indexing"))?;
            position += 1;
        }
        self.volume.cluster_offset(cluster)?;
        self.cursor = Some((position, cluster));
        Ok(cluster)
    }

    /// Return exact requested bytes, clamped at logical EOF. A request retains
    /// its output privately until every FAT/data read and checkpoint succeeds.
    /// The existing 16 MiB request bound and 64 KiB physical-run bound apply.
    pub fn read(&mut self, cx: &Cx, offset: u64, size: usize) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        if size > MAX_READ_BYTES {
            return Err(FfsError::Format("FAT read request exceeds 16 MiB".into()));
        }
        let length = self.len_bytes().saturating_sub(offset).min(size as u64) as usize;
        let mut result = allocate(length)?;
        let cluster_bytes = u64::from(self.volume.geometry.cluster_bytes());
        let mut done = 0;
        while done < length {
            checkpoint(cx)?;
            let logical = offset + done as u64;
            let mut index = (logical / cluster_bytes) as usize;
            let within = logical % cluster_bytes;
            let mut cluster = self.cluster_at(cx, index)?;
            let physical = self.volume.cluster_offset(cluster)? + within;
            let limit = (length - done).min(MAX_READ_RUN_BYTES);
            let mut count = limit.min((cluster_bytes - within) as usize);
            while count < limit {
                let next = self.cluster_at(cx, index + 1)?;
                if cluster.checked_add(1) != Some(next) {
                    break;
                }
                if physical.checked_add(count as u64) != Some(self.volume.cluster_offset(next)?) {
                    return Err(corrupt(
                        self.report_offset,
                        "FAT read run is not contiguous",
                    ));
                }
                count += (limit - count).min(cluster_bytes as usize);
                cluster = next;
                index += 1;
            }
            self.volume
                .read_exact(cx, physical, &mut result[done..done + count])?;
            done += count;
        }
        checkpoint(cx)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
