#![forbid(unsafe_code)]
//! Block I/O layer with ARC (Adaptive Replacement Cache).
//!
//! Provides the `BlockDevice` trait, cached block reads/writes with
//! `&Cx` capability context for cooperative cancellation, dirty page
//! tracking, and background flush coordination.

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, BlockNumber, ByteOffset, CommitSeq,
    EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, TxnId,
};
use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

#[inline]
fn cx_checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

/// Owned block buffer.
///
/// Invariant: length == device block size for the originating device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBuf {
    bytes: Vec<u8>,
}

impl BlockBuf {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

/// Byte-addressed device for fixed-offset I/O (pread/pwrite semantics).
pub trait ByteDevice: Send + Sync {
    /// Total length in bytes.
    fn len_bytes(&self) -> u64;

    /// Read exactly `buf.len()` bytes from `offset` into `buf`.
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()>;

    /// Write all bytes in `buf` to `offset`.
    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()>;

    /// Flush pending writes to stable storage.
    fn sync(&self, cx: &Cx) -> Result<()>;
}

/// File-backed byte device using Linux `pread`/`pwrite` style I/O.
///
/// This uses `std::os::unix::fs::FileExt`, which is thread-safe and does not
/// require a shared seek position.
#[derive(Debug, Clone)]
pub struct FileByteDevice {
    file: Arc<File>,
    len: u64,
    writable: bool,
}

impl FileByteDevice {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let (file, writable) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.as_ref())
            .map(|file| (file, true))
            .or_else(|_| {
                OpenOptions::new()
                    .read(true)
                    .open(path.as_ref())
                    .map(|file| (file, false))
            })?;
        let len = file.metadata()?.len();
        Ok(Self {
            file: Arc::new(file),
            len,
            writable,
        })
    }

    #[must_use]
    pub fn file(&self) -> &Arc<File> {
        &self.file
    }
}

impl ByteDevice for FileByteDevice {
    fn len_bytes(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        let end = offset
            .0
            .checked_add(
                u64::try_from(buf.len())
                    .map_err(|_| FfsError::Format("read length overflows u64".to_owned()))?,
            )
            .ok_or_else(|| FfsError::Format("read range overflows u64".to_owned()))?;
        if end > self.len {
            return Err(FfsError::Format(format!(
                "read out of bounds: offset={offset} len={} file_len={}",
                buf.len(),
                self.len
            )));
        }

        self.file.read_exact_at(buf, offset.0)?;
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        if !self.writable {
            return Err(FfsError::PermissionDenied);
        }
        let end = offset
            .0
            .checked_add(
                u64::try_from(buf.len())
                    .map_err(|_| FfsError::Format("write length overflows u64".to_owned()))?,
            )
            .ok_or_else(|| FfsError::Format("write range overflows u64".to_owned()))?;
        if end > self.len {
            return Err(FfsError::Format(format!(
                "write out of bounds: offset={offset} len={} file_len={}",
                buf.len(),
                self.len
            )));
        }

        self.file.write_all_at(buf, offset.0)?;
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;
        self.file.sync_all()?;
        cx_checkpoint(cx)?;
        Ok(())
    }
}

/// Block-addressed I/O interface.
pub trait BlockDevice: Send + Sync {
    /// Read a block by number.
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf>;

    /// Write a block by number. `data.len()` MUST equal `block_size()`.
    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()>;

    /// Device block size in bytes.
    fn block_size(&self) -> u32;

    /// Total number of blocks.
    fn block_count(&self) -> u64;

    /// Flush pending writes to stable storage.
    fn sync(&self, cx: &Cx) -> Result<()>;
}

/// Cache-specific operations used by write-back control paths.
pub trait BlockCache: BlockDevice {
    /// Mark a block clean after it has been durably flushed.
    fn mark_clean(&self, block: BlockNumber);

    /// Return dirty blocks ordered from oldest to newest dirty mark.
    fn dirty_blocks_oldest_first(&self) -> Vec<BlockNumber>;

    /// Evict a block from the cache.
    ///
    /// Implementations must panic if the target block is dirty.
    fn evict(&self, block: BlockNumber);
}

/// Opaque flush pin token used to hold MVCC/GC protection across flush I/O.
#[derive(Default)]
pub struct FlushPinToken(Option<Box<dyn Send + Sync>>);

impl std::fmt::Debug for FlushPinToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FlushPinToken")
            .field(&self.0.is_some())
            .finish()
    }
}

impl FlushPinToken {
    #[must_use]
    pub fn noop() -> Self {
        Self(None)
    }

    #[must_use]
    pub fn new<T>(token: T) -> Self
    where
        T: Send + Sync + 'static,
    {
        Self(Some(Box::new(token)))
    }

    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.0.is_none()
    }
}

/// MVCC coordination hook for write-back flush lifecycle.
///
/// Implementations can pin version chains before disk write and mark versions
/// persisted after successful write completion.
pub trait MvccFlushLifecycle: Send + Sync + std::fmt::Debug {
    fn pin_for_flush(&self, block: BlockNumber, commit_seq: CommitSeq) -> Result<FlushPinToken>;
    fn mark_persisted(&self, block: BlockNumber, commit_seq: CommitSeq) -> Result<()>;
}

#[derive(Debug, Default)]
struct NoopMvccFlushLifecycle;

impl MvccFlushLifecycle for NoopMvccFlushLifecycle {
    fn pin_for_flush(&self, _block: BlockNumber, _commit_seq: CommitSeq) -> Result<FlushPinToken> {
        Ok(FlushPinToken::noop())
    }

    fn mark_persisted(&self, _block: BlockNumber, _commit_seq: CommitSeq) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct ByteBlockDevice<D: ByteDevice> {
    inner: D,
    block_size: u32,
    block_count: u64,
}

impl<D: ByteDevice> ByteBlockDevice<D> {
    pub fn new(inner: D, block_size: u32) -> Result<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(FfsError::Format(format!(
                "invalid block_size={block_size} (must be power of two)"
            )));
        }

        let len = inner.len_bytes();
        let block_size_u64 = u64::from(block_size);
        let remainder = len % block_size_u64;
        if remainder != 0 {
            return Err(FfsError::Format(format!(
                "image length is not block-aligned: len_bytes={len} block_size={block_size} remainder={remainder}"
            )));
        }
        let block_count = len / block_size_u64;
        Ok(Self {
            inner,
            block_size,
            block_count,
        })
    }

    #[must_use]
    pub fn inner(&self) -> &D {
        &self.inner
    }
}

impl<D: ByteDevice> BlockDevice for ByteBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        cx_checkpoint(cx)?;
        if block.0 >= self.block_count {
            return Err(FfsError::Format(format!(
                "block out of range: block={} block_count={}",
                block.0, self.block_count
            )));
        }

        let offset = block
            .0
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(|| FfsError::Format("block offset overflow".to_owned()))?;
        let mut buf = vec![
            0_u8;
            usize::try_from(self.block_size).map_err(|_| {
                FfsError::Format("block_size does not fit usize".to_owned())
            })?
        ];
        self.inner.read_exact_at(cx, ByteOffset(offset), &mut buf)?;
        cx_checkpoint(cx)?;
        Ok(BlockBuf::new(buf))
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        let expected = usize::try_from(self.block_size)
            .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;
        if data.len() != expected {
            return Err(FfsError::Format(format!(
                "write_block data size mismatch: got={} expected={expected}",
                data.len()
            )));
        }
        if block.0 >= self.block_count {
            return Err(FfsError::Format(format!(
                "block out of range: block={} block_count={}",
                block.0, self.block_count
            )));
        }

        let offset = block
            .0
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(|| FfsError::Format("block offset overflow".to_owned()))?;
        self.inner.write_all_at(cx, ByteOffset(offset), data)?;
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)
    }
}

/// Read the ext4 superblock region (1024 bytes at offset 1024).
pub fn read_ext4_superblock_region(
    cx: &Cx,
    dev: &dyn ByteDevice,
) -> Result<[u8; EXT4_SUPERBLOCK_SIZE]> {
    let mut buf = [0_u8; EXT4_SUPERBLOCK_SIZE];
    let offset = u64::try_from(EXT4_SUPERBLOCK_OFFSET)
        .map_err(|_| FfsError::Format("ext4 superblock offset does not fit u64".to_owned()))?;
    dev.read_exact_at(cx, ByteOffset(offset), &mut buf)?;
    Ok(buf)
}

/// Read the btrfs superblock region (4096 bytes at offset 64 KiB).
pub fn read_btrfs_superblock_region(
    cx: &Cx,
    dev: &dyn ByteDevice,
) -> Result<[u8; BTRFS_SUPER_INFO_SIZE]> {
    let mut buf = [0_u8; BTRFS_SUPER_INFO_SIZE];
    let offset = u64::try_from(BTRFS_SUPER_INFO_OFFSET)
        .map_err(|_| FfsError::Format("btrfs superblock offset does not fit u64".to_owned()))?;
    dev.read_exact_at(cx, ByteOffset(offset), &mut buf)?;
    Ok(buf)
}

/// Snapshot of ARC cache statistics.
///
/// Obtained via [`ArcCache::metrics()`] with a single lock acquisition.
/// All counters are monotonically increasing for the lifetime of the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheMetrics {
    /// Number of read requests satisfied from the cache.
    pub hits: u64,
    /// Number of read requests that required a device read.
    pub misses: u64,
    /// Number of resident blocks evicted to make room for new entries.
    pub evictions: u64,
    /// Number of dirty flushes (dirty blocks written during sync/retry paths).
    pub dirty_flushes: u64,
    /// Current number of blocks in the T1 (recently accessed) list.
    pub t1_len: usize,
    /// Current number of blocks in the T2 (frequently accessed) list.
    pub t2_len: usize,
    /// Current number of ghost entries in B1 (evicted from T1).
    pub b1_len: usize,
    /// Current number of ghost entries in B2 (evicted from T2).
    pub b2_len: usize,
    /// Total number of resident (cached) blocks.
    pub resident: usize,
    /// Current number of dirty (modified but not yet flushed) blocks.
    pub dirty_blocks: usize,
    /// Total bytes represented by dirty blocks.
    pub dirty_bytes: usize,
    /// Age of the oldest dirty block in write-order ticks.
    ///
    /// This is a logical clock (not wall time), incremented per dirty-mark.
    pub oldest_dirty_age_ticks: Option<u64>,
    /// Maximum cache capacity in blocks.
    pub capacity: usize,
    /// Current adaptive target size for T1.
    pub p: usize,
}

impl CacheMetrics {
    /// Cache hit ratio in the range [0.0, 1.0].
    ///
    /// Returns 0.0 if no accesses have been made.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Dirty block ratio in the range [0.0, 1.0].
    #[must_use]
    pub fn dirty_ratio(&self) -> f64 {
        if self.capacity == 0 {
            0.0
        } else {
            self.dirty_blocks as f64 / self.capacity as f64
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArcList {
    T1,
    T2,
    B1,
    B2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirtyState {
    InFlight,
    Committed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirtyEntry {
    seq: u64,
    bytes: usize,
    txn_id: TxnId,
    commit_seq: Option<CommitSeq>,
    state: DirtyState,
}

impl DirtyEntry {
    fn is_flushable(self) -> bool {
        matches!(self.state, DirtyState::Committed)
    }
}

#[derive(Debug, Clone)]
struct FlushCandidate {
    block: BlockNumber,
    data: Vec<u8>,
    txn_id: TxnId,
    commit_seq: CommitSeq,
}

/// Ordered tracking of dirty blocks with deterministic age semantics.
#[derive(Debug, Default)]
struct DirtyTracker {
    next_seq: u64,
    by_block: HashMap<BlockNumber, DirtyEntry>,
    by_age: BTreeSet<(u64, BlockNumber)>,
    dirty_bytes: usize,
}

impl DirtyTracker {
    fn mark_dirty(
        &mut self,
        block: BlockNumber,
        bytes: usize,
        txn_id: TxnId,
        commit_seq: Option<CommitSeq>,
        state: DirtyState,
    ) {
        if let Some(prev) = self.by_block.remove(&block) {
            let _ = self.by_age.remove(&(prev.seq, block));
            self.dirty_bytes = self.dirty_bytes.saturating_sub(prev.bytes);
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let entry = DirtyEntry {
            seq,
            bytes,
            txn_id,
            commit_seq,
            state,
        };
        self.by_block.insert(block, entry);
        self.by_age.insert((seq, block));
        self.dirty_bytes = self.dirty_bytes.saturating_add(bytes);
    }

    fn clear_dirty(&mut self, block: BlockNumber) {
        if let Some(entry) = self.by_block.remove(&block) {
            let _ = self.by_age.remove(&(entry.seq, block));
            self.dirty_bytes = self.dirty_bytes.saturating_sub(entry.bytes);
        }
    }

    fn is_dirty(&self, block: BlockNumber) -> bool {
        self.by_block.contains_key(&block)
    }

    fn entry(&self, block: BlockNumber) -> Option<DirtyEntry> {
        self.by_block.get(&block).copied()
    }

    fn dirty_count(&self) -> usize {
        self.by_block.len()
    }

    fn dirty_bytes(&self) -> usize {
        self.dirty_bytes
    }

    fn oldest_dirty_age_ticks(&self) -> Option<u64> {
        self.by_age
            .iter()
            .next()
            .map(|(oldest_seq, _)| self.next_seq.saturating_sub(*oldest_seq))
    }

    fn dirty_blocks_oldest_first(&self) -> Vec<BlockNumber> {
        self.by_age.iter().map(|(_, block)| *block).collect()
    }

    fn state_counts(&self) -> (usize, usize) {
        let mut in_flight = 0_usize;
        let mut committed = 0_usize;
        for entry in self.by_block.values() {
            match entry.state {
                DirtyState::InFlight => in_flight += 1,
                DirtyState::Committed => committed += 1,
            }
        }
        (in_flight, committed)
    }
}

#[derive(Debug)]
struct ArcState {
    capacity: usize,
    /// Target size for the T1 list.
    p: usize,
    t1: VecDeque<BlockNumber>,
    t2: VecDeque<BlockNumber>,
    b1: VecDeque<BlockNumber>,
    b2: VecDeque<BlockNumber>,
    loc: HashMap<BlockNumber, ArcList>,
    resident: HashMap<BlockNumber, Vec<u8>>,
    /// Ordered dirty block tracking for write-back and durability accounting.
    dirty: DirtyTracker,
    /// Dirty payloads queued for retry after a failed flush attempt.
    pending_flush: Vec<FlushCandidate>,
    /// Staged, not-yet-committed transactional payloads.
    staged_txn_writes: HashMap<TxnId, HashMap<BlockNumber, Vec<u8>>>,
    /// Reverse map for staged payload ownership checks.
    staged_block_owner: HashMap<BlockNumber, TxnId>,
    /// Monotonic hit counter (resident data found).
    hits: u64,
    /// Monotonic miss counter (device read required).
    misses: u64,
    /// Monotonic eviction counter (resident block displaced).
    evictions: u64,
    /// Monotonic dirty flush counter (dirty blocks written during sync/retry paths).
    dirty_flushes: u64,
}

impl ArcState {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            p: 0,
            t1: VecDeque::new(),
            t2: VecDeque::new(),
            b1: VecDeque::new(),
            b2: VecDeque::new(),
            loc: HashMap::new(),
            resident: HashMap::new(),
            dirty: DirtyTracker::default(),
            pending_flush: Vec::new(),
            staged_txn_writes: HashMap::new(),
            staged_block_owner: HashMap::new(),
            hits: 0,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
        }
    }

    fn resident_len(&self) -> usize {
        self.t1.len() + self.t2.len()
    }

    fn total_len(&self) -> usize {
        self.t1.len() + self.t2.len() + self.b1.len() + self.b2.len()
    }

    fn snapshot_metrics(&self) -> CacheMetrics {
        CacheMetrics {
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
            dirty_flushes: self.dirty_flushes,
            t1_len: self.t1.len(),
            t2_len: self.t2.len(),
            b1_len: self.b1.len(),
            b2_len: self.b2.len(),
            resident: self.resident_len(),
            dirty_blocks: self.dirty.dirty_count(),
            dirty_bytes: self.dirty.dirty_bytes(),
            oldest_dirty_age_ticks: self.dirty.oldest_dirty_age_ticks(),
            capacity: self.capacity,
            p: self.p,
        }
    }

    fn remove_from_list(list: &mut VecDeque<BlockNumber>, key: BlockNumber) -> bool {
        if let Some(pos) = list.iter().position(|k| *k == key) {
            let _ = list.remove(pos);
            return true;
        }
        false
    }

    fn evict_resident(&mut self, victim: BlockNumber) {
        if self.is_dirty(victim) {
            let metrics = self.snapshot_metrics();
            warn!(
                event = "dirty_evict_attempt",
                block = victim.0,
                dirty_blocks = metrics.dirty_blocks,
                dirty_bytes = metrics.dirty_bytes,
                dirty_ratio = metrics.dirty_ratio(),
                oldest_dirty_age_ticks = metrics.oldest_dirty_age_ticks.unwrap_or(0),
                "dirty block cannot be evicted before flush"
            );
            panic!("dirty block {} cannot be evicted before flush", victim.0);
        }
        let _ = self.resident.remove(&victim);
        self.clear_dirty(victim);
        trace!(event = "cache_evict_clean", block = victim.0);
    }

    fn touch_mru(&mut self, key: BlockNumber) {
        let Some(list) = self.loc.get(&key).copied() else {
            return;
        };

        match list {
            ArcList::T1 => {
                let _ = Self::remove_from_list(&mut self.t1, key);
                self.t2.push_back(key);
                self.loc.insert(key, ArcList::T2);
            }
            ArcList::T2 => {
                let _ = Self::remove_from_list(&mut self.t2, key);
                self.t2.push_back(key);
            }
            ArcList::B1 | ArcList::B2 => {}
        }
    }

    fn replace(&mut self, incoming: BlockNumber) {
        // `replace()` is only meaningful when the resident set is full.
        // Guard against accidental calls during warm-up, which would cause
        // premature eviction and underutilize the cache.
        if self.resident_len() < self.capacity {
            return;
        }

        let t1_len = self.t1.len();
        if t1_len >= 1
            && (t1_len > self.p
                || (matches!(self.loc.get(&incoming), Some(ArcList::B2)) && t1_len == self.p))
        {
            if let Some(victim) = self.t1.pop_front() {
                self.loc.insert(victim, ArcList::B1);
                self.evict_resident(victim);
                self.b1.push_back(victim);
                self.evictions += 1;
            }
        } else if let Some(victim) = self.t2.pop_front() {
            self.loc.insert(victim, ArcList::B2);
            self.evict_resident(victim);
            self.b2.push_back(victim);
            self.evictions += 1;
        }

        while self.b1.len() > self.capacity {
            if let Some(victim) = self.b1.pop_front() {
                let _ = self.loc.remove(&victim);
            }
        }
        while self.b2.len() > self.capacity {
            if let Some(victim) = self.b2.pop_front() {
                let _ = self.loc.remove(&victim);
            }
        }
    }

    fn on_hit(&mut self, key: BlockNumber) {
        self.hits += 1;
        self.touch_mru(key);
    }

    fn on_miss_or_ghost_hit(&mut self, key: BlockNumber) {
        self.misses += 1;
        // Defensive: callers use `resident.contains_key()` to decide hit vs miss.
        // If we ever see a "miss" for a resident key, treat it as a hit to avoid
        // duplicating list entries.
        if matches!(self.loc.get(&key), Some(ArcList::T1 | ArcList::T2)) {
            debug_assert!(
                false,
                "ARC invariant violated: loc says resident but resident map is missing"
            );
            self.on_hit(key);
            return;
        }

        if matches!(self.loc.get(&key), Some(ArcList::B1)) {
            let b1_len = self.b1.len().max(1);
            let b2_len = self.b2.len().max(1);
            let delta = (b2_len / b1_len).max(1);
            self.p = (self.p + delta).min(self.capacity);
            let _ = Self::remove_from_list(&mut self.b1, key);
            self.replace(key);
            self.t2.push_back(key);
            self.loc.insert(key, ArcList::T2);
            return;
        }

        if matches!(self.loc.get(&key), Some(ArcList::B2)) {
            let b1_len = self.b1.len().max(1);
            let b2_len = self.b2.len().max(1);
            let delta = (b1_len / b2_len).max(1);
            self.p = self.p.saturating_sub(delta);
            let _ = Self::remove_from_list(&mut self.b2, key);
            self.replace(key);
            self.t2.push_back(key);
            self.loc.insert(key, ArcList::T2);
            return;
        }

        // Not present in any list.
        let l1_len = self.t1.len() + self.b1.len();
        let total_len = self.total_len();
        if l1_len == self.capacity {
            if self.t1.len() < self.capacity {
                let _ = self.b1.pop_front().and_then(|v| self.loc.remove(&v));
                self.replace(key);
            } else if let Some(victim) = self.t1.pop_front() {
                let _ = self.loc.remove(&victim);
                self.evict_resident(victim);
                self.evictions += 1;
            }
        } else if l1_len < self.capacity && total_len >= self.capacity {
            if total_len >= self.capacity.saturating_mul(2) {
                let _ = self.b2.pop_front().and_then(|v| self.loc.remove(&v));
            }
            self.replace(key);
        }

        self.t1.push_back(key);
        self.loc.insert(key, ArcList::T1);
    }

    /// Mark a block as dirty (written but not yet flushed to disk).
    fn mark_dirty(
        &mut self,
        block: BlockNumber,
        bytes: usize,
        txn_id: TxnId,
        commit_seq: Option<CommitSeq>,
        state: DirtyState,
    ) {
        self.dirty
            .mark_dirty(block, bytes, txn_id, commit_seq, state);
    }

    /// Clear the dirty flag for a block (after flushing to disk).
    fn clear_dirty(&mut self, block: BlockNumber) {
        self.dirty.clear_dirty(block);
    }

    /// Check if a block is dirty.
    fn is_dirty(&self, block: BlockNumber) -> bool {
        self.dirty.is_dirty(block)
    }

    /// Return list of dirty blocks that need flushing.
    fn dirty_blocks(&self) -> Vec<BlockNumber> {
        self.dirty.dirty_blocks_oldest_first()
    }

    fn stage_txn_write(&mut self, txn_id: TxnId, block: BlockNumber, data: Vec<u8>) -> Result<()> {
        if let Some(owner) = self.staged_block_owner.get(&block).copied()
            && owner != txn_id
        {
            return Err(FfsError::Format(format!(
                "block {} already staged by txn {}",
                block.0, owner.0
            )));
        }

        self.staged_txn_writes
            .entry(txn_id)
            .or_default()
            .insert(block, data.clone());
        self.staged_block_owner.insert(block, txn_id);
        self.mark_dirty(block, data.len(), txn_id, None, DirtyState::InFlight);
        trace!(
            event = "mvcc_dirty_stage",
            txn_id = txn_id.0,
            block = block.0,
            commit_seq_opt = 0_u64,
            state = "in_flight"
        );
        Ok(())
    }

    fn take_staged_txn(&mut self, txn_id: TxnId) -> HashMap<BlockNumber, Vec<u8>> {
        let staged = self.staged_txn_writes.remove(&txn_id).unwrap_or_default();
        for block in staged.keys() {
            let _ = self.staged_block_owner.remove(block);
        }
        staged
    }

    fn take_pending_flush(&mut self) -> Vec<FlushCandidate> {
        std::mem::take(&mut self.pending_flush)
    }

    fn take_dirty_and_pending_flushes(&mut self) -> Vec<FlushCandidate> {
        let mut flushes = self.take_pending_flush();
        let requested_blocks = self.dirty.dirty_count();
        let (in_flight_blocks, _) = self.dirty.state_counts();
        let mut queued = HashSet::with_capacity(flushes.len());
        for candidate in &flushes {
            queued.insert(candidate.block);
        }

        for block in self.dirty_blocks() {
            if queued.contains(&block) {
                continue;
            }
            let Some(entry) = self.dirty.entry(block) else {
                continue;
            };
            if !entry.is_flushable() {
                warn!(
                    event = "mvcc_flush_skipped_uncommitted",
                    txn_id = entry.txn_id.0,
                    block = block.0,
                    state = "in_flight"
                );
                continue;
            }
            let Some(commit_seq) = entry.commit_seq else {
                continue;
            };
            if let Some(data) = self.resident.get(&block).cloned() {
                trace!(
                    event = "mvcc_flush_candidate",
                    block = block.0,
                    commit_seq = commit_seq.0,
                    flushable = true
                );
                flushes.push(FlushCandidate {
                    block,
                    data,
                    txn_id: entry.txn_id,
                    commit_seq,
                });
                queued.insert(block);
            }
        }

        debug!(
            event = "mvcc_flush_batch_filter",
            requested_blocks,
            eligible_blocks = flushes.len(),
            in_flight_blocks,
            aborted_blocks = 0_usize
        );
        flushes
    }

    fn take_dirty_and_pending_flushes_limited(&mut self, limit: usize) -> Vec<FlushCandidate> {
        if limit == 0 {
            return Vec::new();
        }

        let pending = self.take_pending_flush();
        let requested_blocks = self.dirty.dirty_count();
        let (in_flight_blocks, _) = self.dirty.state_counts();
        let mut flushes = Vec::with_capacity(limit.min(pending.len()));
        let mut overflow_pending = Vec::new();

        for item in pending {
            if flushes.len() < limit {
                flushes.push(item);
            } else {
                overflow_pending.push(item);
            }
        }

        if !overflow_pending.is_empty() {
            self.pending_flush.extend(overflow_pending);
        }

        let mut queued = HashSet::with_capacity(flushes.len());
        for candidate in &flushes {
            queued.insert(candidate.block);
        }

        for block in self.dirty_blocks() {
            if flushes.len() >= limit {
                break;
            }
            if queued.contains(&block) {
                continue;
            }
            let Some(entry) = self.dirty.entry(block) else {
                continue;
            };
            if !entry.is_flushable() {
                warn!(
                    event = "mvcc_flush_skipped_uncommitted",
                    txn_id = entry.txn_id.0,
                    block = block.0,
                    state = "in_flight"
                );
                continue;
            }
            let Some(commit_seq) = entry.commit_seq else {
                continue;
            };
            if let Some(data) = self.resident.get(&block).cloned() {
                trace!(
                    event = "mvcc_flush_candidate",
                    block = block.0,
                    commit_seq = commit_seq.0,
                    flushable = true
                );
                flushes.push(FlushCandidate {
                    block,
                    data,
                    txn_id: entry.txn_id,
                    commit_seq,
                });
                queued.insert(block);
            }
        }

        debug!(
            event = "mvcc_flush_batch_filter",
            requested_blocks,
            eligible_blocks = flushes.len(),
            in_flight_blocks,
            aborted_blocks = 0_usize
        );

        flushes
    }
}

/// ARC-cached wrapper around a [`BlockDevice`].
///
/// Current behavior:
/// - read caching of whole blocks
/// - default write-through (writes update cache and the underlying device immediately)
/// - optional write-back mode via [`ArcCache::new_with_policy`]
///
/// # Concurrency design
///
/// **Locking strategy:** A single `parking_lot::Mutex<ArcState>` protects all
/// cache metadata (T1/T2/B1/B2 lists, resident map, counters).  This is
/// sufficient because:
///
/// 1. The lock is **never held during I/O**.  `read_block` drops the lock
///    before issuing a device read and re-acquires it afterwards.
///    `write_block` writes through to the device first, then acquires the lock
///    only to update metadata.
/// 2. `parking_lot::Mutex` is non-poisoning and uses adaptive spinning, so
///    contention under typical FUSE workloads (many concurrent reads, few
///    writes) remains low.
///
/// **Future sharding:** If profiling reveals lock contention under heavy
/// parallel read workloads, the cache can be sharded by `BlockNumber` into N
/// independent `Mutex<ArcState>` segments (e.g. `block.0 % N`).  The current
/// single-lock design keeps the implementation simple and correct as a
/// baseline.
///
/// TODO: replace write-through with deferred write-back and async background flushing.
#[derive(Debug)]
pub struct ArcCache<D: BlockDevice> {
    inner: D,
    state: Mutex<ArcState>,
    write_policy: ArcWritePolicy,
    mvcc_flush_lifecycle: Arc<dyn MvccFlushLifecycle>,
}

/// Write policy for [`ArcCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcWritePolicy {
    /// Always write to the underlying device immediately.
    WriteThrough,
    /// Keep writes in cache until sync; dirty blocks cannot be evicted.
    WriteBack,
}

/// Default dirty-ratio threshold where aggressive flush is preferred.
pub const DIRTY_HIGH_WATERMARK: f64 = 0.80;
/// Default dirty-ratio threshold where new writes are backpressured.
pub const DIRTY_CRITICAL_WATERMARK: f64 = 0.95;

/// Runtime configuration for background dirty flushing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlushDaemonConfig {
    /// Sleep interval between flush cycles.
    pub interval: Duration,
    /// Maximum number of dirty blocks to flush per non-aggressive cycle.
    pub batch_size: usize,
    /// Dirty ratio threshold that triggers aggressive full flush.
    pub high_watermark: f64,
    /// Dirty ratio threshold that blocks writes until flushed below high watermark.
    pub critical_watermark: f64,
}

impl Default for FlushDaemonConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            batch_size: 256,
            high_watermark: DIRTY_HIGH_WATERMARK,
            critical_watermark: DIRTY_CRITICAL_WATERMARK,
        }
    }
}

impl FlushDaemonConfig {
    fn validate(self) -> Result<Self> {
        if self.interval.is_zero() {
            return Err(FfsError::Format(
                "flush daemon interval must be > 0".to_owned(),
            ));
        }
        if self.batch_size == 0 {
            return Err(FfsError::Format(
                "flush daemon batch_size must be > 0".to_owned(),
            ));
        }
        if !(0.0..=1.0).contains(&self.high_watermark)
            || !(0.0..=1.0).contains(&self.critical_watermark)
            || self.high_watermark >= self.critical_watermark
        {
            return Err(FfsError::Format(
                "flush daemon watermarks must satisfy 0<=high<critical<=1".to_owned(),
            ));
        }
        Ok(self)
    }
}

/// Handle for a running background flush daemon.
#[derive(Debug)]
pub struct FlushDaemon {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl FlushDaemon {
    /// Request shutdown and block until the daemon exits.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for FlushDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl<D: BlockDevice> ArcCache<D> {
    pub fn new(inner: D, capacity_blocks: usize) -> Result<Self> {
        Self::new_with_policy(inner, capacity_blocks, ArcWritePolicy::WriteThrough)
    }

    pub fn new_with_policy(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
    ) -> Result<Self> {
        Self::new_with_policy_and_mvcc_lifecycle(
            inner,
            capacity_blocks,
            write_policy,
            Arc::new(NoopMvccFlushLifecycle),
        )
    }

    pub fn new_with_policy_and_mvcc_lifecycle(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
        mvcc_flush_lifecycle: Arc<dyn MvccFlushLifecycle>,
    ) -> Result<Self> {
        if capacity_blocks == 0 {
            return Err(FfsError::Format(
                "ArcCache capacity_blocks must be > 0".to_owned(),
            ));
        }
        Ok(Self {
            inner,
            state: Mutex::new(ArcState::new(capacity_blocks)),
            write_policy,
            mvcc_flush_lifecycle,
        })
    }

    #[must_use]
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Take a snapshot of current cache metrics.
    ///
    /// Acquires the state lock briefly to read counters and list sizes.
    /// The returned [`CacheMetrics`] is a frozen point-in-time snapshot.
    #[must_use]
    pub fn metrics(&self) -> CacheMetrics {
        self.state.lock().snapshot_metrics()
    }

    #[must_use]
    pub fn write_policy(&self) -> ArcWritePolicy {
        self.write_policy
    }

    fn dirty_state_counts(&self) -> (usize, usize) {
        self.state.lock().dirty.state_counts()
    }

    fn committed_dirty_ratio(&self) -> f64 {
        let guard = self.state.lock();
        let (_, committed_blocks) = guard.dirty.state_counts();
        if guard.capacity == 0 {
            0.0
        } else {
            committed_blocks as f64 / guard.capacity as f64
        }
    }

    /// Stage a transactional write that is not yet visible/flushable.
    ///
    /// The payload is tracked as in-flight dirty state and only becomes
    /// cache-visible + flushable after [`Self::commit_staged_txn`].
    pub fn stage_txn_write(
        &self,
        cx: &Cx,
        txn_id: TxnId,
        block: BlockNumber,
        data: &[u8],
    ) -> Result<()> {
        cx_checkpoint(cx)?;
        let expected = usize::try_from(self.block_size())
            .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;
        if data.len() != expected {
            return Err(FfsError::Format(format!(
                "stage_txn_write data size mismatch: got={} expected={expected}",
                data.len()
            )));
        }

        let mut guard = self.state.lock();
        guard.stage_txn_write(txn_id, block, data.to_vec())
    }

    /// Commit all staged writes for `txn_id` and mark them flushable.
    ///
    /// Returns the number of blocks transitioned from in-flight to committed.
    pub fn commit_staged_txn(
        &self,
        cx: &Cx,
        txn_id: TxnId,
        commit_seq: CommitSeq,
    ) -> Result<usize> {
        cx_checkpoint(cx)?;
        let staged = {
            let mut guard = self.state.lock();
            guard.take_staged_txn(txn_id)
        };
        if staged.is_empty() {
            return Ok(0);
        }

        let mut enforce_backpressure = false;
        let mut committed_blocks = 0_usize;
        let mut guard = self.state.lock();
        for (block, data) in &staged {
            if guard.resident.contains_key(block) {
                guard.resident.insert(*block, data.clone());
                guard.on_hit(*block);
            } else {
                guard.on_miss_or_ghost_hit(*block);
                guard.resident.insert(*block, data.clone());
            }
            guard.mark_dirty(
                *block,
                data.len(),
                txn_id,
                Some(commit_seq),
                DirtyState::Committed,
            );
            trace!(
                event = "mvcc_dirty_stage",
                txn_id = txn_id.0,
                block = block.0,
                commit_seq_opt = commit_seq.0,
                state = "committed"
            );
            committed_blocks += 1;
        }

        if matches!(self.write_policy, ArcWritePolicy::WriteBack) {
            let (_, committed_blocks_now) = guard.dirty.state_counts();
            let dirty_ratio = if guard.capacity == 0 {
                0.0
            } else {
                committed_blocks_now as f64 / guard.capacity as f64
            };
            if dirty_ratio > DIRTY_CRITICAL_WATERMARK {
                enforce_backpressure = true;
                warn!(
                    event = "flush_backpressure_critical",
                    txn_id = txn_id.0,
                    dirty_ratio,
                    critical_watermark = DIRTY_CRITICAL_WATERMARK
                );
            } else if dirty_ratio > DIRTY_HIGH_WATERMARK {
                warn!(
                    event = "flush_backpressure_high",
                    txn_id = txn_id.0,
                    dirty_ratio,
                    high_watermark = DIRTY_HIGH_WATERMARK
                );
            }
        }

        let pending_flush = guard.take_pending_flush();
        drop(guard);
        self.flush_pending_evictions(cx, pending_flush)?;

        if enforce_backpressure {
            loop {
                let dirty_ratio = self.committed_dirty_ratio();
                if dirty_ratio <= DIRTY_HIGH_WATERMARK {
                    break;
                }
                self.flush_dirty(cx)?;
            }
        }

        Ok(committed_blocks)
    }

    /// Abort all staged writes for `txn_id`, discarding in-flight dirty state.
    ///
    /// Returns the number of discarded staged blocks.
    #[must_use]
    pub fn abort_staged_txn(&self, txn_id: TxnId) -> usize {
        let mut guard = self.state.lock();
        let staged = guard.take_staged_txn(txn_id);
        let discarded_blocks = staged.len();
        for block in staged.keys() {
            let is_same_txn_inflight = guard.dirty.entry(*block).is_some_and(|entry| {
                entry.txn_id == txn_id && matches!(entry.state, DirtyState::InFlight)
            });
            if is_same_txn_inflight {
                guard.clear_dirty(*block);
            }
        }
        if discarded_blocks > 0 {
            warn!(
                event = "mvcc_discard_aborted_dirty",
                txn_id = txn_id.0,
                discarded_blocks
            );
        }
        discarded_blocks
    }

    /// Spawn a background thread that periodically flushes dirty blocks.
    ///
    /// The daemon flushes oldest dirty blocks first using `batch_size`, unless
    /// dirty ratio exceeds `high_watermark`, in which case it flushes all dirty
    /// blocks aggressively. On shutdown it performs a final full flush.
    pub fn start_flush_daemon(self: &Arc<Self>, config: FlushDaemonConfig) -> Result<FlushDaemon>
    where
        D: 'static,
    {
        let config = config.validate()?;
        let stop = Arc::new(AtomicBool::new(false));
        let cache = Arc::clone(self);
        let stop_flag = Arc::clone(&stop);

        let join = thread::Builder::new()
            .name("ffs-flush-daemon".to_owned())
            .spawn(move || {
                // Daemon uses a long-lived context for periodic background work.
                let cx = Cx::for_testing();
                let mut cycle_seq = 0_u64;

                loop {
                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }

                    thread::sleep(config.interval);
                    cycle_seq = cycle_seq.saturating_add(1);

                    let metrics = cache.metrics();
                    let dirty_ratio = metrics.dirty_ratio();
                    let (in_flight_blocks, committed_blocks) = cache.dirty_state_counts();
                    let committed_dirty_ratio = if metrics.capacity == 0 {
                        0.0
                    } else {
                        committed_blocks as f64 / metrics.capacity as f64
                    };
                    trace!(
                        event = "flush_daemon_tick",
                        cycle_seq,
                        dirty_blocks = metrics.dirty_blocks,
                        in_flight_blocks,
                        committed_blocks,
                        dirty_bytes = metrics.dirty_bytes,
                        dirty_ratio,
                        committed_dirty_ratio,
                        oldest_dirty_age_ticks = metrics.oldest_dirty_age_ticks.unwrap_or(0)
                    );

                    if committed_blocks == 0 {
                        trace!(
                            event = "flush_daemon_sleep",
                            cycle_seq,
                            interval_ms = config.interval.as_millis()
                        );
                        continue;
                    }

                    let flush_res = if committed_dirty_ratio > config.high_watermark {
                        if committed_dirty_ratio > config.critical_watermark {
                            warn!(
                                event = "flush_backpressure_critical",
                                cycle_seq,
                                dirty_ratio = committed_dirty_ratio,
                                critical_watermark = config.critical_watermark
                            );
                        } else {
                            warn!(
                                event = "flush_backpressure_high",
                                cycle_seq,
                                dirty_ratio = committed_dirty_ratio,
                                high_watermark = config.high_watermark
                            );
                        }
                        cache.flush_dirty(&cx).map(|()| committed_blocks)
                    } else {
                        cache.flush_dirty_batch(&cx, config.batch_size)
                    };

                    if let Err(err) = flush_res {
                        error!(
                            event = "flush_batch_failed",
                            cycle_seq,
                            error = %err,
                            attempted_blocks = metrics.dirty_blocks,
                            attempted_bytes = metrics.dirty_bytes
                        );
                    }

                    trace!(
                        event = "flush_daemon_sleep",
                        cycle_seq,
                        interval_ms = config.interval.as_millis()
                    );
                }

                if let Err(err) = cache.flush_dirty(&cx) {
                    error!(
                        event = "flush_shutdown_failed",
                        error = %err,
                        remaining_dirty_blocks = cache.dirty_count()
                    );
                }
            })
            .map_err(FfsError::from)?;

        Ok(FlushDaemon {
            stop,
            join: Some(join),
        })
    }

    fn flush_blocks(&self, cx: &Cx, flushes: &[FlushCandidate]) -> Result<()> {
        let lifecycle = Arc::clone(&self.mvcc_flush_lifecycle);
        for candidate in flushes {
            cx_checkpoint(cx)?;
            let pin = match lifecycle.pin_for_flush(candidate.block, candidate.commit_seq) {
                Ok(pin) => pin,
                Err(err) => {
                    error!(
                        event = "mvcc_flush_pin_conflict",
                        block = candidate.block.0,
                        commit_seq = candidate.commit_seq.0,
                        error = %err
                    );
                    return Err(err);
                }
            };
            self.inner
                .write_block(cx, candidate.block, &candidate.data)?;
            if let Err(err) = lifecycle.mark_persisted(candidate.block, candidate.commit_seq) {
                error!(
                    event = "mvcc_flush_commit_state_update_failed",
                    txn_id = candidate.txn_id.0,
                    block = candidate.block.0,
                    commit_seq = candidate.commit_seq.0,
                    error = %err
                );
                return Err(err);
            }
            drop(pin);
        }
        Ok(())
    }

    fn flush_pending_evictions(&self, cx: &Cx, pending_flush: Vec<FlushCandidate>) -> Result<()> {
        if pending_flush.is_empty() {
            return Ok(());
        }

        debug!(
            event = "pending_flush_batch_start",
            blocks = pending_flush.len(),
            "flushing pending dirty evictions"
        );

        if let Err(err) = self.flush_blocks(cx, &pending_flush) {
            // Restore the pending queue on failure so callers can retry.
            let mut guard = self.state.lock();
            for candidate in &pending_flush {
                guard.mark_dirty(
                    candidate.block,
                    candidate.data.len(),
                    candidate.txn_id,
                    Some(candidate.commit_seq),
                    DirtyState::Committed,
                );
            }
            guard.pending_flush.extend(pending_flush);
            drop(guard);
            error!(event = "pending_flush_batch_failed", error = %err);
            return Err(err);
        }

        let mut guard = self.state.lock();
        guard.dirty_flushes += pending_flush.len() as u64;
        info!(
            event = "pending_flush_batch_complete",
            blocks = pending_flush.len(),
            dirty_flushes = guard.dirty_flushes
        );
        drop(guard);
        Ok(())
    }
}

impl<D: BlockDevice> BlockDevice for ArcCache<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        cx_checkpoint(cx)?;
        {
            let mut guard = self.state.lock();
            if let Some(bytes) = guard.resident.get(&block).cloned() {
                guard.on_hit(block);
                drop(guard);
                return Ok(BlockBuf::new(bytes));
            }
        }

        let buf = self.inner.read_block(cx, block)?;

        let mut guard = self.state.lock();
        // Re-check: another thread may have populated this block while we
        // were reading from the device (TOCTOU race).  If so, treat as a hit
        // and discard our redundant device read.
        if guard.resident.contains_key(&block) {
            guard.on_hit(block);
        } else {
            guard.on_miss_or_ghost_hit(block);
            guard.resident.insert(block, buf.as_slice().to_vec());
        }
        let pending_flush = guard.take_pending_flush();
        drop(guard);
        self.flush_pending_evictions(cx, pending_flush)?;
        Ok(buf)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if matches!(self.write_policy, ArcWritePolicy::WriteThrough) {
            self.inner.write_block(cx, block, data)?;
        } else {
            cx_checkpoint(cx)?;
        }

        let mut enforce_backpressure = false;
        let mut guard = self.state.lock();
        if guard.resident.contains_key(&block) {
            // Block already cached — just update data and touch for recency.
            guard.resident.insert(block, data.to_vec());
            guard.on_hit(block);
        } else {
            guard.on_miss_or_ghost_hit(block);
            guard.resident.insert(block, data.to_vec());
        }

        if matches!(self.write_policy, ArcWritePolicy::WriteBack) {
            guard.mark_dirty(
                block,
                data.len(),
                TxnId(0),
                Some(CommitSeq(0)),
                DirtyState::Committed,
            );
            trace!(
                event = "mvcc_dirty_stage",
                txn_id = 0_u64,
                block = block.0,
                commit_seq_opt = 0_u64,
                state = "committed"
            );
        } else {
            guard.clear_dirty(block);
        }

        let metrics = guard.snapshot_metrics();
        trace!(
            event = "cache_write",
            block = block.0,
            bytes = data.len(),
            write_policy = ?self.write_policy,
            dirty_blocks = metrics.dirty_blocks,
            dirty_bytes = metrics.dirty_bytes,
            dirty_ratio = metrics.dirty_ratio(),
            oldest_dirty_age_ticks = metrics.oldest_dirty_age_ticks.unwrap_or(0)
        );

        if matches!(self.write_policy, ArcWritePolicy::WriteBack) {
            let (_, committed_blocks) = guard.dirty.state_counts();
            let dirty_ratio = if guard.capacity == 0 {
                0.0
            } else {
                committed_blocks as f64 / guard.capacity as f64
            };
            if dirty_ratio > DIRTY_CRITICAL_WATERMARK {
                enforce_backpressure = true;
                warn!(
                    event = "flush_backpressure_critical",
                    block = block.0,
                    dirty_ratio,
                    critical_watermark = DIRTY_CRITICAL_WATERMARK
                );
            } else if dirty_ratio > DIRTY_HIGH_WATERMARK {
                warn!(
                    event = "flush_backpressure_high",
                    block = block.0,
                    dirty_ratio,
                    high_watermark = DIRTY_HIGH_WATERMARK
                );
            }
        }

        let pending_flush = guard.take_pending_flush();
        drop(guard);
        self.flush_pending_evictions(cx, pending_flush)?;

        if enforce_backpressure {
            // Block writers by synchronously draining until we're back under high watermark.
            loop {
                let dirty_ratio = self.committed_dirty_ratio();
                if dirty_ratio <= DIRTY_HIGH_WATERMARK {
                    break;
                }
                self.flush_dirty(cx)?;
            }
        }

        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        // Flush any deferred dirty blocks before syncing the underlying device.
        self.flush_dirty(cx)?;
        self.inner.sync(cx)
    }
}

impl<D: BlockDevice> BlockCache for ArcCache<D> {
    fn mark_clean(&self, block: BlockNumber) {
        let mut guard = self.state.lock();
        guard.clear_dirty(block);
        let metrics = guard.snapshot_metrics();
        drop(guard);
        trace!(
            event = "mark_clean",
            block = block.0,
            dirty_blocks = metrics.dirty_blocks,
            dirty_bytes = metrics.dirty_bytes
        );
    }

    fn dirty_blocks_oldest_first(&self) -> Vec<BlockNumber> {
        self.state.lock().dirty_blocks()
    }

    fn evict(&self, block: BlockNumber) {
        let mut guard = self.state.lock();
        if guard.is_dirty(block) {
            let metrics = guard.snapshot_metrics();
            warn!(
                event = "dirty_evict_attempt",
                block = block.0,
                dirty_blocks = metrics.dirty_blocks,
                dirty_bytes = metrics.dirty_bytes,
                dirty_ratio = metrics.dirty_ratio(),
                oldest_dirty_age_ticks = metrics.oldest_dirty_age_ticks.unwrap_or(0),
                "dirty block cannot be evicted before flush"
            );
            panic!("dirty block {} cannot be evicted before flush", block.0);
        }

        let mut removed = false;
        removed |= ArcState::remove_from_list(&mut guard.t1, block);
        removed |= ArcState::remove_from_list(&mut guard.t2, block);
        removed |= ArcState::remove_from_list(&mut guard.b1, block);
        removed |= ArcState::remove_from_list(&mut guard.b2, block);
        removed |= guard.resident.remove(&block).is_some();
        guard.clear_dirty(block);
        let _ = guard.loc.remove(&block);

        let evicted = if removed {
            guard.evictions += 1;
            true
        } else {
            false
        };
        drop(guard);

        if evicted {
            trace!(event = "cache_evict_clean", block = block.0);
        }
    }
}

impl<D: BlockDevice> ArcCache<D> {
    /// Flush at most `max_blocks` dirty blocks in oldest-first order.
    ///
    /// Returns the number of blocks flushed in this batch.
    pub fn flush_dirty_batch(&self, cx: &Cx, max_blocks: usize) -> Result<usize> {
        cx_checkpoint(cx)?;
        if max_blocks == 0 {
            return Ok(0);
        }

        let (flushes, pre_metrics) = {
            let mut guard = self.state.lock();
            let metrics = guard.snapshot_metrics();
            let flushes = guard.take_dirty_and_pending_flushes_limited(max_blocks);
            drop(guard);
            (flushes, metrics)
        };

        if flushes.is_empty() {
            return Ok(0);
        }

        let flush_bytes: usize = flushes.iter().map(|candidate| candidate.data.len()).sum();
        let min_commit_seq = flushes.iter().map(|candidate| candidate.commit_seq.0).min();
        let max_commit_seq = flushes.iter().map(|candidate| candidate.commit_seq.0).max();
        debug!(
            event = "flush_batch_start",
            batch_len = flushes.len(),
            oldest_block = flushes.first().map_or(0, |candidate| candidate.block.0),
            oldest_dirty_age_ticks = pre_metrics.oldest_dirty_age_ticks.unwrap_or(0),
            policy = ?self.write_policy,
            attempted_bytes = flush_bytes
        );

        let started = Instant::now();
        if let Err(err) = self.flush_blocks(cx, &flushes) {
            let attempted_blocks = flushes.len();
            let mut guard = self.state.lock();
            for candidate in &flushes {
                guard.mark_dirty(
                    candidate.block,
                    candidate.data.len(),
                    candidate.txn_id,
                    Some(candidate.commit_seq),
                    DirtyState::Committed,
                );
            }
            guard.pending_flush.extend(flushes);
            drop(guard);
            error!(
                event = "flush_batch_failed",
                error = %err,
                attempted_blocks,
                duration_ms = started.elapsed().as_millis(),
                attempted_bytes = flush_bytes
            );
            return Err(err);
        }

        let mut guard = self.state.lock();
        for candidate in &flushes {
            guard.clear_dirty(candidate.block);
        }
        guard.dirty_flushes += flushes.len() as u64;
        let metrics = guard.snapshot_metrics();
        drop(guard);
        info!(
            event = "mvcc_flush_commit_batch",
            flushed_blocks = flushes.len(),
            min_commit_seq = min_commit_seq.unwrap_or(0),
            max_commit_seq = max_commit_seq.unwrap_or(0),
            duration_ms = started.elapsed().as_millis()
        );
        info!(
            event = "flush_batch_complete",
            flushed_blocks = flushes.len(),
            flushed_bytes = flush_bytes,
            duration_ms = started.elapsed().as_millis(),
            remaining_dirty_blocks = metrics.dirty_blocks,
            remaining_dirty_ratio = metrics.dirty_ratio()
        );

        Ok(flushes.len())
    }

    /// Flush all dirty blocks to the underlying device.
    ///
    /// Write-through mode should normally have zero dirty blocks; write-back
    /// mode accumulates dirty blocks until this method (or a future daemon)
    /// flushes them durably.
    ///
    /// Returns Ok(()) if all dirty blocks were successfully flushed.
    pub fn flush_dirty(&self, cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;

        // Collect all dirty payloads (resident + evicted pending) under lock.
        let flushes = {
            let mut guard = self.state.lock();
            guard.take_dirty_and_pending_flushes()
        };

        if flushes.is_empty() {
            return Ok(());
        }

        let flush_bytes: usize = flushes.iter().map(|candidate| candidate.data.len()).sum();
        let min_commit_seq = flushes.iter().map(|candidate| candidate.commit_seq.0).min();
        let max_commit_seq = flushes.iter().map(|candidate| candidate.commit_seq.0).max();
        debug!(
            event = "flush_dirty_start",
            blocks = flushes.len(),
            bytes = flush_bytes
        );

        let started = Instant::now();
        if let Err(err) = self.flush_blocks(cx, &flushes) {
            // Restore flush state on failure so retry logic can recover.
            let mut guard = self.state.lock();
            for candidate in &flushes {
                guard.mark_dirty(
                    candidate.block,
                    candidate.data.len(),
                    candidate.txn_id,
                    Some(candidate.commit_seq),
                    DirtyState::Committed,
                );
            }
            guard.pending_flush.extend(flushes);
            drop(guard);
            error!(
                event = "flush_dirty_failed",
                error = %err,
                duration_ms = started.elapsed().as_millis()
            );
            return Err(err);
        }

        let mut guard = self.state.lock();
        for candidate in &flushes {
            guard.clear_dirty(candidate.block);
        }
        guard.dirty_flushes += flushes.len() as u64;
        let metrics = guard.snapshot_metrics();
        info!(
            event = "mvcc_flush_commit_batch",
            flushed_blocks = flushes.len(),
            min_commit_seq = min_commit_seq.unwrap_or(0),
            max_commit_seq = max_commit_seq.unwrap_or(0),
            duration_ms = started.elapsed().as_millis()
        );
        info!(
            event = "flush_dirty_complete",
            blocks = flushes.len(),
            bytes = flush_bytes,
            duration_ms = started.elapsed().as_millis(),
            dirty_flushes = guard.dirty_flushes,
            remaining_dirty_blocks = metrics.dirty_blocks,
            remaining_dirty_bytes = metrics.dirty_bytes,
            remaining_dirty_ratio = metrics.dirty_ratio()
        );

        Ok(())
    }

    /// Return the number of currently dirty blocks.
    #[must_use]
    pub fn dirty_count(&self) -> usize {
        self.state.lock().dirty.dirty_count()
    }

    /// Return dirty blocks in oldest-first order.
    #[must_use]
    pub fn dirty_blocks_oldest_first(&self) -> Vec<BlockNumber> {
        self.state.lock().dirty_blocks()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn arc_access(state: &mut ArcState, key: BlockNumber) {
        if state.resident.contains_key(&key) {
            state.on_hit(key);
        } else {
            state.on_miss_or_ghost_hit(key);
            state.resident.insert(key, vec![0_u8]);
        }

        // Invariants: loc is the source of truth for membership; resident contains
        // only T1/T2 entries.
        assert_eq!(state.resident.len(), state.t1.len() + state.t2.len());
        assert!(state.resident.len() <= state.capacity);
        assert!(state.total_len() <= state.capacity.saturating_mul(2));
        assert_eq!(state.loc.len(), state.total_len());

        for &k in &state.t1 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::T1)));
            assert!(state.resident.contains_key(&k));
        }
        for &k in &state.t2 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::T2)));
            assert!(state.resident.contains_key(&k));
        }
        for &k in &state.b1 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::B1)));
            assert!(!state.resident.contains_key(&k));
        }
        for &k in &state.b2 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::B2)));
            assert!(!state.resident.contains_key(&k));
        }
    }

    #[derive(Debug)]
    struct MemoryByteDevice {
        bytes: Mutex<Vec<u8>>,
    }

    impl MemoryByteDevice {
        fn new(len: usize) -> Self {
            Self {
                bytes: Mutex::new(vec![0_u8; len]),
            }
        }
    }

    impl ByteDevice for MemoryByteDevice {
        fn len_bytes(&self) -> u64 {
            u64::try_from(self.bytes.lock().len()).unwrap_or(0)
        }

        fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
            let offset = usize::try_from(offset.0)
                .map_err(|_| FfsError::Format("offset overflow".into()))?;
            let end = offset
                .checked_add(buf.len())
                .ok_or_else(|| FfsError::Format("range overflow".into()))?;
            let bytes = self.bytes.lock();
            if end > bytes.len() {
                return Err(FfsError::Format("oob".into()));
            }
            buf.copy_from_slice(&bytes[offset..end]);
            drop(bytes);
            Ok(())
        }

        fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
            let offset = usize::try_from(offset.0)
                .map_err(|_| FfsError::Format("offset overflow".into()))?;
            let end = offset
                .checked_add(buf.len())
                .ok_or_else(|| FfsError::Format("range overflow".into()))?;
            let mut bytes = self.bytes.lock();
            if end > bytes.len() {
                return Err(FfsError::Format("oob".into()));
            }
            bytes[offset..end].copy_from_slice(buf);
            drop(bytes);
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct CountingBlockDevice<D: BlockDevice> {
        inner: D,
        writes: Mutex<Vec<BlockNumber>>,
        sync_calls: AtomicUsize,
    }

    impl<D: BlockDevice> CountingBlockDevice<D> {
        fn new(inner: D) -> Self {
            Self {
                inner,
                writes: Mutex::new(Vec::new()),
                sync_calls: AtomicUsize::new(0),
            }
        }

        fn write_count(&self) -> usize {
            self.writes.lock().len()
        }

        fn write_sequence(&self) -> Vec<BlockNumber> {
            self.writes.lock().clone()
        }

        fn sync_count(&self) -> usize {
            self.sync_calls.load(Ordering::SeqCst)
        }
    }

    #[derive(Debug, Default)]
    struct RecordingFlushLifecycle {
        pins: AtomicUsize,
        persisted: AtomicUsize,
    }

    impl RecordingFlushLifecycle {
        fn pin_count(&self) -> usize {
            self.pins.load(Ordering::SeqCst)
        }

        fn persisted_count(&self) -> usize {
            self.persisted.load(Ordering::SeqCst)
        }
    }

    impl MvccFlushLifecycle for RecordingFlushLifecycle {
        fn pin_for_flush(
            &self,
            _block: BlockNumber,
            _commit_seq: CommitSeq,
        ) -> Result<FlushPinToken> {
            self.pins.fetch_add(1, Ordering::SeqCst);
            Ok(FlushPinToken::new(()))
        }

        fn mark_persisted(&self, _block: BlockNumber, _commit_seq: CommitSeq) -> Result<()> {
            self.persisted.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl<D: BlockDevice> BlockDevice for CountingBlockDevice<D> {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.inner.read_block(cx, block)
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.writes.lock().push(block);
            self.inner.write_block(cx, block, data)
        }

        fn block_size(&self) -> u32 {
            self.inner.block_size()
        }

        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
            self.sync_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.sync(cx)
        }
    }

    #[test]
    fn byte_block_device_round_trips() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");

        dev.write_block(&cx, BlockNumber(2), &[7_u8; 4096])
            .expect("write");
        let read = dev.read_block(&cx, BlockNumber(2)).expect("read");
        assert_eq!(read.as_slice(), &[7_u8; 4096]);
    }

    #[test]
    fn arc_cache_hits_after_first_read() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 2).expect("cache");

        cache
            .write_block(&cx, BlockNumber(1), &[3_u8; 4096])
            .expect("write");
        let r1 = cache.read_block(&cx, BlockNumber(1)).expect("read1");
        let r2 = cache.read_block(&cx, BlockNumber(1)).expect("read2");
        assert_eq!(r1.as_slice(), &[3_u8; 4096]);
        assert_eq!(r2.as_slice(), &[3_u8; 4096]);
    }

    #[test]
    fn arc_state_warms_up_without_premature_eviction() {
        let mut state = ArcState::new(2);
        arc_access(&mut state, BlockNumber(1));
        arc_access(&mut state, BlockNumber(2));

        assert_eq!(state.resident.len(), 2);
        assert!(state.resident.contains_key(&BlockNumber(1)));
        assert!(state.resident.contains_key(&BlockNumber(2)));
        assert_eq!(
            state.t1,
            VecDeque::from(vec![BlockNumber(1), BlockNumber(2)])
        );
        assert!(state.t2.is_empty());
        assert!(state.b1.is_empty());
        assert!(state.b2.is_empty());
    }

    #[test]
    fn arc_state_ghost_hits_adjust_p_and_eviction_policy() {
        let mut state = ArcState::new(2);

        // Warm up + create a mix of recency/frequency:
        // 1 seen twice -> T2, 2/3 seen once -> T1.
        arc_access(&mut state, BlockNumber(1)); // miss -> T1
        arc_access(&mut state, BlockNumber(1)); // hit  -> T2
        arc_access(&mut state, BlockNumber(2)); // miss -> T1
        arc_access(&mut state, BlockNumber(3)); // miss -> replaces -> B1 contains 2

        assert_eq!(state.p, 0);
        assert_eq!(state.t1, VecDeque::from(vec![BlockNumber(3)]));
        assert_eq!(state.t2, VecDeque::from(vec![BlockNumber(1)]));
        assert_eq!(state.b1, VecDeque::from(vec![BlockNumber(2)]));
        assert!(state.b2.is_empty());

        // Ghost hit in B1 should increase p and evict from T2 (since |T1| == p after bump).
        arc_access(&mut state, BlockNumber(2));
        assert_eq!(state.p, 1);
        assert_eq!(state.t1, VecDeque::from(vec![BlockNumber(3)]));
        assert_eq!(state.t2, VecDeque::from(vec![BlockNumber(2)]));
        assert!(state.b1.is_empty());
        assert_eq!(state.b2, VecDeque::from(vec![BlockNumber(1)]));

        // Ghost hit in B2 should decrease p and evict from T1 (since |T1| > p).
        arc_access(&mut state, BlockNumber(1));
        assert_eq!(state.p, 0);
        assert!(state.t1.is_empty());
        assert_eq!(
            state.t2,
            VecDeque::from(vec![BlockNumber(2), BlockNumber(1)])
        );
        assert_eq!(state.b1, VecDeque::from(vec![BlockNumber(3)]));
        assert!(state.b2.is_empty());
    }

    #[test]
    fn arc_cache_does_not_evict_before_capacity_is_full() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");

        // Populate underlying device; cache starts empty.
        dev.write_block(&cx, BlockNumber(0), &[1_u8; 4096])
            .expect("write0");
        dev.write_block(&cx, BlockNumber(1), &[2_u8; 4096])
            .expect("write1");
        dev.write_block(&cx, BlockNumber(2), &[3_u8; 4096])
            .expect("write2");

        let cache = ArcCache::new(dev, 2).expect("cache");

        let _ = cache.read_block(&cx, BlockNumber(0)).expect("read0");
        let _ = cache.read_block(&cx, BlockNumber(1)).expect("read1");

        let guard = cache.state.lock();
        assert_eq!(guard.resident.len(), 2);
        assert!(guard.resident.contains_key(&BlockNumber(0)));
        assert!(guard.resident.contains_key(&BlockNumber(1)));
        drop(guard);

        let _ = cache.read_block(&cx, BlockNumber(2)).expect("read2");
        let guard = cache.state.lock();
        assert_eq!(guard.resident.len(), 2);
        drop(guard);
    }

    #[test]
    fn arc_cache_sync_flushes_and_clears_dirty_tracking() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 2, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[9_u8; 4096])
            .expect("write");
        assert_eq!(cache.dirty_count(), 1);
        assert_eq!(cache.inner().write_count(), 0);

        cache.sync(&cx).expect("sync");
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.inner().write_count(), 1);
        assert_eq!(cache.inner().sync_count(), 1);

        // Second sync should not rewrite flushed data.
        cache.sync(&cx).expect("sync again");
        assert_eq!(cache.inner().write_count(), 1);
        assert_eq!(cache.inner().sync_count(), 2);
    }

    #[test]
    #[should_panic(expected = "cannot be evicted before flush")]
    fn arc_cache_explicit_evict_panics_for_dirty_block() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 2, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[1_u8; 4096])
            .expect("write0");
        assert_eq!(cache.dirty_count(), 1);

        cache.evict(BlockNumber(0));
    }

    #[test]
    fn arc_cache_explicit_evict_succeeds_for_clean_block() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 2).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[1_u8; 4096])
            .expect("write0");
        assert_eq!(cache.dirty_count(), 0);

        cache.evict(BlockNumber(0));
        let metrics = cache.metrics();
        assert_eq!(metrics.resident, 0);
    }

    #[test]
    fn arc_cache_default_policy_is_write_through() {
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 1).expect("cache");
        assert_eq!(cache.write_policy(), ArcWritePolicy::WriteThrough);
    }

    #[test]
    fn arc_cache_write_through_keeps_dirty_tracker_clean() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 1).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[5_u8; 4096])
            .expect("write");
        assert_eq!(cache.dirty_count(), 0);
        assert!(cache.dirty_blocks_oldest_first().is_empty());
    }

    #[test]
    fn arc_cache_write_back_defers_direct_write_until_sync() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 2, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[7_u8; 4096])
            .expect("write");
        assert_eq!(cache.inner().write_count(), 0);
        assert_eq!(cache.dirty_count(), 1);

        // Read must hit cache before sync.
        let read = cache.read_block(&cx, BlockNumber(0)).expect("read");
        assert_eq!(read.as_slice(), &[7_u8; 4096]);
        assert_eq!(cache.inner().write_count(), 0);

        cache.sync(&cx).expect("sync");
        assert_eq!(cache.inner().write_count(), 1);
        assert_eq!(cache.inner().sync_count(), 1);
        assert_eq!(cache.dirty_count(), 0);

        cache.sync(&cx).expect("sync again");
        assert_eq!(cache.inner().write_count(), 1);
    }

    #[test]
    fn arc_cache_write_back_replacement_succeeds_after_critical_backpressure_flush() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 1, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[1_u8; 4096])
            .expect("write0");
        // Capacity=1, so ratio is 1.0 and critical backpressure flushes immediately.
        assert_eq!(cache.inner().write_count(), 1);
        assert_eq!(cache.dirty_count(), 0);

        // Replacement is now safe because previous dirty block is already clean.
        cache
            .write_block(&cx, BlockNumber(1), &[2_u8; 4096])
            .expect("write1");
        assert_eq!(cache.inner().write_count(), 2);
        assert_eq!(cache.dirty_count(), 0);
    }

    #[test]
    fn arc_cache_dirty_blocks_order_oldest_first_and_rewrite_moves_to_tail() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 3, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[1_u8; 4096])
            .expect("write0");
        cache
            .write_block(&cx, BlockNumber(1), &[2_u8; 4096])
            .expect("write1");
        assert_eq!(
            cache.dirty_blocks_oldest_first(),
            vec![BlockNumber(0), BlockNumber(1)]
        );

        // Re-writing block 0 should move it to the newest position.
        cache
            .write_block(&cx, BlockNumber(0), &[3_u8; 4096])
            .expect("rewrite0");
        assert_eq!(
            cache.dirty_blocks_oldest_first(),
            vec![BlockNumber(1), BlockNumber(0)]
        );

        let metrics = cache.metrics();
        assert_eq!(metrics.dirty_blocks, 2);
        assert_eq!(metrics.dirty_bytes, 4096 * 2);
        assert!(metrics.oldest_dirty_age_ticks.is_some());
        assert!((metrics.dirty_ratio() - (2.0 / 3.0)).abs() < 1e-12);
    }

    #[test]
    fn arc_cache_write_back_critical_ratio_triggers_backpressure_flush() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 2, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[1_u8; 4096])
            .expect("write0");
        assert_eq!(cache.dirty_count(), 1);
        assert_eq!(cache.inner().write_count(), 0);

        // Capacity=2 and write-back: second write drives dirty_ratio to 1.0,
        // which should trigger critical backpressure + synchronous flush.
        cache
            .write_block(&cx, BlockNumber(1), &[2_u8; 4096])
            .expect("write1");
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.inner().write_count(), 2);

        // Further writes continue after backpressure relief.
        cache
            .write_block(&cx, BlockNumber(2), &[3_u8; 4096])
            .expect("write2");
    }

    #[test]
    fn flush_daemon_batch_flushes_oldest_first() {
        use std::sync::Arc as StdArc;

        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache = StdArc::new(
            ArcCache::new_with_policy(counted, 8, ArcWritePolicy::WriteBack).expect("cache"),
        );

        cache
            .write_block(&cx, BlockNumber(1), &[1_u8; 4096])
            .expect("write1");
        cache
            .write_block(&cx, BlockNumber(2), &[2_u8; 4096])
            .expect("write2");
        cache
            .write_block(&cx, BlockNumber(3), &[3_u8; 4096])
            .expect("write3");
        assert_eq!(
            cache.dirty_blocks_oldest_first(),
            vec![BlockNumber(1), BlockNumber(2), BlockNumber(3)]
        );

        let daemon = cache
            .start_flush_daemon(FlushDaemonConfig {
                interval: Duration::from_millis(10),
                batch_size: 1,
                high_watermark: 0.99,
                critical_watermark: 1.0,
            })
            .expect("start daemon");

        for _ in 0..80 {
            if cache.dirty_count() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        daemon.shutdown();

        assert_eq!(cache.dirty_count(), 0);
        let writes = cache.inner().write_sequence();
        assert!(writes.starts_with(&[BlockNumber(1), BlockNumber(2), BlockNumber(3)]));
        assert_eq!(cache.inner().write_count(), 3);
    }

    #[test]
    fn flush_daemon_shutdown_flushes_all_dirty_blocks() {
        use std::sync::Arc as StdArc;

        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 32);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache = StdArc::new(
            ArcCache::new_with_policy(counted, 16, ArcWritePolicy::WriteBack).expect("cache"),
        );
        let daemon = cache
            .start_flush_daemon(FlushDaemonConfig {
                interval: Duration::from_millis(5),
                batch_size: 4,
                ..FlushDaemonConfig::default()
            })
            .expect("start daemon");

        for i in 0..6_u64 {
            cache
                .write_block(&cx, BlockNumber(i), &[1_u8; 4096])
                .expect("write");
        }
        assert!(cache.dirty_count() > 0);

        daemon.shutdown();
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.inner().write_count(), 6);
    }

    #[test]
    fn flush_daemon_flushes_1000_blocks_within_two_intervals() {
        use std::sync::Arc as StdArc;

        let cx = Cx::for_testing();
        let interval = Duration::from_millis(20);
        let mem = MemoryByteDevice::new(4096 * 1500);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache = StdArc::new(
            ArcCache::new_with_policy(counted, 1200, ArcWritePolicy::WriteBack).expect("cache"),
        );
        let daemon = cache
            .start_flush_daemon(FlushDaemonConfig {
                interval,
                batch_size: 256,
                ..FlushDaemonConfig::default()
            })
            .expect("start daemon");

        for i in 0..1000_u64 {
            let fill = u8::try_from(i & 0xFF).expect("u8");
            cache
                .write_block(&cx, BlockNumber(i), &vec![fill; 4096])
                .expect("write");
        }
        assert_eq!(cache.dirty_count(), 1000);

        let deadline = Instant::now() + interval.saturating_mul(2) + Duration::from_millis(30);
        while Instant::now() < deadline {
            if cache.dirty_count() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        daemon.shutdown();

        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.inner().write_count(), 1000);
    }

    #[test]
    fn mvcc_uncommitted_dirty_blocks_are_not_flushed() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 4, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .stage_txn_write(&cx, TxnId(41), BlockNumber(1), &[0xAA; 4096])
            .expect("stage");
        assert_eq!(cache.dirty_count(), 1);

        cache.flush_dirty(&cx).expect("flush");
        assert_eq!(cache.inner().write_count(), 0);
        assert_eq!(cache.dirty_count(), 1);

        let discarded = cache.abort_staged_txn(TxnId(41));
        assert_eq!(discarded, 1);
        assert_eq!(cache.dirty_count(), 0);
    }

    #[test]
    fn mvcc_commit_then_flush_marks_persisted_with_pin() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let lifecycle = StdArc::new(RecordingFlushLifecycle::default());
        let cache = ArcCache::new_with_policy_and_mvcc_lifecycle(
            counted,
            8,
            ArcWritePolicy::WriteBack,
            lifecycle.clone(),
        )
        .expect("cache");

        cache
            .stage_txn_write(&cx, TxnId(7), BlockNumber(2), &[0x11; 4096])
            .expect("stage");
        cache
            .commit_staged_txn(&cx, TxnId(7), CommitSeq(77))
            .expect("commit");

        // Committed-but-unflushed block is served from cache immediately.
        let read = cache.read_block(&cx, BlockNumber(2)).expect("read");
        assert_eq!(read.as_slice(), &[0x11; 4096]);
        assert_eq!(cache.inner().write_count(), 0);

        cache.flush_dirty(&cx).expect("flush");
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.inner().write_count(), 1);
        assert_eq!(lifecycle.pin_count(), 1);
        assert_eq!(lifecycle.persisted_count(), 1);
    }

    #[test]
    fn mvcc_concurrent_commit_abort_with_daemon_running() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 32);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let lifecycle = StdArc::new(RecordingFlushLifecycle::default());
        let cache = StdArc::new(
            ArcCache::new_with_policy_and_mvcc_lifecycle(
                counted,
                16,
                ArcWritePolicy::WriteBack,
                lifecycle.clone(),
            )
            .expect("cache"),
        );
        let daemon = cache
            .start_flush_daemon(FlushDaemonConfig {
                interval: Duration::from_millis(10),
                batch_size: 2,
                ..FlushDaemonConfig::default()
            })
            .expect("start daemon");

        let c1 = StdArc::clone(&cache);
        let t1 = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            c1.stage_txn_write(&cx, TxnId(100), BlockNumber(4), &[0x44; 4096])
                .expect("stage t1");
            c1.commit_staged_txn(&cx, TxnId(100), CommitSeq(100))
                .expect("commit t1");
        });

        let c2 = StdArc::clone(&cache);
        let t2 = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            c2.stage_txn_write(&cx, TxnId(200), BlockNumber(5), &[0x55; 4096])
                .expect("stage t2");
            let discarded = c2.abort_staged_txn(TxnId(200));
            assert_eq!(discarded, 1);
        });

        let c3 = StdArc::clone(&cache);
        let t3 = std::thread::spawn(move || {
            let cx = Cx::for_testing();
            c3.stage_txn_write(&cx, TxnId(300), BlockNumber(6), &[0x66; 4096])
                .expect("stage t3");
            c3.commit_staged_txn(&cx, TxnId(300), CommitSeq(300))
                .expect("commit t3");
        });

        t1.join().expect("t1 join");
        t2.join().expect("t2 join");
        t3.join().expect("t3 join");

        for _ in 0..120 {
            if cache.dirty_count() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        daemon.shutdown();

        assert_eq!(cache.dirty_count(), 0);
        let writes = cache.inner().write_sequence();
        assert!(writes.contains(&BlockNumber(4)));
        assert!(writes.contains(&BlockNumber(6)));
        assert!(!writes.contains(&BlockNumber(5)));
        assert_eq!(lifecycle.pin_count(), 2);
        assert_eq!(lifecycle.persisted_count(), 2);

        // Aborted txn data is not visible.
        let aborted_read = cache.read_block(&cx, BlockNumber(5)).expect("aborted read");
        assert_eq!(aborted_read.as_slice(), &[0_u8; 4096]);
    }

    // ── CacheMetrics tests ──────────────────────────────────────────────

    #[test]
    fn cache_metrics_initial_state() {
        let state = ArcState::new(4);
        let m = state.snapshot_metrics();
        assert_eq!(m.hits, 0);
        assert_eq!(m.misses, 0);
        assert_eq!(m.evictions, 0);
        assert_eq!(m.t1_len, 0);
        assert_eq!(m.t2_len, 0);
        assert_eq!(m.b1_len, 0);
        assert_eq!(m.b2_len, 0);
        assert_eq!(m.resident, 0);
        assert_eq!(m.dirty_blocks, 0);
        assert_eq!(m.dirty_bytes, 0);
        assert_eq!(m.oldest_dirty_age_ticks, None);
        assert!(m.dirty_ratio().abs() < f64::EPSILON);
        assert_eq!(m.capacity, 4);
        assert_eq!(m.p, 0);
        assert!(m.hit_ratio().abs() < f64::EPSILON);
    }

    #[test]
    fn cache_metrics_track_hits_and_misses() {
        let mut state = ArcState::new(4);
        // First access to block 0: miss
        arc_access(&mut state, BlockNumber(0));
        let m = state.snapshot_metrics();
        assert_eq!(m.misses, 1);
        assert_eq!(m.hits, 0);

        // Second access to block 0: hit (it's now resident)
        arc_access(&mut state, BlockNumber(0));
        let m = state.snapshot_metrics();
        assert_eq!(m.misses, 1);
        assert_eq!(m.hits, 1);
        assert!((m.hit_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn cache_metrics_track_evictions() {
        let mut state = ArcState::new(2);
        // Fill cache: blocks 0, 1
        arc_access(&mut state, BlockNumber(0));
        arc_access(&mut state, BlockNumber(1));
        let m = state.snapshot_metrics();
        assert_eq!(m.evictions, 0);
        assert_eq!(m.resident, 2);

        // Block 2 causes eviction
        arc_access(&mut state, BlockNumber(2));
        let m = state.snapshot_metrics();
        assert_eq!(m.evictions, 1);
        assert_eq!(m.resident, 2);
    }

    #[test]
    fn cache_metrics_list_sizes() {
        let mut state = ArcState::new(4);
        arc_access(&mut state, BlockNumber(10));
        arc_access(&mut state, BlockNumber(20));
        let m = state.snapshot_metrics();
        assert_eq!(m.t1_len, 2); // both in T1 (first access)
        assert_eq!(m.t2_len, 0);

        // Hit block 10: moves T1 → T2
        arc_access(&mut state, BlockNumber(10));
        let m = state.snapshot_metrics();
        assert_eq!(m.t1_len, 1);
        assert_eq!(m.t2_len, 1);
    }

    #[test]
    fn arc_cache_metrics_via_block_device() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 4).expect("cache");

        let m = cache.metrics();
        assert_eq!(m.hits, 0);
        assert_eq!(m.misses, 0);

        let _ = cache.read_block(&cx, BlockNumber(0)).expect("read0");
        let m = cache.metrics();
        assert_eq!(m.misses, 1);
        assert_eq!(m.hits, 0);

        let _ = cache.read_block(&cx, BlockNumber(0)).expect("read0 again");
        let m = cache.metrics();
        assert_eq!(m.misses, 1);
        assert_eq!(m.hits, 1);
        assert!((m.hit_ratio() - 0.5).abs() < f64::EPSILON);
    }

    // ── Concurrency stress tests ────────────────────────────────────────

    #[test]
    fn arc_cache_concurrent_reads_no_deadlock() {
        use std::sync::Arc as StdArc;
        use std::thread;

        const NUM_THREADS: usize = 8;
        const OPS_PER_THREAD: usize = 500;
        const NUM_BLOCKS: usize = 16;
        const BLOCK_SIZE: u32 = 4096;
        const CACHE_CAPACITY: usize = 4;

        let mem = MemoryByteDevice::new(BLOCK_SIZE as usize * NUM_BLOCKS);
        let dev = ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device");

        // Pre-populate the device so reads succeed.
        let cx = Cx::for_testing();
        for i in 0..NUM_BLOCKS {
            let fill = u8::try_from(i & 0xFF).unwrap_or(0);
            let data = vec![fill; BLOCK_SIZE as usize];
            dev.write_block(&cx, BlockNumber(i as u64), &data)
                .expect("seed");
        }

        let cache = StdArc::new(ArcCache::new(dev, CACHE_CAPACITY).expect("cache"));

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|t| {
                let cache = StdArc::clone(&cache);
                thread::spawn(move || {
                    let cx = Cx::for_testing();
                    for i in 0..OPS_PER_THREAD {
                        let idx = (t + i) % NUM_BLOCKS;
                        let block = BlockNumber(idx as u64);
                        let buf = cache.read_block(&cx, block).expect("read");
                        let expected = u8::try_from(idx & 0xFF).unwrap_or(0);
                        assert_eq!(buf.as_slice()[0], expected);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        let m = cache.metrics();
        let total_ops = u64::try_from(NUM_THREADS * OPS_PER_THREAD).expect("fits u64");
        assert_eq!(m.hits + m.misses, total_ops);
        assert!(m.hits > 0, "should have some cache hits");
    }

    #[test]
    fn arc_cache_concurrent_mixed_read_write() {
        use std::sync::Arc as StdArc;
        use std::thread;

        const READERS: usize = 4;
        const WRITERS: usize = 2;
        const OPS: usize = 200;
        const NUM_BLOCKS: usize = 8;
        const BLOCK_SIZE: u32 = 4096;

        let mem = MemoryByteDevice::new(BLOCK_SIZE as usize * NUM_BLOCKS);
        let dev = ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device");

        // Seed device.
        let cx = Cx::for_testing();
        for i in 0..NUM_BLOCKS {
            dev.write_block(&cx, BlockNumber(i as u64), &vec![0u8; BLOCK_SIZE as usize])
                .expect("seed");
        }

        let cache = StdArc::new(ArcCache::new(dev, 4).expect("cache"));

        let mut handles = Vec::new();

        // Reader threads.
        for t in 0..READERS {
            let cache = StdArc::clone(&cache);
            handles.push(thread::spawn(move || {
                let cx = Cx::for_testing();
                for i in 0..OPS {
                    let idx = (t + i) % NUM_BLOCKS;
                    let _ = cache
                        .read_block(&cx, BlockNumber(idx as u64))
                        .expect("read");
                }
            }));
        }

        // Writer threads.
        for t in 0..WRITERS {
            let cache = StdArc::clone(&cache);
            handles.push(thread::spawn(move || {
                let cx = Cx::for_testing();
                for i in 0..OPS {
                    let idx = (t + i) % NUM_BLOCKS;
                    let fill = u8::try_from((t + i) & 0xFF).unwrap_or(0);
                    let data = vec![fill; BLOCK_SIZE as usize];
                    cache
                        .write_block(&cx, BlockNumber(idx as u64), &data)
                        .expect("write");
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        let m = cache.metrics();
        assert!(m.hits + m.misses > 0, "should have recorded some accesses");
        assert!(m.resident <= 4, "resident should not exceed capacity");
    }
}
