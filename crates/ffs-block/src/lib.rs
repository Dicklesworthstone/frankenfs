#![forbid(unsafe_code)]
//! Block I/O layer with pluggable cache policy.
//!
//! Provides the `BlockDevice` trait, cached block reads/writes with
//! `&Cx` capability context for cooperative cancellation, dirty page
//! tracking, and background flush coordination.
//!
//! See [`io_engine`] for the pluggable I/O engine abstraction
//! (pread/pwrite, future io_uring/SPDK backends).

pub mod io_engine;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, BlockNumber, ByteOffset, CommitSeq,
    EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, TxnId,
};
use nix::sys::uio::preadv;
use parking_lot::{Condvar, Mutex, RwLock};
use serde::{Deserialize, Serialize};
#[cfg(feature = "s3fifo")]
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, IoSliceMut};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;
#[cfg(feature = "s3fifo")]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

#[inline]
fn cx_checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

#[inline]
fn saturating_fetch_increment(counter: &std::sync::atomic::AtomicU64) -> u64 {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(1);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(previous) => return previous,
            Err(actual) => current = actual,
        }
    }
}

fn sleep_for_flush_budget_yield(cx: &Cx, duration: Duration) {
    if duration.is_zero() || cx_checkpoint(cx).is_err() {
        return;
    }

    let mut remaining = duration;
    let cancel_check_interval = Duration::from_millis(10);
    while !remaining.is_zero() {
        let slice = remaining.min(cancel_check_interval);
        let budget = cx.budget();
        let now = cx.now();
        if budget.is_past_deadline(now)
            || budget
                .remaining_time(now)
                .is_some_and(|remaining_time| remaining_time <= slice)
        {
            return;
        }

        thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
        if cx_checkpoint(cx).is_err() {
            return;
        }
    }
}

const DEFAULT_BLOCK_ALIGNMENT: usize = 4096;
// AlignedVec over-allocates by alignment - 1, so the public alignment input
// must stay bounded even when callers pass extreme usize values.
const MAX_SUPPORTED_ALIGNMENT: usize = 1 << 20;

#[inline]
fn normalized_alignment(requested: usize) -> usize {
    let rounded = if requested <= 1 {
        1
    } else if requested.is_power_of_two() {
        requested
    } else {
        requested
            .checked_next_power_of_two()
            .unwrap_or(MAX_SUPPORTED_ALIGNMENT)
    };
    rounded.min(MAX_SUPPORTED_ALIGNMENT)
}

/// Owned byte buffer whose exposed slice starts at a requested alignment.
///
/// This type remains fully safe by keeping the original backing allocation and
/// exposing an aligned subslice.
#[derive(Debug)]
pub struct AlignedVec {
    storage: Vec<u8>,
    start: usize,
    len: usize,
    alignment: usize,
}

impl Clone for AlignedVec {
    fn clone(&self) -> Self {
        let mut new = Self::new(self.len, self.alignment);
        new.as_mut_slice().copy_from_slice(self.as_slice());
        new
    }
}

impl AlignedVec {
    #[must_use]
    pub fn new(size: usize, alignment: usize) -> Self {
        let alignment = normalized_alignment(alignment);
        if size == 0 {
            trace!(
                target: "ffs::block::io",
                event = "buffer_alloc",
                size = 0,
                alignment = alignment
            );
            return Self {
                storage: Vec::new(),
                start: 0,
                len: 0,
                alignment,
            };
        }

        let padding = alignment.saturating_sub(1);
        let storage_len = size.saturating_add(padding);
        let storage = vec![0_u8; storage_len];
        let base = storage.as_ptr() as usize;
        let misalignment = base & (alignment - 1);
        let start = if misalignment == 0 {
            0
        } else {
            alignment - misalignment
        };
        debug_assert!(start + size <= storage.len());
        trace!(
            target: "ffs::block::io",
            event = "buffer_alloc",
            size = size,
            alignment = alignment
        );
        Self {
            storage,
            start,
            len: size,
            alignment,
        }
    }

    #[must_use]
    pub fn from_vec(bytes: Vec<u8>, alignment: usize) -> Self {
        let alignment = normalized_alignment(alignment);
        if bytes.is_empty() {
            return Self::new(0, alignment);
        }

        let len = bytes.len();
        if (bytes.as_ptr() as usize) % alignment == 0 {
            return Self {
                storage: bytes,
                start: 0,
                len,
                alignment,
            };
        }

        trace!(
            target: "ffs::block::io",
            event = "copy_detected",
            source = "vec",
            dest = "aligned_vec",
            size = len
        );
        let mut aligned = Self::new(len, alignment);
        aligned.as_mut_slice().copy_from_slice(&bytes);
        aligned
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.start + self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let start = self.start;
        let end = start + self.len;
        &mut self.storage[start..end]
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        let Self {
            storage,
            start,
            len,
            alignment: _,
        } = self;
        if len == 0 {
            return Vec::new();
        }
        if start == 0 && len == storage.len() {
            return storage;
        }
        storage[start..start + len].to_vec()
    }
}

impl PartialEq for AlignedVec {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for AlignedVec {}

/// Owned block buffer.
///
/// Invariant: length == device block size for the originating device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBuf {
    bytes: Arc<AlignedVec>,
}

impl BlockBuf {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(AlignedVec::from_vec(bytes, DEFAULT_BLOCK_ALIGNMENT)),
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[must_use]
    pub fn clone_ref(&self) -> Self {
        Self {
            bytes: Arc::clone(&self.bytes),
        }
    }

    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        Self {
            bytes: Arc::new(AlignedVec::new(len, DEFAULT_BLOCK_ALIGNMENT)),
        }
    }

    #[must_use]
    pub fn alignment(&self) -> usize {
        self.bytes.alignment()
    }

    pub fn make_mut(&mut self) -> &mut [u8] {
        Arc::make_mut(&mut self.bytes).as_mut_slice()
    }

    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        match Arc::try_unwrap(self.bytes) {
            Ok(bytes) => bytes.into_vec(),
            Err(shared) => shared.as_slice().to_vec(),
        }
    }
}

/// Byte-addressed device for fixed-offset I/O (pread/pwrite semantics).
pub trait ByteDevice: Send + Sync {
    /// Total length in bytes.
    fn len_bytes(&self) -> u64;

    /// Returns true when `read_vectored_exact_at` can collapse contiguous
    /// buffers into fewer device I/O operations than scalar reads.
    fn supports_vectored_reads(&self) -> bool {
        false
    }

    /// Read exactly `buf.len()` bytes from `offset` into `buf`.
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()>;

    /// Read a contiguous byte range into multiple buffers.
    ///
    /// The default preserves scalar `read_exact_at` semantics. File-backed
    /// implementations can override this with `preadv`-style I/O.
    fn read_vectored_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        cx_checkpoint(cx)?;
        let mut next_offset = offset.0;
        for buf in bufs {
            let len = u64::try_from(buf.len())
                .map_err(|_| FfsError::Format("read length overflows u64".to_owned()))?;
            self.read_exact_at(cx, ByteOffset(next_offset), buf)?;
            next_offset = next_offset
                .checked_add(len)
                .ok_or_else(|| FfsError::Format("read range overflows u64".to_owned()))?;
        }
        cx_checkpoint(cx)?;
        Ok(())
    }

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

    fn supports_vectored_reads(&self) -> bool {
        true
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

    fn read_vectored_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        cx_checkpoint(cx)?;
        let total_len = bufs.iter().try_fold(0_usize, |total, buf| {
            total
                .checked_add(buf.len())
                .ok_or_else(|| FfsError::Format("read length overflows usize".to_owned()))
        })?;
        let end = offset
            .0
            .checked_add(
                u64::try_from(total_len)
                    .map_err(|_| FfsError::Format("read length overflows u64".to_owned()))?,
            )
            .ok_or_else(|| FfsError::Format("read range overflows u64".to_owned()))?;
        if end > self.len {
            return Err(FfsError::Format(format!(
                "read out of bounds: offset={offset} len={total_len} file_len={}",
                self.len
            )));
        }

        let mut total_read = 0_usize;
        let mut remaining = bufs;
        while !remaining.is_empty() {
            let next_offset = offset
                .0
                .checked_add(
                    u64::try_from(total_read)
                        .map_err(|_| FfsError::Format("read length overflows u64".to_owned()))?,
                )
                .ok_or_else(|| FfsError::Format("read range overflows u64".to_owned()))?;
            let next_offset = i64::try_from(next_offset)
                .map_err(|_| FfsError::Format("read offset does not fit off_t".to_owned()))?;
            let n = preadv(self.file.as_ref().as_fd(), remaining, next_offset)
                .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                )
                .into());
            }
            total_read = total_read
                .checked_add(n)
                .ok_or_else(|| FfsError::Format("read length overflows usize".to_owned()))?;
            IoSliceMut::advance_slices(&mut remaining, n);
        }

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

    /// Returns true when `read_contiguous_blocks` is expected to reduce device
    /// I/O operations compared with scalar `read_block` calls.
    fn supports_contiguous_reads(&self) -> bool {
        false
    }

    /// Read a contiguous block range starting at `start` into `bufs`.
    ///
    /// Implementations may override this to collapse adjacent block reads into
    /// one device I/O. The default preserves scalar `read_block` semantics.
    fn read_contiguous_blocks(
        &self,
        cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        cx_checkpoint(cx)?;
        for (idx, buf) in bufs.iter_mut().enumerate() {
            let delta = u64::try_from(idx)
                .map_err(|_| FfsError::Format("block index does not fit u64".to_owned()))?;
            let block = BlockNumber(start.0.checked_add(delta).ok_or_else(|| {
                FfsError::Format("contiguous read block range overflow".to_owned())
            })?);
            *buf = self.read_block(cx, block)?;
        }
        cx_checkpoint(cx)?;
        Ok(())
    }

    /// Write a block by number. `data.len()` MUST equal `block_size()`.
    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()>;

    /// Write a contiguous run of blocks starting at `start`. `data` holds the
    /// concatenated block contents (`data.len()` MUST be a multiple of
    /// `block_size()`); block `start + i` receives `data[i*bs .. (i+1)*bs]`.
    ///
    /// Implementations backed by a byte device may override this to collapse
    /// the run into a single ranged write (one `pwrite`/`write_all_at` instead
    /// of one per block). The default preserves scalar `write_block` semantics,
    /// so the final on-disk state is identical either way.
    fn write_contiguous_blocks(&self, cx: &Cx, start: BlockNumber, data: &[u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        let bs = self.block_size() as usize;
        if bs == 0 || data.len() % bs != 0 {
            return Err(FfsError::Format(
                "write_contiguous_blocks: data length must be a multiple of block size".to_owned(),
            ));
        }
        for (idx, chunk) in data.chunks(bs).enumerate() {
            let delta = u64::try_from(idx)
                .map_err(|_| FfsError::Format("block index does not fit u64".to_owned()))?;
            let block = BlockNumber(start.0.checked_add(delta).ok_or_else(|| {
                FfsError::Format("contiguous write block range overflow".to_owned())
            })?);
            self.write_block(cx, block, chunk)?;
        }
        cx_checkpoint(cx)?;
        Ok(())
    }

    /// Device block size in bytes.
    fn block_size(&self) -> u32;

    /// Total number of blocks.
    fn block_count(&self) -> u64;

    /// Flush pending writes to stable storage.
    fn sync(&self, cx: &Cx) -> Result<()>;
}

impl<D: BlockDevice + ?Sized> BlockDevice for Arc<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        (**self).read_block(cx, block)
    }

    fn supports_contiguous_reads(&self) -> bool {
        (**self).supports_contiguous_reads()
    }

    fn read_contiguous_blocks(
        &self,
        cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        (**self).read_contiguous_blocks(cx, start, bufs)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        (**self).write_block(cx, block, data)
    }

    fn write_contiguous_blocks(&self, cx: &Cx, start: BlockNumber, data: &[u8]) -> Result<()> {
        (**self).write_contiguous_blocks(cx, start, data)
    }

    fn block_size(&self) -> u32 {
        (**self).block_size()
    }

    fn block_count(&self) -> u64 {
        (**self).block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        (**self).sync(cx)
    }
}

/// Multi-block I/O helpers.
///
/// Default implementations preserve correctness by delegating to scalar
/// operations, while allowing implementations to override for true vectored
/// syscalls in the future.
pub trait VectoredBlockDevice: BlockDevice {
    fn read_vectored(&self, blocks: &[BlockNumber], bufs: &mut [BlockBuf], cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;
        if blocks.len() != bufs.len() {
            return Err(FfsError::Format(format!(
                "read_vectored length mismatch: blocks={} bufs={}",
                blocks.len(),
                bufs.len()
            )));
        }
        trace!(
            target: "ffs::block::io",
            event = "read_vectored",
            block_count = blocks.len()
        );
        for (block, buf) in blocks.iter().copied().zip(bufs.iter_mut()) {
            *buf = self.read_block(cx, block)?;
        }
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn write_vectored(&self, blocks: &[BlockNumber], bufs: &[BlockBuf], cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;
        if blocks.len() != bufs.len() {
            return Err(FfsError::Format(format!(
                "write_vectored length mismatch: blocks={} bufs={}",
                blocks.len(),
                bufs.len()
            )));
        }
        trace!(
            target: "ffs::block::io",
            event = "write_vectored",
            block_count = blocks.len()
        );
        for (block, buf) in blocks.iter().copied().zip(bufs.iter()) {
            self.write_block(cx, block, buf.as_slice())?;
        }
        cx_checkpoint(cx)?;
        Ok(())
    }
}

impl<T: BlockDevice + ?Sized> VectoredBlockDevice for T {}

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

/// Repair refresh coordination hook for write-back flush lifecycle.
///
/// Implementations receive the set of blocks durably flushed in one batch and
/// can queue downstream symbol refresh work.
pub trait RepairFlushLifecycle: Send + Sync + std::fmt::Debug {
    fn on_flush_committed(&self, cx: &Cx, blocks: &[BlockNumber]) -> Result<()>;
}

#[derive(Debug, Default)]
struct NoopRepairFlushLifecycle;

impl RepairFlushLifecycle for NoopRepairFlushLifecycle {
    fn on_flush_committed(&self, _cx: &Cx, _blocks: &[BlockNumber]) -> Result<()> {
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
        let block_size = usize::try_from(self.block_size)
            .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;
        let mut buf = BlockBuf::zeroed(block_size);
        self.inner
            .read_exact_at(cx, ByteOffset(offset), buf.make_mut())?;
        cx_checkpoint(cx)?;
        Ok(buf)
    }

    fn supports_contiguous_reads(&self) -> bool {
        self.inner.supports_vectored_reads()
    }

    fn read_contiguous_blocks(
        &self,
        cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        cx_checkpoint(cx)?;
        if bufs.is_empty() {
            return Ok(());
        }

        let count = u64::try_from(bufs.len())
            .map_err(|_| FfsError::Format("block count does not fit u64".to_owned()))?;
        let end = start
            .0
            .checked_add(count)
            .ok_or_else(|| FfsError::Format("block range overflow".to_owned()))?;
        if end > self.block_count {
            return Err(FfsError::Format(format!(
                "block range out of range: start={} count={} block_count={}",
                start.0, count, self.block_count
            )));
        }

        let block_size = usize::try_from(self.block_size)
            .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;
        let offset = start
            .0
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(|| FfsError::Format("block offset overflow".to_owned()))?;

        for buf in bufs.iter_mut() {
            // A successful exact vectored read overwrites every byte below; on
            // error the caller observes Err and must not consume partial data.
            if buf.len() != block_size {
                *buf = BlockBuf::zeroed(block_size);
            }
        }
        let mut slices: Vec<IoSliceMut<'_>> = bufs
            .iter_mut()
            .map(|buf| IoSliceMut::new(buf.make_mut()))
            .collect();
        self.inner
            .read_vectored_exact_at(cx, ByteOffset(offset), &mut slices)?;
        cx_checkpoint(cx)?;
        Ok(())
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
    /// Current number of committed dirty blocks waiting for writeback.
    pub writeback_queue_depth: usize,
    /// Age of the oldest dirty block in write-order ticks.
    ///
    /// This is a logical clock (not wall time), incremented per dirty-mark.
    pub oldest_dirty_age_ticks: Option<u64>,
    /// Maximum cache capacity in blocks.
    pub capacity: usize,
    /// Current adaptive target size for T1.
    pub p: usize,
    /// Number of ghost hits in B1 (blocks re-admitted from T1 ghost list).
    ///
    /// A high B1 ghost hit rate indicates T1 was undersized — the adaptive
    /// policy will have already increased `p` in response.
    pub b1_ghost_hits: u64,
    /// Number of ghost hits in B2 (blocks re-admitted from T2 ghost list).
    ///
    /// A high B2 ghost hit rate indicates T2 was undersized — the adaptive
    /// policy will have already decreased `p` in response.
    pub b2_ghost_hits: u64,
}

impl CacheMetrics {
    /// Aggregate shard-local cache metrics into one cache-wide snapshot.
    ///
    /// Shards keep independent recency queues and dirty clocks, so queue
    /// lengths and monotonic counters are additive. The oldest dirty age uses
    /// the maximum shard-local age as the conservative cache-wide age.
    #[must_use]
    pub fn aggregate(shards: impl IntoIterator<Item = Self>) -> Self {
        let mut total = Self {
            hits: 0,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
            t1_len: 0,
            t2_len: 0,
            b1_len: 0,
            b2_len: 0,
            resident: 0,
            dirty_blocks: 0,
            dirty_bytes: 0,
            writeback_queue_depth: 0,
            oldest_dirty_age_ticks: None,
            capacity: 0,
            p: 0,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
        };

        for shard in shards {
            total.hits = total.hits.saturating_add(shard.hits);
            total.misses = total.misses.saturating_add(shard.misses);
            total.evictions = total.evictions.saturating_add(shard.evictions);
            total.dirty_flushes = total.dirty_flushes.saturating_add(shard.dirty_flushes);
            total.t1_len = total.t1_len.saturating_add(shard.t1_len);
            total.t2_len = total.t2_len.saturating_add(shard.t2_len);
            total.b1_len = total.b1_len.saturating_add(shard.b1_len);
            total.b2_len = total.b2_len.saturating_add(shard.b2_len);
            total.resident = total.resident.saturating_add(shard.resident);
            total.dirty_blocks = total.dirty_blocks.saturating_add(shard.dirty_blocks);
            total.dirty_bytes = total.dirty_bytes.saturating_add(shard.dirty_bytes);
            total.writeback_queue_depth = total
                .writeback_queue_depth
                .saturating_add(shard.writeback_queue_depth);
            total.oldest_dirty_age_ticks =
                match (total.oldest_dirty_age_ticks, shard.oldest_dirty_age_ticks) {
                    (Some(lhs), Some(rhs)) => Some(lhs.max(rhs)),
                    (None, Some(rhs)) => Some(rhs),
                    (Some(lhs), None) => Some(lhs),
                    (None, None) => None,
                };
            total.capacity = total.capacity.saturating_add(shard.capacity);
            total.p = total.p.saturating_add(shard.p);
            total.b1_ghost_hits = total.b1_ghost_hits.saturating_add(shard.b1_ghost_hits);
            total.b2_ghost_hits = total.b2_ghost_hits.saturating_add(shard.b2_ghost_hits);
        }

        total
    }

    /// Cache hit ratio in the range [0.0, 1.0].
    ///
    /// Returns 0.0 if no accesses have been made.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits as f64 + self.misses as f64;
        if total == 0.0 {
            0.0
        } else {
            self.hits as f64 / total
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

    /// Convert the internal cache counters into the shared runtime export shape.
    #[must_use]
    pub fn runtime_metrics_snapshot(&self) -> CacheRuntimeMetricsSnapshot {
        CacheRuntimeMetricsSnapshot {
            cache_hits: self.hits,
            cache_misses: self.misses,
            cache_evictions: self.evictions,
            cache_dirty_count: u64::try_from(self.dirty_blocks).unwrap_or(u64::MAX),
            writeback_queue_depth: u64::try_from(self.writeback_queue_depth).unwrap_or(u64::MAX),
            hit_rate: self.hit_ratio(),
        }
    }
}

/// JSON-friendly cache metrics export used by runtime/e2e reporting.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CacheRuntimeMetricsSnapshot {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    pub cache_dirty_count: u64,
    pub writeback_queue_depth: u64,
    pub hit_rate: f64,
}

/// Minimum host RAM required before a cache result can be described as a
/// large-RAM swarm-host proof.
pub const LARGE_RAM_CACHE_PROOF_FLOOR_BYTES: u64 = 256 * 1024 * 1024 * 1024;

/// Cache admission policy represented in large-RAM proof artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheAdmissionPolicy {
    /// Existing ARC implementation and the required fallback path.
    CurrentArc,
    /// Segmented FIFO/S3-FIFO-style admission candidate.
    SegmentedS3Fifo,
}

/// Explicit artifact gates required before cache tuning can be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheAdmissionEvidenceGate {
    ReproductionCommand,
    RawLogs,
    ReleaseClaimState,
    BackpressurePolicy,
    FlushPolicy,
}

impl CacheAdmissionEvidenceGate {
    const ALL: [Self; 5] = [
        Self::ReproductionCommand,
        Self::RawLogs,
        Self::ReleaseClaimState,
        Self::BackpressurePolicy,
        Self::FlushPolicy,
    ];
}

/// JSON-friendly proof gates attached to a cache-admission artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheAdmissionArtifactEvidence {
    pub gates: Vec<CacheAdmissionEvidenceGate>,
}

impl CacheAdmissionArtifactEvidence {
    /// Evidence packet with every required artifact gate present.
    #[must_use]
    pub fn complete() -> Self {
        Self {
            gates: CacheAdmissionEvidenceGate::ALL.to_vec(),
        }
    }

    /// Evidence packet with no required gates present.
    #[must_use]
    pub const fn empty() -> Self {
        Self { gates: Vec::new() }
    }

    /// Return a copy with `gate` removed.
    #[must_use]
    pub fn without(mut self, gate: CacheAdmissionEvidenceGate) -> Self {
        self.gates.retain(|candidate| *candidate != gate);
        self
    }

    /// Return true when `gate` is present.
    #[must_use]
    pub fn contains(&self, gate: CacheAdmissionEvidenceGate) -> bool {
        self.gates.contains(&gate)
    }

    /// First missing gate in stable policy order.
    #[must_use]
    pub fn first_missing(&self) -> Option<CacheAdmissionEvidenceGate> {
        CacheAdmissionEvidenceGate::ALL
            .into_iter()
            .find(|gate| !self.contains(*gate))
    }
}

impl Default for CacheAdmissionArtifactEvidence {
    fn default() -> Self {
        Self::empty()
    }
}

/// Observed host memory fields used to classify large-RAM proof claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheHostMemoryObservation {
    pub total_ram_bytes: Option<u64>,
    pub available_ram_bytes: Option<u64>,
    pub numa_nodes: Option<u32>,
}

/// Expected-loss weights for comparing cache admission policies.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CacheAdmissionLossWeights {
    pub miss_penalty_weight: f64,
    pub p99_latency_weight: f64,
    pub dirty_pressure_weight: f64,
    pub writeback_queue_weight: f64,
    pub eviction_pressure_weight: f64,
    pub memory_overhead_weight: f64,
}

impl Default for CacheAdmissionLossWeights {
    fn default() -> Self {
        Self {
            miss_penalty_weight: 100.0,
            p99_latency_weight: 0.01,
            dirty_pressure_weight: 60.0,
            writeback_queue_weight: 0.25,
            eviction_pressure_weight: 40.0,
            memory_overhead_weight: 50.0,
        }
    }
}

/// Budget and safety thresholds for the large-RAM cache admission contract.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LargeRamCacheBudgetConfig {
    pub min_host_ram_bytes: u64,
    pub cache_budget_bytes: u64,
    pub max_dirty_ratio: f64,
    pub max_eviction_pressure: f64,
    pub max_memory_overhead_ratio: f64,
    pub max_writeback_queue_depth: u64,
    pub min_hit_rate_gain: f64,
    pub max_p99_latency_regression_ratio: f64,
    pub loss_weights: CacheAdmissionLossWeights,
}

impl Default for LargeRamCacheBudgetConfig {
    fn default() -> Self {
        Self {
            min_host_ram_bytes: LARGE_RAM_CACHE_PROOF_FLOOR_BYTES,
            cache_budget_bytes: 16 * 1024 * 1024 * 1024,
            max_dirty_ratio: 0.40,
            max_eviction_pressure: 0.20,
            max_memory_overhead_ratio: 0.10,
            max_writeback_queue_depth: 1_000_000,
            min_hit_rate_gain: 0.03,
            max_p99_latency_regression_ratio: 0.05,
            loss_weights: CacheAdmissionLossWeights::default(),
        }
    }
}

/// Observed policy sample for ARC versus a candidate admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CacheAdmissionPolicySample {
    pub policy: CacheAdmissionPolicy,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    pub p99_latency_micros: u64,
    pub memory_overhead_bytes: u64,
    pub dirty_ratio: f64,
    pub writeback_queue_depth: u64,
}

impl CacheAdmissionPolicySample {
    /// Hit rate in [0.0, 1.0], or 0.0 when no accesses were observed.
    #[must_use]
    pub fn hit_rate(self) -> f64 {
        let total = self.cache_hits.saturating_add(self.cache_misses);
        if total == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / total as f64
    }

    /// Evictions per observed access.
    #[must_use]
    pub fn eviction_pressure(self) -> f64 {
        let total = self.cache_hits.saturating_add(self.cache_misses);
        if total == 0 {
            return 0.0;
        }
        self.cache_evictions as f64 / total as f64
    }

    fn memory_overhead_ratio(self, config: LargeRamCacheBudgetConfig) -> f64 {
        if config.cache_budget_bytes == 0 {
            return f64::INFINITY;
        }
        self.memory_overhead_bytes as f64 / config.cache_budget_bytes as f64
    }

    fn expected_loss(self, config: LargeRamCacheBudgetConfig) -> f64 {
        let weights = config.loss_weights;
        let miss_ratio = 1.0 - self.hit_rate();
        let memory_ratio = self.memory_overhead_ratio(config);
        let loss = weights.miss_penalty_weight.mul_add(miss_ratio, 0.0);
        let loss = weights
            .p99_latency_weight
            .mul_add(self.p99_latency_micros as f64, loss);
        let loss = weights
            .dirty_pressure_weight
            .mul_add(self.dirty_ratio, loss);
        let loss = weights
            .writeback_queue_weight
            .mul_add(self.writeback_queue_depth as f64, loss);
        let loss = weights
            .eviction_pressure_weight
            .mul_add(self.eviction_pressure(), loss);
        weights.memory_overhead_weight.mul_add(memory_ratio, loss)
    }
}

/// Input artifact for the large-RAM cache admission evaluator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LargeRamCacheAdmissionInput {
    pub config: LargeRamCacheBudgetConfig,
    pub host_memory: CacheHostMemoryObservation,
    pub artifact_evidence: CacheAdmissionArtifactEvidence,
    pub current_arc: CacheAdmissionPolicySample,
    pub candidate: CacheAdmissionPolicySample,
}

/// Public claim state emitted by the cache contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheAdmissionClaimState {
    MissingReference,
    SmallHostSmoke,
    Experimental,
}

/// Contract decision for the candidate cache admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheAdmissionMode {
    KeepCurrentArc,
    CandidateDesignOnly,
    CapabilitySkip,
}

/// Stable reason code for cache admission decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheAdmissionReason {
    MissingHostMemory,
    HostBelowLargeRamFloor,
    MissingArtifactGate(CacheAdmissionEvidenceGate),
    CandidateDirtyPressureTooHigh,
    CandidateWritebackQueueTooDeep,
    CandidateEvictionPressureTooHigh,
    CandidateMemoryOverheadTooHigh,
    CandidateP99LatencyRegressed,
    CandidateHitRateGainTooSmall,
    CandidateExpectedLossNotLower,
    CandidateLowerExpectedLoss,
}

/// Evaluated cache admission report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheAdmissionDecisionReport {
    pub mode: CacheAdmissionMode,
    pub reason: CacheAdmissionReason,
    pub selected_policy: CacheAdmissionPolicy,
    pub fallback_policy: CacheAdmissionPolicy,
    pub claim_state: CacheAdmissionClaimState,
    pub hit_rate_gain: f64,
    pub p99_latency_regression_ratio: f64,
    pub candidate_memory_overhead_ratio: f64,
    pub candidate_eviction_pressure: f64,
    pub candidate_dirty_ratio: f64,
    pub current_expected_loss: f64,
    pub candidate_expected_loss: f64,
}

/// Evaluate the large-RAM cache admission contract without changing runtime
/// policy selection.
#[must_use]
pub fn evaluate_large_ram_cache_admission(
    input: &LargeRamCacheAdmissionInput,
) -> CacheAdmissionDecisionReport {
    if let Some((reason, claim_state)) = cache_host_capability_skip(input) {
        return cache_admission_report(
            input,
            CacheAdmissionMode::CapabilitySkip,
            reason,
            CacheAdmissionPolicy::CurrentArc,
            claim_state,
        );
    }
    if let Some(gate) = input.artifact_evidence.first_missing() {
        return cache_admission_report(
            input,
            CacheAdmissionMode::KeepCurrentArc,
            CacheAdmissionReason::MissingArtifactGate(gate),
            CacheAdmissionPolicy::CurrentArc,
            CacheAdmissionClaimState::MissingReference,
        );
    }
    if let Some(reason) = cache_candidate_limit_rejection(input) {
        return cache_admission_report(
            input,
            CacheAdmissionMode::KeepCurrentArc,
            reason,
            CacheAdmissionPolicy::CurrentArc,
            CacheAdmissionClaimState::Experimental,
        );
    }
    let candidate_expected_loss = input.candidate.expected_loss(input.config);
    let current_expected_loss = input.current_arc.expected_loss(input.config);
    if candidate_expected_loss >= current_expected_loss {
        return cache_admission_report(
            input,
            CacheAdmissionMode::KeepCurrentArc,
            CacheAdmissionReason::CandidateExpectedLossNotLower,
            CacheAdmissionPolicy::CurrentArc,
            CacheAdmissionClaimState::Experimental,
        );
    }

    cache_admission_report(
        input,
        CacheAdmissionMode::CandidateDesignOnly,
        CacheAdmissionReason::CandidateLowerExpectedLoss,
        input.candidate.policy,
        CacheAdmissionClaimState::Experimental,
    )
}

fn cache_host_capability_skip(
    input: &LargeRamCacheAdmissionInput,
) -> Option<(CacheAdmissionReason, CacheAdmissionClaimState)> {
    let Some(total_ram_bytes) = input.host_memory.total_ram_bytes else {
        return Some((
            CacheAdmissionReason::MissingHostMemory,
            CacheAdmissionClaimState::MissingReference,
        ));
    };
    if input.host_memory.available_ram_bytes.is_none() {
        return Some((
            CacheAdmissionReason::MissingHostMemory,
            CacheAdmissionClaimState::MissingReference,
        ));
    }
    if total_ram_bytes < input.config.min_host_ram_bytes {
        return Some((
            CacheAdmissionReason::HostBelowLargeRamFloor,
            CacheAdmissionClaimState::SmallHostSmoke,
        ));
    }
    None
}

fn cache_candidate_limit_rejection(
    input: &LargeRamCacheAdmissionInput,
) -> Option<CacheAdmissionReason> {
    if input.candidate.dirty_ratio > input.config.max_dirty_ratio {
        return Some(CacheAdmissionReason::CandidateDirtyPressureTooHigh);
    }
    if input.candidate.writeback_queue_depth > input.config.max_writeback_queue_depth {
        return Some(CacheAdmissionReason::CandidateWritebackQueueTooDeep);
    }
    if input.candidate.eviction_pressure() > input.config.max_eviction_pressure {
        return Some(CacheAdmissionReason::CandidateEvictionPressureTooHigh);
    }
    if input.candidate.memory_overhead_ratio(input.config) > input.config.max_memory_overhead_ratio
    {
        return Some(CacheAdmissionReason::CandidateMemoryOverheadTooHigh);
    }
    let p99_latency_regression_ratio = p99_regression_ratio(
        input.current_arc.p99_latency_micros,
        input.candidate.p99_latency_micros,
    );
    if p99_latency_regression_ratio > input.config.max_p99_latency_regression_ratio {
        return Some(CacheAdmissionReason::CandidateP99LatencyRegressed);
    }
    let hit_rate_gain = input.candidate.hit_rate() - input.current_arc.hit_rate();
    if hit_rate_gain < input.config.min_hit_rate_gain {
        return Some(CacheAdmissionReason::CandidateHitRateGainTooSmall);
    }
    None
}

fn cache_admission_report(
    input: &LargeRamCacheAdmissionInput,
    mode: CacheAdmissionMode,
    reason: CacheAdmissionReason,
    selected_policy: CacheAdmissionPolicy,
    claim_state: CacheAdmissionClaimState,
) -> CacheAdmissionDecisionReport {
    CacheAdmissionDecisionReport {
        mode,
        reason,
        selected_policy,
        fallback_policy: CacheAdmissionPolicy::CurrentArc,
        claim_state,
        hit_rate_gain: input.candidate.hit_rate() - input.current_arc.hit_rate(),
        p99_latency_regression_ratio: p99_regression_ratio(
            input.current_arc.p99_latency_micros,
            input.candidate.p99_latency_micros,
        ),
        candidate_memory_overhead_ratio: input.candidate.memory_overhead_ratio(input.config),
        candidate_eviction_pressure: input.candidate.eviction_pressure(),
        candidate_dirty_ratio: input.candidate.dirty_ratio,
        current_expected_loss: input.current_arc.expected_loss(input.config),
        candidate_expected_loss: input.candidate.expected_loss(input.config),
    }
}

fn p99_regression_ratio(current_p99_micros: u64, candidate_p99_micros: u64) -> f64 {
    if candidate_p99_micros <= current_p99_micros {
        return 0.0;
    }
    if current_p99_micros == 0 {
        return f64::INFINITY;
    }
    candidate_p99_micros.saturating_sub(current_p99_micros) as f64 / current_p99_micros as f64
}

/// Memory pressure levels used to adapt cache target size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPressure {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl MemoryPressure {
    #[must_use]
    const fn target_fraction(self) -> (usize, usize) {
        match self {
            Self::None => (10, 10),
            Self::Low => (9, 10),
            Self::Medium => (7, 10),
            Self::High => (5, 10),
            Self::Critical => (2, 10),
        }
    }

    #[must_use]
    fn target_capacity(self, max_capacity: usize) -> usize {
        let (numerator, denominator) = self.target_fraction();
        let rounded = max_capacity
            .saturating_mul(numerator)
            .saturating_add(denominator / 2)
            / denominator;
        rounded.clamp(1, max_capacity)
    }
}

/// Snapshot of cache pressure state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CachePressureReport {
    pub current_size: usize,
    pub target_size: usize,
    pub dirty_count: usize,
    pub eviction_rate: f64,
}

/// Number of page-lock shards to provision per available CPU.
pub const PAGE_LOCK_SHARDS_PER_CORE: usize = 4;
/// Minimum page-lock shard count.
pub const MIN_PAGE_LOCK_SHARDS: usize = 16;
/// Maximum page-lock shard count.
pub const MAX_PAGE_LOCK_SHARDS: usize = 1024;
const PAGE_LOCK_INLINE_CAPACITY: usize = 8;

#[derive(Debug)]
enum InFlightBlocks {
    Inline(Vec<BlockNumber>),
    Large(HashSet<BlockNumber>),
}

impl InFlightBlocks {
    fn new() -> Self {
        Self::Inline(Vec::with_capacity(PAGE_LOCK_INLINE_CAPACITY))
    }

    fn len(&self) -> usize {
        match self {
            Self::Inline(blocks) => blocks.len(),
            Self::Large(blocks) => blocks.len(),
        }
    }

    fn contains(&self, block: BlockNumber) -> bool {
        match self {
            Self::Inline(blocks) => blocks.contains(&block),
            Self::Large(blocks) => blocks.contains(&block),
        }
    }

    fn insert(&mut self, block: BlockNumber) -> bool {
        match self {
            Self::Inline(blocks) => {
                if blocks.contains(&block) {
                    return false;
                }
                if blocks.len() < PAGE_LOCK_INLINE_CAPACITY {
                    blocks.push(block);
                    return true;
                }

                let mut promoted = HashSet::with_capacity(PAGE_LOCK_INLINE_CAPACITY * 2);
                promoted.extend(blocks.drain(..));
                let inserted = promoted.insert(block);
                *self = Self::Large(promoted);
                inserted
            }
            Self::Large(blocks) => blocks.insert(block),
        }
    }

    fn remove(&mut self, block: BlockNumber) -> bool {
        match self {
            Self::Inline(blocks) => blocks
                .iter()
                .position(|existing| *existing == block)
                .map(|idx| blocks.swap_remove(idx))
                .is_some(),
            Self::Large(blocks) => {
                let removed = blocks.remove(&block);
                if blocks.len() <= PAGE_LOCK_INLINE_CAPACITY / 2 {
                    let mut demoted = Vec::with_capacity(PAGE_LOCK_INLINE_CAPACITY);
                    demoted.extend(blocks.drain());
                    *self = Self::Inline(demoted);
                }
                removed
            }
        }
    }
}

/// One shard of the cache miss page-lock table.
///
/// Wait protocol: a waiter holds `in_flight`, loops on the target block
/// membership predicate, increments `waiters` immediately before parking on
/// `ready`, and decrements after every wake before re-checking the predicate.
/// A permit drop must remove the block while holding `in_flight`, release that
/// mutex, then notify waiters so the cleared predicate is visible before wakeup.
struct PageLockShard {
    in_flight: Mutex<InFlightBlocks>,
    ready: Condvar,
    waiters: AtomicUsize,
}

impl PageLockShard {
    fn new() -> Self {
        Self {
            in_flight: Mutex::new(InFlightBlocks::new()),
            ready: Condvar::new(),
            waiters: AtomicUsize::new(0),
        }
    }
}

impl std::fmt::Debug for PageLockShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageLockShard")
            .field("in_flight", &self.in_flight.lock().len())
            .finish_non_exhaustive()
    }
}

/// Sharded per-block miss coalescer for cache read misses.
///
/// The table serializes only concurrent cold reads for the same block. Distinct
/// blocks map to independent shards, so large readdir/readahead and metadata
/// walks can continue to exploit device-level parallelism while avoiding a
/// same-block stampede during hot metadata warm-up.
pub struct PageLockTable {
    shards: Vec<PageLockShard>,
}

impl PageLockTable {
    /// Create a page-lock table with a rounded, bounded shard count.
    #[must_use]
    pub fn new(shard_count: usize) -> Self {
        let shard_count = shard_count
            .clamp(1, MAX_PAGE_LOCK_SHARDS)
            .next_power_of_two();
        let shards = (0..shard_count).map(|_| PageLockShard::new()).collect();
        Self { shards }
    }

    /// Create a host-sized table (`available_parallelism * 4`, bounded).
    #[must_use]
    pub fn for_host_parallelism() -> Self {
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let shard_count = cores
            .saturating_mul(PAGE_LOCK_SHARDS_PER_CORE)
            .clamp(MIN_PAGE_LOCK_SHARDS, MAX_PAGE_LOCK_SHARDS);
        Self::new(shard_count)
    }

    /// Number of lock shards in the table.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Current number of blocks being loaded through this table.
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.in_flight.lock().len())
            .sum()
    }

    fn acquire(&self, block: BlockNumber) -> PageLockPermit<'_> {
        let shard = &self.shards[self.shard_index(block)];
        let mut in_flight = shard.in_flight.lock();
        while in_flight.contains(block) {
            shard.waiters.fetch_add(1, Ordering::AcqRel);
            shard.ready.wait(&mut in_flight);
            shard.waiters.fetch_sub(1, Ordering::AcqRel);
        }
        let inserted = in_flight.insert(block);
        debug_assert!(inserted, "block should not already be in flight");
        drop(in_flight);
        PageLockPermit { shard, block }
    }

    fn shard_index(&self, block: BlockNumber) -> usize {
        let len = self.shards.len();
        let mixed = mix_block_number(block.0);
        let len_u64 = u64::try_from(len).unwrap_or(u64::MAX);
        let idx = if len.is_power_of_two() {
            mixed & len_u64.saturating_sub(1)
        } else {
            mixed % len_u64
        };
        usize::try_from(idx).unwrap_or(0)
    }
}

impl std::fmt::Debug for PageLockTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageLockTable")
            .field("shard_count", &self.shard_count())
            .field("in_flight", &self.in_flight_len())
            .finish()
    }
}

/// Held while a single block is being populated after a cache miss.
pub struct PageLockPermit<'a> {
    shard: &'a PageLockShard,
    block: BlockNumber,
}

impl Drop for PageLockPermit<'_> {
    fn drop(&mut self) {
        let mut in_flight = self.shard.in_flight.lock();
        let removed = in_flight.remove(self.block);
        drop(in_flight);
        if removed && self.shard.waiters.load(Ordering::Acquire) > 0 {
            self.shard.ready.notify_all();
        }
    }
}

#[inline]
fn mix_block_number(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "s3fifo", allow(dead_code))]
enum ArcList {
    T1,
    T2,
    B1,
    B2,
}

#[cfg(feature = "s3fifo")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct S3GhostEntry {
    key: BlockNumber,
    generation: u64,
}

#[cfg(feature = "s3fifo")]
type GhostQueueEntry = S3GhostEntry;

#[cfg(not(feature = "s3fifo"))]
type GhostQueueEntry = BlockNumber;

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
    data: BlockBuf,
    txn_id: TxnId,
    commit_seq: CommitSeq,
    /// Internal dirty-tracker sequence number at the time this candidate was captured.
    seq: u64,
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

    fn clear_dirty(&mut self, block: BlockNumber, seq: u64) {
        if let Some(entry) = self.by_block.get(&block).copied() {
            if entry.seq == seq {
                self.by_block.remove(&block);
                let _ = self.by_age.remove(&(entry.seq, block));
                self.dirty_bytes = self.dirty_bytes.saturating_sub(entry.bytes);
            }
        }
    }

    fn clear_dirty_unconditional(&mut self, block: BlockNumber) {
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

    fn flushable_count(&self) -> usize {
        let (_, committed) = self.state_counts();
        committed
    }
}

#[cfg(feature = "s3fifo")]
const S3_FAST_HIT_MAX_SLOTS: usize = 4096;

#[cfg(feature = "s3fifo")]
const S3_THREAD_FAST_HIT_SLOTS: usize = 256;

#[cfg(feature = "s3fifo")]
static S3_FAST_CACHE_IDS: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "s3fifo")]
thread_local! {
    static S3_THREAD_FAST_RESIDENTS: RefCell<S3ThreadFastResidentSlab> =
        RefCell::new(S3ThreadFastResidentSlab::new());
}

#[cfg(feature = "s3fifo")]
fn next_s3_fast_cache_id() -> u64 {
    S3_FAST_CACHE_IDS.fetch_add(1, Ordering::Relaxed)
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3AccessHandle {
    count: AtomicU8,
    valid: AtomicBool,
}

#[cfg(feature = "s3fifo")]
impl S3AccessHandle {
    fn new(count: u8) -> Arc<Self> {
        Arc::new(Self {
            count: AtomicU8::new(count),
            valid: AtomicBool::new(true),
        })
    }

    fn load_count(&self) -> u8 {
        self.count.load(Ordering::Relaxed)
    }

    fn store_count(&self, count: u8) {
        self.count.store(count, Ordering::Relaxed);
    }

    fn increment_count(&self) -> u8 {
        let mut current = self.count.load(Ordering::Relaxed);
        loop {
            if current == u8::MAX {
                return current;
            }
            let next = current.saturating_add(1);
            match self.count.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }

    fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
    }

    fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }
}

#[cfg(feature = "s3fifo")]
#[derive(Debug, Clone)]
struct S3FastResident {
    data: BlockBuf,
    access: Arc<S3AccessHandle>,
}

#[cfg(feature = "s3fifo")]
#[derive(Debug, Clone)]
struct S3ThreadFastResident {
    cache_id: u64,
    block: BlockNumber,
    epoch: u64,
    data: BlockBuf,
    access: Arc<S3AccessHandle>,
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3ThreadFastResidentSlab {
    slots: Vec<Option<S3ThreadFastResident>>,
}

#[cfg(feature = "s3fifo")]
impl S3ThreadFastResidentSlab {
    fn new() -> Self {
        Self {
            slots: vec![None; S3_THREAD_FAST_HIT_SLOTS],
        }
    }

    fn slot_index(block: BlockNumber) -> usize {
        let mask = u64::try_from(S3_THREAD_FAST_HIT_SLOTS - 1).unwrap_or(u64::MAX);
        usize::try_from(block.0 & mask).unwrap_or(0)
    }

    fn get_valid(
        &self,
        cache_id: u64,
        block: BlockNumber,
        epoch: u64,
    ) -> Option<(BlockBuf, Arc<S3AccessHandle>)> {
        let slot = Self::slot_index(block);
        self.slots[slot].as_ref().and_then(|entry| {
            (entry.cache_id == cache_id
                && entry.block == block
                && entry.epoch == epoch
                && entry.access.is_valid())
            .then(|| (entry.data.clone_ref(), Arc::clone(&entry.access)))
        })
    }

    fn insert(&mut self, cache_id: u64, block: BlockNumber, epoch: u64, resident: S3FastResident) {
        let slot = Self::slot_index(block);
        self.slots[slot] = Some(S3ThreadFastResident {
            cache_id,
            block,
            epoch,
            data: resident.data,
            access: resident.access,
        });
    }
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3FastResidentTable {
    slots: Vec<RwLock<Option<(BlockNumber, S3FastResident)>>>,
    slot_mask: u64,
}

#[cfg(feature = "s3fifo")]
impl S3FastResidentTable {
    fn for_capacity(capacity_blocks: usize) -> Self {
        let target_slots = capacity_blocks
            .saturating_mul(2)
            .clamp(1, S3_FAST_HIT_MAX_SLOTS);
        let slot_count = target_slots
            .checked_next_power_of_two()
            .unwrap_or(S3_FAST_HIT_MAX_SLOTS)
            .min(S3_FAST_HIT_MAX_SLOTS);
        Self::new(slot_count)
    }

    fn new(slot_count: usize) -> Self {
        let slot_count = slot_count.max(1).next_power_of_two();
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            slots.push(RwLock::new(None));
        }
        let slot_mask = u64::try_from(slot_count - 1).unwrap_or(u64::MAX);
        Self { slots, slot_mask }
    }

    fn slot_index(&self, block: BlockNumber) -> usize {
        usize::try_from(block.0 & self.slot_mask).unwrap_or(0)
    }

    fn get_valid(&self, block: BlockNumber) -> Option<S3FastResident> {
        let slot = &self.slots[self.slot_index(block)];
        let guard = slot.read();
        let entry = guard.as_ref().and_then(|(resident_block, entry)| {
            (*resident_block == block && entry.access.is_valid()).then(|| entry.clone())
        });
        drop(guard);
        entry
    }

    fn insert(&self, block: BlockNumber, entry: S3FastResident) {
        let slot = &self.slots[self.slot_index(block)];
        *slot.write() = Some((block, entry));
    }

    fn remove(&self, block: BlockNumber) {
        let slot = &self.slots[self.slot_index(block)];
        let mut guard = slot.write();
        if let Some((resident_block, entry)) = guard.take() {
            if resident_block == block {
                entry.access.invalidate();
            } else {
                *guard = Some((resident_block, entry));
            }
        }
    }
}

#[cfg(feature = "s3fifo")]
#[repr(align(64))]
#[derive(Debug)]
struct S3FastHitStripe {
    hits: AtomicU64,
}

#[cfg(feature = "s3fifo")]
impl S3FastHitStripe {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
        }
    }
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3FastHitCounter {
    stripes: Vec<S3FastHitStripe>,
    stripe_mask: u64,
}

#[cfg(feature = "s3fifo")]
impl S3FastHitCounter {
    fn for_capacity(capacity_blocks: usize) -> Self {
        let target_stripes = capacity_blocks
            .saturating_mul(2)
            .clamp(1, S3_FAST_HIT_MAX_SLOTS);
        let stripe_count = target_stripes
            .checked_next_power_of_two()
            .unwrap_or(S3_FAST_HIT_MAX_SLOTS)
            .min(S3_FAST_HIT_MAX_SLOTS);
        Self::new(stripe_count)
    }

    fn new(stripe_count: usize) -> Self {
        let stripe_count = stripe_count.max(1).next_power_of_two();
        let mut stripes = Vec::with_capacity(stripe_count);
        for _ in 0..stripe_count {
            stripes.push(S3FastHitStripe::new());
        }
        let stripe_mask = u64::try_from(stripe_count - 1).unwrap_or(u64::MAX);
        Self {
            stripes,
            stripe_mask,
        }
    }

    fn stripe_index(&self, block: BlockNumber) -> usize {
        usize::try_from(block.0 & self.stripe_mask).unwrap_or(0)
    }

    fn increment(&self, block: BlockNumber) {
        self.stripes[self.stripe_index(block)]
            .hits
            .fetch_add(1, Ordering::Relaxed);
    }

    fn total(&self, ordering: Ordering) -> u64 {
        self.stripes.iter().fold(0_u64, |total, stripe| {
            total.saturating_add(stripe.hits.load(ordering))
        })
    }
}

#[cfg(feature = "s3fifo")]
#[derive(Debug)]
struct S3FastMutationGuard<'a> {
    active: &'a AtomicUsize,
    epoch: &'a AtomicU64,
}

#[cfg(feature = "s3fifo")]
impl Drop for S3FastMutationGuard<'_> {
    fn drop(&mut self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.active.fetch_sub(1, Ordering::Release);
    }
}

#[derive(Debug)]
struct ArcState {
    /// Active target capacity in blocks (may be reduced under pressure).
    capacity: usize,
    /// Nominal maximum capacity configured at cache creation.
    max_capacity: usize,
    /// Last applied memory pressure level.
    pressure_level: MemoryPressure,
    /// Target size for the T1 list.
    #[cfg(not(feature = "s3fifo"))]
    p: usize,
    t1: VecDeque<BlockNumber>,
    t2: VecDeque<BlockNumber>,
    b1: VecDeque<GhostQueueEntry>,
    b2: VecDeque<GhostQueueEntry>,
    #[cfg(feature = "s3fifo")]
    b1_live_len: usize,
    #[cfg(feature = "s3fifo")]
    b2_live_len: usize,
    #[cfg(feature = "s3fifo")]
    ghost_generations: HashMap<BlockNumber, u64>,
    #[cfg(feature = "s3fifo")]
    next_ghost_generation: u64,
    loc: HashMap<BlockNumber, ArcList>,
    resident: HashMap<BlockNumber, BlockBuf>,
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
    /// Monotonic B1 ghost hit counter (re-admissions from T1 ghost list).
    b1_ghost_hits: u64,
    /// Monotonic B2 ghost hit counter (re-admissions from T2 ghost list).
    b2_ghost_hits: u64,
    #[cfg(feature = "s3fifo")]
    small_capacity: usize,
    #[cfg(feature = "s3fifo")]
    main_capacity: usize,
    #[cfg(feature = "s3fifo")]
    ghost_capacity: usize,
    #[cfg(feature = "s3fifo")]
    last_read_miss: Option<BlockNumber>,
    #[cfg(feature = "s3fifo")]
    sequential_read_miss_streak: u8,
    #[cfg(feature = "s3fifo")]
    access_count: HashMap<BlockNumber, Arc<S3AccessHandle>>,
    #[cfg(feature = "s3fifo")]
    fast_invalidations: Vec<BlockNumber>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PressureEvictionBatch {
    evicted_blocks: usize,
    evicted_bytes: usize,
}

impl ArcState {
    #[cfg(feature = "s3fifo")]
    fn s3_capacity_split(capacity: usize) -> (usize, usize, usize) {
        let (small_capacity, main_capacity) = if capacity <= 1 {
            (1, 0)
        } else if capacity <= 4 {
            // Tiny caches need relaxed split targets; otherwise S3-FIFO
            // under-fills and violates generic cache warm-up expectations.
            (capacity, capacity)
        } else {
            let small = (capacity / 10).max(1).min(capacity - 1);
            let main = capacity.saturating_sub(small);
            (small, main)
        };
        let ghost_capacity = capacity.max(1);
        (small_capacity, main_capacity, ghost_capacity)
    }

    fn new(capacity: usize) -> Self {
        #[cfg(feature = "s3fifo")]
        let (small_capacity, main_capacity, ghost_capacity) = Self::s3_capacity_split(capacity);
        Self {
            capacity,
            max_capacity: capacity,
            pressure_level: MemoryPressure::None,
            #[cfg(not(feature = "s3fifo"))]
            p: 0,
            t1: VecDeque::new(),
            t2: VecDeque::new(),
            b1: VecDeque::new(),
            b2: VecDeque::new(),
            #[cfg(feature = "s3fifo")]
            b1_live_len: 0,
            #[cfg(feature = "s3fifo")]
            b2_live_len: 0,
            #[cfg(feature = "s3fifo")]
            ghost_generations: HashMap::new(),
            #[cfg(feature = "s3fifo")]
            next_ghost_generation: 1,
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
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
            #[cfg(feature = "s3fifo")]
            small_capacity,
            #[cfg(feature = "s3fifo")]
            main_capacity,
            #[cfg(feature = "s3fifo")]
            ghost_capacity,
            #[cfg(feature = "s3fifo")]
            last_read_miss: None,
            #[cfg(feature = "s3fifo")]
            sequential_read_miss_streak: 0,
            #[cfg(feature = "s3fifo")]
            access_count: HashMap::new(),
            #[cfg(feature = "s3fifo")]
            fast_invalidations: Vec::new(),
        }
    }

    fn increment_counter(counter: &mut u64) {
        *counter = counter.saturating_add(1);
    }

    fn add_usize_to_counter(counter: &mut u64, delta: usize) {
        let delta = u64::try_from(delta).unwrap_or(u64::MAX);
        *counter = counter.saturating_add(delta);
    }

    #[cfg(feature = "s3fifo")]
    fn s3_access_handle(&mut self, key: BlockNumber, initial_count: u8) -> Arc<S3AccessHandle> {
        self.access_count
            .entry(key)
            .or_insert_with(|| S3AccessHandle::new(initial_count))
            .clone()
    }

    #[cfg(feature = "s3fifo")]
    fn s3_access_count(&self, key: BlockNumber) -> u8 {
        self.access_count
            .get(&key)
            .map_or(0, |handle| handle.load_count())
    }

    #[cfg(feature = "s3fifo")]
    fn take_fast_invalidations(&mut self) -> Vec<BlockNumber> {
        std::mem::take(&mut self.fast_invalidations)
    }

    fn resident_len(&self) -> usize {
        self.t1.len() + self.t2.len()
    }

    fn b1_len(&self) -> usize {
        #[cfg(feature = "s3fifo")]
        {
            self.b1_live_len
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.b1.len()
        }
    }

    fn b2_len(&self) -> usize {
        #[cfg(feature = "s3fifo")]
        {
            self.b2_live_len
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.b2.len()
        }
    }

    #[cfg(not(feature = "s3fifo"))]
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
            b1_len: self.b1_len(),
            b2_len: self.b2_len(),
            resident: self.resident_len(),
            dirty_blocks: self.dirty.dirty_count(),
            dirty_bytes: self.dirty.dirty_bytes(),
            writeback_queue_depth: self.dirty.flushable_count(),
            oldest_dirty_age_ticks: self.dirty.oldest_dirty_age_ticks(),
            capacity: self.capacity,
            p: {
                #[cfg(feature = "s3fifo")]
                {
                    0
                }
                #[cfg(not(feature = "s3fifo"))]
                {
                    self.p
                }
            },
            b1_ghost_hits: self.b1_ghost_hits,
            b2_ghost_hits: self.b2_ghost_hits,
        }
    }

    fn pressure_report(&self) -> CachePressureReport {
        let total_accesses = self.hits.saturating_add(self.misses);
        let eviction_rate = if total_accesses == 0 {
            0.0
        } else {
            self.evictions as f64 / total_accesses as f64
        };
        CachePressureReport {
            current_size: self.resident_len(),
            target_size: self.capacity,
            dirty_count: self.dirty.dirty_count(),
            eviction_rate,
        }
    }

    fn set_pressure_level(&mut self, pressure: MemoryPressure) {
        self.pressure_level = pressure;
        let target = pressure.target_capacity(self.max_capacity);
        self.set_target_capacity(target);
    }

    fn restore_target_capacity(&mut self) {
        self.set_target_capacity(self.max_capacity);
    }

    fn set_target_capacity(&mut self, target: usize) {
        self.capacity = target.clamp(1, self.max_capacity);
    }

    fn trim_to_capacity(&mut self) -> PressureEvictionBatch {
        let mut batch = PressureEvictionBatch::default();
        while self.resident_len() > self.capacity {
            let Some(victim) = self.next_pressure_victim() else {
                // All candidates are dirty; keep data durable and stop shrinking.
                break;
            };
            let from_t1 = Self::remove_from_list(&mut self.t1, victim);
            let from_t2 = if from_t1 {
                false
            } else {
                Self::remove_from_list(&mut self.t2, victim)
            };
            if !from_t1 && !from_t2 {
                let _ = self.loc.remove(&victim);
                continue;
            }
            let freed_bytes = self.resident.get(&victim).map_or(0, BlockBuf::len);
            if self.evict_resident(victim) {
                self.push_ghost(victim, if from_t1 { ArcList::B1 } else { ArcList::B2 });
                self.evictions = self.evictions.saturating_add(1);
                batch.evicted_blocks = batch.evicted_blocks.saturating_add(1);
                batch.evicted_bytes = batch.evicted_bytes.saturating_add(freed_bytes);
            } else {
                if from_t1 {
                    self.t1.push_back(victim);
                    self.loc.insert(victim, ArcList::T1);
                } else {
                    self.t2.push_back(victim);
                    self.loc.insert(victim, ArcList::T2);
                }
                // Dirty races are tolerated; stop shrinking until flush catches up.
                break;
            }
        }
        self.trim_ghosts_to(self.capacity);
        batch
    }

    fn next_pressure_victim(&self) -> Option<BlockNumber> {
        self.t1
            .iter()
            .copied()
            .find(|block| !self.is_dirty(*block))
            .or_else(|| self.t2.iter().copied().find(|block| !self.is_dirty(*block)))
    }

    fn remove_from_list(list: &mut VecDeque<BlockNumber>, key: BlockNumber) -> bool {
        if let Some(pos) = list.iter().position(|k| *k == key) {
            let _ = list.remove(pos);
            return true;
        }
        false
    }

    #[cfg(feature = "s3fifo")]
    fn live_ghost_entry(&self, entry: S3GhostEntry, list: ArcList) -> bool {
        matches!(self.loc.get(&entry.key), Some(current) if *current == list)
            && self
                .ghost_generations
                .get(&entry.key)
                .is_some_and(|generation| *generation == entry.generation)
    }

    #[cfg(feature = "s3fifo")]
    fn should_compact_ghost_queue(physical_len: usize, live_len: usize, capacity: usize) -> bool {
        let stale_len = physical_len.saturating_sub(live_len);
        stale_len > capacity / 2 && physical_len > live_len.saturating_mul(2)
    }

    #[cfg(feature = "s3fifo")]
    fn compact_b1_ghosts(&mut self) {
        let old = std::mem::take(&mut self.b1);
        let mut compact = VecDeque::with_capacity(self.b1_live_len);
        let mut live_len = 0_usize;
        for entry in old {
            if self.live_ghost_entry(entry, ArcList::B1) {
                compact.push_back(entry);
                live_len = live_len.saturating_add(1);
            }
        }
        self.b1 = compact;
        self.b1_live_len = live_len;
    }

    #[cfg(feature = "s3fifo")]
    fn compact_b2_ghosts(&mut self) {
        let old = std::mem::take(&mut self.b2);
        let mut compact = VecDeque::with_capacity(self.b2_live_len);
        let mut live_len = 0_usize;
        for entry in old {
            if self.live_ghost_entry(entry, ArcList::B2) {
                compact.push_back(entry);
                live_len = live_len.saturating_add(1);
            }
        }
        self.b2 = compact;
        self.b2_live_len = live_len;
    }

    #[cfg(feature = "s3fifo")]
    fn compact_ghosts_if_sparse(&mut self, list: ArcList) {
        match list {
            ArcList::B1
                if Self::should_compact_ghost_queue(
                    self.b1.len(),
                    self.b1_live_len,
                    self.ghost_capacity,
                ) =>
            {
                self.compact_b1_ghosts();
            }
            ArcList::B2
                if Self::should_compact_ghost_queue(
                    self.b2.len(),
                    self.b2_live_len,
                    self.ghost_capacity,
                ) =>
            {
                self.compact_b2_ghosts();
            }
            ArcList::T1 | ArcList::T2 | ArcList::B1 | ArcList::B2 => {}
        }
    }

    #[cfg(feature = "s3fifo")]
    fn next_ghost_entry(&mut self, key: BlockNumber) -> S3GhostEntry {
        let generation = self.next_ghost_generation;
        self.next_ghost_generation = self.next_ghost_generation.saturating_add(1);
        let _ = self.ghost_generations.insert(key, generation);
        S3GhostEntry { key, generation }
    }

    #[cfg(all(feature = "s3fifo", test))]
    fn b1_live_keys(&self) -> impl Iterator<Item = BlockNumber> + '_ {
        self.b1
            .iter()
            .copied()
            .filter(|entry| self.live_ghost_entry(*entry, ArcList::B1))
            .map(|entry| entry.key)
    }

    #[cfg(all(feature = "s3fifo", test))]
    fn b2_live_keys(&self) -> impl Iterator<Item = BlockNumber> + '_ {
        self.b2
            .iter()
            .copied()
            .filter(|entry| self.live_ghost_entry(*entry, ArcList::B2))
            .map(|entry| entry.key)
    }

    #[cfg(all(feature = "s3fifo", test))]
    fn b1_front_live(&self) -> Option<BlockNumber> {
        self.b1_live_keys().next()
    }

    #[cfg(all(feature = "s3fifo", test))]
    fn b1_contains_live(&self, key: BlockNumber) -> bool {
        self.b1_live_keys().any(|entry| entry == key)
    }

    fn push_ghost(&mut self, key: BlockNumber, list: ArcList) {
        match list {
            ArcList::B1 => {
                #[cfg(feature = "s3fifo")]
                {
                    let _ = self.remove_live_ghost(key);
                    let entry = self.next_ghost_entry(key);
                    self.b1.push_back(entry);
                    self.b1_live_len = self.b1_live_len.saturating_add(1);
                }
                #[cfg(not(feature = "s3fifo"))]
                {
                    self.b1.push_back(key);
                }
                self.loc.insert(key, ArcList::B1);
            }
            ArcList::B2 => {
                #[cfg(feature = "s3fifo")]
                {
                    let _ = self.remove_live_ghost(key);
                    let entry = self.next_ghost_entry(key);
                    self.b2.push_back(entry);
                    self.b2_live_len = self.b2_live_len.saturating_add(1);
                }
                #[cfg(not(feature = "s3fifo"))]
                {
                    self.b2.push_back(key);
                }
                self.loc.insert(key, ArcList::B2);
            }
            ArcList::T1 | ArcList::T2 => {}
        }
    }

    #[cfg(feature = "s3fifo")]
    fn remove_live_ghost(&mut self, key: BlockNumber) -> bool {
        match self.loc.get(&key).copied() {
            Some(ArcList::B1) => {
                self.b1_live_len = self.b1_live_len.saturating_sub(1);
                let _ = self.ghost_generations.remove(&key);
                let _ = self.loc.remove(&key);
                self.compact_ghosts_if_sparse(ArcList::B1);
                true
            }
            Some(ArcList::B2) => {
                self.b2_live_len = self.b2_live_len.saturating_sub(1);
                let _ = self.ghost_generations.remove(&key);
                let _ = self.loc.remove(&key);
                self.compact_ghosts_if_sparse(ArcList::B2);
                true
            }
            Some(ArcList::T1 | ArcList::T2) | None => false,
        }
    }

    fn pop_b1_front(&mut self) -> Option<BlockNumber> {
        #[cfg(feature = "s3fifo")]
        {
            while let Some(victim) = self.b1.pop_front() {
                if self.live_ghost_entry(victim, ArcList::B1) {
                    self.b1_live_len = self.b1_live_len.saturating_sub(1);
                    let _ = self.ghost_generations.remove(&victim.key);
                    let _ = self.loc.remove(&victim.key);
                    return Some(victim.key);
                }
            }
            self.b1_live_len = 0;
            None
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.b1.pop_front().inspect(|victim| {
                let _ = self.loc.remove(victim);
            })
        }
    }

    fn pop_b2_front(&mut self) -> Option<BlockNumber> {
        #[cfg(feature = "s3fifo")]
        {
            while let Some(victim) = self.b2.pop_front() {
                if self.live_ghost_entry(victim, ArcList::B2) {
                    self.b2_live_len = self.b2_live_len.saturating_sub(1);
                    let _ = self.ghost_generations.remove(&victim.key);
                    let _ = self.loc.remove(&victim.key);
                    return Some(victim.key);
                }
            }
            self.b2_live_len = 0;
            None
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.b2.pop_front().inspect(|victim| {
                let _ = self.loc.remove(victim);
            })
        }
    }

    fn trim_ghosts_to(&mut self, capacity: usize) {
        while self.b1_len() > capacity {
            let _ = self.pop_b1_front();
        }
        while self.b2_len() > capacity {
            let _ = self.pop_b2_front();
        }
    }

    fn remove_ghost_block(&mut self, key: BlockNumber) -> bool {
        #[cfg(feature = "s3fifo")]
        {
            self.remove_live_ghost(key)
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            let removed = Self::remove_from_list(&mut self.b1, key)
                | Self::remove_from_list(&mut self.b2, key);
            if removed {
                let _ = self.loc.remove(&key);
            }
            removed
        }
    }

    fn evict_resident(&mut self, victim: BlockNumber) -> bool {
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
            return false;
        }
        let _ = self.resident.remove(&victim);
        #[cfg(feature = "s3fifo")]
        {
            if let Some(handle) = self.access_count.remove(&victim) {
                handle.invalidate();
                self.fast_invalidations.push(victim);
            }
        }
        self.clear_dirty_unconditional(victim);
        trace!(event = "cache_evict_clean", block = victim.0);
        true
    }

    #[cfg(not(feature = "s3fifo"))]
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

    #[cfg(not(feature = "s3fifo"))]
    fn replace(&mut self, incoming: BlockNumber) {
        // `replace()` is only meaningful when the resident set is full.
        // Guard against accidental calls during warm-up, which would cause
        // premature eviction and underutilize the cache.
        if self.resident_len() < self.capacity {
            return;
        }

        let t1_len = self.t1.len();
        let target_t1 = t1_len >= 1
            && (t1_len > self.p
                || (matches!(self.loc.get(&incoming), Some(ArcList::B2)) && t1_len == self.p));

        let mut victim = None;
        let mut from_t1 = target_t1;

        if from_t1 {
            if let Some(pos) = self.t1.iter().position(|b| !self.is_dirty(*b)) {
                victim = self.t1.remove(pos);
            } else if let Some(pos) = self.t2.iter().position(|b| !self.is_dirty(*b)) {
                victim = self.t2.remove(pos);
                from_t1 = false;
            }
        } else {
            if let Some(pos) = self.t2.iter().position(|b| !self.is_dirty(*b)) {
                victim = self.t2.remove(pos);
            } else if let Some(pos) = self.t1.iter().position(|b| !self.is_dirty(*b)) {
                victim = self.t1.remove(pos);
                from_t1 = true;
            }
        }

        if let Some(victim) = victim {
            if self.evict_resident(victim) {
                if from_t1 {
                    self.loc.insert(victim, ArcList::B1);
                    self.b1.push_back(victim);
                } else {
                    self.loc.insert(victim, ArcList::B2);
                    self.b2.push_back(victim);
                }
                Self::increment_counter(&mut self.evictions);
            } else if from_t1 {
                self.t1.push_back(victim);
                self.loc.insert(victim, ArcList::T1);
            } else {
                self.t2.push_back(victim);
                self.loc.insert(victim, ArcList::T2);
            }
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
        Self::increment_counter(&mut self.hits);
        #[cfg(feature = "s3fifo")]
        {
            self.s3_on_hit(key);
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.touch_mru(key);
        }
    }

    fn on_miss_or_ghost_hit(&mut self, key: BlockNumber) {
        Self::increment_counter(&mut self.misses);
        #[cfg(feature = "s3fifo")]
        {
            self.s3_on_miss_or_ghost_hit(key);
        }
        #[cfg(not(feature = "s3fifo"))]
        {
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
                Self::increment_counter(&mut self.b1_ghost_hits);
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
                Self::increment_counter(&mut self.b2_ghost_hits);
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
                    if self.evict_resident(victim) {
                        let _ = self.loc.remove(&victim);
                        Self::increment_counter(&mut self.evictions);
                    } else {
                        self.t1.push_front(victim);
                        self.loc.insert(victim, ArcList::T1);
                    }
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
    }

    #[cfg(feature = "s3fifo")]
    fn on_read_miss_or_scan_bypass(&mut self, key: BlockNumber) -> bool {
        Self::increment_counter(&mut self.misses);

        let is_sequential = self
            .last_read_miss
            .is_some_and(|previous| previous.0.wrapping_add(1) == key.0);
        self.last_read_miss = Some(key);
        if is_sequential {
            self.sequential_read_miss_streak = self.sequential_read_miss_streak.saturating_add(1);
        } else {
            self.sequential_read_miss_streak = 0;
        }

        let has_cache_history = self.loc.contains_key(&key);
        let bypass = self.sequential_read_miss_streak >= 2 && !has_cache_history;
        if bypass {
            self.push_ghost(key, ArcList::B1);
            self.trim_ghosts_to(self.ghost_capacity);
            trace!(
                target: "ffs::block::s3fifo",
                event = "admission_decision",
                block = key.0,
                reason = "sequential_scan_ghost_only",
                sequential_read_miss_streak = self.sequential_read_miss_streak,
                small_len = self.t1.len(),
                main_len = self.t2.len(),
                ghost_len = self.b1_len()
            );
            self.s3_emit_summary_if_due();
            true
        } else {
            self.s3_on_miss_or_ghost_hit(key);
            false
        }
    }

    #[cfg(not(feature = "s3fifo"))]
    fn on_read_miss_or_scan_bypass(&mut self, key: BlockNumber) -> bool {
        self.on_miss_or_ghost_hit(key);
        false
    }

    #[cfg(feature = "s3fifo")]
    fn s3_on_hit(&mut self, key: BlockNumber) {
        let list = self.loc.get(&key).copied();
        match list {
            Some(ArcList::T1) => {
                // Keep large-cache hit path O(1): defer T1->T2 promotion until
                // queue rebalance when the small queue overflows.
                if self.small_capacity <= 32 {
                    let _ = Self::remove_from_list(&mut self.t1, key);
                    self.t2.push_back(key);
                    self.loc.insert(key, ArcList::T2);
                }
            }
            Some(ArcList::T2) => {}
            Some(ArcList::B1 | ArcList::B2) => {
                warn!(
                    target: "ffs::block::s3fifo",
                    event = "invariant_recovery",
                    block = key.0,
                    queue = "resident",
                    detail = "hit observed for ghost location; repairing to resident queue"
                );
                let _ = self.remove_live_ghost(key);
                let _ = Self::remove_from_list(&mut self.t1, key);
                let _ = Self::remove_from_list(&mut self.t2, key);
                self.t1.push_back(key);
                self.loc.insert(key, ArcList::T1);
            }
            None => {
                warn!(
                    target: "ffs::block::s3fifo",
                    event = "invariant_recovery",
                    block = key.0,
                    queue = "resident",
                    detail = "hit observed without location metadata; repairing to resident queue"
                );
                let _ = Self::remove_from_list(&mut self.t1, key);
                let _ = Self::remove_from_list(&mut self.t2, key);
                let _ = self.remove_live_ghost(key);
                self.t1.push_back(key);
                self.loc.insert(key, ArcList::T1);
            }
        }
        let access_count = self.s3_access_handle(key, 0).increment_count();
        trace!(
            target: "ffs::block::s3fifo",
            event = "queue_transition",
            block = key.0,
            from_queue = "resident",
            to_queue = "resident",
            access_count,
            small_len = self.t1.len(),
            main_len = self.t2.len(),
            ghost_len = self.b1_len()
        );
        self.s3_emit_summary_if_due();
    }

    #[cfg(feature = "s3fifo")]
    fn s3_on_miss_or_ghost_hit(&mut self, key: BlockNumber) {
        // Defensive: callers use `resident.contains_key()` to decide hit vs miss.
        // If we ever see a "miss" for a resident key, we have stale queue metadata.
        // Repair metadata and continue through miss admission.
        if matches!(self.loc.get(&key), Some(ArcList::T1 | ArcList::T2)) {
            warn!(
                target: "ffs::block::s3fifo",
                event = "invariant_recovery",
                block = key.0,
                queue = "resident",
                detail = "miss observed for resident metadata without payload; dropping stale resident metadata"
            );
            let _ = Self::remove_from_list(&mut self.t1, key);
            let _ = Self::remove_from_list(&mut self.t2, key);
            let _ = self.loc.remove(&key);
            if let Some(handle) = self.access_count.remove(&key) {
                handle.invalidate();
                self.fast_invalidations.push(key);
            }
        }

        let ghost_hit = matches!(self.loc.get(&key), Some(ArcList::B1 | ArcList::B2));
        if ghost_hit {
            let _ = self.remove_live_ghost(key);
            self.loc.insert(key, ArcList::T2);
            self.t2.push_back(key);
            let _ = self.access_count.insert(key, S3AccessHandle::new(1));
            debug!(
                target: "ffs::block::s3fifo",
                event = "admission_decision",
                block = key.0,
                reason = "ghost_hit_readmit_main",
                policy_state = "s3fifo",
                capacity_state = %format!(
                    "small={}/{},main={}/{},ghost={}/{}",
                    self.t1.len(),
                    self.small_capacity,
                    self.t2.len(),
                    self.main_capacity,
                    self.b1_len(),
                    self.ghost_capacity
                )
            );
            trace!(
                target: "ffs::block::s3fifo",
                event = "queue_transition",
                block = key.0,
                from_queue = "ghost",
                to_queue = "main",
                access_count = 1_u8,
                small_len = self.t1.len(),
                main_len = self.t2.len(),
                ghost_len = self.b1_len()
            );
        } else {
            self.loc.insert(key, ArcList::T1);
            self.t1.push_back(key);
            let _ = self.access_count.insert(key, S3AccessHandle::new(0));
            debug!(
                target: "ffs::block::s3fifo",
                event = "admission_decision",
                block = key.0,
                reason = "new_admit_small",
                policy_state = "s3fifo",
                capacity_state = %format!(
                    "small={}/{},main={}/{},ghost={}/{}",
                    self.t1.len(),
                    self.small_capacity,
                    self.t2.len(),
                    self.main_capacity,
                    self.b1_len(),
                    self.ghost_capacity
                )
            );
            trace!(
                target: "ffs::block::s3fifo",
                event = "queue_transition",
                block = key.0,
                from_queue = "none",
                to_queue = "small",
                access_count = 0_u8,
                small_len = self.t1.len(),
                main_len = self.t2.len(),
                ghost_len = self.b1_len()
            );
        }

        self.s3_rebalance_queues(Some(key));
        self.s3_emit_summary_if_due();
    }

    #[cfg(feature = "s3fifo")]
    #[allow(clippy::too_many_lines)]
    fn s3_rebalance_queues(&mut self, block_hint: Option<BlockNumber>) {
        let pending_admission = block_hint.filter(|block| !self.resident.contains_key(block));

        let mut t1_attempts = self.t1.len().saturating_mul(2).max(1);
        while self.t1.len() > self.small_capacity && t1_attempts > 0 {
            t1_attempts -= 1;
            let Some(victim) = self.t1.pop_front() else {
                break;
            };
            if Some(victim) == pending_admission {
                self.t1.push_back(victim);
                continue;
            }
            if self.is_dirty(victim) {
                self.t1.push_back(victim);
                continue;
            }
            let access_count = self.s3_access_count(victim);
            if access_count > 0 {
                self.loc.insert(victim, ArcList::T2);
                self.t2.push_back(victim);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "queue_transition",
                    block = victim.0,
                    from_queue = "small",
                    to_queue = "main",
                    access_count,
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
            } else if self.evict_resident(victim) {
                self.push_ghost(victim, ArcList::B1);
                self.evictions = self.evictions.saturating_add(1);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "victim_selection",
                    block = victim.0,
                    from_queue = "small",
                    to_queue = "ghost",
                    access_count,
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
            } else {
                self.t1.push_back(victim);
                self.loc.insert(victim, ArcList::T1);
            }
        }

        let mut t2_attempts = self.t2.len().max(1);
        while self.t2.len() > self.main_capacity && t2_attempts > 0 {
            t2_attempts -= 1;
            let Some(victim) = self.t2.pop_front() else {
                break;
            };
            if Some(victim) == pending_admission {
                self.t2.push_back(victim);
                continue;
            }
            if self.is_dirty(victim) {
                self.t2.push_back(victim);
                continue;
            }
            let access_count = self.s3_access_count(victim);
            if access_count > 0 {
                let next_count = access_count.saturating_sub(1);
                if let Some(handle) = self.access_count.get(&victim) {
                    handle.store_count(next_count);
                }
                self.t2.push_back(victim);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "second_chance_rotation",
                    block = victim.0,
                    from_queue = "main",
                    to_queue = "main",
                    access_count = next_count,
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
                continue;
            }

            if self.evict_resident(victim) {
                self.push_ghost(victim, ArcList::B1);
                self.evictions = self.evictions.saturating_add(1);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "victim_selection",
                    block = victim.0,
                    from_queue = "main",
                    to_queue = "ghost",
                    access_count,
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
            } else {
                self.t2.push_back(victim);
                self.loc.insert(victim, ArcList::T2);
            }
        }

        while self.b1_len() > self.ghost_capacity {
            let overflow_by = self.b1_len().saturating_sub(self.ghost_capacity);
            if let Some(victim) = self.pop_b1_front() {
                warn!(
                    target: "ffs::block::s3fifo",
                    event = "ghost_overflow_recovery",
                    block = victim.0,
                    queue = "ghost",
                    overflow_by,
                    "ghost queue exceeded capacity and oldest key was dropped"
                );
            }
        }

        // If second-chance rotation still left us above target, force clean evictions.
        let mut emergency_attempts = self.t1.len().saturating_add(self.t2.len());
        while self.resident_len() > self.capacity && emergency_attempts > 0 {
            emergency_attempts -= 1;
            let t1_pos = self.t1.iter().position(|candidate| {
                Some(*candidate) != pending_admission && !self.is_dirty(*candidate)
            });
            let (victim, from_t1) = if let Some(pos) = t1_pos {
                (self.t1.remove(pos), true)
            } else {
                let t2_pos = self.t2.iter().position(|candidate| {
                    Some(*candidate) != pending_admission && !self.is_dirty(*candidate)
                });
                (t2_pos.and_then(|pos| self.t2.remove(pos)), false)
            };
            let Some(victim) = victim else {
                break;
            };
            if self.evict_resident(victim) {
                self.push_ghost(victim, ArcList::B1);
                self.evictions = self.evictions.saturating_add(1);
                trace!(
                    target: "ffs::block::s3fifo",
                    event = "pressure_fallback_evict",
                    block = victim.0,
                    from_queue = if from_t1 { "small" } else { "main" },
                    to_queue = "ghost",
                    small_len = self.t1.len(),
                    main_len = self.t2.len(),
                    ghost_len = self.b1_len()
                );
            } else if from_t1 {
                self.t1.push_back(victim);
                self.loc.insert(victim, ArcList::T1);
            } else {
                self.t2.push_back(victim);
                self.loc.insert(victim, ArcList::T2);
            }
        }

        if self.resident_len() > self.capacity {
            let repaired_entries = self.s3_reconcile_resident_queues(pending_admission);
            if repaired_entries > 0 {
                warn!(
                    target: "ffs::block::s3fifo",
                    event = "invariant_recovery",
                    repaired_entries,
                    detail = "dropped stale or duplicate resident queue metadata"
                );
            }

            let has_clean_candidate = self
                .t1
                .iter()
                .chain(self.t2.iter())
                .copied()
                .any(|candidate| Some(candidate) != pending_admission && !self.is_dirty(candidate));
            if !has_clean_candidate {
                debug!(
                    target: "ffs::block::s3fifo",
                    event = "overflow_tolerated_dirty",
                    resident = self.resident_len(),
                    capacity = self.capacity
                );
                return;
            }

            // Last-resort forced clean eviction. Keep process alive while preserving data.
            while self.resident_len() > self.capacity {
                let Some(victim) =
                    self.t1
                        .iter()
                        .chain(self.t2.iter())
                        .copied()
                        .find(|candidate| {
                            Some(*candidate) != pending_admission && !self.is_dirty(*candidate)
                        })
                else {
                    break;
                };
                let from_t1 = Self::remove_from_list(&mut self.t1, victim);
                if !from_t1 {
                    let _ = Self::remove_from_list(&mut self.t2, victim);
                }
                if self.evict_resident(victim) {
                    self.push_ghost(victim, ArcList::B1);
                    self.evictions = self.evictions.saturating_add(1);
                } else if from_t1 {
                    self.t1.push_back(victim);
                    self.loc.insert(victim, ArcList::T1);
                    break;
                } else {
                    self.t2.push_back(victim);
                    self.loc.insert(victim, ArcList::T2);
                    break;
                }
            }

            if self.resident_len() > self.capacity {
                let block = block_hint.map_or(0_u64, |b| b.0);
                error!(
                    target: "ffs::block::s3fifo",
                    event = "invariant_violation",
                    block,
                    queue = "resident",
                    detail = "resident set exceeded configured capacity after all recoveries"
                );
            }
        }
    }

    #[cfg(feature = "s3fifo")]
    fn s3_reconcile_resident_queues(&mut self, pending_admission: Option<BlockNumber>) -> usize {
        let before = self.t1.len().saturating_add(self.t2.len());
        let mut resident_keys: HashSet<BlockNumber> = self.resident.keys().copied().collect();
        if let Some(block) = pending_admission {
            resident_keys.insert(block);
        }
        let mut seen = HashSet::with_capacity(resident_keys.len());

        self.t1
            .retain(|candidate| resident_keys.contains(candidate) && seen.insert(*candidate));
        self.t2
            .retain(|candidate| resident_keys.contains(candidate) && seen.insert(*candidate));
        let stale_access_keys: Vec<BlockNumber> = self
            .access_count
            .keys()
            .copied()
            .filter(|candidate| !resident_keys.contains(candidate))
            .collect();
        for key in stale_access_keys {
            if let Some(handle) = self.access_count.remove(&key) {
                handle.invalidate();
                self.fast_invalidations.push(key);
            }
        }

        let queue_loc_keys: Vec<BlockNumber> = self
            .loc
            .iter()
            .filter_map(|(key, list)| matches!(list, ArcList::T1 | ArcList::T2).then_some(*key))
            .collect();
        for key in queue_loc_keys {
            let _ = self.loc.remove(&key);
        }
        for &key in &self.t1 {
            self.loc.insert(key, ArcList::T1);
        }
        for &key in &self.t2 {
            self.loc.insert(key, ArcList::T2);
        }

        before.saturating_sub(self.resident_len())
    }

    #[cfg(feature = "s3fifo")]
    fn s3_emit_summary_if_due(&self) {
        let accesses = self.hits.saturating_add(self.misses);
        if accesses == 0 || accesses % 1024 != 0 {
            return;
        }
        info!(
            target: "ffs::block::s3fifo",
            event = "cache_summary",
            hits = self.hits,
            misses = self.misses,
            evictions = self.evictions,
            ghost_hits = self.b1_len(),
            occupancy = self.resident_len(),
            mode = "s3fifo"
        );
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
    fn clear_dirty(&mut self, block: BlockNumber, seq: u64) {
        self.dirty.clear_dirty(block, seq);
    }

    /// Clear the dirty flag for a block unconditionally.
    fn clear_dirty_unconditional(&mut self, block: BlockNumber) {
        self.dirty.clear_dirty_unconditional(block);
    }

    /// Check if a block is dirty.
    fn is_dirty(&self, block: BlockNumber) -> bool {
        self.dirty.is_dirty(block)
    }

    /// Return list of dirty blocks that need flushing.
    fn dirty_blocks(&self) -> Vec<BlockNumber> {
        self.dirty.dirty_blocks_oldest_first()
    }

    fn stage_txn_write(&mut self, txn_id: TxnId, block: BlockNumber, data: &[u8]) -> Result<()> {
        if let Some(owner) = self.staged_block_owner.get(&block).copied()
            && owner != txn_id
        {
            return Err(FfsError::Format(format!(
                "block {} already staged by txn {}",
                block.0, owner.0
            )));
        }

        let payload = data.to_vec();
        self.staged_txn_writes
            .entry(txn_id)
            .or_default()
            .insert(block, payload);
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

    fn is_current_flush_candidate(&self, candidate: &FlushCandidate) -> bool {
        self.dirty.entry(candidate.block).is_some_and(|entry| {
            entry.seq == candidate.seq
                && entry.txn_id == candidate.txn_id
                && entry.commit_seq == Some(candidate.commit_seq)
                && entry.is_flushable()
        })
    }

    fn take_pending_flush(&mut self) -> Vec<FlushCandidate> {
        let pending = std::mem::take(&mut self.pending_flush);
        let pending_count = pending.len();
        let mut current = Vec::with_capacity(pending_count);
        for candidate in pending {
            if self.is_current_flush_candidate(&candidate) {
                current.push(candidate);
            } else {
                warn!(
                    event = "stale_pending_flush_dropped",
                    block = candidate.block.0,
                    txn_id = candidate.txn_id.0,
                    commit_seq = candidate.commit_seq.0,
                    dirty_seq = candidate.seq
                );
            }
        }
        current
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
                    seq: entry.seq,
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
                    seq: entry.seq,
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
/// cache metadata (T1/T2/B1/B2 lists, resident map, counters). A sharded
/// [`PageLockTable`] coalesces concurrent cold reads for the same block so
/// worker bursts do not stampede the underlying device. This is sufficient
/// because:
///
/// 1. The lock is **never held during I/O**.  `read_block` drops the lock
///    before issuing a device read and re-acquires it afterwards.
///    `write_block` writes through to the device first, then acquires the lock
///    only to update metadata.
/// 2. `parking_lot::Mutex` is non-poisoning and uses adaptive spinning, so
///    contention under typical FUSE workloads (many concurrent reads, few
///    writes) remains low.
///
/// **High-core sharding:** [`ShardedArcCache`] shards resident metadata by
/// `BlockNumber` into N independent `Mutex<ArcState>` segments for workloads
/// that show metadata lock contention under heavy parallel read bursts. This
/// type remains the single-policy default for smaller deployments and for
/// callers that need one global adaptive replacement policy.
///
/// See [`DeferredArcCache`] for an integrated write-back + background flush variant.
#[derive(Debug)]
pub struct ArcCache<D: BlockDevice> {
    inner: D,
    state: Mutex<ArcState>,
    page_locks: PageLockTable,
    write_policy: ArcWritePolicy,
    mvcc_flush_lifecycle: Arc<dyn MvccFlushLifecycle>,
    repair_flush_lifecycle: Arc<dyn RepairFlushLifecycle>,
    #[cfg(feature = "s3fifo")]
    s3_fast_residents: S3FastResidentTable,
    #[cfg(feature = "s3fifo")]
    s3_fast_hits: S3FastHitCounter,
    #[cfg(feature = "s3fifo")]
    s3_fast_hits_enabled: bool,
    #[cfg(feature = "s3fifo")]
    s3_fast_cache_id: u64,
    #[cfg(feature = "s3fifo")]
    s3_fast_mutation_active: AtomicUsize,
    #[cfg(feature = "s3fifo")]
    s3_fast_mutation_epoch: AtomicU64,
}

/// Write policy for [`ArcCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcWritePolicy {
    /// Always write to the underlying device immediately.
    WriteThrough,
    /// Keep writes in cache until sync; dirty blocks cannot be evicted.
    WriteBack,
}

/// Maximum default shard count selected by [`ShardedArcCache::for_host_parallelism`].
pub const MAX_HOST_PARALLEL_CACHE_SHARDS: usize = 64;

/// Block-number-sharded wrapper around [`ArcCache`] for high-core read bursts.
///
/// Each shard owns an independent [`ArcCache`] and metadata lock. A block is
/// routed by `block % shard_count`, so any given block has exactly one cache
/// owner while unrelated hot blocks can be served by different locks. The
/// policy tradeoff is deliberate: replacement is shard-local instead of global,
/// buying lower contention for 64+ core swarms without weakening write-back
/// durability, dirty tracking, or same-block miss coalescing within a shard.
#[derive(Debug)]
pub struct ShardedArcCache<D: BlockDevice> {
    inner: Arc<D>,
    shards: Vec<ArcCache<Arc<D>>>,
    shard_mask: Option<u64>,
}

impl<D: BlockDevice> ShardedArcCache<D> {
    /// Create a write-through sharded cache with an explicit shard count.
    pub fn new(inner: D, capacity_blocks: usize, shard_count: usize) -> Result<Self> {
        Self::new_with_policy(
            inner,
            capacity_blocks,
            shard_count,
            ArcWritePolicy::WriteThrough,
        )
    }

    /// Create a sharded cache sized to the current host's hardware parallelism.
    pub fn for_host_parallelism(inner: D, capacity_blocks: usize) -> Result<Self> {
        let host_threads = thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let shard_count = host_threads
            .clamp(1, MAX_HOST_PARALLEL_CACHE_SHARDS)
            .min(capacity_blocks.max(1));
        Self::new(inner, capacity_blocks, shard_count)
    }

    /// Create a sharded cache with the requested write policy.
    pub fn new_with_policy(
        inner: D,
        capacity_blocks: usize,
        shard_count: usize,
        write_policy: ArcWritePolicy,
    ) -> Result<Self> {
        if capacity_blocks == 0 {
            return Err(FfsError::Format(
                "ShardedArcCache capacity_blocks must be > 0".to_owned(),
            ));
        }
        if shard_count == 0 {
            return Err(FfsError::Format(
                "ShardedArcCache shard_count must be > 0".to_owned(),
            ));
        }

        let shard_count = shard_count.min(capacity_blocks);
        let base_capacity = capacity_blocks / shard_count;
        let remainder = capacity_blocks % shard_count;
        let inner = Arc::new(inner);
        let mut shards = Vec::with_capacity(shard_count);

        for shard_index in 0..shard_count {
            let shard_capacity = base_capacity + usize::from(shard_index < remainder);
            shards.push(ArcCache::new_with_policy(
                Arc::clone(&inner),
                shard_capacity,
                write_policy,
            )?);
        }

        let shard_mask = shard_count
            .is_power_of_two()
            .then_some(u64::try_from(shard_count - 1).unwrap_or(u64::MAX));

        Ok(Self {
            inner,
            shards,
            shard_mask,
        })
    }

    /// Return the underlying block device shared by all shards.
    #[must_use]
    pub fn inner(&self) -> &Arc<D> {
        &self.inner
    }

    /// Number of independently locked cache shards.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Deterministic owner shard for `block`.
    #[must_use]
    pub fn shard_index_for(&self, block: BlockNumber) -> usize {
        if let Some(mask) = self.shard_mask {
            return usize::try_from(block.0 & mask).unwrap_or(0);
        }
        let shard_count = u64::try_from(self.shards.len()).unwrap_or(u64::MAX);
        usize::try_from(block.0 % shard_count).unwrap_or(0)
    }

    fn shard_for(&self, block: BlockNumber) -> &ArcCache<Arc<D>> {
        &self.shards[self.shard_index_for(block)]
    }

    /// Per-shard metric snapshots for diagnosing imbalance.
    #[must_use]
    pub fn shard_metrics(&self) -> Vec<CacheMetrics> {
        self.shards.iter().map(ArcCache::metrics).collect()
    }

    /// Aggregate metric snapshot across all shards.
    #[must_use]
    pub fn metrics(&self) -> CacheMetrics {
        CacheMetrics::aggregate(self.shard_metrics())
    }

    /// Export aggregate cache metrics using the runtime/e2e JSON field names.
    #[must_use]
    pub fn runtime_metrics(&self) -> CacheRuntimeMetricsSnapshot {
        self.metrics().runtime_metrics_snapshot()
    }
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
    /// Poll quota threshold below which flush batches are reduced.
    pub budget_poll_quota_threshold: u32,
    /// Reduced batch size used when budget pressure is active.
    pub reduced_batch_size: usize,
    /// Yield duration when budget pressure is active.
    pub budget_yield_sleep: Duration,
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
            budget_poll_quota_threshold: 256,
            reduced_batch_size: 64,
            budget_yield_sleep: Duration::from_millis(10),
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
        if self.reduced_batch_size == 0 {
            return Err(FfsError::Format(
                "flush daemon reduced_batch_size must be > 0".to_owned(),
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
    stop: Arc<FlushDaemonStop>,
    join: Option<JoinHandle<()>>,
}

impl FlushDaemon {
    /// Request shutdown and block until the daemon exits.
    pub fn shutdown(mut self) {
        self.stop.request_stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for FlushDaemon {
    fn drop(&mut self) {
        self.stop.request_stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct FlushDaemonStop {
    stopped: Mutex<bool>,
    condvar: Condvar,
}

impl std::fmt::Debug for FlushDaemonStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlushDaemonStop").finish_non_exhaustive()
    }
}

impl FlushDaemonStop {
    fn new() -> Self {
        Self {
            stopped: Mutex::new(false),
            condvar: Condvar::new(),
        }
    }

    fn request_stop(&self) {
        *self.stopped.lock() = true;
        self.condvar.notify_all();
    }

    fn wait_interval_or_stopped(&self, interval: Duration) -> bool {
        let mut stopped = self.stopped.lock();
        if *stopped {
            return true;
        }
        self.condvar.wait_for(&mut stopped, interval);
        *stopped
    }
}

/// Write-back [`ArcCache`] with an integrated background [`FlushDaemon`].
///
/// Combines a write-back ARC cache with a background flush daemon that
/// periodically writes dirty blocks to the underlying device.  When the
/// `DeferredArcCache` is dropped, the daemon is stopped and a final flush
/// is performed before the cache is released.
///
/// # Example
///
/// ```text
/// let deferred = DeferredArcCache::new(device, 1024, FlushDaemonConfig::default())?;
/// deferred.write_block(&cx, BlockNumber(0), &data)?; // deferred to cache
/// // daemon flushes dirty blocks in background …
/// drop(deferred); // final flush + shutdown
/// ```
pub struct DeferredArcCache<D: BlockDevice + 'static> {
    /// Dropped first — joins the daemon thread (which does a final flush).
    daemon: FlushDaemon,
    /// Dropped second — the underlying cache (kept alive by daemon's Arc clone
    /// until the daemon thread exits in `FlushDaemon::drop`).
    cache: Arc<ArcCache<D>>,
}

impl<D: BlockDevice + 'static> DeferredArcCache<D> {
    /// Create a write-back cache with a background flush daemon.
    pub fn new(inner: D, capacity_blocks: usize, config: FlushDaemonConfig) -> Result<Self> {
        let cache = Arc::new(ArcCache::new_with_policy(
            inner,
            capacity_blocks,
            ArcWritePolicy::WriteBack,
        )?);
        let daemon = cache.start_flush_daemon(config)?;
        Ok(Self { daemon, cache })
    }

    /// Access the underlying [`ArcCache`].
    #[must_use]
    pub fn cache(&self) -> &Arc<ArcCache<D>> {
        &self.cache
    }

    /// Shut down the daemon and perform a final flush, consuming the wrapper.
    ///
    /// Returns the inner `Arc<ArcCache<D>>` for continued (non-deferred) use.
    #[must_use]
    pub fn shutdown(self) -> Arc<ArcCache<D>> {
        let Self { daemon, cache } = self;
        daemon.shutdown();
        cache
    }
}

impl<D: BlockDevice + 'static> std::ops::Deref for DeferredArcCache<D> {
    type Target = ArcCache<D>;
    fn deref(&self) -> &Self::Target {
        &self.cache
    }
}

impl<D: BlockDevice + 'static> BlockDevice for DeferredArcCache<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        self.cache.read_block(cx, block)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.cache.write_block(cx, block, data)
    }

    fn block_size(&self) -> u32 {
        self.cache.block_size()
    }

    fn block_count(&self) -> u64 {
        self.cache.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.cache.sync(cx)
    }
}

impl<D: BlockDevice + std::fmt::Debug + 'static> std::fmt::Debug for DeferredArcCache<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredArcCache")
            .field("cache", &self.cache)
            .field("daemon", &self.daemon)
            .finish()
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
        Self::new_with_policy_and_lifecycles(
            inner,
            capacity_blocks,
            write_policy,
            Arc::new(NoopMvccFlushLifecycle),
            Arc::new(NoopRepairFlushLifecycle),
        )
    }

    pub fn new_with_policy_and_mvcc_lifecycle(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
        mvcc_flush_lifecycle: Arc<dyn MvccFlushLifecycle>,
    ) -> Result<Self> {
        Self::new_with_policy_and_lifecycles(
            inner,
            capacity_blocks,
            write_policy,
            mvcc_flush_lifecycle,
            Arc::new(NoopRepairFlushLifecycle),
        )
    }

    pub fn new_with_policy_and_repair_lifecycle(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
        repair_flush_lifecycle: Arc<dyn RepairFlushLifecycle>,
    ) -> Result<Self> {
        Self::new_with_policy_and_lifecycles(
            inner,
            capacity_blocks,
            write_policy,
            Arc::new(NoopMvccFlushLifecycle),
            repair_flush_lifecycle,
        )
    }

    pub fn new_with_policy_and_lifecycles(
        inner: D,
        capacity_blocks: usize,
        write_policy: ArcWritePolicy,
        mvcc_flush_lifecycle: Arc<dyn MvccFlushLifecycle>,
        repair_flush_lifecycle: Arc<dyn RepairFlushLifecycle>,
    ) -> Result<Self> {
        if capacity_blocks == 0 {
            return Err(FfsError::Format(
                "ArcCache capacity_blocks must be > 0".to_owned(),
            ));
        }
        #[cfg(feature = "s3fifo")]
        let s3_fast_hits_enabled = ArcState::s3_capacity_split(capacity_blocks).0 > 32;
        let cache = Self {
            inner,
            state: Mutex::new(ArcState::new(capacity_blocks)),
            page_locks: PageLockTable::for_host_parallelism(),
            write_policy,
            mvcc_flush_lifecycle,
            repair_flush_lifecycle,
            #[cfg(feature = "s3fifo")]
            s3_fast_residents: S3FastResidentTable::for_capacity(capacity_blocks),
            #[cfg(feature = "s3fifo")]
            s3_fast_hits: S3FastHitCounter::for_capacity(capacity_blocks),
            #[cfg(feature = "s3fifo")]
            s3_fast_hits_enabled,
            #[cfg(feature = "s3fifo")]
            s3_fast_cache_id: next_s3_fast_cache_id(),
            #[cfg(feature = "s3fifo")]
            s3_fast_mutation_active: AtomicUsize::new(0),
            #[cfg(feature = "s3fifo")]
            s3_fast_mutation_epoch: AtomicU64::new(0),
        };
        #[cfg(feature = "s3fifo")]
        info!(
            target: "ffs::block::s3fifo",
            event = "cache_mode_selected",
            mode = "s3fifo",
            capacity = capacity_blocks
        );
        #[cfg(not(feature = "s3fifo"))]
        info!(
            event = "cache_mode_selected",
            mode = "arc",
            capacity = capacity_blocks
        );
        Ok(cache)
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
        #[cfg(feature = "s3fifo")]
        {
            let mut metrics = self.state.lock().snapshot_metrics();
            metrics.hits = metrics
                .hits
                .saturating_add(self.s3_fast_hits.total(Ordering::Relaxed));
            metrics
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            self.state.lock().snapshot_metrics()
        }
    }

    /// Export cache metrics using the runtime/e2e JSON field names.
    #[must_use]
    pub fn runtime_metrics(&self) -> CacheRuntimeMetricsSnapshot {
        self.metrics().runtime_metrics_snapshot()
    }

    #[must_use]
    pub fn write_policy(&self) -> ArcWritePolicy {
        self.write_policy
    }

    #[cfg(feature = "s3fifo")]
    fn s3_fast_hit(&self, block: BlockNumber) -> Option<BlockBuf> {
        if !self.s3_fast_hits_enabled {
            return None;
        }
        let epoch = self.s3_fast_mutation_epoch.load(Ordering::Acquire);
        if self.s3_fast_mutation_active.load(Ordering::Acquire) != 0 {
            return None;
        }
        if let Some(buf) = self.s3_thread_fast_hit(block, epoch) {
            return Some(buf);
        }
        let entry = self.s3_fast_residents.get_valid(block)?;
        if self.s3_fast_mutation_active.load(Ordering::Acquire) != 0
            || self.s3_fast_mutation_epoch.load(Ordering::Acquire) != epoch
            || !entry.access.is_valid()
        {
            return None;
        }
        entry.access.increment_count();
        self.s3_fast_hits.increment(block);
        let data = entry.data.clone_ref();
        self.store_s3_thread_fast_hit(block, epoch, entry);
        Some(data)
    }

    #[cfg(feature = "s3fifo")]
    fn s3_thread_fast_hit(&self, block: BlockNumber, epoch: u64) -> Option<BlockBuf> {
        let (data, access) = S3_THREAD_FAST_RESIDENTS.with(|residents| {
            residents
                .borrow()
                .get_valid(self.s3_fast_cache_id, block, epoch)
        })?;
        if self.s3_fast_mutation_active.load(Ordering::Acquire) != 0
            || self.s3_fast_mutation_epoch.load(Ordering::Acquire) != epoch
            || !access.is_valid()
        {
            return None;
        }
        access.increment_count();
        self.s3_fast_hits.increment(block);
        Some(data)
    }

    #[cfg(feature = "s3fifo")]
    fn store_s3_thread_fast_hit(&self, block: BlockNumber, epoch: u64, resident: S3FastResident) {
        S3_THREAD_FAST_RESIDENTS.with(|residents| {
            residents
                .borrow_mut()
                .insert(self.s3_fast_cache_id, block, epoch, resident);
        });
    }

    #[cfg(feature = "s3fifo")]
    fn begin_s3_fast_mutation(&self) -> S3FastMutationGuard<'_> {
        self.s3_fast_mutation_active.fetch_add(1, Ordering::AcqRel);
        self.s3_fast_mutation_epoch.fetch_add(1, Ordering::AcqRel);
        S3FastMutationGuard {
            active: &self.s3_fast_mutation_active,
            epoch: &self.s3_fast_mutation_epoch,
        }
    }

    #[cfg(feature = "s3fifo")]
    fn s3_fast_entry_for(
        &self,
        state: &ArcState,
        block: BlockNumber,
        data: &BlockBuf,
    ) -> Option<S3FastResident> {
        if !self.s3_fast_hits_enabled {
            return None;
        }
        let access = state.access_count.get(&block)?;
        access.is_valid().then(|| S3FastResident {
            data: data.clone_ref(),
            access: Arc::clone(access),
        })
    }

    #[cfg(feature = "s3fifo")]
    fn apply_s3_fast_resident_updates(
        &self,
        invalidations: Vec<BlockNumber>,
        insert: Option<(BlockNumber, S3FastResident)>,
    ) {
        for block in invalidations {
            self.s3_fast_residents.remove(block);
        }
        if let Some((block, entry)) = insert {
            self.s3_fast_residents.insert(block, entry);
        }
    }

    /// Apply a memory-pressure signal and adjust cache target size.
    ///
    /// This reduces (or restores) the active target capacity and evicts clean
    /// cold entries when possible. Dirty entries are never evicted.
    #[must_use]
    pub fn memory_pressure_callback(&self, pressure: MemoryPressure) -> CachePressureReport {
        #[cfg(feature = "s3fifo")]
        let mutation_guard = self.begin_s3_fast_mutation();
        let (old_pressure, old_target, new_target, batch, report, fast_invalidations) = {
            let mut guard = self.state.lock();
            let old_pressure = guard.pressure_level;
            let old_target = guard.capacity;
            guard.set_pressure_level(pressure);
            let batch = guard.trim_to_capacity();
            (
                old_pressure,
                old_target,
                guard.capacity,
                batch,
                guard.pressure_report(),
                {
                    #[cfg(feature = "s3fifo")]
                    {
                        guard.take_fast_invalidations()
                    }
                    #[cfg(not(feature = "s3fifo"))]
                    {
                        Vec::<BlockNumber>::new()
                    }
                },
            )
        };
        #[cfg(feature = "s3fifo")]
        self.apply_s3_fast_resident_updates(fast_invalidations, None);
        #[cfg(feature = "s3fifo")]
        drop(mutation_guard);
        #[cfg(not(feature = "s3fifo"))]
        let _ = fast_invalidations;

        if old_pressure != pressure {
            info!(
                event = "cache_pressure_level_change",
                old_level = ?old_pressure,
                new_level = ?pressure
            );
        }
        if old_target != new_target {
            debug!(event = "cache_target_size_change", old_target, new_target);
        }
        if batch.evicted_blocks > 0 {
            debug!(
                event = "cache_pressure_evict_batch",
                evicted_blocks = batch.evicted_blocks,
                evicted_bytes = batch.evicted_bytes
            );
        }
        report
    }

    /// Restore cache target size to the configured nominal capacity.
    #[must_use]
    pub fn restore_target_size(&self) -> CachePressureReport {
        #[cfg(feature = "s3fifo")]
        let mutation_guard = self.begin_s3_fast_mutation();
        let (old_level, old_target, new_target, batch, report, fast_invalidations) = {
            let mut guard = self.state.lock();
            let old_level = guard.pressure_level;
            let old_target = guard.capacity;
            guard.pressure_level = MemoryPressure::None;
            guard.restore_target_capacity();
            let batch = guard.trim_to_capacity();
            (
                old_level,
                old_target,
                guard.capacity,
                batch,
                guard.pressure_report(),
                {
                    #[cfg(feature = "s3fifo")]
                    {
                        guard.take_fast_invalidations()
                    }
                    #[cfg(not(feature = "s3fifo"))]
                    {
                        Vec::<BlockNumber>::new()
                    }
                },
            )
        };
        #[cfg(feature = "s3fifo")]
        self.apply_s3_fast_resident_updates(fast_invalidations, None);
        #[cfg(feature = "s3fifo")]
        drop(mutation_guard);
        #[cfg(not(feature = "s3fifo"))]
        let _ = fast_invalidations;
        if old_level != MemoryPressure::None {
            info!(
                event = "cache_pressure_level_change",
                old_level = ?old_level,
                new_level = ?MemoryPressure::None
            );
        }
        if old_target != new_target {
            debug!(event = "cache_target_size_change", old_target, new_target);
        }
        if batch.evicted_blocks > 0 {
            debug!(
                event = "cache_pressure_evict_batch",
                evicted_blocks = batch.evicted_blocks,
                evicted_bytes = batch.evicted_bytes
            );
        }
        report
    }

    /// Current cache pressure snapshot.
    #[must_use]
    pub fn pressure_report(&self) -> CachePressureReport {
        self.state.lock().pressure_report()
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
        guard.stage_txn_write(txn_id, block, data)
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
        for (block, data) in staged {
            let payload = BlockBuf::new(data);
            let payload_len = payload.len();
            if guard.resident.contains_key(&block) {
                guard.resident.insert(block, payload);
                guard.on_hit(block);
            } else {
                guard.on_miss_or_ghost_hit(block);
                guard.resident.insert(block, payload);
            }
            guard.mark_dirty(
                block,
                payload_len,
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
                warn!(
                    event = "backpressure_activated",
                    source = "commit_staged_txn",
                    level = "critical",
                    txn_id = txn_id.0,
                    dirty_ratio,
                    threshold = DIRTY_CRITICAL_WATERMARK
                );
            } else if dirty_ratio > DIRTY_HIGH_WATERMARK {
                warn!(
                    event = "flush_backpressure_high",
                    txn_id = txn_id.0,
                    dirty_ratio,
                    high_watermark = DIRTY_HIGH_WATERMARK
                );
                warn!(
                    event = "backpressure_activated",
                    source = "commit_staged_txn",
                    level = "high",
                    txn_id = txn_id.0,
                    dirty_ratio,
                    threshold = DIRTY_HIGH_WATERMARK
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
        let discarded_block_ids = {
            let mut guard = self.state.lock();
            let staged = guard.take_staged_txn(txn_id);
            let mut discarded = Vec::new();
            for block in staged.keys() {
                let is_same_txn_inflight = guard.dirty.entry(*block).is_some_and(|entry| {
                    entry.txn_id == txn_id && matches!(entry.state, DirtyState::InFlight)
                });
                if is_same_txn_inflight {
                    guard.clear_dirty_unconditional(*block);
                    discarded.push(block.0);
                }
            }
            drop(guard);
            discarded
        };
        let discarded_blocks = discarded_block_ids.len();
        if discarded_blocks > 0 {
            warn!(
                event = "mvcc_discard_aborted_dirty",
                txn_id = txn_id.0,
                discarded_blocks
            );
            for block_id in discarded_block_ids {
                warn!(
                    event = "dirty_block_discarded",
                    block_id,
                    txn_id = txn_id.0,
                    reason = "abort"
                );
            }
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
        let stop = Arc::new(FlushDaemonStop::new());
        let cache = Arc::clone(self);
        let stop_signal = Arc::clone(&stop);

        let join = thread::Builder::new()
            .name("ffs-flush-daemon".to_owned())
            .spawn(move || {
                // Daemon uses a long-lived context for periodic background work.
                let cx = Cx::for_testing();
                let mut cycle_seq = 0_u64;
                let mut daemon_throttled = false;

                loop {
                    if stop_signal.wait_interval_or_stopped(config.interval) {
                        break;
                    }
                    cycle_seq = cycle_seq.saturating_add(1);
                    cache.run_flush_daemon_cycle(&cx, &config, cycle_seq, &mut daemon_throttled);
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

    fn run_flush_daemon_cycle(
        &self,
        cx: &Cx,
        config: &FlushDaemonConfig,
        cycle_seq: u64,
        daemon_throttled: &mut bool,
    ) {
        let metrics = self.metrics();
        let dirty_ratio = metrics.dirty_ratio();
        let (in_flight_blocks, committed_blocks) = self.dirty_state_counts();
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
            Self::maybe_log_daemon_resumed(daemon_throttled, cx.budget().poll_quota);
            trace!(
                event = "flush_daemon_sleep",
                cycle_seq,
                interval_ms = config.interval.as_millis()
            );
            return;
        }

        let batch_size = Self::effective_flush_batch_size(cx, config, daemon_throttled);
        let flush_res = self.flush_cycle_batch(
            cx,
            config,
            cycle_seq,
            committed_dirty_ratio,
            committed_blocks,
            batch_size,
        );

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

    fn maybe_log_daemon_resumed(daemon_throttled: &mut bool, new_budget: u32) {
        if *daemon_throttled {
            debug!(
                event = "daemon_resumed",
                daemon_name = "flush_daemon",
                new_budget
            );
            *daemon_throttled = false;
        }
    }

    fn effective_flush_batch_size(
        cx: &Cx,
        config: &FlushDaemonConfig,
        daemon_throttled: &mut bool,
    ) -> usize {
        let budget = cx.budget();
        let budget_pressure =
            budget.is_exhausted() || budget.poll_quota <= config.budget_poll_quota_threshold;
        if budget_pressure {
            let reduced = config.reduced_batch_size.min(config.batch_size).max(1);
            if reduced < config.batch_size {
                debug!(
                    event = "batch_size_reduced",
                    daemon_name = "flush_daemon",
                    original_size = config.batch_size,
                    reduced_size = reduced,
                    pressure_level = "budget"
                );
            }
            debug!(
                event = "daemon_throttled",
                daemon_name = "flush_daemon",
                budget_remaining = budget.poll_quota,
                yield_duration_ms = config.budget_yield_sleep.as_millis(),
                pressure_level = "budget"
            );
            *daemon_throttled = true;
            sleep_for_flush_budget_yield(cx, config.budget_yield_sleep);
            reduced
        } else {
            Self::maybe_log_daemon_resumed(daemon_throttled, budget.poll_quota);
            config.batch_size
        }
    }

    fn flush_cycle_batch(
        &self,
        cx: &Cx,
        config: &FlushDaemonConfig,
        cycle_seq: u64,
        committed_dirty_ratio: f64,
        committed_blocks: usize,
        batch_size: usize,
    ) -> Result<usize> {
        if committed_dirty_ratio > config.high_watermark {
            if committed_dirty_ratio > config.critical_watermark {
                warn!(
                    event = "flush_backpressure_critical",
                    cycle_seq,
                    dirty_ratio = committed_dirty_ratio,
                    critical_watermark = config.critical_watermark
                );
                warn!(
                    event = "backpressure_activated",
                    source = "flush_daemon",
                    level = "critical",
                    cycle_seq,
                    dirty_ratio = committed_dirty_ratio,
                    threshold = config.critical_watermark
                );
            } else {
                warn!(
                    event = "flush_backpressure_high",
                    cycle_seq,
                    dirty_ratio = committed_dirty_ratio,
                    high_watermark = config.high_watermark
                );
                warn!(
                    event = "backpressure_activated",
                    source = "flush_daemon",
                    level = "high",
                    cycle_seq,
                    dirty_ratio = committed_dirty_ratio,
                    threshold = config.high_watermark
                );
            }
            self.flush_dirty(cx).map(|()| committed_blocks)
        } else {
            self.flush_dirty_batch(cx, batch_size)
        }
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
                .write_block(cx, candidate.block, candidate.data.as_slice())?;
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

    fn notify_repair_flush(&self, cx: &Cx, flushes: &[FlushCandidate]) -> Result<()> {
        if flushes.is_empty() {
            return Ok(());
        }

        let blocks: Vec<BlockNumber> = flushes.iter().map(|candidate| candidate.block).collect();
        let block_preview: Vec<u64> = blocks.iter().take(16).map(|block| block.0).collect();
        debug!(
            target: "ffs::repair::refresh",
            event = "flush_triggers_refresh",
            block_count = blocks.len(),
            block_ids = ?block_preview,
            truncated = blocks.len() > block_preview.len()
        );
        self.repair_flush_lifecycle.on_flush_committed(cx, &blocks)
    }

    fn restore_pending_flush_candidates(&self, flushes: Vec<FlushCandidate>) {
        let attempted = flushes.len();
        let mut stale = Vec::new();
        let restored = {
            let mut guard = self.state.lock();
            let mut restored = 0_usize;
            for candidate in flushes {
                if guard.is_current_flush_candidate(&candidate) {
                    guard.pending_flush.push(candidate);
                    restored = restored.saturating_add(1);
                } else {
                    stale.push((
                        candidate.block.0,
                        candidate.txn_id.0,
                        candidate.commit_seq.0,
                        candidate.seq,
                    ));
                }
            }
            drop(guard);
            restored
        };
        for (block, txn_id, commit_seq, dirty_seq) in stale {
            warn!(
                event = "stale_pending_flush_not_restored",
                block, txn_id, commit_seq, dirty_seq
            );
        }
        if restored < attempted {
            debug!(
                event = "pending_flush_restore_filtered",
                attempted,
                restored,
                dropped = attempted.saturating_sub(restored)
            );
        }
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
            self.restore_pending_flush_candidates(pending_flush);
            error!(event = "pending_flush_batch_failed", error = %err);
            return Err(err);
        }

        if let Err(err) = self.notify_repair_flush(cx, &pending_flush) {
            // Blocks were already written to device by flush_blocks above.
            // Do NOT restore them as dirty — just log the repair notification
            // failure and continue. The blocks are persisted; only the repair
            // system missed the notification.
            error!(event = "pending_flush_batch_repair_notify_failed", error = %err);
        }

        let mut guard = self.state.lock();
        for candidate in &pending_flush {
            guard.clear_dirty(candidate.block, candidate.seq);
        }
        ArcState::add_usize_to_counter(&mut guard.dirty_flushes, pending_flush.len());
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
        #[cfg(feature = "s3fifo")]
        if let Some(buf) = self.s3_fast_hit(block) {
            return Ok(buf);
        }
        {
            let mut guard = self.state.lock();
            if let Some(buf) = guard.resident.get(&block).cloned() {
                guard.on_hit(block);
                #[cfg(feature = "s3fifo")]
                let fast_invalidations = guard.take_fast_invalidations();
                drop(guard);
                #[cfg(feature = "s3fifo")]
                self.apply_s3_fast_resident_updates(fast_invalidations, None);
                return Ok(buf);
            }
        }

        let _page_lock = self.page_locks.acquire(block);
        {
            let mut guard = self.state.lock();
            if let Some(buf) = guard.resident.get(&block).cloned() {
                guard.on_hit(block);
                #[cfg(feature = "s3fifo")]
                let fast_invalidations = guard.take_fast_invalidations();
                drop(guard);
                #[cfg(feature = "s3fifo")]
                self.apply_s3_fast_resident_updates(fast_invalidations, None);
                return Ok(buf);
            }
        }

        let buf = self.inner.read_block(cx, block)?;

        #[cfg(feature = "s3fifo")]
        let mutation_guard = self.begin_s3_fast_mutation();
        let mut guard = self.state.lock();
        // Re-check: another thread may have populated this block while we
        // were reading from the device (TOCTOU race).  If so, treat as a hit
        // and return the data already in the cache (it might be newer).
        #[cfg(feature = "s3fifo")]
        let mut fast_insert = None;
        let final_buf = if let Some(existing) = guard.resident.get(&block).cloned() {
            guard.on_hit(block);
            #[cfg(feature = "s3fifo")]
            {
                fast_insert = self
                    .s3_fast_entry_for(&guard, block, &existing)
                    .map(|entry| (block, entry));
            }
            existing
        } else {
            let bypass_cache = guard.on_read_miss_or_scan_bypass(block);
            if !bypass_cache {
                guard.resident.insert(block, buf.clone_ref());
                #[cfg(feature = "s3fifo")]
                {
                    fast_insert = self
                        .s3_fast_entry_for(&guard, block, &buf)
                        .map(|entry| (block, entry));
                }
            }
            buf
        };
        let pending_flush = guard.take_pending_flush();
        #[cfg(feature = "s3fifo")]
        let fast_invalidations = guard.take_fast_invalidations();
        drop(guard);
        #[cfg(feature = "s3fifo")]
        self.apply_s3_fast_resident_updates(fast_invalidations, fast_insert);
        #[cfg(feature = "s3fifo")]
        drop(mutation_guard);
        self.flush_pending_evictions(cx, pending_flush)?;
        Ok(final_buf)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if matches!(self.write_policy, ArcWritePolicy::WriteThrough) {
            self.inner.write_block(cx, block, data)?;
        } else {
            cx_checkpoint(cx)?;
        }

        let mut enforce_backpressure = false;
        #[cfg(feature = "s3fifo")]
        let mutation_guard = self.begin_s3_fast_mutation();
        let mut guard = self.state.lock();
        let payload = BlockBuf::new(data.to_vec());
        if guard.resident.contains_key(&block) {
            // Block already cached — just update data and touch for recency.
            guard.resident.insert(block, payload.clone_ref());
            guard.on_hit(block);
        } else {
            guard.on_miss_or_ghost_hit(block);
            guard.resident.insert(block, payload.clone_ref());
        }
        #[cfg(feature = "s3fifo")]
        let fast_insert = self
            .s3_fast_entry_for(&guard, block, &payload)
            .map(|entry| (block, entry));

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
            guard.clear_dirty_unconditional(block);
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
        #[cfg(feature = "s3fifo")]
        let fast_invalidations = guard.take_fast_invalidations();
        drop(guard);
        #[cfg(feature = "s3fifo")]
        self.apply_s3_fast_resident_updates(fast_invalidations, fast_insert);
        #[cfg(feature = "s3fifo")]
        drop(mutation_guard);
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

impl<D: BlockDevice> BlockDevice for ShardedArcCache<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        self.shard_for(block).read_block(cx, block)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.shard_for(block).write_block(cx, block, data)
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        for shard in &self.shards {
            shard.flush_dirty(cx)?;
        }
        self.inner.sync(cx)
    }
}

impl<D: BlockDevice> BlockCache for ShardedArcCache<D> {
    fn mark_clean(&self, block: BlockNumber) {
        self.shard_for(block).mark_clean(block);
    }

    fn dirty_blocks_oldest_first(&self) -> Vec<BlockNumber> {
        let mut dirty = Vec::new();
        for shard in &self.shards {
            dirty.extend(shard.dirty_blocks_oldest_first());
        }
        dirty
    }

    fn evict(&self, block: BlockNumber) {
        self.shard_for(block).evict(block);
    }
}

impl<D: BlockDevice> BlockCache for ArcCache<D> {
    fn mark_clean(&self, block: BlockNumber) {
        let mut guard = self.state.lock();
        guard.clear_dirty_unconditional(block);
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
            return;
        }

        let mut removed = false;
        removed |= ArcState::remove_from_list(&mut guard.t1, block);
        removed |= ArcState::remove_from_list(&mut guard.t2, block);
        removed |= guard.remove_ghost_block(block);
        removed |= guard.resident.remove(&block).is_some();
        guard.clear_dirty_unconditional(block);
        let _ = guard.loc.remove(&block);

        let evicted = if removed {
            ArcState::increment_counter(&mut guard.evictions);
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
            self.restore_pending_flush_candidates(flushes);
            error!(
                event = "flush_batch_failed",
                error = %err,
                attempted_blocks,
                duration_ms = started.elapsed().as_millis(),
                attempted_bytes = flush_bytes
            );
            return Err(err);
        }

        if let Err(err) = self.notify_repair_flush(cx, &flushes) {
            // Blocks were already written to device by flush_blocks above.
            // Do NOT restore them as dirty — the write is durable. Only
            // the repair notification was lost; log and continue.
            error!(
                event = "flush_batch_repair_notify_failed",
                error = %err,
                attempted_blocks = flushes.len(),
                duration_ms = started.elapsed().as_millis(),
                attempted_bytes = flush_bytes
            );
        }

        let mut guard = self.state.lock();
        for candidate in &flushes {
            guard.clear_dirty(candidate.block, candidate.seq);
        }
        ArcState::add_usize_to_counter(&mut guard.dirty_flushes, flushes.len());
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
        info!(
            event = "flush_batch",
            blocks_flushed = flushes.len(),
            bytes_written = flush_bytes,
            flush_duration_us = started.elapsed().as_micros()
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
            self.restore_pending_flush_candidates(flushes);
            error!(
                event = "flush_dirty_failed",
                error = %err,
                duration_ms = started.elapsed().as_millis()
            );
            return Err(err);
        }

        if let Err(err) = self.notify_repair_flush(cx, &flushes) {
            // Blocks already persisted by flush_blocks. Only repair
            // notification was lost — log and continue.
            error!(
                event = "flush_dirty_repair_notify_failed",
                error = %err,
                duration_ms = started.elapsed().as_millis()
            );
        }

        let mut guard = self.state.lock();
        for candidate in &flushes {
            guard.clear_dirty(candidate.block, candidate.seq);
        }
        ArcState::add_usize_to_counter(&mut guard.dirty_flushes, flushes.len());
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
        info!(
            event = "flush_batch",
            blocks_flushed = flushes.len(),
            bytes_written = flush_bytes,
            flush_duration_us = started.elapsed().as_micros()
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

// ── Fault injection framework ──────────────────────────────────────────────

/// Fault trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMode {
    /// Fire once, then clear.
    OneShot,
    /// Fire on every matching access.
    Persistent,
    /// Fire exactly N times, then clear.
    CountLimited(u32),
}

/// What kind of operation a fault targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultTarget {
    Read(BlockNumber),
    Write(BlockNumber),
}

/// Record of a fault that was triggered.
#[derive(Debug, Clone)]
pub struct FaultRecord {
    pub target: FaultTarget,
    pub sequence: u64,
}

struct FaultRule {
    target: FaultTarget,
    mode: FaultMode,
    fired: bool,
    fire_count: u32,
}

/// A `BlockDevice` wrapper that injects configurable faults for testing.
///
/// In passthrough mode (no rules) it delegates transparently. Rules can
/// target specific block reads or writes, and operate in one-shot or
/// persistent mode. A deterministic seed controls fault sequencing for
/// reproducibility.
///
/// # Lock-ordering invariant: never-hold-both (bd-6owbg)
///
/// The struct holds two `parking_lot::Mutex`es (`rules` + `log`).
/// Production code paths NEVER hold both simultaneously:
///
///   * `check_fault` acquires `rules`, mutates it, **drops** the
///     guard (explicit `drop(rules)` after the inspection loop),
///     and only THEN acquires `log` to push a fault record.
///   * `fail_on_read` / `fail_on_write` / `reset` acquire `rules`
///     alone or sequentially with `log`.
///   * `fault_log` acquires `log` alone.
///
/// **Any new method that needs both must follow the same
/// sequential pattern: read out of one lock into a local, drop
/// that lock, then take the other.** A nested acquisition (e.g.,
/// holding `rules` while pushing into `log`) would silently
/// introduce a deadlock against any concurrent caller that took
/// the locks in the opposite order.
///
/// This is a stricter contract than the documented order on
/// PersistentMvccStore (bd-7zd94) / ShardedMvccStore (bd-bky2f) /
/// FuseInodeLocks (bd-pfv55), where both locks ARE held but in a
/// fixed order. Here, neither lock is held while the other is
/// acquired. The
/// `fault_injector_concurrent_inject_and_reset_no_hang` regression
/// test exercises this contract under contention.
pub struct FaultInjector<D: BlockDevice> {
    inner: D,
    /// Active fault rules. **Never held simultaneously with `log`.**
    /// `check_fault` MUST `drop(rules)` before acquiring `log`.
    rules: Mutex<Vec<FaultRule>>,
    /// Recorded fault firings. **Never held simultaneously with
    /// `rules`.**
    log: Mutex<Vec<FaultRecord>>,
    sequence: std::sync::atomic::AtomicU64,
    seed: u64,
}

impl<D: BlockDevice> FaultInjector<D> {
    /// Wrap a device with no faults configured (pure passthrough).
    #[must_use]
    pub fn new(inner: D, seed: u64) -> Self {
        Self {
            inner,
            rules: Mutex::new(Vec::new()),
            log: Mutex::new(Vec::new()),
            sequence: std::sync::atomic::AtomicU64::new(0),
            seed,
        }
    }

    /// Register a fault on a specific read target.
    pub fn fail_on_read(&self, block: BlockNumber, mode: FaultMode) {
        self.rules.lock().push(FaultRule {
            target: FaultTarget::Read(block),
            mode,
            fired: false,
            fire_count: 0,
        });
    }

    /// Register a fault on a specific write target.
    pub fn fail_on_write(&self, block: BlockNumber, mode: FaultMode) {
        self.rules.lock().push(FaultRule {
            target: FaultTarget::Write(block),
            mode,
            fired: false,
            fire_count: 0,
        });
    }

    /// Return the fault log (all triggered faults in order).
    pub fn fault_log(&self) -> Vec<FaultRecord> {
        self.log.lock().clone()
    }

    /// The seed used for deterministic replay.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Clear all rules and reset the log.
    pub fn reset(&self) {
        self.rules.lock().clear();
        self.log.lock().clear();
        self.sequence.store(0, Ordering::Relaxed);
    }

    /// Check if any rule matches and should fire, returning an error if so.
    fn check_fault(&self, target: FaultTarget) -> Option<FfsError> {
        let matched = {
            let mut rules = self.rules.lock();
            let mut found = false;
            for rule in rules.iter_mut() {
                if rule.target == target {
                    match rule.mode {
                        FaultMode::OneShot => {
                            if !rule.fired {
                                rule.fired = true;
                                found = true;
                                break;
                            }
                        }
                        FaultMode::Persistent => {
                            found = true;
                            break;
                        }
                        FaultMode::CountLimited(n) => {
                            if rule.fire_count < n {
                                rule.fire_count += 1;
                                if rule.fire_count >= n {
                                    rule.fired = true;
                                }
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }
            drop(rules);
            found
        };

        if matched {
            let seq = saturating_fetch_increment(&self.sequence);
            self.log.lock().push(FaultRecord {
                target,
                sequence: seq,
            });
            Some(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "injected fault on {target:?} (seq={seq}, seed={})",
                    self.seed
                ),
            })
        } else {
            None
        }
    }
}

impl<D: BlockDevice> BlockDevice for FaultInjector<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        if let Some(err) = self.check_fault(FaultTarget::Read(block)) {
            return Err(err);
        }
        self.inner.read_block(cx, block)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if let Some(err) = self.check_fault(FaultTarget::Write(block)) {
            return Err(err);
        }
        self.inner.write_block(cx, block, data)
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)
    }
}

// ── I/O throttle injection framework (bd-32yn.4) ──────────────────────────

/// Configuration for I/O throttle injection.
///
/// Wraps a `BlockDevice` and adds configurable latency to read/write
/// operations for testing behavior under degraded I/O performance.
#[derive(Debug, Clone)]
pub struct ThrottleConfig {
    /// Fixed latency added to every read.
    pub read_latency: Duration,
    /// Fixed latency added to every write.
    pub write_latency: Duration,
    /// If > 0, simulates bandwidth limiting: delay = data_len / bps.
    /// Value is in bytes per second.
    pub bandwidth_bps: u64,
    /// Probability (0.0–1.0) that an individual operation stalls for
    /// `stall_duration` instead of the normal latency.
    pub stall_probability: f64,
    /// Duration of a random stall when triggered.
    pub stall_duration: Duration,
    /// If true, I/O operations that exceed the Cx deadline return
    /// `FfsError::Cancelled` instead of sleeping the full duration.
    pub respect_deadline: bool,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            read_latency: Duration::ZERO,
            write_latency: Duration::ZERO,
            bandwidth_bps: 0,
            stall_probability: 0.0,
            stall_duration: Duration::ZERO,
            respect_deadline: true,
        }
    }
}

/// Record of a throttle event that was applied.
#[derive(Debug, Clone)]
pub struct ThrottleRecord {
    /// Whether this was a read or write.
    pub is_read: bool,
    /// Block number targeted.
    pub block: BlockNumber,
    /// Actual delay applied.
    pub delay: Duration,
    /// Whether a stall was triggered.
    pub stalled: bool,
    /// Monotonic sequence number.
    pub sequence: u64,
}

/// A `BlockDevice` wrapper that injects configurable I/O latency.
///
/// Designed to test filesystem behavior under degraded I/O:
/// - Uniform latency (every op delayed)
/// - Random stalls (probabilistic, deterministic via seed)
/// - Bandwidth throttling (per-byte delay)
/// - Cx deadline integration (respects cancellation)
///
/// The configuration can be updated at runtime via `update_config`.
/// # Lock-ordering invariant: never-hold-both (bd-6owbg)
///
/// Same contract as [`FaultInjector`]: this struct holds two
/// `parking_lot::Mutex`es (`config` + `log`) and production code
/// paths NEVER hold both simultaneously:
///
///   * `apply_delay` clones `config` from a brief `config.lock()`
///     (released at the end of the cloning expression), sleeps,
///     then acquires `log.lock()` to push a record.
///   * `update_config` acquires `config` alone.
///   * `throttle_log` / `reset` acquire `log` alone.
///   * The `Debug` impl acquires one Mutex per `.field(...)` call;
///     successive calls release their guards between calls.
///
/// **Any new method that needs both must follow the same
/// sequential pattern: read out of one lock into a local, drop
/// that lock, then take the other.** A nested acquisition would
/// silently introduce a deadlock against any concurrent caller
/// that took the locks in the opposite order. The
/// `throttle_injector_concurrent_apply_and_reset_no_hang`
/// regression test exercises this under contention.
pub struct ThrottleInjector<D: BlockDevice> {
    inner: D,
    /// Active throttle policy. **Never held simultaneously with
    /// `log`.** `apply_delay` clones the config and drops the
    /// guard before any `log` access.
    config: Mutex<ThrottleConfig>,
    /// Recorded throttle events. **Never held simultaneously with
    /// `config`.**
    log: Mutex<Vec<ThrottleRecord>>,
    sequence: std::sync::atomic::AtomicU64,
    seed: u64,
    rng_state: std::sync::atomic::AtomicU64,
}

const DEFAULT_THROTTLE_RNG_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

impl<D: BlockDevice> ThrottleInjector<D> {
    fn sleep_with_cx_deadline(cx: &Cx, duration: Duration) -> Result<()> {
        if duration.is_zero() {
            return Ok(());
        }

        let mut remaining = duration;
        let cancel_check_interval = Duration::from_millis(10);
        while !remaining.is_zero() {
            let slice = remaining.min(cancel_check_interval);
            cx_checkpoint(cx)?;
            let budget = cx.budget();
            let now = cx.now();
            if budget.is_past_deadline(now)
                || budget
                    .remaining_time(now)
                    .is_some_and(|remaining_time| remaining_time <= slice)
            {
                return Err(FfsError::Cancelled);
            }

            std::thread::sleep(slice);
            remaining = remaining.saturating_sub(slice);
        }

        cx_checkpoint(cx)
    }

    /// Wrap a device with the given throttle configuration.
    #[must_use]
    pub fn new(inner: D, config: ThrottleConfig, seed: u64) -> Self {
        let seed = Self::normalize_seed(seed);
        Self {
            inner,
            config: Mutex::new(config),
            log: Mutex::new(Vec::new()),
            sequence: std::sync::atomic::AtomicU64::new(0),
            seed,
            rng_state: std::sync::atomic::AtomicU64::new(seed),
        }
    }

    const fn normalize_seed(seed: u64) -> u64 {
        if seed == 0 {
            DEFAULT_THROTTLE_RNG_SEED
        } else {
            seed
        }
    }

    /// Update the throttle configuration at runtime.
    ///
    /// This enables progressive degradation scenarios where latency
    /// increases over time.
    pub fn update_config(&self, config: ThrottleConfig) {
        *self.config.lock() = config;
    }

    /// Return the throttle log (all recorded delays).
    pub fn throttle_log(&self) -> Vec<ThrottleRecord> {
        self.log.lock().clone()
    }

    /// The seed used for deterministic stall scheduling.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Clear the log and reset sequence counter.
    pub fn reset(&self) {
        self.log.lock().clear();
        self.sequence.store(0, Ordering::Relaxed);
        self.rng_state.store(self.seed, Ordering::Relaxed);
    }

    /// Deterministic pseudo-random: returns value in [0.0, 1.0).
    fn next_random(&self) -> f64 {
        let mut state = self.rng_state.load(Ordering::Relaxed);
        loop {
            let next = Self::advance_rng_state(state);
            match self.rng_state.compare_exchange_weak(
                state,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Self::rng_state_to_unit_interval(next),
                Err(current) => state = current,
            }
        }
    }

    fn advance_rng_state(mut state: u64) -> u64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }

    fn rng_state_to_unit_interval(state: u64) -> f64 {
        (state >> 11) as f64 / ((1_u64 << 53) as f64)
    }

    /// Compute and apply the delay for an operation.
    fn apply_delay(&self, cx: &Cx, is_read: bool, block: BlockNumber, data_len: u32) -> Result<()> {
        let config = self.config.lock().clone();

        let base_latency = if is_read {
            config.read_latency
        } else {
            config.write_latency
        };

        // Bandwidth throttle: delay = data_len / bps
        let bw_delay = if config.bandwidth_bps > 0 {
            Duration::from_secs_f64(f64::from(data_len) / config.bandwidth_bps as f64)
        } else {
            Duration::ZERO
        };

        // Random stall check
        let stalled =
            config.stall_probability > 0.0 && self.next_random() < config.stall_probability;
        let stall_delay = if stalled {
            config.stall_duration
        } else {
            Duration::ZERO
        };

        let total_delay = base_latency
            .saturating_add(bw_delay)
            .saturating_add(stall_delay);

        if total_delay > Duration::ZERO {
            if config.respect_deadline {
                Self::sleep_with_cx_deadline(cx, total_delay)?;
            } else {
                std::thread::sleep(total_delay);
            }
        }

        let seq = saturating_fetch_increment(&self.sequence);
        self.log.lock().push(ThrottleRecord {
            is_read,
            block,
            delay: total_delay,
            stalled,
            sequence: seq,
        });
        Ok(())
    }
}

impl<D: BlockDevice> BlockDevice for ThrottleInjector<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        self.apply_delay(cx, true, block, self.inner.block_size())?;
        self.inner.read_block(cx, block)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        self.apply_delay(cx, false, block, len)?;
        self.inner.write_block(cx, block, data)
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)
    }
}

impl<D: BlockDevice> std::fmt::Debug for ThrottleInjector<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThrottleInjector")
            .field("config", &*self.config.lock())
            .field("seed", &self.seed)
            .field("events", &self.sequence.load(Ordering::Relaxed))
            .field("log_len", &self.log.lock().len())
            .field("rng_state", &self.rng_state.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "s3fifo")]
    use sha2::{Digest, Sha256};
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn arc_access(state: &mut ArcState, key: BlockNumber) {
        if state.resident.contains_key(&key) {
            state.on_hit(key);
        } else {
            state.on_miss_or_ghost_hit(key);
            state.resident.insert(key, BlockBuf::new(vec![0_u8]));
        }

        // Invariants: loc is the source of truth for membership; resident contains
        // only T1/T2 entries.
        assert_eq!(state.resident.len(), state.t1.len() + state.t2.len());
        assert!(state.resident.len() <= state.capacity);
        #[cfg(not(feature = "s3fifo"))]
        {
            assert!(state.total_len() <= state.capacity.saturating_mul(2));
            assert_eq!(state.loc.len(), state.total_len());
        }

        for &k in &state.t1 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::T1)));
            assert!(state.resident.contains_key(&k));
        }
        for &k in &state.t2 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::T2)));
            assert!(state.resident.contains_key(&k));
        }
        #[cfg(feature = "s3fifo")]
        {
            let b1_live: Vec<_> = state.b1_live_keys().collect();
            let b2_live: Vec<_> = state.b2_live_keys().collect();
            assert_eq!(b1_live.len(), state.b1_len());
            assert_eq!(b2_live.len(), state.b2_len());
            for k in b1_live {
                assert!(matches!(state.loc.get(&k), Some(ArcList::B1)));
                assert!(!state.resident.contains_key(&k));
            }
            for k in b2_live {
                assert!(matches!(state.loc.get(&k), Some(ArcList::B2)));
                assert!(!state.resident.contains_key(&k));
            }
        }
        #[cfg(not(feature = "s3fifo"))]
        {
            for &k in &state.b1 {
                assert!(matches!(state.loc.get(&k), Some(ArcList::B1)));
                assert!(!state.resident.contains_key(&k));
            }
            for &k in &state.b2 {
                assert!(matches!(state.loc.get(&k), Some(ArcList::B2)));
                assert!(!state.resident.contains_key(&k));
            }
        }
    }

    fn wait_until_dirty_count<D: BlockDevice>(
        cache: &ArcCache<D>,
        expected: usize,
        timeout: Duration,
    ) -> usize {
        let deadline = Instant::now() + timeout;
        loop {
            let current = cache.dirty_count();
            if current == expected || Instant::now() >= deadline {
                return current;
            }
            std::thread::yield_now();
        }
    }

    const PAGE_LOCK_WAITER_TIMEOUT: Duration = Duration::from_secs(2);
    const PAGE_LOCK_WAITER_POLL: Duration = Duration::from_millis(2);

    fn wait_until_page_lock_waiters(
        table: &PageLockTable,
        block: BlockNumber,
        expected: usize,
        timeout: Duration,
    ) -> usize {
        let deadline = Instant::now() + timeout;
        let shard = &table.shards[table.shard_index(block)];
        loop {
            let current = shard.waiters.load(Ordering::Acquire);
            if current >= expected || Instant::now() >= deadline {
                return current;
            }
            std::thread::sleep(PAGE_LOCK_WAITER_POLL);
        }
    }

    #[cfg(feature = "s3fifo")]
    fn s3_access(state: &mut ArcState, key: BlockNumber) {
        arc_access(state, key);
    }

    #[cfg(feature = "s3fifo")]
    fn s3_access_count(state: &ArcState, key: BlockNumber) -> Option<u8> {
        state
            .access_count
            .get(&key)
            .map(|handle| handle.load_count())
    }

    #[cfg(feature = "s3fifo")]
    fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
        let digest = Sha256::digest(bytes.as_ref());
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").expect("format sha256");
        }
        hex
    }

    #[derive(Debug)]
    struct MemoryByteDevice {
        bytes: Mutex<Vec<u8>>,
        read_count: AtomicUsize,
    }

    impl MemoryByteDevice {
        fn new(len: usize) -> Self {
            Self {
                bytes: Mutex::new(vec![0_u8; len]),
                read_count: AtomicUsize::new(0),
            }
        }

        fn read_count(&self) -> usize {
            self.read_count.load(Ordering::Relaxed)
        }
    }

    impl ByteDevice for MemoryByteDevice {
        fn len_bytes(&self) -> u64 {
            u64::try_from(self.bytes.lock().len()).unwrap_or(0)
        }

        fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
            self.read_count.fetch_add(1, Ordering::Relaxed);
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

        fn read_vectored_exact_at(
            &self,
            _cx: &Cx,
            offset: ByteOffset,
            bufs: &mut [IoSliceMut<'_>],
        ) -> Result<()> {
            self.read_count.fetch_add(1, Ordering::Relaxed);
            let mut offset = usize::try_from(offset.0)
                .map_err(|_| FfsError::Format("offset overflow".into()))?;
            let bytes = self.bytes.lock();
            for buf in bufs {
                let end = offset
                    .checked_add(buf.len())
                    .ok_or_else(|| FfsError::Format("range overflow".into()))?;
                if end > bytes.len() {
                    return Err(FfsError::Format("oob".into()));
                }
                (**buf).copy_from_slice(&bytes[offset..end]);
                offset = end;
            }
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
        reads: AtomicUsize,
        writes: Mutex<Vec<BlockNumber>>,
        sync_calls: AtomicUsize,
    }

    impl<D: BlockDevice> CountingBlockDevice<D> {
        fn new(inner: D) -> Self {
            Self {
                inner,
                reads: AtomicUsize::new(0),
                writes: Mutex::new(Vec::new()),
                sync_calls: AtomicUsize::new(0),
            }
        }

        fn read_count(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
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

    #[derive(Debug, Default)]
    struct RecordingRepairFlushLifecycle {
        calls: Mutex<Vec<Vec<BlockNumber>>>,
    }

    impl RecordingRepairFlushLifecycle {
        fn call_count(&self) -> usize {
            self.calls.lock().len()
        }

        fn flushed_blocks(&self) -> Vec<Vec<BlockNumber>> {
            self.calls.lock().clone()
        }
    }

    impl RepairFlushLifecycle for RecordingRepairFlushLifecycle {
        fn on_flush_committed(&self, _cx: &Cx, blocks: &[BlockNumber]) -> Result<()> {
            self.calls.lock().push(blocks.to_vec());
            Ok(())
        }
    }

    impl<D: BlockDevice> BlockDevice for CountingBlockDevice<D> {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.reads.fetch_add(1, Ordering::SeqCst);
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

    #[derive(Debug)]
    struct PausingFirstReadBlockDevice<D: BlockDevice> {
        inner: D,
        target: BlockNumber,
        reads: AtomicUsize,
        first_read_started: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        first_read_release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl<D: BlockDevice> PausingFirstReadBlockDevice<D> {
        fn new(
            inner: D,
            target: BlockNumber,
            first_read_started: std::sync::mpsc::Sender<()>,
            first_read_release: std::sync::mpsc::Receiver<()>,
        ) -> Self {
            Self {
                inner,
                target,
                reads: AtomicUsize::new(0),
                first_read_started: Mutex::new(Some(first_read_started)),
                first_read_release: Mutex::new(first_read_release),
            }
        }

        fn read_count(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl<D: BlockDevice> BlockDevice for PausingFirstReadBlockDevice<D> {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if block == self.target {
                let notify = self.first_read_started.lock().take();
                if let Some(notify) = notify {
                    notify.send(()).expect("notify first read started");
                    self.first_read_release
                        .lock()
                        .recv_timeout(PAGE_LOCK_WAITER_TIMEOUT)
                        .expect("release first read before timeout");
                }
            }

            self.inner.read_block(cx, block)
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.inner.write_block(cx, block, data)
        }

        fn block_size(&self) -> u32 {
            self.inner.block_size()
        }

        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
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
    fn byte_block_device_reads_contiguous_blocks_with_one_byte_read() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(16);
        let dev = ByteBlockDevice::new(mem, 4).expect("device");

        dev.write_block(&cx, BlockNumber(0), &[0, 1, 2, 3])
            .expect("write block 0");
        dev.write_block(&cx, BlockNumber(1), &[4, 5, 6, 7])
            .expect("write block 1");
        dev.write_block(&cx, BlockNumber(2), &[8, 9, 10, 11])
            .expect("write block 2");

        let mut bufs = vec![BlockBuf::new(Vec::new()), BlockBuf::new(Vec::new())];
        dev.read_contiguous_blocks(&cx, BlockNumber(1), &mut bufs)
            .expect("contiguous read");

        assert_eq!(bufs[0].as_slice(), &[4, 5, 6, 7]);
        assert_eq!(bufs[1].as_slice(), &[8, 9, 10, 11]);
        assert_eq!(dev.inner().read_count(), 1);
    }

    #[test]
    fn byte_block_device_reuses_sized_contiguous_buffers() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(16);
        let dev = ByteBlockDevice::new(mem, 4).expect("device");

        dev.write_block(&cx, BlockNumber(1), &[4, 5, 6, 7])
            .expect("write block 1");
        dev.write_block(&cx, BlockNumber(2), &[8, 9, 10, 11])
            .expect("write block 2");

        let mut bufs = vec![BlockBuf::new(vec![0xAA; 4]), BlockBuf::new(vec![0xBB; 4])];
        dev.read_contiguous_blocks(&cx, BlockNumber(1), &mut bufs)
            .expect("contiguous read");

        assert_eq!(bufs[0].as_slice(), &[4, 5, 6, 7]);
        assert_eq!(bufs[1].as_slice(), &[8, 9, 10, 11]);
        assert_eq!(dev.inner().read_count(), 1);
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
    fn block_buf_clone_ref_is_zero_copy_cow() {
        let mut buf = BlockBuf::new(vec![1, 2, 3, 4]);
        let clone = buf.clone_ref();
        assert_eq!(clone.as_slice(), &[1, 2, 3, 4]);

        // Mutating one shared reference triggers COW and preserves the clone.
        buf.make_mut()[0] = 9;
        assert_eq!(buf.as_slice(), &[9, 2, 3, 4]);
        assert_eq!(clone.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn block_buf_into_inner_round_trip() {
        let buf = BlockBuf::new(vec![7, 8, 9]);
        assert_eq!(buf.clone_ref().as_slice(), &[7, 8, 9]);
        assert_eq!(buf.into_inner(), vec![7, 8, 9]);
    }

    #[test]
    fn aligned_vec_respects_requested_alignment() {
        let aligned = AlignedVec::new(4096, 4096);
        assert_eq!(aligned.len(), 4096);
        assert_eq!(aligned.alignment(), 4096);
        assert_eq!((aligned.as_slice().as_ptr() as usize) % 4096, 0);
    }

    #[test]
    fn block_buf_uses_page_alignment() {
        let buf = BlockBuf::new(vec![0xAA; 4096]);
        assert_eq!(buf.alignment(), DEFAULT_BLOCK_ALIGNMENT);
        assert_eq!(
            (buf.as_slice().as_ptr() as usize) % DEFAULT_BLOCK_ALIGNMENT,
            0
        );
    }

    #[test]
    fn vectored_io_round_trip_is_correct() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");

        let blocks = [BlockNumber(1), BlockNumber(3)];
        let writes = [
            BlockBuf::new(vec![0x11; 4096]),
            BlockBuf::new(vec![0x22; 4096]),
        ];
        dev.write_vectored(&blocks, &writes, &cx)
            .expect("vectored write");

        let mut reads = [BlockBuf::new(Vec::new()), BlockBuf::new(Vec::new())];
        dev.read_vectored(&blocks, &mut reads, &cx)
            .expect("vectored read");

        assert_eq!(reads[0].as_slice(), writes[0].as_slice());
        assert_eq!(reads[1].as_slice(), writes[1].as_slice());
    }

    #[test]
    fn vectored_io_rejects_length_mismatch() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let blocks = [BlockNumber(0), BlockNumber(1)];
        let writes = [BlockBuf::new(vec![0x44; 4096])];

        let err = dev
            .write_vectored(&blocks, &writes, &cx)
            .expect_err("length mismatch should fail");
        assert!(matches!(err, FfsError::Format(_)));
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

    #[cfg(not(feature = "s3fifo"))]
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

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_one_hit_wonders_are_filtered_to_ghost() {
        let mut state = ArcState::new(16);

        for key in 0..12_u64 {
            s3_access(&mut state, BlockNumber(key));
        }

        assert!(
            state.t2.is_empty(),
            "single touches should not stay in main"
        );
        assert!(
            state.b1_len() > 0,
            "single-touch entries should be demoted into ghost queue"
        );
        assert!(state.resident_len() <= state.capacity);
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_ghost_hit_promotes_entry_to_main() {
        let mut state = ArcState::new(12);

        for key in 0..9_u64 {
            s3_access(&mut state, BlockNumber(key));
        }
        let ghost_key = state.b1_front_live().expect("ghost entry");
        s3_access(&mut state, ghost_key);

        assert!(
            state.t2.contains(&ghost_key),
            "ghost-hit entry should be readmitted into main"
        );
        assert_eq!(state.loc.get(&ghost_key), Some(&ArcList::T2));
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_resident_never_exceeds_capacity() {
        let mut state = ArcState::new(10);

        for i in 0..1_000_u64 {
            let key = BlockNumber((i.wrapping_mul(37).wrapping_add(11)) % 23);
            s3_access(&mut state, key);
            assert!(
                state.resident_len() <= state.capacity,
                "resident set exceeded capacity at iteration {i}"
            );
        }
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_new_entry_goes_to_small_queue() {
        let mut state = ArcState::new(20);
        // First access of a new key goes to T1 (small queue).
        s3_access(&mut state, BlockNumber(42));
        assert!(state.t1.contains(&BlockNumber(42)));
        assert_eq!(state.loc.get(&BlockNumber(42)), Some(&ArcList::T1));
        assert!(!state.t2.contains(&BlockNumber(42)));
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_capacity_split_ratios() {
        // Verify 10/90 split for various capacities.
        let (s, m, g) = ArcState::s3_capacity_split(100);
        assert_eq!(s, 10);
        assert_eq!(m, 90);
        assert_eq!(g, 100);

        let (s, m, g) = ArcState::s3_capacity_split(10);
        assert_eq!(s, 1);
        assert_eq!(m, 9);
        assert_eq!(g, 10);

        // Edge case: capacity 1.
        let (s, m, _g) = ArcState::s3_capacity_split(1);
        assert_eq!(s, 1);
        assert_eq!(m, 0);
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_access_count_increments_on_hit() {
        let mut state = ArcState::new(20);
        s3_access(&mut state, BlockNumber(5));
        assert_eq!(s3_access_count(&state, BlockNumber(5)), Some(0));

        // Second access: on_hit increments count.
        s3_access(&mut state, BlockNumber(5));
        assert_eq!(s3_access_count(&state, BlockNumber(5)), Some(1));

        // Third access: increments again.
        s3_access(&mut state, BlockNumber(5));
        assert_eq!(s3_access_count(&state, BlockNumber(5)), Some(2));
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_accessed_entry_promoted_from_small_to_main() {
        // With capacity 10: small_capacity=1, main_capacity=9.
        let mut state = ArcState::new(10);

        // Insert key 0 into small queue.
        s3_access(&mut state, BlockNumber(0));
        assert!(state.t1.contains(&BlockNumber(0)));

        // Touch key 0 again to set access_count=1.
        s3_access(&mut state, BlockNumber(0));

        // Insert key 1 — this will overflow small queue.
        // Since key 0 has access_count > 0, it should be promoted to main.
        s3_access(&mut state, BlockNumber(1));

        assert!(
            state.t2.contains(&BlockNumber(0)),
            "block 0 with access_count>0 should be promoted to main"
        );
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_untouched_entry_evicted_from_small_to_ghost() {
        // With capacity 10: small_capacity=1.
        let mut state = ArcState::new(10);

        s3_access(&mut state, BlockNumber(0)); // small queue
        s3_access(&mut state, BlockNumber(1)); // overflows small, key 0 (access_count=0) -> ghost

        assert!(
            state.b1_contains_live(BlockNumber(0)),
            "block 0 with access_count=0 should be moved to ghost"
        );
        assert!(
            !state.resident.contains_key(&BlockNumber(0)),
            "evicted block should not remain in resident set"
        );
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_small_queue_evicts_in_fifo_order() {
        // With capacity 20: small_capacity=2.
        let mut state = ArcState::new(20);

        for key in 0..5_u64 {
            s3_access(&mut state, BlockNumber(key));
        }

        let expected_ghost = VecDeque::from(vec![BlockNumber(0), BlockNumber(1), BlockNumber(2)]);
        let actual_ghost: VecDeque<_> = state.b1_live_keys().collect();
        assert_eq!(
            actual_ghost, expected_ghost,
            "small-queue victims should enter ghost in FIFO order"
        );
        assert!(
            state.t2.is_empty(),
            "single-touch keys should not be promoted to main during small-queue eviction"
        );
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_second_chance_rotation_in_main() {
        // With capacity 10: small_capacity=1, main_capacity=9.
        let mut state = ArcState::new(10);

        // Fill main queue: insert + touch keys 0..9 to promote them.
        for key in 0..10_u64 {
            s3_access(&mut state, BlockNumber(key));
            s3_access(&mut state, BlockNumber(key)); // touch to set access_count=1
        }

        // Count main queue entries.
        let main_count = state.t2.len();
        assert!(main_count > 0, "main queue should have entries");

        // Push more entries to force main eviction.
        // Blocks with access_count > 0 get second-chance (rotated, count decremented).
        for key in 100..120_u64 {
            s3_access(&mut state, BlockNumber(key));
        }

        // Verify capacity held.
        assert!(state.resident_len() <= state.capacity);
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_ghost_queue_bounded() {
        let mut state = ArcState::new(5);

        // Insert many unique keys to generate ghost entries.
        for key in 0..100_u64 {
            s3_access(&mut state, BlockNumber(key));
        }

        assert!(
            state.b1_len() <= state.ghost_capacity,
            "live ghost queue {} should not exceed ghost_capacity {}",
            state.b1_len(),
            state.ghost_capacity
        );
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_hot_entries_survive_sequential_scan() {
        // With capacity 20: small=2, main=18.
        let mut state = ArcState::new(20);

        // Create 5 "hot" keys with multiple touches.
        // They may end up in T1 or T2 depending on overflow timing.
        for key in 0..5_u64 {
            s3_access(&mut state, BlockNumber(key));
            s3_access(&mut state, BlockNumber(key));
            s3_access(&mut state, BlockNumber(key));
        }

        // Count how many hot keys are resident (T1 or T2).
        let hot_before: usize = (0..5_u64)
            .filter(|k| state.resident.contains_key(&BlockNumber(*k)))
            .count();
        assert!(
            hot_before >= 2,
            "at least 2 hot keys should be resident before scan"
        );

        // Now scan through 30 unique one-touch keys.
        for key in 100..130_u64 {
            s3_access(&mut state, BlockNumber(key));
        }

        // Hot keys with high access counts should survive via second-chance.
        let hot_after: usize = (0..5_u64)
            .filter(|k| state.resident.contains_key(&BlockNumber(*k)))
            .count();
        assert!(
            hot_after >= 2,
            "at least 2 of 5 hot keys should survive the scan, got {hot_after}"
        );
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_sequential_scan_cold_keys_stay_out_of_main() {
        let mut state = ArcState::new(20);
        let hot_keys: Vec<BlockNumber> = (0..8_u64).map(BlockNumber).collect();

        for &key in &hot_keys {
            for _ in 0..3 {
                s3_access(&mut state, key);
            }
        }
        assert!(
            hot_keys.iter().any(|key| state.t2.contains(key)),
            "warming should place at least one hot key into main queue"
        );

        for key in 100..160_u64 {
            s3_access(&mut state, BlockNumber(key));
        }

        for key in 100..160_u64 {
            assert!(
                !state.t2.contains(&BlockNumber(key)),
                "cold scan key {key} should remain filtered from main queue"
            );
        }
        assert!(
            state.t2.iter().all(|key| hot_keys.contains(key)),
            "main queue should only contain hot keys after scan"
        );
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_metrics_track_hits_misses_evictions() {
        // Use capacity 20 (small=2, main=18) so entries stay resident.
        let mut state = ArcState::new(20);

        // 5 misses.
        for key in 0..5_u64 {
            s3_access(&mut state, BlockNumber(key));
        }
        assert_eq!(state.misses, 5);
        assert_eq!(state.hits, 0);

        // Access resident keys again — should be hits.
        // Only keys still in resident will produce hits.
        let hits_before = state.hits;
        for key in 0..5_u64 {
            s3_access(&mut state, BlockNumber(key));
        }
        let new_hits = state.hits - hits_before;
        assert!(new_hits > 0, "some accesses to recent keys should be hits");

        // Force evictions by exceeding capacity.
        for key in 100..130_u64 {
            s3_access(&mut state, BlockNumber(key));
        }
        assert!(state.evictions > 0, "evictions should be tracked");
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_main_eviction_when_small_is_empty() {
        // When small queue is empty, continued insertions should still evict
        // from the main queue. Capacity 10: small=1, main=9.
        let mut state = ArcState::new(10);

        // Fill with keys, touching each to promote to main.
        for key in 0..10_u64 {
            s3_access(&mut state, BlockNumber(key));
            s3_access(&mut state, BlockNumber(key)); // touch -> access_count=1
        }

        // Drain the small queue explicitly: all promoted entries are in main.
        // Now add new keys beyond capacity. Some main entries must be evicted.
        let evictions_before = state.evictions;
        for key in 50..65_u64 {
            s3_access(&mut state, BlockNumber(key));
        }

        assert!(
            state.evictions > evictions_before,
            "evictions should occur from main when small empties"
        );
        assert!(state.resident_len() <= state.capacity);
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_mixed_workload_hot_retained_scan_evicted() {
        // Simulate a realistic mixed workload: 10 hot keys accessed repeatedly,
        // interleaved with 100 unique scan keys. Hot keys should be retained.
        let mut state = ArcState::new(30); // small=3, main=27

        let hot_keys: Vec<BlockNumber> = (0..10_u64).map(BlockNumber).collect();
        let scan_keys: Vec<BlockNumber> = (1000..1100_u64).map(BlockNumber).collect();

        // Warm up hot keys with 5 accesses each.
        for &k in &hot_keys {
            for _ in 0..5 {
                s3_access(&mut state, k);
            }
        }

        // Interleave scan keys with occasional hot key re-access.
        for (i, &sk) in scan_keys.iter().enumerate() {
            s3_access(&mut state, sk);
            if i % 10 == 0 {
                // Re-touch a hot key periodically.
                let hk = hot_keys[i % hot_keys.len()];
                s3_access(&mut state, hk);
            }
        }

        // Count how many hot keys survived.
        let hot_survived: usize = hot_keys
            .iter()
            .filter(|k| state.resident.contains_key(k))
            .count();

        // Count how many scan keys are resident.
        let scan_resident: usize = scan_keys
            .iter()
            .filter(|k| state.resident.contains_key(k))
            .count();

        // Scan resistance: hot keys should dominate.
        assert!(
            hot_survived >= 5,
            "at least half of hot keys should survive, got {hot_survived}/10"
        );
        assert!(
            scan_resident < state.capacity,
            "scan keys should not fill the entire cache"
        );
        assert!(state.resident_len() <= state.capacity);
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_arc_cache_read_path_preserves_written_bytes() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2_048);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 500).expect("cache");
        let block_len = usize::try_from(cache.block_size()).expect("block size fits usize");

        for block in 0_u64..1_000_u64 {
            let byte = u8::try_from((block.wrapping_mul(31)) % 251).expect("value <= 250");
            cache
                .write_block(&cx, BlockNumber(block), &vec![byte; block_len])
                .expect("write");
        }

        for block in 0_u64..1_000_u64 {
            let expected = u8::try_from((block.wrapping_mul(31)) % 251).expect("value <= 250");
            let buf = cache.read_block(&cx, BlockNumber(block)).expect("read");
            assert!(buf.as_slice().iter().all(|byte| *byte == expected));
        }

        for block in (0_u64..1_000_u64).step_by(3) {
            let updated = u8::try_from((block.wrapping_mul(17).wrapping_add(13)) % 251)
                .expect("value <= 250");
            cache
                .write_block(&cx, BlockNumber(block), &vec![updated; block_len])
                .expect("rewrite");
            let buf = cache.read_block(&cx, BlockNumber(block)).expect("re-read");
            assert!(buf.as_slice().iter().all(|byte| *byte == updated));
        }

        let metrics = cache.metrics();
        assert!(metrics.resident <= metrics.capacity);
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_arc_cache_large_hot_read_golden_report() {
        const BLOCK_SIZE: u32 = 4096;
        const HOT_BLOCKS: u64 = 32;
        const ROUNDS: usize = 4;

        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(BLOCK_SIZE as usize * 128);
        let dev = ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device");
        let block_len = usize::try_from(dev.block_size()).expect("block size fits usize");

        for block in 0_u64..HOT_BLOCKS {
            let fill = u8::try_from(block.wrapping_mul(37).wrapping_add(11) % 251)
                .expect("fill byte fits");
            dev.write_block(&cx, BlockNumber(block), &vec![fill; block_len])
                .expect("seed block");
        }

        let cache = ArcCache::new(dev, 512).expect("cache");
        let mut payload_sha = Sha256::new();
        let mut first_byte_sum = 0_u64;
        for _ in 0..ROUNDS {
            for block in 0_u64..HOT_BLOCKS {
                let buf = cache.read_block(&cx, BlockNumber(block)).expect("hot read");
                payload_sha.update(buf.as_slice());
                first_byte_sum = first_byte_sum.saturating_add(u64::from(buf.as_slice()[0]));
            }
        }

        let payload_sha_hex = {
            let mut hex = String::with_capacity(64);
            for byte in payload_sha.finalize() {
                use std::fmt::Write as _;
                write!(&mut hex, "{byte:02x}").expect("format payload sha256");
            }
            hex
        };
        let metrics = cache.metrics();
        let report = format!(
            "BLOCK_CACHE_HOT_READ_GOLDEN|rounds={ROUNDS}|blocks={HOT_BLOCKS}|hits={}|misses={}|resident={}|capacity={}|first_byte_sum={first_byte_sum}|payload_sha256={payload_sha_hex}",
            metrics.hits, metrics.misses, metrics.resident, metrics.capacity
        );
        let report_sha = sha256_hex(&report);
        println!("{report}|sha256={report_sha}");
        assert_eq!(
            report_sha,
            "63bf85d8f27125241944f9a9b1713367bc7da9992af55e950d3bb009d04e21e5"
        );
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_arc_cache_scan_resistance_on_read_path() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4_096);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 256).expect("cache");

        let hot_set: Vec<BlockNumber> = (0_u64..64_u64).map(BlockNumber).collect();
        for _ in 0..10 {
            for block in &hot_set {
                let _ = cache.read_block(&cx, *block).expect("warm hot");
            }
        }

        for block in 512_u64..2_560_u64 {
            let _ = cache
                .read_block(&cx, BlockNumber(block))
                .expect("scan cold");
        }

        let hits_before_probe = cache.metrics().hits;
        for block in &hot_set {
            let _ = cache.read_block(&cx, *block).expect("probe hot");
        }
        let hits_after_probe = cache.metrics().hits;
        let recovered_hot_hits = hits_after_probe.saturating_sub(hits_before_probe);
        assert!(
            recovered_hot_hits >= 32,
            "expected at least half of hot set to survive scan, got {recovered_hot_hits}/64 hits"
        );

        let metrics = cache.metrics();
        assert!(metrics.resident <= metrics.capacity);
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_arc_cache_scan_bypass_leaves_one_pass_scan_uncached() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 256);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 32).expect("cache");

        for block in 0_u64..128_u64 {
            let buf = cache
                .read_block(&cx, BlockNumber(block))
                .expect("scan read");
            assert_eq!(buf.len(), 4096);
        }

        let metrics = cache.metrics();
        assert_eq!(metrics.hits, 0);
        assert_eq!(metrics.misses, 128);
        assert!(
            metrics.resident <= 2,
            "scan bypass should avoid filling resident queue, got {}",
            metrics.resident
        );
        assert_eq!(
            metrics.b1_len, 32,
            "bypassed scan should keep only bounded ghost history"
        );

        let guard = cache.state.lock();
        assert!(guard.resident.contains_key(&BlockNumber(0)));
        assert!(guard.resident.contains_key(&BlockNumber(1)));
        assert!(!guard.resident.contains_key(&BlockNumber(127)));
        drop(guard);
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_arc_cache_ghost_reaccess_promotes_to_main_queue() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 128);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 12).expect("cache");

        for block in 0_u64..9_u64 {
            let _ = cache.read_block(&cx, BlockNumber(block)).expect("read");
        }
        let ghost_key = {
            let guard = cache.state.lock();
            guard.b1_front_live().expect("ghost entry")
        };

        let _ = cache.read_block(&cx, ghost_key).expect("ghost re-read");
        let guard = cache.state.lock();
        assert!(
            guard.t2.contains(&ghost_key),
            "ghost-hit key should be promoted into main queue"
        );
        assert_eq!(guard.loc.get(&ghost_key), Some(&ArcList::T2));
        drop(guard);
    }

    #[cfg(feature = "s3fifo")]
    #[test]
    fn s3fifo_arc_cache_capacity_invariant_under_random_access() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2_048);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 128).expect("cache");
        let mut rng_state = 0xA5A5_5A5A_9E37_79B9_u64;

        for _ in 0..100_000_u64 {
            rng_state = rng_state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let block = BlockNumber(rng_state % 2_048);
            let _ = cache.read_block(&cx, block).expect("random read");
        }

        let metrics = cache.metrics();
        assert!(
            metrics.resident <= metrics.capacity,
            "resident set {} exceeded capacity {}",
            metrics.resident,
            metrics.capacity
        );
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
    fn arc_cache_explicit_evict_skips_dirty_block() {
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
        assert_eq!(cache.dirty_count(), 1);
        let guard = cache.state.lock();
        assert!(guard.resident.contains_key(&BlockNumber(0)));
        drop(guard);
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
    fn arc_cache_failed_flush_retry_does_not_resurrect_stale_payload() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let faulted = FaultInjector::new(dev, 0xA11CE);
        faulted.fail_on_write(BlockNumber(0), FaultMode::OneShot);
        let cache =
            ArcCache::new_with_policy(faulted, 2, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[0x11; 4096])
            .expect("initial write");
        cache
            .flush_dirty(&cx)
            .expect_err("one-shot injected write fault should fail first flush");
        assert_eq!(cache.dirty_count(), 1);

        cache
            .write_block(&cx, BlockNumber(0), &[0x22; 4096])
            .expect("overwrite after failed flush");
        cache.sync(&cx).expect("sync latest payload");

        assert_eq!(cache.dirty_count(), 0);
        let persisted = cache
            .inner()
            .inner
            .read_block(&cx, BlockNumber(0))
            .expect("read backing device");
        assert_eq!(persisted.as_slice(), &[0x22; 4096]);
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
                ..FlushDaemonConfig::default()
            })
            .expect("start daemon");

        let final_dirty_count = wait_until_dirty_count(&cache, 0, Duration::from_millis(400));
        daemon.shutdown();

        assert_eq!(
            final_dirty_count, 0,
            "dirty count did not reach zero within 400ms; final dirty count={final_dirty_count}"
        );
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
    fn flush_daemon_shutdown_wakes_sleeping_interval_promptly() -> Result<()> {
        use std::sync::Arc as StdArc;

        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096)?;
        let counted = CountingBlockDevice::new(dev);
        let cache = StdArc::new(ArcCache::new_with_policy(
            counted,
            8,
            ArcWritePolicy::WriteBack,
        )?);
        let interval = Duration::from_secs(2);
        let daemon = cache.start_flush_daemon(FlushDaemonConfig {
            interval,
            batch_size: 1,
            ..FlushDaemonConfig::default()
        })?;

        let started = Instant::now();
        daemon.shutdown();
        let elapsed = started.elapsed();

        if elapsed >= interval / 4 {
            return Err(FfsError::Format(format!(
                "shutdown should wake the daemon instead of waiting for interval, elapsed={elapsed:?}"
            )));
        }
        if cache.dirty_count() != 0 {
            return Err(FfsError::Format(format!(
                "shutdown should leave no dirty blocks, dirty_count={}",
                cache.dirty_count()
            )));
        }
        if cache.inner().write_count() != 0 {
            return Err(FfsError::Format(format!(
                "idle shutdown should not write blocks, write_count={}",
                cache.inner().write_count()
            )));
        }
        Ok(())
    }

    #[test]
    fn flush_daemon_reduces_batch_size_under_budget_pressure() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 8, ArcWritePolicy::WriteBack).expect("cache");

        for i in 0..4_u64 {
            cache
                .write_block(&cx, BlockNumber(i), &[0xA5; 4096])
                .expect("write");
        }
        assert_eq!(cache.dirty_count(), 4);

        let low_budget_cx =
            Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(8));
        let config = FlushDaemonConfig {
            interval: Duration::from_millis(1),
            batch_size: 4,
            reduced_batch_size: 1,
            budget_poll_quota_threshold: 16,
            budget_yield_sleep: Duration::ZERO,
            high_watermark: 0.99,
            critical_watermark: 1.0,
        };
        let mut daemon_throttled = false;
        cache.run_flush_daemon_cycle(&low_budget_cx, &config, 1, &mut daemon_throttled);

        assert!(daemon_throttled);
        assert_eq!(cache.inner().write_count(), 1);
        assert_eq!(cache.dirty_count(), 3);
    }

    #[test]
    fn flush_daemon_budget_yield_honors_expired_cx_without_sleeping() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 8, ArcWritePolicy::WriteBack).expect("cache");

        for i in 0..4_u64 {
            cache
                .write_block(&cx, BlockNumber(i), &[0xC3; 4096])
                .expect("write");
        }
        assert_eq!(cache.dirty_count(), 4);

        let expired = asupersync::Budget::new().with_deadline(asupersync::types::Time::ZERO);
        let expired_cx = Cx::for_testing_with_budget(expired);
        let yield_sleep = Duration::from_millis(250);
        let config = FlushDaemonConfig {
            interval: Duration::from_millis(1),
            batch_size: 4,
            reduced_batch_size: 1,
            budget_poll_quota_threshold: u32::MAX,
            budget_yield_sleep: yield_sleep,
            high_watermark: 0.99,
            critical_watermark: 1.0,
        };
        let mut daemon_throttled = false;

        let start = Instant::now();
        cache.run_flush_daemon_cycle(&expired_cx, &config, 1, &mut daemon_throttled);
        let elapsed = start.elapsed();

        assert!(daemon_throttled);
        assert!(
            elapsed < yield_sleep / 2,
            "expired Cx should skip flush yield sleep promptly, elapsed={elapsed:?}"
        );
        assert_eq!(cache.inner().write_count(), 0);
        assert_eq!(cache.dirty_count(), 4);
    }

    #[test]
    fn flush_daemon_budget_yield_observes_mid_sleep_cancellation() {
        use std::thread;

        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 8, ArcWritePolicy::WriteBack).expect("cache");

        for i in 0..4_u64 {
            cache
                .write_block(&cx, BlockNumber(i), &[0xD4; 4096])
                .expect("write");
        }
        assert_eq!(cache.dirty_count(), 4);

        let low_budget_cx =
            Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(8));
        let cancel_cx = low_budget_cx.clone();
        let yield_sleep = Duration::from_millis(250);
        let config = FlushDaemonConfig {
            interval: Duration::from_millis(1),
            batch_size: 4,
            reduced_batch_size: 1,
            budget_poll_quota_threshold: 16,
            budget_yield_sleep: yield_sleep,
            high_watermark: 0.99,
            critical_watermark: 1.0,
        };
        let mut daemon_throttled = false;

        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(15));
            cancel_cx.set_cancel_requested(true);
        });

        let start = Instant::now();
        cache.run_flush_daemon_cycle(&low_budget_cx, &config, 1, &mut daemon_throttled);
        let elapsed = start.elapsed();
        canceller.join().expect("canceller thread should finish");

        assert!(daemon_throttled);
        assert!(
            elapsed < yield_sleep / 2,
            "cancelled Cx should interrupt flush yield sleep promptly, elapsed={elapsed:?}"
        );
        assert!(
            cache.inner().write_count() <= 1,
            "cancelled cycle should not flush more than one reduced batch"
        );
        assert!(cache.dirty_count() >= 3);
    }

    #[test]
    fn foreground_reads_remain_responsive_under_budget_pressure() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 32);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 16, ArcWritePolicy::WriteBack).expect("cache");

        for i in 0..8_u64 {
            cache
                .write_block(&cx, BlockNumber(i), &[0x5A; 4096])
                .expect("write");
        }
        assert_eq!(cache.dirty_count(), 8);

        let low_budget_cx =
            Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(8));
        let config = FlushDaemonConfig {
            interval: Duration::from_millis(1),
            batch_size: 8,
            reduced_batch_size: 1,
            budget_poll_quota_threshold: 16,
            budget_yield_sleep: Duration::from_millis(1),
            ..FlushDaemonConfig::default()
        };
        let mut daemon_throttled = false;
        cache.run_flush_daemon_cycle(&low_budget_cx, &config, 1, &mut daemon_throttled);
        assert!(daemon_throttled);

        let start = Instant::now();
        let _ = cache
            .read_block(&cx, BlockNumber(0))
            .expect("foreground read");
        let elapsed = start.elapsed();
        assert!(
            elapsed <= Duration::from_millis(20),
            "foreground read exceeded latency bound under pressure: {elapsed:?}"
        );
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
        for i in 0..1000_u64 {
            let fill = u8::try_from(i & 0xFF).expect("u8");
            cache
                .write_block(&cx, BlockNumber(i), &vec![fill; 4096])
                .expect("write");
        }
        assert_eq!(cache.dirty_count(), 1000);

        let daemon = cache
            .start_flush_daemon(FlushDaemonConfig {
                interval,
                batch_size: 256,
                ..FlushDaemonConfig::default()
            })
            .expect("start daemon");

        let timeout = interval.saturating_mul(2) + Duration::from_millis(30);
        let final_dirty_count = wait_until_dirty_count(&cache, 0, timeout);
        daemon.shutdown();

        assert_eq!(
            final_dirty_count, 0,
            "dirty count did not reach zero within {timeout:?}; final dirty count={final_dirty_count}"
        );
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
    fn flush_batch_notifies_repair_lifecycle_with_flushed_blocks() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let repair_lifecycle = StdArc::new(RecordingRepairFlushLifecycle::default());
        let cache = ArcCache::new_with_policy_and_repair_lifecycle(
            counted,
            8,
            ArcWritePolicy::WriteBack,
            repair_lifecycle.clone(),
        )
        .expect("cache");

        cache
            .write_block(&cx, BlockNumber(1), &[0xAA; 4096])
            .expect("write block 1");
        cache
            .write_block(&cx, BlockNumber(2), &[0xBB; 4096])
            .expect("write block 2");

        let flushed = cache.flush_dirty_batch(&cx, 8).expect("flush dirty batch");
        assert_eq!(flushed, 2);
        assert_eq!(repair_lifecycle.call_count(), 1);
        assert_eq!(
            repair_lifecycle.flushed_blocks(),
            vec![vec![BlockNumber(1), BlockNumber(2)]]
        );
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

        let final_dirty_count = wait_until_dirty_count(&cache, 0, Duration::from_millis(600));
        daemon.shutdown();

        assert_eq!(
            final_dirty_count, 0,
            "dirty count did not reach zero within 600ms; final dirty count={final_dirty_count}"
        );
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

    // ── Transaction staging/commit/abort edge-case tests ────────────────

    #[test]
    fn stage_txn_write_rejects_wrong_data_size() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new_with_policy(dev, 4, ArcWritePolicy::WriteBack).expect("cache");

        // Too short
        let err = cache.stage_txn_write(&cx, TxnId(1), BlockNumber(0), &[0xAA; 100]);
        assert!(err.is_err());
        // Too long
        let err = cache.stage_txn_write(&cx, TxnId(1), BlockNumber(0), &[0xAA; 8192]);
        assert!(err.is_err());
        // Exact size succeeds
        cache
            .stage_txn_write(&cx, TxnId(1), BlockNumber(0), &[0xAA; 4096])
            .expect("exact size should succeed");
    }

    #[test]
    fn commit_staged_txn_returns_zero_for_empty_staging() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new_with_policy(dev, 4, ArcWritePolicy::WriteBack).expect("cache");

        // Commit a txn that was never staged
        let committed = cache
            .commit_staged_txn(&cx, TxnId(999), CommitSeq(1))
            .expect("commit empty");
        assert_eq!(committed, 0);
    }

    #[test]
    fn abort_staged_txn_returns_zero_for_unknown_txn() {
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new_with_policy(dev, 4, ArcWritePolicy::WriteBack).expect("cache");

        let discarded = cache.abort_staged_txn(TxnId(42));
        assert_eq!(discarded, 0);
    }

    #[test]
    fn commit_multiple_blocks_in_single_txn() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 8, ArcWritePolicy::WriteBack).expect("cache");

        let txn = TxnId(10);
        for block in 0..5_u64 {
            cache
                .stage_txn_write(
                    &cx,
                    txn,
                    BlockNumber(block),
                    &[u8::try_from(block).unwrap(); 4096],
                )
                .expect("stage");
        }
        assert_eq!(cache.dirty_count(), 5);
        // Staged but not committed — should not flush
        cache.flush_dirty(&cx).expect("flush");
        assert_eq!(cache.inner().write_count(), 0);

        let committed = cache
            .commit_staged_txn(&cx, txn, CommitSeq(1))
            .expect("commit");
        assert_eq!(committed, 5);

        // All blocks should be readable from cache
        for block in 0..5_u64 {
            let buf = cache.read_block(&cx, BlockNumber(block)).expect("read");
            assert_eq!(buf.as_slice()[0], u8::try_from(block).unwrap());
        }

        // Now flush should write all 5 blocks
        cache.flush_dirty(&cx).expect("flush after commit");
        assert_eq!(cache.inner().write_count(), 5);
        assert_eq!(cache.dirty_count(), 0);
    }

    #[test]
    fn commit_overwrites_existing_cached_block() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 8, ArcWritePolicy::WriteBack).expect("cache");

        // Pre-populate block 0 via direct write
        cache
            .write_block(&cx, BlockNumber(0), &[0x11; 4096])
            .expect("initial write");

        // Stage a txn write to the same block with different data
        cache
            .stage_txn_write(&cx, TxnId(50), BlockNumber(0), &[0x22; 4096])
            .expect("stage overwrite");
        cache
            .commit_staged_txn(&cx, TxnId(50), CommitSeq(50))
            .expect("commit overwrite");

        // Read should return the txn-committed data, not the original
        let buf = cache
            .read_block(&cx, BlockNumber(0))
            .expect("read after overwrite");
        assert_eq!(buf.as_slice(), &[0x22; 4096]);
    }

    #[test]
    fn stage_commit_abort_interleaved_txns() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let cache =
            ArcCache::new_with_policy(counted, 8, ArcWritePolicy::WriteBack).expect("cache");

        // Stage txn A on blocks 0,1
        cache
            .stage_txn_write(&cx, TxnId(1), BlockNumber(0), &[0xAA; 4096])
            .expect("stage A-0");
        cache
            .stage_txn_write(&cx, TxnId(1), BlockNumber(1), &[0xAB; 4096])
            .expect("stage A-1");

        // Stage txn B on blocks 2,3
        cache
            .stage_txn_write(&cx, TxnId(2), BlockNumber(2), &[0xBB; 4096])
            .expect("stage B-2");
        cache
            .stage_txn_write(&cx, TxnId(2), BlockNumber(3), &[0xBC; 4096])
            .expect("stage B-3");

        // Commit A, abort B
        let committed_a = cache
            .commit_staged_txn(&cx, TxnId(1), CommitSeq(1))
            .expect("commit A");
        assert_eq!(committed_a, 2);
        let discarded_b = cache.abort_staged_txn(TxnId(2));
        assert_eq!(discarded_b, 2);

        // A's blocks should be readable
        let buf0 = cache.read_block(&cx, BlockNumber(0)).expect("read 0");
        assert_eq!(buf0.as_slice(), &[0xAA; 4096]);
        let buf1 = cache.read_block(&cx, BlockNumber(1)).expect("read 1");
        assert_eq!(buf1.as_slice(), &[0xAB; 4096]);

        // B's blocks should read as zeros (never committed)
        let buf2 = cache.read_block(&cx, BlockNumber(2)).expect("read 2");
        assert_eq!(buf2.as_slice(), &[0_u8; 4096]);
        let buf3 = cache.read_block(&cx, BlockNumber(3)).expect("read 3");
        assert_eq!(buf3.as_slice(), &[0_u8; 4096]);

        // Flush should only write A's blocks
        cache.flush_dirty(&cx).expect("flush");
        let writes = cache.inner().write_sequence();
        assert!(writes.contains(&BlockNumber(0)));
        assert!(writes.contains(&BlockNumber(1)));
        assert!(!writes.contains(&BlockNumber(2)));
        assert!(!writes.contains(&BlockNumber(3)));
    }

    #[test]
    fn restage_same_block_in_txn_updates_data() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new_with_policy(dev, 4, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .stage_txn_write(&cx, TxnId(1), BlockNumber(0), &[0x11; 4096])
            .expect("stage first");
        cache
            .stage_txn_write(&cx, TxnId(1), BlockNumber(0), &[0x22; 4096])
            .expect("stage second");

        cache
            .commit_staged_txn(&cx, TxnId(1), CommitSeq(1))
            .expect("commit");

        let buf = cache.read_block(&cx, BlockNumber(0)).expect("read");
        assert_eq!(buf.as_slice(), &[0x22; 4096], "second staging should win");
    }

    #[test]
    fn new_with_policy_and_both_lifecycles() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);
        let mvcc_lifecycle = StdArc::new(RecordingFlushLifecycle::default());
        let repair_lifecycle = StdArc::new(RecordingRepairFlushLifecycle::default());
        let cache = ArcCache::new_with_policy_and_lifecycles(
            counted,
            8,
            ArcWritePolicy::WriteBack,
            mvcc_lifecycle.clone(),
            repair_lifecycle.clone(),
        )
        .expect("cache with both lifecycles");

        // Stage and commit a txn write
        cache
            .stage_txn_write(&cx, TxnId(7), BlockNumber(0), &[0x77; 4096])
            .expect("stage");
        cache
            .commit_staged_txn(&cx, TxnId(7), CommitSeq(7))
            .expect("commit");

        // Also do a direct write
        cache
            .write_block(&cx, BlockNumber(1), &[0x88; 4096])
            .expect("direct write");

        cache.flush_dirty(&cx).expect("flush");

        // Mvcc lifecycle should see the committed block
        assert!(mvcc_lifecycle.pin_count() >= 1);
        assert!(mvcc_lifecycle.persisted_count() >= 1);

        // Repair lifecycle should see all flushed blocks
        assert!(repair_lifecycle.call_count() >= 1);
    }

    #[test]
    fn deferred_arc_cache_txn_operations() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);

        let deferred = DeferredArcCache::new(
            counted,
            8,
            FlushDaemonConfig {
                interval: Duration::from_millis(5),
                batch_size: 4,
                ..FlushDaemonConfig::default()
            },
        )
        .expect("deferred cache");

        // Stage and commit through the deferred cache's inner Arc
        deferred
            .cache()
            .stage_txn_write(&cx, TxnId(10), BlockNumber(0), &[0xDD; 4096])
            .expect("stage via deferred");
        deferred
            .cache()
            .commit_staged_txn(&cx, TxnId(10), CommitSeq(10))
            .expect("commit via deferred");

        // Read should be served from cache
        let buf = deferred.read_block(&cx, BlockNumber(0)).expect("read");
        assert_eq!(buf.as_slice(), &[0xDD; 4096]);

        // Shutdown cleanly
        let inner = deferred.shutdown();
        // After shutdown, the cache should have flushed
        assert_eq!(inner.dirty_count(), 0);
    }

    #[test]
    fn memory_pressure_none_preserves_capacity() {
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 10).expect("cache");

        let report = cache.memory_pressure_callback(MemoryPressure::None);
        assert_eq!(report.target_size, 10);
    }

    #[test]
    fn memory_pressure_levels_decrease_capacity_monotonically() {
        let mem = MemoryByteDevice::new(4096 * 64);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 32).expect("cache");

        let none = cache.memory_pressure_callback(MemoryPressure::None);
        let _ = cache.restore_target_size();
        let low = cache.memory_pressure_callback(MemoryPressure::Low);
        let _ = cache.restore_target_size();
        let medium = cache.memory_pressure_callback(MemoryPressure::Medium);
        let _ = cache.restore_target_size();
        let high = cache.memory_pressure_callback(MemoryPressure::High);
        let _ = cache.restore_target_size();
        let critical = cache.memory_pressure_callback(MemoryPressure::Critical);

        assert!(critical.target_size <= high.target_size);
        assert!(high.target_size <= medium.target_size);
        assert!(medium.target_size <= low.target_size);
        assert!(low.target_size <= none.target_size);
    }

    #[test]
    fn flush_daemon_config_default_is_valid() {
        let config = FlushDaemonConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn flush_daemon_config_zero_interval_is_invalid() {
        let config = FlushDaemonConfig {
            interval: Duration::ZERO,
            ..FlushDaemonConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn flush_daemon_config_zero_batch_size_is_invalid() {
        let config = FlushDaemonConfig {
            batch_size: 0,
            ..FlushDaemonConfig::default()
        };
        assert!(config.validate().is_err());
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
        assert_eq!(m.writeback_queue_depth, 0);
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
    fn cache_metrics_hit_ratio_handles_numeric_limits() {
        let mut metrics = ArcState::new(4).snapshot_metrics();
        metrics.hits = u64::MAX;
        metrics.misses = u64::MAX;

        assert!((metrics.hit_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn arc_state_metric_counters_saturate_at_numeric_limits() {
        let mut state = ArcState::new(2);

        state.hits = u64::MAX;
        state.on_hit(BlockNumber(0));
        assert_eq!(state.hits, u64::MAX);

        state.misses = u64::MAX;
        state.on_miss_or_ghost_hit(BlockNumber(1));
        assert_eq!(state.misses, u64::MAX);

        state.evictions = u64::MAX;
        ArcState::increment_counter(&mut state.evictions);
        assert_eq!(state.evictions, u64::MAX);

        state.dirty_flushes = u64::MAX - 1;
        ArcState::add_usize_to_counter(&mut state.dirty_flushes, 2);
        assert_eq!(state.dirty_flushes, u64::MAX);

        #[cfg(not(feature = "s3fifo"))]
        {
            let mut b1_state = ArcState::new(2);
            b1_state.b1_ghost_hits = u64::MAX;
            b1_state.b1.push_back(BlockNumber(10));
            b1_state.loc.insert(BlockNumber(10), ArcList::B1);
            b1_state.on_miss_or_ghost_hit(BlockNumber(10));
            assert_eq!(b1_state.b1_ghost_hits, u64::MAX);

            let mut b2_state = ArcState::new(2);
            b2_state.b2_ghost_hits = u64::MAX;
            b2_state.b2.push_back(BlockNumber(20));
            b2_state.loc.insert(BlockNumber(20), ArcList::B2);
            b2_state.on_miss_or_ghost_hit(BlockNumber(20));
            assert_eq!(b2_state.b2_ghost_hits, u64::MAX);
        }
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

    #[test]
    fn cache_runtime_metrics_snapshot_uses_export_field_names() {
        let metrics = CacheMetrics {
            hits: 7,
            misses: 3,
            evictions: 2,
            dirty_flushes: 0,
            t1_len: 0,
            t2_len: 0,
            b1_len: 0,
            b2_len: 0,
            resident: 4,
            dirty_blocks: 5,
            dirty_bytes: 4096 * 5,
            writeback_queue_depth: 2,
            oldest_dirty_age_ticks: Some(9),
            capacity: 8,
            p: 0,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
        };

        let export = metrics.runtime_metrics_snapshot();
        assert_eq!(export.cache_hits, 7);
        assert_eq!(export.cache_misses, 3);
        assert_eq!(export.cache_evictions, 2);
        assert_eq!(export.cache_dirty_count, 5);
        assert_eq!(export.writeback_queue_depth, 2);
        assert!((export.hit_rate - 0.7).abs() < 1e-12);
    }

    const REPRESENTATIVE_CACHE_RUNTIME_METRICS_JSON_GOLDEN: &str = r#"{
  "cache_hits": 6,
  "cache_misses": 2,
  "cache_evictions": 1,
  "cache_dirty_count": 3,
  "writeback_queue_depth": 2,
  "hit_rate": 0.75
}"#;

    fn representative_cache_runtime_metrics_snapshot() -> CacheRuntimeMetricsSnapshot {
        CacheMetrics {
            hits: 6,
            misses: 2,
            evictions: 1,
            dirty_flushes: 0,
            t1_len: 1,
            t2_len: 2,
            b1_len: 0,
            b2_len: 1,
            resident: 4,
            dirty_blocks: 3,
            dirty_bytes: 4096 * 3,
            writeback_queue_depth: 2,
            oldest_dirty_age_ticks: Some(4),
            capacity: 8,
            p: 1,
            b1_ghost_hits: 2,
            b2_ghost_hits: 1,
        }
        .runtime_metrics_snapshot()
    }

    #[test]
    fn representative_cache_runtime_metrics_json_exact_golden_contract() {
        let metrics = representative_cache_runtime_metrics_snapshot();
        let json = serde_json::to_string_pretty(&metrics).expect("serialize representative JSON");

        assert_eq!(json, REPRESENTATIVE_CACHE_RUNTIME_METRICS_JSON_GOLDEN);

        let parsed: CacheRuntimeMetricsSnapshot =
            serde_json::from_str(&json).expect("deserialize representative JSON");
        assert_eq!(parsed, metrics);
    }

    #[test]
    fn arc_cache_runtime_metrics_export_serializes_to_json() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 2).expect("cache");

        let _ = cache.read_block(&cx, BlockNumber(0)).expect("read miss");
        let _ = cache.read_block(&cx, BlockNumber(0)).expect("read hit");

        let json = serde_json::to_value(cache.runtime_metrics()).expect("serialize metrics");
        assert_eq!(json["cache_hits"], 1);
        assert_eq!(json["cache_misses"], 1);
        assert_eq!(json["cache_evictions"], 0);
        assert_eq!(json["cache_dirty_count"], 0);
        assert_eq!(json["writeback_queue_depth"], 0);
        assert!((json["hit_rate"].as_f64().expect("hit rate") - 0.5).abs() < 1e-12);
    }

    fn current_arc_cache_admission_sample() -> CacheAdmissionPolicySample {
        CacheAdmissionPolicySample {
            policy: CacheAdmissionPolicy::CurrentArc,
            cache_hits: 8_500,
            cache_misses: 1_500,
            cache_evictions: 700,
            p99_latency_micros: 900,
            memory_overhead_bytes: 256 * 1024 * 1024,
            dirty_ratio: 0.22,
            writeback_queue_depth: 1_000,
        }
    }

    fn segmented_s3fifo_cache_admission_sample() -> CacheAdmissionPolicySample {
        CacheAdmissionPolicySample {
            policy: CacheAdmissionPolicy::SegmentedS3Fifo,
            cache_hits: 9_300,
            cache_misses: 700,
            cache_evictions: 300,
            p99_latency_micros: 650,
            memory_overhead_bytes: 512 * 1024 * 1024,
            dirty_ratio: 0.18,
            writeback_queue_depth: 500,
        }
    }

    fn large_ram_cache_admission_input() -> LargeRamCacheAdmissionInput {
        LargeRamCacheAdmissionInput {
            config: LargeRamCacheBudgetConfig::default(),
            host_memory: CacheHostMemoryObservation {
                total_ram_bytes: Some(384 * 1024 * 1024 * 1024),
                available_ram_bytes: Some(320 * 1024 * 1024 * 1024),
                numa_nodes: Some(4),
            },
            artifact_evidence: CacheAdmissionArtifactEvidence::complete(),
            current_arc: current_arc_cache_admission_sample(),
            candidate: segmented_s3fifo_cache_admission_sample(),
        }
    }

    #[test]
    fn large_ram_cache_contract_downgrades_missing_and_small_hosts() {
        let missing = LargeRamCacheAdmissionInput {
            host_memory: CacheHostMemoryObservation {
                total_ram_bytes: None,
                available_ram_bytes: Some(16 * 1024 * 1024 * 1024),
                numa_nodes: None,
            },
            ..large_ram_cache_admission_input()
        };
        let missing_report = evaluate_large_ram_cache_admission(&missing);
        assert_eq!(missing_report.mode, CacheAdmissionMode::CapabilitySkip);
        assert_eq!(
            missing_report.reason,
            CacheAdmissionReason::MissingHostMemory
        );
        assert_eq!(
            missing_report.claim_state,
            CacheAdmissionClaimState::MissingReference
        );

        let small_host = LargeRamCacheAdmissionInput {
            host_memory: CacheHostMemoryObservation {
                total_ram_bytes: Some(64 * 1024 * 1024 * 1024),
                available_ram_bytes: Some(48 * 1024 * 1024 * 1024),
                numa_nodes: Some(1),
            },
            ..large_ram_cache_admission_input()
        };
        let small_report = evaluate_large_ram_cache_admission(&small_host);
        assert_eq!(small_report.mode, CacheAdmissionMode::CapabilitySkip);
        assert_eq!(
            small_report.reason,
            CacheAdmissionReason::HostBelowLargeRamFloor
        );
        assert_eq!(
            small_report.claim_state,
            CacheAdmissionClaimState::SmallHostSmoke
        );
    }

    #[test]
    fn large_ram_cache_contract_requires_artifact_gates() {
        let input = LargeRamCacheAdmissionInput {
            artifact_evidence: CacheAdmissionArtifactEvidence::complete()
                .without(CacheAdmissionEvidenceGate::RawLogs),
            ..large_ram_cache_admission_input()
        };
        let report = evaluate_large_ram_cache_admission(&input);
        assert_eq!(report.mode, CacheAdmissionMode::KeepCurrentArc);
        assert_eq!(
            report.reason,
            CacheAdmissionReason::MissingArtifactGate(CacheAdmissionEvidenceGate::RawLogs)
        );
        assert_eq!(report.selected_policy, CacheAdmissionPolicy::CurrentArc);
        assert_eq!(
            report.claim_state,
            CacheAdmissionClaimState::MissingReference
        );
    }

    #[test]
    fn large_ram_cache_contract_rejects_dirty_queue_and_memory_pressure() {
        let dirty = LargeRamCacheAdmissionInput {
            candidate: CacheAdmissionPolicySample {
                dirty_ratio: 0.60,
                ..segmented_s3fifo_cache_admission_sample()
            },
            ..large_ram_cache_admission_input()
        };
        let dirty_report = evaluate_large_ram_cache_admission(&dirty);
        assert_eq!(
            dirty_report.reason,
            CacheAdmissionReason::CandidateDirtyPressureTooHigh
        );

        let deep_queue = LargeRamCacheAdmissionInput {
            candidate: CacheAdmissionPolicySample {
                writeback_queue_depth: 2_000_000,
                ..segmented_s3fifo_cache_admission_sample()
            },
            ..large_ram_cache_admission_input()
        };
        let queue_report = evaluate_large_ram_cache_admission(&deep_queue);
        assert_eq!(
            queue_report.reason,
            CacheAdmissionReason::CandidateWritebackQueueTooDeep
        );

        let memory = LargeRamCacheAdmissionInput {
            candidate: CacheAdmissionPolicySample {
                memory_overhead_bytes: 3 * 1024 * 1024 * 1024,
                ..segmented_s3fifo_cache_admission_sample()
            },
            ..large_ram_cache_admission_input()
        };
        let memory_report = evaluate_large_ram_cache_admission(&memory);
        assert_eq!(
            memory_report.reason,
            CacheAdmissionReason::CandidateMemoryOverheadTooHigh
        );
    }

    #[test]
    fn large_ram_cache_contract_selects_candidate_design_only_with_fallback() {
        let input = large_ram_cache_admission_input();
        let report = evaluate_large_ram_cache_admission(&input);

        assert_eq!(report.mode, CacheAdmissionMode::CandidateDesignOnly);
        assert_eq!(
            report.reason,
            CacheAdmissionReason::CandidateLowerExpectedLoss
        );
        assert_eq!(
            report.selected_policy,
            CacheAdmissionPolicy::SegmentedS3Fifo
        );
        assert_eq!(report.fallback_policy, CacheAdmissionPolicy::CurrentArc);
        assert_eq!(report.claim_state, CacheAdmissionClaimState::Experimental);
        assert!(report.hit_rate_gain >= input.config.min_hit_rate_gain);
        assert!(report.candidate_expected_loss < report.current_expected_loss);
    }

    #[test]
    fn large_ram_cache_contract_json_fixture_records_flush_backpressure_and_claim() {
        let input = large_ram_cache_admission_input();
        let input_json = serde_json::to_value(&input).expect("serialize input");
        let gates = input_json["artifact_evidence"]["gates"]
            .as_array()
            .expect("artifact gates");
        assert!(
            gates
                .iter()
                .any(|gate| gate.as_str() == Some("BackpressurePolicy"))
        );
        assert!(
            gates
                .iter()
                .any(|gate| gate.as_str() == Some("FlushPolicy"))
        );
        assert!(
            gates
                .iter()
                .any(|gate| gate.as_str() == Some("ReleaseClaimState"))
        );

        let report = evaluate_large_ram_cache_admission(&input);
        let report_json = serde_json::to_value(report).expect("serialize report");
        assert_eq!(report_json["mode"], "CandidateDesignOnly");
        assert_eq!(report_json["fallback_policy"], "CurrentArc");
        assert_eq!(report_json["claim_state"], "Experimental");
    }

    #[test]
    fn arc_cache_pressure_reduces_and_restores_target_size() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 10).expect("cache");

        for block in 0..6_u64 {
            let _ = cache
                .read_block(&cx, BlockNumber(block))
                .expect("warm read");
        }

        let reduced = cache.memory_pressure_callback(MemoryPressure::High);
        assert_eq!(reduced.target_size, 5);
        assert_eq!(cache.metrics().capacity, 5);

        let restored = cache.restore_target_size();
        assert_eq!(restored.target_size, 10);
        assert_eq!(cache.metrics().capacity, 10);
    }

    #[test]
    fn arc_cache_pressure_prefers_evicting_cold_clean_entries() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 8).expect("cache");

        // Warm seven cold blocks and one hot block, filling the cache to capacity.
        //
        // The reads use a stride of 2 deliberately: under the default S3-FIFO
        // policy a *consecutive* read-miss streak (0,1,2,3,...) is detected as a
        // one-pass scan and admitted to the ghost queue only, so those blocks
        // would never become resident. Non-consecutive block numbers keep the
        // scan detector disarmed, so every block is genuinely admitted and the
        // pressure path has real cold residents to evict.
        let cold_blocks = [0_u64, 2, 4, 6, 8, 10, 12];
        for block in cold_blocks {
            let _ = cache
                .read_block(&cx, BlockNumber(block))
                .expect("cold read");
        }
        let hot_block = 14_u64;
        let _ = cache
            .read_block(&cx, BlockNumber(hot_block))
            .expect("hot admit");
        // Re-access promotes the hot block to the frequent (main) queue and makes
        // it the youngest entry there, so the oldest-first pressure victim search
        // reaches it last.
        let _ = cache
            .read_block(&cx, BlockNumber(hot_block))
            .expect("hot touch");

        // High pressure halves the target. With eight residents (one hot, seven
        // cold) the four evictions can be satisfied entirely from cold entries.
        let report = cache.memory_pressure_callback(MemoryPressure::High);
        assert_eq!(report.target_size, 4);
        assert!(report.current_size <= 4);

        let before = cache.metrics();
        let _ = cache
            .read_block(&cx, BlockNumber(hot_block))
            .expect("read hot block");
        let after_hot = cache.metrics();
        assert_eq!(
            after_hot.hits,
            before.hits.saturating_add(1),
            "hot block should remain resident under pressure"
        );

        // The first-warmed cold block is the oldest clean resident, so it is the
        // first pressure victim and must miss after the shrink.
        let _ = cache
            .read_block(&cx, BlockNumber(cold_blocks[0]))
            .expect("read colder block");
        let after_cold = cache.metrics();
        assert_eq!(
            after_cold.misses,
            after_hot.misses.saturating_add(1),
            "cold block should be evicted first under pressure"
        );
    }

    #[test]
    fn arc_cache_pressure_preserves_dirty_entries_until_flushed() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 32);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new_with_policy(dev, 10, ArcWritePolicy::WriteBack).expect("cache");

        for block in 0..6_u64 {
            let payload = vec![u8::try_from(block).expect("block fits u8"); 4096];
            cache
                .write_block(&cx, BlockNumber(block), &payload)
                .expect("write");
        }

        let report = cache.memory_pressure_callback(MemoryPressure::Critical);
        let metrics = cache.metrics();
        assert_eq!(report.target_size, 2);
        assert_eq!(metrics.capacity, 2);
        assert_eq!(metrics.dirty_blocks, 6);
        assert!(
            metrics.resident > metrics.capacity,
            "dirty entries must not be evicted under pressure"
        );

        cache.flush_dirty(&cx).expect("flush dirty");
        let post_flush_report = cache.memory_pressure_callback(MemoryPressure::Critical);
        let post_flush_metrics = cache.metrics();
        assert_eq!(post_flush_metrics.dirty_blocks, 0);
        assert!(post_flush_metrics.resident <= post_flush_metrics.capacity);
        assert!(post_flush_report.current_size <= post_flush_report.target_size);
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
    fn arc_cache_same_block_concurrent_miss_coalesces_device_read() {
        use std::sync::Barrier;
        use std::thread;

        const THREADS: usize = 32;
        const NUM_BLOCKS: usize = 16;
        const BLOCK_SIZE: u32 = 4096;

        let mem = MemoryByteDevice::new(BLOCK_SIZE as usize * NUM_BLOCKS);
        let dev = ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device");

        let cx = Cx::for_testing();
        let payload = vec![0x5A; BLOCK_SIZE as usize];
        dev.write_block(&cx, BlockNumber(7), &payload)
            .expect("seed");

        let counted = CountingBlockDevice::new(dev);
        let cache = StdArc::new(ArcCache::new(counted, 8).expect("cache"));
        let barrier = StdArc::new(Barrier::new(THREADS));

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let cache = StdArc::clone(&cache);
                let barrier = StdArc::clone(&barrier);
                thread::spawn(move || {
                    let cx = Cx::for_testing();
                    barrier.wait();
                    let buf = cache.read_block(&cx, BlockNumber(7)).expect("read");
                    assert_eq!(buf.as_slice()[0], 0x5A);
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let metrics = cache.metrics();
        assert_eq!(
            cache.inner().read_count(),
            1,
            "same-block concurrent cold miss should hit the device once"
        );
        assert_eq!(metrics.misses, 1);
        assert_eq!(metrics.hits, u64::try_from(THREADS - 1).expect("fits u64"));
        assert_eq!(cache.page_locks.in_flight_len(), 0);
    }

    #[test]
    fn page_lock_table_same_block_waiter_notifies_with_bounded_join() {
        use std::sync::mpsc;
        use std::thread;

        const NUM_BLOCKS: usize = 16;
        const BLOCK_SIZE: u32 = 4096;
        const TARGET_BLOCK: BlockNumber = BlockNumber(7);

        let mem = MemoryByteDevice::new(BLOCK_SIZE as usize * NUM_BLOCKS);
        let dev = ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device");

        let cx = Cx::for_testing();
        let payload = vec![0x5A; BLOCK_SIZE as usize];
        dev.write_block(&cx, TARGET_BLOCK, &payload)
            .expect("seed target block");

        let (first_read_started_tx, first_read_started_rx) = mpsc::channel();
        let (first_read_release_tx, first_read_release_rx) = mpsc::channel();
        let pausing = PausingFirstReadBlockDevice::new(
            dev,
            TARGET_BLOCK,
            first_read_started_tx,
            first_read_release_rx,
        );
        let cache = StdArc::new(ArcCache::new(pausing, 8).expect("cache"));
        let (done_tx, done_rx) = mpsc::channel();

        let leader_cache = StdArc::clone(&cache);
        let leader_done = done_tx.clone();
        let leader = thread::spawn(move || {
            let cx = Cx::for_testing();
            let buf = leader_cache
                .read_block(&cx, TARGET_BLOCK)
                .expect("leader read");
            assert_eq!(buf.as_slice()[0], 0x5A);
            leader_done.send("leader").expect("send leader completion");
        });

        first_read_started_rx
            .recv_timeout(PAGE_LOCK_WAITER_TIMEOUT)
            .expect("first same-block miss reached the device");

        let waiter_cache = StdArc::clone(&cache);
        let waiter_done = done_tx;
        let waiter = thread::spawn(move || {
            let cx = Cx::for_testing();
            let buf = waiter_cache
                .read_block(&cx, TARGET_BLOCK)
                .expect("waiter read");
            assert_eq!(buf.as_slice()[0], 0x5A);
            waiter_done.send("waiter").expect("send waiter completion");
        });

        let waiters = wait_until_page_lock_waiters(
            &cache.page_locks,
            TARGET_BLOCK,
            1,
            PAGE_LOCK_WAITER_TIMEOUT,
        );
        first_read_release_tx
            .send(())
            .expect("release first same-block miss");
        assert_eq!(
            waiters, 1,
            "same-block second reader should park on the page-lock condvar"
        );

        let mut completions = [
            done_rx
                .recv_timeout(PAGE_LOCK_WAITER_TIMEOUT)
                .expect("first reader completed after notify"),
            done_rx
                .recv_timeout(PAGE_LOCK_WAITER_TIMEOUT)
                .expect("second reader completed after notify"),
        ];
        completions.sort_unstable();
        assert_eq!(completions, ["leader", "waiter"]);

        leader.join().expect("leader thread panicked");
        waiter.join().expect("waiter thread panicked");

        let metrics = cache.metrics();
        assert_eq!(
            cache.inner().read_count(),
            1,
            "parked waiter should reuse the leader's populated cache entry"
        );
        assert_eq!(metrics.misses, 1);
        assert_eq!(metrics.hits, 1);
        assert_eq!(cache.page_locks.in_flight_len(), 0);
    }

    #[test]
    fn sharded_arc_cache_aggregates_hits_and_capacity() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 32);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ShardedArcCache::new(dev, 8, 4).expect("sharded cache");

        assert_eq!(cache.shard_count(), 4);
        assert_eq!(cache.metrics().capacity, 8);

        for block in 0..8_u64 {
            let first = cache
                .read_block(&cx, BlockNumber(block))
                .expect("first read");
            let second = cache
                .read_block(&cx, BlockNumber(block))
                .expect("second read");
            assert_eq!(first.as_slice(), second.as_slice());
        }

        let metrics = cache.metrics();
        assert_eq!(metrics.misses, 8);
        assert_eq!(metrics.hits, 8);
        assert_eq!(metrics.resident, 8);
        assert_eq!(metrics.capacity, 8);
        assert!(
            cache
                .shard_metrics()
                .iter()
                .all(|shard| shard.capacity == 2)
        );
    }

    #[test]
    fn sharded_arc_cache_power_of_two_mask_matches_modulo_routing() {
        let power_two_dev = ByteBlockDevice::new(MemoryByteDevice::new(4096 * 64), 4096)
            .expect("power-of-two device");
        let power_two_cache =
            ShardedArcCache::new(power_two_dev, 16, 8).expect("power-of-two sharded cache");
        let non_power_two_dev = ByteBlockDevice::new(MemoryByteDevice::new(4096 * 64), 4096)
            .expect("non-power-of-two device");
        let non_power_two_cache =
            ShardedArcCache::new(non_power_two_dev, 15, 5).expect("non-power-of-two sharded cache");

        for block in 0..128_u64 {
            assert_eq!(
                power_two_cache.shard_index_for(BlockNumber(block)),
                usize::try_from(block % 8).expect("modulo shard fits usize"),
            );
            assert_eq!(
                non_power_two_cache.shard_index_for(BlockNumber(block)),
                usize::try_from(block % 5).expect("modulo shard fits usize"),
            );
        }
    }

    #[test]
    fn sharded_arc_cache_writeback_sync_flushes_all_shards_once() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache =
            ShardedArcCache::new_with_policy(dev, 8, 4, ArcWritePolicy::WriteBack).expect("cache");

        let block_len = usize::try_from(cache.block_size()).expect("block size fits usize");
        cache
            .write_block(&cx, BlockNumber(0), &vec![7_u8; block_len])
            .expect("write block 0");
        cache
            .write_block(&cx, BlockNumber(5), &vec![9_u8; block_len])
            .expect("write block 5");
        assert_eq!(cache.metrics().dirty_blocks, 2);

        cache.sync(&cx).expect("sync");
        assert_eq!(cache.metrics().dirty_blocks, 0);

        let block0 = cache
            .inner()
            .read_block(&cx, BlockNumber(0))
            .expect("underlying block 0");
        let block5 = cache
            .inner()
            .read_block(&cx, BlockNumber(5))
            .expect("underlying block 5");
        assert!(block0.as_slice().iter().all(|byte| *byte == 7));
        assert!(block5.as_slice().iter().all(|byte| *byte == 9));
    }

    #[test]
    fn page_lock_table_tracks_large_distinct_in_flight_set() {
        const IN_FLIGHT_BLOCKS: usize = 256;

        let table = PageLockTable::new(1);
        let mut permits = Vec::with_capacity(IN_FLIGHT_BLOCKS);
        for block in 0..IN_FLIGHT_BLOCKS {
            permits.push(table.acquire(BlockNumber(u64::try_from(block).expect("block id fits"))));
        }

        assert_eq!(table.in_flight_len(), IN_FLIGHT_BLOCKS);
        assert!(matches!(
            &*table.shards[0].in_flight.lock(),
            InFlightBlocks::Large(_)
        ));
        permits.truncate(IN_FLIGHT_BLOCKS / 2);
        assert_eq!(table.in_flight_len(), IN_FLIGHT_BLOCKS / 2);
        drop(permits);
        assert_eq!(table.in_flight_len(), 0);
        assert!(matches!(
            &*table.shards[0].in_flight.lock(),
            InFlightBlocks::Inline(blocks) if blocks.is_empty()
        ));
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

    // ── Lab runtime deterministic concurrency tests ─────────────────────

    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::types::Budget;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    struct YieldOnce {
        yielded: bool,
    }

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    async fn lab_yield_now() {
        YieldOnce { yielded: false }.await;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct LabCacheSummary {
        hits: u64,
        misses: u64,
        resident: usize,
        dirty_blocks: usize,
        read_events: usize,
    }

    fn run_lab_arc_cache_scenario(seed: u64) -> LabCacheSummary {
        const READERS: usize = 3;
        const WRITERS: usize = 2;
        const READ_OPS: usize = 40;
        const WRITE_OPS: usize = 25;
        const NUM_BLOCKS: usize = 8;
        const BLOCK_SIZE: u32 = 4096;
        const CAPACITY: usize = 4;

        info!(
            target: "ffs::block::lab",
            event = "lab_seed",
            seed = seed
        );

        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(200_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);

        let mem = MemoryByteDevice::new(BLOCK_SIZE as usize * NUM_BLOCKS);
        let dev = ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device");
        let cx = Cx::for_testing();
        for block in 0..NUM_BLOCKS {
            let seed_byte = u8::try_from(block).expect("block index fits u8");
            dev.write_block(
                &cx,
                BlockNumber(u64::try_from(block).expect("block index fits u64")),
                &vec![seed_byte; BLOCK_SIZE as usize],
            )
            .expect("seed write");
        }

        let cache = StdArc::new(ArcCache::new(dev, CAPACITY).expect("cache"));
        let read_events = StdArc::new(std::sync::Mutex::new(Vec::<u8>::new()));

        for reader in 0..READERS {
            let cache = StdArc::clone(&cache);
            let read_events = StdArc::clone(&read_events);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::for_testing();
                    for step in 0..READ_OPS {
                        let block_index = (reader + step) % NUM_BLOCKS;
                        let block =
                            BlockNumber(u64::try_from(block_index).expect("block index fits u64"));
                        let buf = cache.read_block(&cx, block).expect("read");
                        read_events
                            .lock()
                            .expect("read events lock not poisoned")
                            .push(buf.as_slice()[0]);
                        lab_yield_now().await;
                    }
                })
                .expect("create reader task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        for writer in 0..WRITERS {
            let cache = StdArc::clone(&cache);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    let cx = Cx::for_testing();
                    for step in 0..WRITE_OPS {
                        let block_index = (writer * 2 + step) % NUM_BLOCKS;
                        let fill = u8::try_from((writer * 97 + step) & 0xFF).unwrap_or(0);
                        let block =
                            BlockNumber(u64::try_from(block_index).expect("block index fits u64"));
                        cache
                            .write_block(&cx, block, &vec![fill; BLOCK_SIZE as usize])
                            .expect("write");
                        lab_yield_now().await;
                    }
                })
                .expect("create writer task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        runtime.run_until_quiescent();

        let observed_reads = StdArc::try_unwrap(read_events)
            .expect("all read event handles dropped")
            .into_inner()
            .expect("read events lock not poisoned")
            .len();
        let metrics = cache.metrics();

        LabCacheSummary {
            hits: metrics.hits,
            misses: metrics.misses,
            resident: metrics.resident,
            dirty_blocks: metrics.dirty_blocks,
            read_events: observed_reads,
        }
    }

    #[test]
    fn lab_arc_cache_same_seed_is_deterministic() {
        let first = run_lab_arc_cache_scenario(21);
        let second = run_lab_arc_cache_scenario(21);
        let third = run_lab_arc_cache_scenario(21);
        assert_eq!(first, second, "same seed should produce same cache summary");
        assert_eq!(second, third, "same seed should remain stable");
    }

    #[test]
    fn lab_arc_cache_invariants_across_seeds() {
        const READERS: usize = 3;
        const WRITERS: usize = 2;
        const READ_OPS: usize = 40;
        const WRITE_OPS: usize = 25;
        const EXPECTED_READS: usize = READERS * READ_OPS;
        const EXPECTED_ACCESSES: usize = EXPECTED_READS + (WRITERS * WRITE_OPS);
        const CAPACITY: usize = 4;

        for seed in 0_u64..25 {
            let summary = run_lab_arc_cache_scenario(seed);
            assert_eq!(
                summary.read_events, EXPECTED_READS,
                "seed {seed}: all reader operations should complete"
            );
            assert_eq!(
                summary.hits + summary.misses,
                u64::try_from(EXPECTED_ACCESSES).expect("expected accesses fit u64"),
                "seed {seed}: hit/miss accounting should match all cache accesses"
            );
            assert!(
                summary.resident <= CAPACITY,
                "seed {seed}: resident {} exceeds capacity {}",
                summary.resident,
                CAPACITY
            );
            assert_eq!(
                summary.dirty_blocks, 0,
                "seed {seed}: write-through cache should not retain dirty blocks"
            );
        }
    }

    // ── Fault injection framework tests (bd-32yn.8) ──────────────────

    /// Simple in-memory BlockDevice for fault injection tests.
    struct MemBlockDevice {
        blocks: Mutex<HashMap<u64, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
    }

    impl MemBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: Mutex::new(HashMap::new()),
                block_size,
                block_count,
            }
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            let data = self
                .blocks
                .lock()
                .get(&block.0)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; self.block_size as usize]);
            Ok(BlockBuf::new(data))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.blocks.lock().insert(block.0, data.to_vec());
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            self.block_count
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn fault_passthrough_no_faults() {
        // With no rules, FaultInjector delegates transparently.
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 42);
        let cx = Cx::for_testing();

        // Write then read — should work identically to unwrapped device.
        let data = vec![0xAB_u8; 4096];
        fi.write_block(&cx, BlockNumber(0), &data).unwrap();
        let buf = fi.read_block(&cx, BlockNumber(0)).unwrap();
        assert_eq!(buf.as_slice(), &data[..]);

        // Fault log should be empty.
        assert!(fi.fault_log().is_empty());
    }

    #[test]
    fn fault_fail_on_read_returns_error() {
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 1);
        let cx = Cx::for_testing();

        fi.fail_on_read(BlockNumber(5), FaultMode::OneShot);

        // Reading block 5 should fail.
        let err = fi.read_block(&cx, BlockNumber(5)).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));

        // Reading a different block should succeed.
        let _ = fi.read_block(&cx, BlockNumber(0)).unwrap();
    }

    #[test]
    fn fault_fail_on_write_returns_error() {
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 2);
        let cx = Cx::for_testing();

        fi.fail_on_write(BlockNumber(3), FaultMode::OneShot);

        let data = vec![0_u8; 4096];
        let err = fi.write_block(&cx, BlockNumber(3), &data).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));

        // Writing a different block should succeed.
        fi.write_block(&cx, BlockNumber(0), &data).unwrap();
    }

    #[test]
    fn fault_oneshot_cleared_after_trigger() {
        // One-shot fault fires once, then subsequent accesses succeed.
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 3);
        let cx = Cx::for_testing();

        fi.fail_on_read(BlockNumber(7), FaultMode::OneShot);

        // First read: fails.
        assert!(fi.read_block(&cx, BlockNumber(7)).is_err());
        // Second read: succeeds (one-shot cleared).
        assert!(fi.read_block(&cx, BlockNumber(7)).is_ok());
    }

    #[test]
    fn fault_persistent_fires_every_time() {
        // Persistent fault fires on every matching access.
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 4);
        let cx = Cx::for_testing();

        fi.fail_on_read(BlockNumber(2), FaultMode::Persistent);

        for _ in 0..5 {
            assert!(fi.read_block(&cx, BlockNumber(2)).is_err());
        }
        // Should have logged 5 faults.
        assert_eq!(fi.fault_log().len(), 5);
    }

    #[test]
    fn fault_mixed_read_write_targets() {
        // Can register both read and write faults on different blocks.
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 5);
        let cx = Cx::for_testing();

        fi.fail_on_read(BlockNumber(1), FaultMode::OneShot);
        fi.fail_on_write(BlockNumber(2), FaultMode::OneShot);

        let data = vec![0_u8; 4096];

        // Read block 1 fails, write block 1 succeeds.
        assert!(fi.read_block(&cx, BlockNumber(1)).is_err());
        fi.write_block(&cx, BlockNumber(1), &data).unwrap();

        // Write block 2 fails, read block 2 succeeds.
        assert!(fi.write_block(&cx, BlockNumber(2), &data).is_err());
        fi.read_block(&cx, BlockNumber(2)).unwrap();
    }

    #[test]
    fn fault_deterministic_same_seed_same_sequence() {
        // Two injectors with the same seed and rules produce the same
        // fault log sequence numbers.
        let run = |seed: u64| -> Vec<u64> {
            let dev = MemBlockDevice::new(4096, 16);
            let fi = FaultInjector::new(dev, seed);
            let cx = Cx::for_testing();

            fi.fail_on_read(BlockNumber(0), FaultMode::Persistent);
            fi.fail_on_write(BlockNumber(1), FaultMode::Persistent);

            let data = vec![0_u8; 4096];
            let _ = fi.read_block(&cx, BlockNumber(0));
            let _ = fi.write_block(&cx, BlockNumber(1), &data);
            let _ = fi.read_block(&cx, BlockNumber(0));

            fi.fault_log().iter().map(|r| r.sequence).collect()
        };

        let seq_a = run(99);
        let seq_b = run(99);
        assert_eq!(seq_a, seq_b);
        assert_eq!(seq_a, vec![0, 1, 2]);
    }

    #[test]
    fn fault_reproducible_across_runs() {
        // Run the same scenario twice and verify identical fault log.
        let scenario = || -> Vec<FaultRecord> {
            let dev = MemBlockDevice::new(4096, 8);
            let fi = FaultInjector::new(dev, 77);
            let cx = Cx::for_testing();

            fi.fail_on_read(BlockNumber(3), FaultMode::OneShot);
            fi.fail_on_write(BlockNumber(5), FaultMode::OneShot);

            let data = vec![0_u8; 4096];
            let _ = fi.read_block(&cx, BlockNumber(3));
            let _ = fi.write_block(&cx, BlockNumber(5), &data);

            fi.fault_log()
        };

        let log_1 = scenario();
        let log_2 = scenario();
        assert_eq!(log_1.len(), log_2.len());
        for (a, b) in log_1.iter().zip(log_2.iter()) {
            assert_eq!(a.target, b.target);
            assert_eq!(a.sequence, b.sequence);
        }
    }

    #[test]
    fn fault_log_captures_all_injected_faults() {
        // Verify the log records every triggered fault with correct target
        // and monotonically increasing sequence numbers.
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 10);
        let cx = Cx::for_testing();

        fi.fail_on_read(BlockNumber(0), FaultMode::Persistent);
        fi.fail_on_write(BlockNumber(1), FaultMode::Persistent);

        let data = vec![0_u8; 4096];
        let _ = fi.read_block(&cx, BlockNumber(0));
        let _ = fi.write_block(&cx, BlockNumber(1), &data);
        let _ = fi.read_block(&cx, BlockNumber(0));

        let log = fi.fault_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].target, FaultTarget::Read(BlockNumber(0)));
        assert_eq!(log[0].sequence, 0);
        assert_eq!(log[1].target, FaultTarget::Write(BlockNumber(1)));
        assert_eq!(log[1].sequence, 1);
        assert_eq!(log[2].target, FaultTarget::Read(BlockNumber(0)));
        assert_eq!(log[2].sequence, 2);
    }

    #[test]
    fn fault_log_sequence_saturates_at_numeric_limit() {
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 11);
        let cx = Cx::for_testing();

        fi.fail_on_read(BlockNumber(0), FaultMode::Persistent);
        fi.sequence.store(u64::MAX, Ordering::Relaxed);

        assert!(fi.read_block(&cx, BlockNumber(0)).is_err());
        assert!(fi.read_block(&cx, BlockNumber(0)).is_err());

        let log = fi.fault_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].sequence, u64::MAX);
        assert_eq!(log[1].sequence, u64::MAX);
        assert_eq!(fi.sequence.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn fault_crash_point_registered_fires_on_operation() {
        // Register a fault that acts as a "crash point" — it fires at
        // a specific write operation, simulating a crash during fsync.
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 20);
        let cx = Cx::for_testing();

        // Simulate: crash when writing metadata block 10.
        fi.fail_on_write(BlockNumber(10), FaultMode::OneShot);

        let data = vec![0xFF_u8; 4096];
        // Writes to blocks 0-9 succeed.
        for b in 0..10 {
            fi.write_block(&cx, BlockNumber(b), &data).unwrap();
        }
        // Write to block 10 crashes.
        assert!(fi.write_block(&cx, BlockNumber(10), &data).is_err());
        // Writes to blocks 11+ succeed (crash point was one-shot).
        fi.write_block(&cx, BlockNumber(11), &data).unwrap();
    }

    #[test]
    fn fault_crash_point_fires_at_correct_moment() {
        // Set up a write-then-sync sequence. The crash point fires on
        // the write, so the sync never executes.
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 30);
        let cx = Cx::for_testing();

        fi.fail_on_write(BlockNumber(5), FaultMode::OneShot);

        let data = vec![0xCC_u8; 4096];
        // Write block 5 fails — "crash before sync".
        let err = fi.write_block(&cx, BlockNumber(5), &data);
        assert!(err.is_err());

        // Block 5 was never written — reading it returns zeros.
        let buf = fi.read_block(&cx, BlockNumber(5)).unwrap();
        assert_eq!(&buf.as_slice()[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn fault_recovery_after_crash_point() {
        // After a crash point fires (one-shot), the device recovers and
        // subsequent I/O works correctly, simulating post-crash remount.
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 40);
        let cx = Cx::for_testing();

        // Write some data before crash.
        let pre_crash = vec![0xAA_u8; 4096];
        fi.write_block(&cx, BlockNumber(0), &pre_crash).unwrap();

        // Crash on block 1.
        fi.fail_on_write(BlockNumber(1), FaultMode::OneShot);
        let data = vec![0xBB_u8; 4096];
        assert!(fi.write_block(&cx, BlockNumber(1), &data).is_err());

        // "Recovery": subsequent I/O works.
        fi.write_block(&cx, BlockNumber(1), &data).unwrap();
        fi.sync(&cx).unwrap();

        // Pre-crash data is intact.
        let buf0 = fi.read_block(&cx, BlockNumber(0)).unwrap();
        assert_eq!(&buf0.as_slice()[..4], &[0xAA, 0xAA, 0xAA, 0xAA]);

        // Post-recovery data is correct.
        let buf1 = fi.read_block(&cx, BlockNumber(1)).unwrap();
        assert_eq!(&buf1.as_slice()[..4], &[0xBB, 0xBB, 0xBB, 0xBB]);
    }

    // ── ThrottleInjector tests (bd-32yn.4) ────────────────────────────

    #[test]
    fn throttle_passthrough_no_delay() {
        let dev = MemBlockDevice::new(4096, 8);
        let config = ThrottleConfig::default();
        let ti = ThrottleInjector::new(dev, config, 42);
        let cx = Cx::for_testing();

        let data = vec![0xCC_u8; 4096];
        ti.write_block(&cx, BlockNumber(0), &data).unwrap();
        let buf = ti.read_block(&cx, BlockNumber(0)).unwrap();
        assert_eq!(&buf.as_slice()[..4], &[0xCC, 0xCC, 0xCC, 0xCC]);

        let log = ti.throttle_log();
        assert_eq!(log.len(), 2); // write + read
        assert!(!log[0].stalled);
        assert!(!log[1].stalled);
    }

    #[test]
    fn throttle_respect_deadline_cancels_before_inner_write() {
        let dev = CountingBlockDevice::new(MemBlockDevice::new(4096, 8));
        let config = ThrottleConfig {
            write_latency: Duration::from_millis(10),
            respect_deadline: true,
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 12);
        let past_deadline = asupersync::Budget::new().with_deadline(asupersync::types::Time::ZERO);
        let cx = Cx::for_testing_with_budget(past_deadline);
        let data = vec![0xEE_u8; 4096];

        let err = ti
            .write_block(&cx, BlockNumber(0), &data)
            .expect_err("expired deadline should cancel before throttled write");

        assert!(matches!(err, FfsError::Cancelled));
        assert_eq!(ti.inner.write_count(), 0);
        assert!(ti.throttle_log().is_empty());
    }

    #[test]
    fn throttle_respect_deadline_rejects_delay_that_cannot_fit() {
        let dev = CountingBlockDevice::new(MemBlockDevice::new(4096, 8));
        let config = ThrottleConfig {
            write_latency: Duration::from_secs(1),
            respect_deadline: true,
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 13);
        let deadline = Cx::for_testing().now() + Duration::from_millis(1);
        let cx = Cx::for_testing_with_budget(asupersync::Budget::new().with_deadline(deadline));
        let data = vec![0xEF_u8; 4096];

        let start = Instant::now();
        let err = ti
            .write_block(&cx, BlockNumber(0), &data)
            .expect_err("delay that exceeds the remaining deadline should cancel");

        assert!(matches!(err, FfsError::Cancelled));
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "cancellation should not sleep the full throttle delay"
        );
        assert_eq!(ti.inner.write_count(), 0);
        assert!(ti.throttle_log().is_empty());
    }

    #[test]
    fn throttle_respect_deadline_observes_mid_sleep_cancellation() {
        let dev = CountingBlockDevice::new(MemBlockDevice::new(4096, 8));
        let config = ThrottleConfig {
            write_latency: Duration::from_millis(250),
            respect_deadline: true,
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 15);
        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();
        let data = vec![0xF1_u8; 4096];

        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(15));
            cancel_cx.set_cancel_requested(true);
        });

        let start = Instant::now();
        let err = ti
            .write_block(&cx, BlockNumber(0), &data)
            .expect_err("mid-sleep cancellation should stop throttled write");
        let elapsed = start.elapsed();
        canceller.join().expect("canceller thread should finish");

        assert!(matches!(err, FfsError::Cancelled));
        assert!(
            elapsed < Duration::from_millis(125),
            "cancelled Cx should interrupt throttle delay promptly, elapsed={elapsed:?}"
        );
        assert_eq!(ti.inner.write_count(), 0);
        assert!(ti.throttle_log().is_empty());
    }

    #[test]
    fn throttle_delay_overflow_saturates_and_respects_deadline() {
        let dev = CountingBlockDevice::new(MemBlockDevice::new(4096, 8));
        let config = ThrottleConfig {
            write_latency: Duration::MAX,
            stall_probability: 1.0,
            stall_duration: Duration::from_nanos(1),
            respect_deadline: true,
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 14);
        let deadline = Cx::for_testing().now() + Duration::from_millis(1);
        let cx = Cx::for_testing_with_budget(asupersync::Budget::new().with_deadline(deadline));
        let data = vec![0xF0_u8; 4096];

        let err = ti
            .write_block(&cx, BlockNumber(0), &data)
            .expect_err("saturated delay should not panic or reach inner write");

        assert!(matches!(err, FfsError::Cancelled));
        assert_eq!(ti.inner.write_count(), 0);
        assert!(ti.throttle_log().is_empty());
    }

    #[test]
    fn throttle_uniform_read_latency() {
        let dev = MemBlockDevice::new(4096, 8);
        let config = ThrottleConfig {
            read_latency: Duration::from_millis(10),
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 1);
        let cx = Cx::for_testing();

        let start = Instant::now();
        let _ = ti.read_block(&cx, BlockNumber(0)).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(9),
            "read should take >= 9ms, took {elapsed:?}"
        );

        let log = ti.throttle_log();
        assert_eq!(log.len(), 1);
        assert!(log[0].is_read);
        assert_eq!(log[0].delay, Duration::from_millis(10));
    }

    #[test]
    fn throttle_uniform_write_latency() {
        let dev = MemBlockDevice::new(4096, 8);
        let config = ThrottleConfig {
            write_latency: Duration::from_millis(10),
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 2);
        let cx = Cx::for_testing();

        let data = vec![0_u8; 4096];
        let start = Instant::now();
        ti.write_block(&cx, BlockNumber(0), &data).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(9),
            "write should take >= 9ms, took {elapsed:?}"
        );

        let log = ti.throttle_log();
        assert_eq!(log.len(), 1);
        assert!(!log[0].is_read);
    }

    #[test]
    fn throttle_bandwidth_limiting() {
        let dev = MemBlockDevice::new(4096, 8);
        // 4096 bytes at 409600 bytes/sec = 10ms delay
        let config = ThrottleConfig {
            bandwidth_bps: 409_600,
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 3);
        let cx = Cx::for_testing();

        let start = Instant::now();
        let _ = ti.read_block(&cx, BlockNumber(0)).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(9),
            "bandwidth-limited read should take >= 9ms, took {elapsed:?}"
        );
    }

    #[test]
    fn throttle_stall_deterministic() {
        let dev = MemBlockDevice::new(4096, 8);
        let config = ThrottleConfig {
            stall_probability: 1.0, // always stall
            stall_duration: Duration::from_millis(15),
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 4);
        let cx = Cx::for_testing();

        let start = Instant::now();
        let _ = ti.read_block(&cx, BlockNumber(0)).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(14),
            "stalled read should take >= 14ms, took {elapsed:?}"
        );

        let log = ti.throttle_log();
        assert!(log[0].stalled);
    }

    #[test]
    fn throttle_no_stall_at_zero_probability() {
        let dev = MemBlockDevice::new(4096, 8);
        let config = ThrottleConfig {
            stall_probability: 0.0,
            stall_duration: Duration::from_secs(10),
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 5);
        let cx = Cx::for_testing();

        let start = Instant::now();
        let _ = ti.read_block(&cx, BlockNumber(0)).unwrap();
        let elapsed = start.elapsed();

        // No stall, no latency → near-instant
        assert!(
            elapsed < Duration::from_millis(100),
            "should be fast, took {elapsed:?}"
        );

        let log = ti.throttle_log();
        assert!(!log[0].stalled);
    }

    #[test]
    fn throttle_progressive_degradation() {
        let dev = MemBlockDevice::new(4096, 8);
        let config = ThrottleConfig {
            read_latency: Duration::from_millis(5),
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 6);
        let cx = Cx::for_testing();

        // First read: 5ms configured latency.
        let _ = ti.read_block(&cx, BlockNumber(0)).unwrap();
        let log = ti.throttle_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].delay, Duration::from_millis(5));

        // Progressive: increase latency to 15ms.
        ti.update_config(ThrottleConfig {
            read_latency: Duration::from_millis(15),
            ..Default::default()
        });

        let _ = ti.read_block(&cx, BlockNumber(0)).unwrap();
        let log = ti.throttle_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].delay, Duration::from_millis(15));
    }

    #[test]
    fn throttle_reset_clears_log() {
        let dev = MemBlockDevice::new(4096, 8);
        let config = ThrottleConfig::default();
        let ti = ThrottleInjector::new(dev, config, 7);
        let cx = Cx::for_testing();

        let _ = ti.read_block(&cx, BlockNumber(0)).unwrap();
        assert_eq!(ti.throttle_log().len(), 1);

        ti.reset();
        assert!(ti.throttle_log().is_empty());
    }

    #[test]
    fn throttle_zero_seed_is_normalized_for_rng_replay() {
        let dev = MemBlockDevice::new(4096, 8);
        let ti = ThrottleInjector::new(dev, ThrottleConfig::default(), 0);
        assert_ne!(
            ti.seed(),
            0,
            "zero is a degenerate xorshift state and must be normalized"
        );

        let first = ti.next_random();
        let second = ti.next_random();
        assert_ne!(
            first.to_bits(),
            0,
            "normalized zero seed should not emit a zero first sample"
        );
        assert_ne!(
            first.to_bits(),
            second.to_bits(),
            "normalized zero seed should advance the RNG state"
        );

        ti.reset();
        assert_eq!(
            ti.next_random().to_bits(),
            first.to_bits(),
            "reset should restore deterministic replay from the normalized seed"
        );
    }

    #[test]
    fn throttle_rng_advances_once_per_concurrent_sample() {
        let dev = MemBlockDevice::new(4096, 8);
        let ti = StdArc::new(ThrottleInjector::new(dev, ThrottleConfig::default(), 321));
        let seed = ti.seed();
        let threads = 4;
        let samples_per_thread = 128;
        let barrier = StdArc::new(std::sync::Barrier::new(threads));

        std::thread::scope(|s| {
            for _ in 0..threads {
                let ti = StdArc::clone(&ti);
                let barrier = StdArc::clone(&barrier);
                s.spawn(move || {
                    barrier.wait();
                    for _ in 0..samples_per_thread {
                        let _ = ti.next_random();
                    }
                });
            }
        });

        let mut expected = seed;
        for _ in 0..threads * samples_per_thread {
            expected = ThrottleInjector::<MemBlockDevice>::advance_rng_state(expected);
        }

        assert_eq!(
            ti.rng_state.load(Ordering::Relaxed),
            expected,
            "concurrent sampling should not lose RNG state advances"
        );
    }

    #[test]
    fn throttle_log_sequence_monotonic() {
        let dev = MemBlockDevice::new(4096, 8);
        let config = ThrottleConfig::default();
        let ti = ThrottleInjector::new(dev, config, 8);
        let cx = Cx::for_testing();

        for i in 0..5 {
            let _ = ti.read_block(&cx, BlockNumber(i)).unwrap();
        }

        let log = ti.throttle_log();
        assert_eq!(log.len(), 5);
        for (i, record) in log.iter().enumerate() {
            assert_eq!(record.sequence, u64::try_from(i).unwrap());
        }
    }

    #[test]
    fn throttle_log_sequence_saturates_at_numeric_limit() {
        let dev = MemBlockDevice::new(4096, 8);
        let ti = ThrottleInjector::new(dev, ThrottleConfig::default(), 9);
        let cx = Cx::for_testing();

        ti.sequence.store(u64::MAX, Ordering::Relaxed);

        let _ = ti.read_block(&cx, BlockNumber(0)).unwrap();
        let _ = ti.read_block(&cx, BlockNumber(1)).unwrap();

        let log = ti.throttle_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].sequence, u64::MAX);
        assert_eq!(log[1].sequence, u64::MAX);
        assert_eq!(ti.sequence.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn throttle_combined_with_fault_injector() {
        // Stack: FaultInjector<ThrottleInjector<MemBlockDevice>>
        let dev = MemBlockDevice::new(4096, 8);
        let config = ThrottleConfig {
            read_latency: Duration::from_millis(5),
            ..Default::default()
        };
        let throttled = ThrottleInjector::new(dev, config, 9);
        let faulted = FaultInjector::new(throttled, 10);
        let cx = Cx::for_testing();

        // Normal read with throttle: should work.
        let data = vec![0xDD_u8; 4096];
        faulted
            .inner
            .inner
            .write_block(&cx, BlockNumber(0), &data)
            .ok();
        let buf = faulted.read_block(&cx, BlockNumber(0)).unwrap();
        assert_eq!(buf.as_slice()[0], 0xDD);

        // Inject fault: read should fail.
        faulted.fail_on_read(BlockNumber(1), FaultMode::OneShot);
        assert!(faulted.read_block(&cx, BlockNumber(1)).is_err());
    }

    #[test]
    fn throttle_concurrent_no_deadlock() {
        let dev = MemBlockDevice::new(4096, 16);
        let config = ThrottleConfig {
            read_latency: Duration::from_millis(1),
            write_latency: Duration::from_millis(1),
            ..Default::default()
        };
        let ti = StdArc::new(ThrottleInjector::new(dev, config, 11));
        let barrier = StdArc::new(std::sync::Barrier::new(4));

        std::thread::scope(|s| {
            for thread_id in 0_u64..4 {
                let ti = StdArc::clone(&ti);
                let barrier = StdArc::clone(&barrier);
                s.spawn(move || {
                    let cx = Cx::for_testing();
                    barrier.wait();
                    for i in 0..10 {
                        let block = BlockNumber(thread_id * 4 + i);
                        let data = vec![u8::try_from(i).unwrap_or(0); 4096];
                        ti.write_block(&cx, block, &data).unwrap();
                        let _ = ti.read_block(&cx, block).unwrap();
                    }
                });
            }
        });

        // 4 threads * 10 iterations * 2 ops (write + read) = 80 events
        assert_eq!(ti.throttle_log().len(), 80);
    }

    #[test]
    fn throttle_debug_format() {
        const THROTTLE_INJECTOR_DEBUG_GOLDEN: &str = "ThrottleInjector { config: ThrottleConfig { read_latency: 10ms, \
write_latency: 0ns, bandwidth_bps: 0, stall_probability: 0.0, stall_duration: \
0ns, respect_deadline: true }, seed: 99, events: 0, log_len: 0, rng_state: 99, \
.. }";

        let dev = MemBlockDevice::new(4096, 4);
        let config = ThrottleConfig {
            read_latency: Duration::from_millis(10),
            ..Default::default()
        };
        let ti = ThrottleInjector::new(dev, config, 99);
        assert_eq!(format!("{ti:?}"), THROTTLE_INJECTOR_DEBUG_GOLDEN);
    }

    #[test]
    fn throttle_same_seed_same_stall_pattern() {
        // Two injectors with the same seed should produce identical stall patterns.
        let config = ThrottleConfig {
            stall_probability: 0.5,
            stall_duration: Duration::from_millis(1),
            ..Default::default()
        };

        let dev1 = MemBlockDevice::new(4096, 8);
        let ti1 = ThrottleInjector::new(dev1, config.clone(), 123);
        let dev2 = MemBlockDevice::new(4096, 8);
        let ti2 = ThrottleInjector::new(dev2, config, 123);
        let cx = Cx::for_testing();

        for i in 0..20 {
            let _ = ti1.read_block(&cx, BlockNumber(i % 8)).unwrap();
            let _ = ti2.read_block(&cx, BlockNumber(i % 8)).unwrap();
        }

        let log1 = ti1.throttle_log();
        let log2 = ti2.throttle_log();
        assert_eq!(log1.len(), log2.len());
        for (r1, r2) in log1.iter().zip(log2.iter()) {
            assert_eq!(
                r1.stalled, r2.stalled,
                "stall mismatch at seq {}",
                r1.sequence
            );
        }
    }

    #[test]
    fn deferred_arc_cache_writes_and_flushes_on_drop() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);

        let deferred = DeferredArcCache::new(
            counted,
            8,
            FlushDaemonConfig {
                // Keep the "writes are initially deferred" assertion below
                // independent of scheduler timing; shutdown/drop still proves
                // the daemon joins and performs its final flush.
                interval: Duration::from_millis(250),
                batch_size: 4,
                ..FlushDaemonConfig::default()
            },
        )
        .expect("deferred cache");

        // Writes should be deferred (not immediately hitting the device).
        for i in 0..4_u64 {
            deferred
                .write_block(&cx, BlockNumber(i), &[u8::try_from(i).unwrap(); 4096])
                .expect("write");
        }
        assert!(deferred.dirty_count() > 0);
        assert_eq!(deferred.cache().inner().write_count(), 0);

        // Read back through the cache to confirm correctness.
        let buf = deferred.read_block(&cx, BlockNumber(2)).expect("read");
        assert_eq!(buf.as_slice()[0], 2);

        // Drop triggers daemon shutdown + final flush.
        drop(deferred);
        // (No assertion possible after drop — verified by absence of panic.)
    }

    #[test]
    fn deferred_arc_cache_shutdown_returns_cache() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let counted = CountingBlockDevice::new(dev);

        let deferred = DeferredArcCache::new(
            counted,
            8,
            FlushDaemonConfig {
                interval: Duration::from_millis(5),
                batch_size: 4,
                ..FlushDaemonConfig::default()
            },
        )
        .expect("deferred cache");

        for i in 0..3_u64 {
            deferred
                .write_block(&cx, BlockNumber(i), &[0xBB_u8; 4096])
                .expect("write");
        }

        let cache = deferred.shutdown();
        // After shutdown, all dirty blocks should be flushed.
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.inner().write_count(), 3);
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn aligned_vec_zero_size_is_empty() {
        let v = AlignedVec::new(0, 4096);
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
        assert_eq!(v.as_slice(), &[] as &[u8]);
        assert_eq!(v.into_vec(), Vec::<u8>::new());
    }

    #[test]
    fn aligned_vec_alignment_one_is_identity() {
        let v = AlignedVec::new(16, 1);
        assert_eq!(v.len(), 16);
        assert_eq!(v.alignment(), 1);
        assert_eq!(v.as_slice(), &[0_u8; 16]);
    }

    #[test]
    fn aligned_vec_from_vec_already_aligned_avoids_copy() {
        // When the vec is already aligned, from_vec should reuse it directly.
        let data = vec![0xAA_u8; 4096];
        let ptr_before = data.as_ptr();
        let v = AlignedVec::from_vec(data, 1);
        // With alignment=1, the original vec pointer should be preserved.
        assert_eq!(v.as_slice().as_ptr(), ptr_before);
        assert_eq!(v.len(), 4096);
    }

    #[test]
    fn aligned_vec_from_vec_empty() {
        let v = AlignedVec::from_vec(Vec::new(), 4096);
        assert!(v.is_empty());
        assert_eq!(v.alignment(), 4096);
    }

    #[test]
    fn aligned_vec_into_vec_with_offset() {
        // Test the non-trivial path where start > 0 and len < storage.len()
        let v = AlignedVec::new(128, 512);
        assert_eq!(v.into_vec().len(), 128);
    }

    #[test]
    fn block_buf_zeroed_zero_length() {
        let buf = BlockBuf::zeroed(0);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn block_buf_make_mut_creates_independent_copy() {
        let mut a = BlockBuf::new(vec![1, 2, 3]);
        let b = a.clone_ref();
        // Both share the same Arc.
        a.make_mut()[0] = 99;
        // After COW, b should still be original data.
        assert_eq!(a.as_slice(), &[99, 2, 3]);
        assert_eq!(b.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn block_buf_into_inner_with_shared_ref_copies() {
        let a = BlockBuf::new(vec![10, 20, 30]);
        let _b = a.clone_ref();
        // Arc refcount > 1, so into_inner must copy.
        let v = a.into_inner();
        assert_eq!(v, vec![10, 20, 30]);
    }

    #[test]
    fn dirty_tracker_empty_has_zero_counts() {
        let dt = DirtyTracker::default();
        assert_eq!(dt.dirty_count(), 0);
        assert_eq!(dt.dirty_bytes(), 0);
        assert!(dt.oldest_dirty_age_ticks().is_none());
        assert!(dt.dirty_blocks_oldest_first().is_empty());
        assert!(!dt.is_dirty(BlockNumber(0)));
        assert!(dt.entry(BlockNumber(0)).is_none());
        let (in_flight, committed) = dt.state_counts();
        assert_eq!(in_flight, 0);
        assert_eq!(committed, 0);
    }

    #[test]
    fn dirty_tracker_mark_clear_roundtrip() {
        let mut dt = DirtyTracker::default();
        dt.mark_dirty(BlockNumber(5), 4096, TxnId(1), None, DirtyState::InFlight);
        assert!(dt.is_dirty(BlockNumber(5)));
        assert_eq!(dt.dirty_count(), 1);
        assert_eq!(dt.dirty_bytes(), 4096);

        dt.clear_dirty_unconditional(BlockNumber(5));
        assert!(!dt.is_dirty(BlockNumber(5)));
        assert_eq!(dt.dirty_count(), 0);
        assert_eq!(dt.dirty_bytes(), 0);
    }

    #[test]
    fn dirty_tracker_clear_conditional_prevents_race() {
        let mut dt = DirtyTracker::default();
        let block = BlockNumber(1);

        // 1. T1 marks block dirty (seq 0)
        dt.mark_dirty(block, 4096, TxnId(1), None, DirtyState::Committed);
        let entry1 = dt.entry(block).unwrap();
        assert_eq!(entry1.seq, 0);

        // 2. T2 marks block dirty again (seq 1) before T1's flush completes
        dt.mark_dirty(block, 4096, TxnId(2), None, DirtyState::InFlight);
        let entry2 = dt.entry(block).unwrap();
        assert_eq!(entry2.seq, 1);

        // 3. T1's flush completes and tries to clear seq 0
        dt.clear_dirty(block, entry1.seq);

        // 4. Verification: entry2 (seq 1) should STILL be there!
        let entry_final = dt
            .entry(block)
            .expect("T2's dirty entry was incorrectly cleared by T1's flush completion!");
        assert_eq!(entry_final.seq, 1);
        assert_eq!(dt.dirty_count(), 1);
    }

    #[test]
    fn pending_flush_candidate_is_dropped_after_new_dirty_sequence() {
        let mut state = ArcState::new(2);
        let block = BlockNumber(1);
        let old_payload = BlockBuf::new(vec![0x11; 4096]);
        let new_payload = BlockBuf::new(vec![0x22; 4096]);

        state.on_miss_or_ghost_hit(block);
        state.resident.insert(block, old_payload);
        state.mark_dirty(
            block,
            4096,
            TxnId(1),
            Some(CommitSeq(1)),
            DirtyState::Committed,
        );

        let stale_retry = state.take_dirty_and_pending_flushes();
        assert_eq!(stale_retry.len(), 1);
        assert_eq!(stale_retry[0].commit_seq, CommitSeq(1));

        state.resident.insert(block, new_payload);
        state.mark_dirty(
            block,
            4096,
            TxnId(2),
            Some(CommitSeq(2)),
            DirtyState::Committed,
        );
        state.pending_flush.extend(stale_retry);

        let retry = state.take_dirty_and_pending_flushes();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].txn_id, TxnId(2));
        assert_eq!(retry[0].commit_seq, CommitSeq(2));
        assert_eq!(retry[0].data.as_slice(), &[0x22; 4096]);
    }

    #[test]
    fn dirty_tracker_clear_unconditional_works() {
        let mut dt = DirtyTracker::default();
        let block = BlockNumber(1);
        dt.mark_dirty(block, 4096, TxnId(1), None, DirtyState::Committed);
        dt.clear_dirty_unconditional(block);
        assert!(!dt.is_dirty(block));
    }

    #[test]
    fn dirty_tracker_remark_updates_age() {
        let mut dt = DirtyTracker::default();
        dt.mark_dirty(BlockNumber(1), 4096, TxnId(1), None, DirtyState::InFlight);
        dt.mark_dirty(BlockNumber(2), 4096, TxnId(1), None, DirtyState::InFlight);
        // Block 1 is oldest.
        assert_eq!(dt.dirty_blocks_oldest_first()[0], BlockNumber(1));

        // Re-mark block 1 — it should move to the tail (newest).
        dt.mark_dirty(
            BlockNumber(1),
            4096,
            TxnId(1),
            Some(CommitSeq(1)),
            DirtyState::Committed,
        );
        assert_eq!(dt.dirty_blocks_oldest_first()[0], BlockNumber(2));
        assert_eq!(dt.dirty_count(), 2);
    }

    #[test]
    fn dirty_tracker_state_counts_partition() {
        let mut dt = DirtyTracker::default();
        dt.mark_dirty(BlockNumber(1), 100, TxnId(1), None, DirtyState::InFlight);
        dt.mark_dirty(
            BlockNumber(2),
            200,
            TxnId(1),
            Some(CommitSeq(1)),
            DirtyState::Committed,
        );
        dt.mark_dirty(BlockNumber(3), 300, TxnId(2), None, DirtyState::InFlight);
        let (in_flight, committed) = dt.state_counts();
        assert_eq!(in_flight, 2);
        assert_eq!(committed, 1);
        assert_eq!(dt.dirty_bytes(), 600);
    }

    #[test]
    fn cache_metrics_hit_ratio_zero_when_no_accesses() {
        let m = CacheMetrics {
            hits: 0,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
            t1_len: 0,
            t2_len: 0,
            b1_len: 0,
            b2_len: 0,
            resident: 0,
            dirty_blocks: 0,
            dirty_bytes: 0,
            writeback_queue_depth: 0,
            oldest_dirty_age_ticks: None,
            capacity: 0,
            p: 0,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
        };
        assert!(
            m.hit_ratio().abs() < f64::EPSILON,
            "hit_ratio should be zero"
        );
        assert!(
            m.dirty_ratio().abs() < f64::EPSILON,
            "dirty_ratio should be zero"
        );
    }

    #[test]
    fn cache_metrics_dirty_ratio_zero_when_zero_capacity() {
        let m = CacheMetrics {
            hits: 10,
            misses: 5,
            evictions: 0,
            dirty_flushes: 0,
            t1_len: 0,
            t2_len: 0,
            b1_len: 0,
            b2_len: 0,
            resident: 0,
            dirty_blocks: 5,
            dirty_bytes: 20480,
            writeback_queue_depth: 0,
            oldest_dirty_age_ticks: Some(3),
            capacity: 0,
            p: 0,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
        };
        assert!(
            m.dirty_ratio().abs() < f64::EPSILON,
            "dirty_ratio should be zero with zero capacity"
        );
        // hit_ratio should still work.
        let ratio = m.hit_ratio();
        assert!((ratio - 10.0 / 15.0).abs() < 1e-10);
    }

    #[test]
    fn memory_pressure_target_capacity_clamps_to_one() {
        // Even under Critical pressure, target should be >= 1.
        assert!(MemoryPressure::Critical.target_capacity(1) >= 1);
        assert!(MemoryPressure::Critical.target_capacity(2) >= 1);
        assert!(MemoryPressure::Critical.target_capacity(100) >= 1);
    }

    #[test]
    fn memory_pressure_none_preserves_full_capacity() {
        assert_eq!(MemoryPressure::None.target_capacity(100), 100);
        assert_eq!(MemoryPressure::None.target_capacity(1), 1);
    }

    #[test]
    fn memory_pressure_ordering_decreases_target() {
        let cap = 100;
        let none = MemoryPressure::None.target_capacity(cap);
        let low = MemoryPressure::Low.target_capacity(cap);
        let med = MemoryPressure::Medium.target_capacity(cap);
        let high = MemoryPressure::High.target_capacity(cap);
        let crit = MemoryPressure::Critical.target_capacity(cap);
        assert!(none >= low);
        assert!(low >= med);
        assert!(med >= high);
        assert!(high >= crit);
        assert!(crit >= 1);
    }

    #[test]
    fn flush_daemon_config_equal_watermarks_is_invalid() {
        let config = FlushDaemonConfig {
            high_watermark: 0.5,
            critical_watermark: 0.5,
            ..FlushDaemonConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn flush_daemon_config_inverted_watermarks_is_invalid() {
        let config = FlushDaemonConfig {
            high_watermark: 0.9,
            critical_watermark: 0.8,
            ..FlushDaemonConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn flush_daemon_config_out_of_range_watermarks_is_invalid() {
        let config = FlushDaemonConfig {
            high_watermark: 1.5,
            critical_watermark: 2.0,
            ..FlushDaemonConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn flush_daemon_config_zero_reduced_batch_is_invalid() {
        let config = FlushDaemonConfig {
            reduced_batch_size: 0,
            ..FlushDaemonConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn byte_block_device_oob_read_returns_error() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        // Block 2 is out of bounds (only blocks 0, 1 exist).
        let result = dev.read_block(&cx, BlockNumber(2));
        assert!(result.is_err());
    }

    #[test]
    fn byte_block_device_oob_write_returns_error() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let result = dev.write_block(&cx, BlockNumber(2), &[0_u8; 4096]);
        assert!(result.is_err());
    }

    #[test]
    fn byte_block_device_block_count_and_size() {
        let mem = MemoryByteDevice::new(4096 * 10);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        assert_eq!(dev.block_size(), 4096);
        assert_eq!(dev.block_count(), 10);
    }

    #[test]
    fn byte_block_device_write_wrong_size_returns_error() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        // Write data that is not exactly block_size.
        let result = dev.write_block(&cx, BlockNumber(0), &[0_u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn arc_cache_capacity_one() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new(dev, 1).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[0xAA; 4096])
            .expect("write 0");
        cache
            .write_block(&cx, BlockNumber(1), &[0xBB; 4096])
            .expect("write 1");

        // With capacity 1, reading block 1 should succeed (most recent).
        let r = cache.read_block(&cx, BlockNumber(1)).expect("read 1");
        assert_eq!(r.as_slice()[0], 0xBB);

        // Block 0 was evicted but still readable from device.
        let r0 = cache.read_block(&cx, BlockNumber(0)).expect("read 0");
        assert_eq!(r0.as_slice()[0], 0xAA);

        let m = cache.metrics();
        assert!(m.resident <= 1);
    }

    #[test]
    fn arc_cache_metrics_after_sync_show_zero_dirty() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 8);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new_with_policy(dev, 4, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[1; 4096])
            .expect("write");
        assert!(cache.dirty_count() > 0);

        cache.sync(&cx).expect("sync");
        assert_eq!(cache.dirty_count(), 0);
        let m = cache.metrics();
        assert_eq!(m.dirty_blocks, 0);
        assert_eq!(m.dirty_bytes, 0);
        assert_eq!(m.writeback_queue_depth, 0);
    }

    #[test]
    fn arc_cache_runtime_metrics_track_writeback_queue_depth() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 16);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new_with_policy(dev, 8, ArcWritePolicy::WriteBack).expect("cache");

        for block in 0..4_u64 {
            cache
                .write_block(
                    &cx,
                    BlockNumber(block),
                    &[u8::try_from(block).expect("fits"); 4096],
                )
                .expect("write");
        }

        let flushed = cache.flush_dirty_batch(&cx, 1).expect("flush batch");
        assert_eq!(flushed, 1);

        let export = cache.runtime_metrics();
        assert_eq!(export.cache_dirty_count, 3);
        assert_eq!(export.writeback_queue_depth, 3);
    }

    #[test]
    fn arc_cache_write_back_read_returns_cached_dirty_data() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let cache = ArcCache::new_with_policy(dev, 4, ArcWritePolicy::WriteBack).expect("cache");

        cache
            .write_block(&cx, BlockNumber(0), &[0xFF; 4096])
            .expect("write");
        // The dirty data should be readable from cache before sync.
        let r = cache.read_block(&cx, BlockNumber(0)).expect("read");
        assert_eq!(r.as_slice(), &[0xFF; 4096]);
    }

    #[test]
    fn fault_injector_reset_clears_rules_and_log() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let fi = FaultInjector::new(dev, 42);

        fi.fail_on_read(BlockNumber(0), FaultMode::Persistent);
        let _ = fi.read_block(&cx, BlockNumber(0)); // triggers fault
        assert!(!fi.fault_log().is_empty());

        fi.reset();
        assert!(fi.fault_log().is_empty());
        // After reset, read should succeed (no rules).
        fi.read_block(&cx, BlockNumber(0))
            .expect("read after reset");
    }

    #[test]
    fn fault_injector_multiple_rules_same_block() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 4);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let fi = FaultInjector::new(dev, 0);

        // Add two OneShot rules for the same read target.
        fi.fail_on_read(BlockNumber(0), FaultMode::OneShot);
        fi.fail_on_read(BlockNumber(0), FaultMode::OneShot);

        // First read triggers first rule.
        assert!(fi.read_block(&cx, BlockNumber(0)).is_err());
        // Second read triggers second rule.
        assert!(fi.read_block(&cx, BlockNumber(0)).is_err());
        // Third read should succeed (both OneShot rules fired).
        fi.read_block(&cx, BlockNumber(0)).expect("third read");
        assert_eq!(fi.fault_log().len(), 2);
    }

    #[test]
    fn fault_count_limited_fires_n_times_then_clears() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 50);

        fi.fail_on_read(BlockNumber(3), FaultMode::CountLimited(3));

        // First 3 reads should fail.
        for i in 0..3 {
            assert!(
                fi.read_block(&cx, BlockNumber(3)).is_err(),
                "read {i} should fail"
            );
        }
        // Fourth read should succeed (count exhausted).
        fi.read_block(&cx, BlockNumber(3))
            .expect("read after count exhausted");
        // Fifth read also succeeds.
        fi.read_block(&cx, BlockNumber(3)).expect("subsequent read");

        assert_eq!(fi.fault_log().len(), 3);
    }

    #[test]
    fn fault_count_limited_write_fires_n_times() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 51);
        let data = vec![0_u8; 4096];

        fi.fail_on_write(BlockNumber(1), FaultMode::CountLimited(2));

        // First 2 writes fail.
        assert!(fi.write_block(&cx, BlockNumber(1), &data).is_err());
        assert!(fi.write_block(&cx, BlockNumber(1), &data).is_err());
        // Third write succeeds.
        fi.write_block(&cx, BlockNumber(1), &data)
            .expect("write after count exhausted");

        assert_eq!(fi.fault_log().len(), 2);
    }

    #[test]
    fn fault_count_limited_one_is_equivalent_to_oneshot() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 52);

        fi.fail_on_read(BlockNumber(0), FaultMode::CountLimited(1));

        // Single read fails.
        assert!(fi.read_block(&cx, BlockNumber(0)).is_err());
        // Next read succeeds, same as OneShot.
        fi.read_block(&cx, BlockNumber(0))
            .expect("read after single count");

        assert_eq!(fi.fault_log().len(), 1);
    }

    #[test]
    fn fault_count_limited_zero_never_fires() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 53);

        fi.fail_on_read(BlockNumber(0), FaultMode::CountLimited(0));

        // Should never fire — count is zero.
        fi.read_block(&cx, BlockNumber(0))
            .expect("read with zero count");
        fi.read_block(&cx, BlockNumber(0))
            .expect("second read with zero count");

        assert!(fi.fault_log().is_empty());
    }

    #[test]
    fn fault_count_limited_reset_clears_count() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096, 16);
        let fi = FaultInjector::new(dev, 54);

        fi.fail_on_read(BlockNumber(0), FaultMode::CountLimited(2));

        // Fire once.
        assert!(fi.read_block(&cx, BlockNumber(0)).is_err());
        assert_eq!(fi.fault_log().len(), 1);

        // Reset clears everything.
        fi.reset();
        assert!(fi.fault_log().is_empty());

        // After reset, reads succeed (rule removed).
        fi.read_block(&cx, BlockNumber(0))
            .expect("read after reset");
    }

    #[test]
    fn flush_pin_token_noop_is_noop() {
        let flush_pin = FlushPinToken::noop();
        assert!(flush_pin.is_noop());
        let real_flush_pin = FlushPinToken::new(42_u32);
        assert!(!real_flush_pin.is_noop());
    }

    #[test]
    fn normalized_alignment_edge_cases() {
        assert_eq!(normalized_alignment(0), 1);
        assert_eq!(normalized_alignment(1), 1);
        assert_eq!(normalized_alignment(2), 2);
        assert_eq!(normalized_alignment(3), 4);
        assert_eq!(normalized_alignment(4), 4);
        assert_eq!(normalized_alignment(5), 8);
        assert_eq!(normalized_alignment(4096), 4096);
    }

    #[test]
    fn normalized_alignment_oversized_request_clamps_to_supported_max() {
        assert_eq!(
            normalized_alignment(MAX_SUPPORTED_ALIGNMENT),
            MAX_SUPPORTED_ALIGNMENT
        );
        assert_eq!(
            normalized_alignment(MAX_SUPPORTED_ALIGNMENT + 1),
            MAX_SUPPORTED_ALIGNMENT
        );
        assert_eq!(normalized_alignment(usize::MAX), MAX_SUPPORTED_ALIGNMENT);
    }

    #[test]
    fn aligned_vec_extreme_alignment_is_bounded() {
        let v = AlignedVec::new(1, usize::MAX);
        assert_eq!(v.alignment(), MAX_SUPPORTED_ALIGNMENT);
        assert_eq!(v.len(), 1);
        assert_eq!(v.as_slice().len(), 1);
        assert_eq!(
            (v.as_slice().as_ptr() as usize) % MAX_SUPPORTED_ALIGNMENT,
            0
        );
    }

    // ── Additional edge-case hardening tests ──────────────────────────

    #[test]
    fn aligned_vec_large_alignment() {
        let v = AlignedVec::new(64, 1024);
        assert_eq!(v.len(), 64);
        assert_eq!(v.alignment(), 1024);
        assert_eq!(v.as_slice().len(), 64);
        let ptr = v.as_slice().as_ptr() as usize;
        assert_eq!(ptr % 1024, 0, "should be 1024-byte aligned");
    }

    #[test]
    fn aligned_vec_non_power_of_two_alignment_rounds_up() {
        let v = AlignedVec::new(32, 7); // 7 → 8
        assert_eq!(v.alignment(), 8);
    }

    #[test]
    fn aligned_vec_mut_slice_writes_persist() {
        let mut v = AlignedVec::new(8, 1);
        v.as_mut_slice().fill(0xAB);
        assert!(v.as_slice().iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn aligned_vec_into_vec_zero_offset_no_copy() {
        let v = AlignedVec::new(16, 1);
        let vec = v.into_vec();
        assert_eq!(vec.len(), 16);
    }

    #[test]
    fn aligned_vec_eq_ignores_alignment() {
        let a = AlignedVec::from_vec(vec![1, 2, 3], 4);
        let b = AlignedVec::from_vec(vec![1, 2, 3], 8);
        assert_eq!(
            a, b,
            "equality should be content-based, not alignment-based"
        );
    }

    #[test]
    fn block_buf_len_matches_content() {
        let buf = BlockBuf::new(vec![0; 512]);
        assert_eq!(buf.len(), 512);
        assert!(!buf.is_empty());

        let empty = BlockBuf::new(Vec::new());
        assert!(empty.is_empty());
    }

    #[test]
    fn block_buf_eq_by_content() {
        let a = BlockBuf::new(vec![0xAA; 128]);
        let b = BlockBuf::new(vec![0xAA; 128]);
        assert_eq!(a, b);

        let c = BlockBuf::new(vec![0xBB; 128]);
        assert_ne!(a, c);
    }

    #[test]
    fn block_buf_alignment_is_page_aligned() {
        let buf = BlockBuf::new(vec![0; 4096]);
        assert_eq!(buf.alignment(), DEFAULT_BLOCK_ALIGNMENT);
    }

    #[test]
    fn block_buf_clone_ref_shares_data() {
        let buf = BlockBuf::new(vec![0xFF; 64]);
        let cloned = buf.clone_ref();
        assert_eq!(buf.as_slice(), cloned.as_slice());
        // They share the same Arc, so modifying one doesn't affect the other
        // (CoW on make_mut).
    }

    #[test]
    fn block_buf_zeroed_is_all_zeros() {
        let buf = BlockBuf::zeroed(4096);
        assert!(buf.as_slice().iter().all(|&b| b == 0));
        assert_eq!(buf.len(), 4096);
    }

    #[test]
    fn cache_metrics_hit_ratio_all_hits() {
        let m = CacheMetrics {
            hits: 100,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
            t1_len: 0,
            t2_len: 0,
            b1_len: 0,
            b2_len: 0,
            resident: 0,
            dirty_blocks: 0,
            dirty_bytes: 0,
            writeback_queue_depth: 0,
            oldest_dirty_age_ticks: None,
            capacity: 10,
            p: 5,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
        };
        assert!((m.hit_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cache_metrics_dirty_ratio_at_capacity() {
        let m = CacheMetrics {
            hits: 0,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
            t1_len: 0,
            t2_len: 0,
            b1_len: 0,
            b2_len: 0,
            resident: 10,
            dirty_blocks: 10,
            dirty_bytes: 40960,
            writeback_queue_depth: 0,
            oldest_dirty_age_ticks: Some(0),
            capacity: 10,
            p: 5,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
        };
        assert!((m.dirty_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn arc_write_policy_debug_and_eq() {
        assert_eq!(ArcWritePolicy::WriteThrough, ArcWritePolicy::WriteThrough);
        assert_ne!(ArcWritePolicy::WriteThrough, ArcWritePolicy::WriteBack);
        let _ = format!("{:?}", ArcWritePolicy::WriteBack);
    }

    #[test]
    fn memory_pressure_all_variants_target_fractions() {
        // Ensure all 5 variants produce distinct target capacities for capacity 100.
        let cap = 100;
        let targets: Vec<usize> = [
            MemoryPressure::None,
            MemoryPressure::Low,
            MemoryPressure::Medium,
            MemoryPressure::High,
            MemoryPressure::Critical,
        ]
        .iter()
        .map(|p| p.target_capacity(cap))
        .collect();

        // Should be monotonically decreasing.
        for w in targets.windows(2) {
            assert!(w[0] >= w[1], "targets should decrease: {targets:?}");
        }
        assert_eq!(targets[0], 100); // None → full capacity
    }

    #[test]
    fn memory_pressure_critical_clamps_to_one() {
        // Even with a small capacity, target should be at least 1.
        assert_eq!(MemoryPressure::Critical.target_capacity(1), 1);
        assert_eq!(MemoryPressure::Critical.target_capacity(2), 1);
    }

    #[test]
    fn flush_daemon_config_default_validates() {
        let cfg = FlushDaemonConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn flush_daemon_config_valid_custom() {
        let cfg = FlushDaemonConfig {
            interval: Duration::from_millis(100),
            batch_size: 64,
            budget_poll_quota_threshold: 128,
            reduced_batch_size: 16,
            budget_yield_sleep: Duration::from_millis(5),
            high_watermark: 0.7,
            critical_watermark: 0.9,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn flush_pin_token_debug_format() {
        const FLUSH_PIN_TOKEN_NOOP_DEBUG_GOLDEN: &str = "FlushPinToken(false)";
        const FLUSH_PIN_TOKEN_REAL_DEBUG_GOLDEN: &str = "FlushPinToken(true)";

        let noop = FlushPinToken::noop();
        let dbg = format!("{noop:?}");
        assert_eq!(dbg, FLUSH_PIN_TOKEN_NOOP_DEBUG_GOLDEN);

        let real = FlushPinToken::new(42_u32);
        let dbg = format!("{real:?}");
        assert_eq!(dbg, FLUSH_PIN_TOKEN_REAL_DEBUG_GOLDEN);
    }

    #[test]
    fn flush_pin_token_default_is_noop() {
        let flush_pin = FlushPinToken::default();
        assert!(flush_pin.is_noop());
    }

    #[test]
    fn fault_mode_debug_and_eq() {
        assert_eq!(FaultMode::OneShot, FaultMode::OneShot);
        assert_ne!(FaultMode::OneShot, FaultMode::Persistent);
        assert_eq!(FaultMode::CountLimited(3), FaultMode::CountLimited(3));
        assert_ne!(FaultMode::CountLimited(3), FaultMode::CountLimited(5));
        assert_ne!(FaultMode::CountLimited(1), FaultMode::OneShot);
        let _ = format!("{:?}", FaultMode::Persistent);
        let _ = format!("{:?}", FaultMode::CountLimited(10));
    }

    #[test]
    fn fault_target_debug_and_eq() {
        let r = FaultTarget::Read(BlockNumber(5));
        let w = FaultTarget::Write(BlockNumber(5));
        assert_ne!(r, w);
        assert_eq!(r, FaultTarget::Read(BlockNumber(5)));
        let _ = format!("{r:?}");
    }

    #[test]
    fn throttle_config_default_is_zero_latency() {
        let cfg = ThrottleConfig::default();
        assert_eq!(cfg.read_latency, Duration::ZERO);
        assert_eq!(cfg.write_latency, Duration::ZERO);
        assert_eq!(cfg.bandwidth_bps, 0);
        assert!(
            cfg.stall_probability.abs() < f64::EPSILON,
            "stall_probability should be zero"
        );
        assert!(cfg.respect_deadline);
    }

    #[test]
    fn cache_pressure_report_debug_and_clone() {
        let report = CachePressureReport {
            current_size: 100,
            target_size: 80,
            dirty_count: 10,
            eviction_rate: 0.05,
        };
        let cloned = report;
        assert_eq!(report.current_size, cloned.current_size);
        let _ = format!("{report:?}");
    }

    // ── Property-based tests (proptest) ────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// ARC invariants hold after arbitrary access sequences.
        #[test]
        fn proptest_arc_invariants_under_random_access(
            capacity in 1_usize..32,
            accesses in prop::collection::vec(0_u64..128, 1..200),
        ) {
            let mut state = ArcState::new(capacity);
            for &key in &accesses {
                arc_access(&mut state, BlockNumber(key));
            }
            // Final invariant checks (arc_access already asserts per-access).
            prop_assert_eq!(state.resident.len(), state.t1.len() + state.t2.len());
            prop_assert!(state.resident.len() <= state.capacity);
        }

        /// All distinct accessed keys are trackable in the ARC loc map.
        #[test]
        fn proptest_arc_loc_map_consistent(
            capacity in 2_usize..16,
            accesses in prop::collection::vec(0_u64..64, 1..100),
        ) {
            let mut state = ArcState::new(capacity);
            for &key in &accesses {
                arc_access(&mut state, BlockNumber(key));
            }
            // Every key in T1/T2/B1/B2 must be in loc.
            for &k in &state.t1 {
                prop_assert!(state.loc.contains_key(&k), "T1 key {:?} not in loc", k);
            }
            for &k in &state.t2 {
                prop_assert!(state.loc.contains_key(&k), "T2 key {:?} not in loc", k);
            }
            #[cfg(feature = "s3fifo")]
            {
                for k in state.b1_live_keys() {
                    prop_assert!(!state.resident.contains_key(&k), "live B1 key {:?} is resident", k);
                }
                for k in state.b2_live_keys() {
                    prop_assert!(!state.resident.contains_key(&k), "live B2 key {:?} is resident", k);
                }
            }
            #[cfg(not(feature = "s3fifo"))]
            {
                for &k in &state.b1 {
                    prop_assert!(state.loc.contains_key(&k), "B1 key {:?} not in loc", k);
                }
                for &k in &state.b2 {
                    prop_assert!(state.loc.contains_key(&k), "B2 key {:?} not in loc", k);
                }
            }
        }

        /// Repeated access to the same key always results in a hit (after first miss).
        #[test]
        fn proptest_repeated_access_is_hit(
            capacity in 1_usize..16,
            key in 0_u64..100,
            repeats in 2_usize..20,
        ) {
            let mut state = ArcState::new(capacity);
            // First access: miss.
            arc_access(&mut state, BlockNumber(key));
            prop_assert_eq!(state.misses, 1);

            let hits_before = state.hits;
            for _ in 1..repeats {
                arc_access(&mut state, BlockNumber(key));
            }
            // All subsequent accesses should be hits.
            prop_assert_eq!(
                state.hits,
                hits_before + (repeats as u64 - 1),
                "repeated access should always hit",
            );
        }

        /// Dirty blocks are never evicted by ARC replacement.
        /// When dirty blocks pin, resident may temporarily exceed capacity;
        /// we test only that the dirty block is never removed from resident.
        #[test]
        fn proptest_dirty_blocks_not_evicted(
            capacity in 2_usize..8,
            dirty_key in 0_u64..4,
            other_keys in prop::collection::vec(4_u64..32, 10..50),
        ) {
            let mut state = ArcState::new(capacity);

            // Insert and mark the dirty block.
            state.on_miss_or_ghost_hit(BlockNumber(dirty_key));
            state.resident.insert(BlockNumber(dirty_key), BlockBuf::new(vec![0xDD]));
            state.dirty.mark_dirty(
                BlockNumber(dirty_key),
                1,
                TxnId(0),
                None,
                DirtyState::InFlight,
            );

            // Access many other distinct keys to force eviction pressure.
            for &key in &other_keys {
                if state.resident.contains_key(&BlockNumber(key)) {
                    state.on_hit(BlockNumber(key));
                } else {
                    state.on_miss_or_ghost_hit(BlockNumber(key));
                    state.resident.insert(BlockNumber(key), BlockBuf::new(vec![0_u8]));
                }
            }

            // The dirty block must still be resident (never evicted).
            prop_assert!(
                state.resident.contains_key(&BlockNumber(dirty_key)),
                "dirty block {} was evicted from resident map",
                dirty_key,
            );
        }

        /// Cache capacity is respected: resident count never exceeds capacity.
        #[test]
        fn proptest_capacity_never_exceeded(
            capacity in 1_usize..16,
            accesses in prop::collection::vec(0_u64..256, 1..300),
        ) {
            let mut state = ArcState::new(capacity);
            for &key in &accesses {
                arc_access(&mut state, BlockNumber(key));
                prop_assert!(
                    state.resident.len() <= state.capacity,
                    "resident {} exceeds capacity {} after accessing key {}",
                    state.resident.len(),
                    state.capacity,
                    key,
                );
            }
        }

        /// hits + misses equals the total number of accesses.
        #[test]
        fn proptest_hits_plus_misses_equals_accesses(
            capacity in 1_usize..16,
            accesses in prop::collection::vec(0_u64..64, 1..100),
        ) {
            let mut state = ArcState::new(capacity);
            for &key in &accesses {
                arc_access(&mut state, BlockNumber(key));
            }
            prop_assert_eq!(
                state.hits + state.misses,
                accesses.len() as u64,
                "hits ({}) + misses ({}) != accesses ({})",
                state.hits,
                state.misses,
                accesses.len(),
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn proptest_lab_arc_cache_seeded_determinism_and_invariants(
            seed in any::<u64>(),
        ) {
            const READERS: usize = 3;
            const WRITERS: usize = 2;
            const READ_OPS: usize = 40;
            const WRITE_OPS: usize = 25;
            const EXPECTED_READS: usize = READERS * READ_OPS;
            const EXPECTED_ACCESSES: usize = EXPECTED_READS + (WRITERS * WRITE_OPS);
            const CAPACITY: usize = 4;

            let first = run_lab_arc_cache_scenario(seed);
            let second = run_lab_arc_cache_scenario(seed);
            prop_assert_eq!(first, second, "same seed should produce same lab summary");

            prop_assert_eq!(first.read_events, EXPECTED_READS);
            prop_assert_eq!(
                first.hits + first.misses,
                u64::try_from(EXPECTED_ACCESSES).expect("expected accesses fit u64"),
            );
            prop_assert!(
                first.resident <= CAPACITY,
                "resident {} exceeds capacity {}",
                first.resident,
                CAPACITY,
            );
            prop_assert_eq!(
                first.dirty_blocks, 0,
                "write-through cache should not retain dirty blocks",
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        // ── Additional property tests (GreenSnow) ─────────────────────

        /// AlignedVec alignment guarantee: exposed slice starts at the
        /// requested alignment for all sizes and alignment values.
        #[test]
        fn proptest_aligned_vec_alignment_guarantee(
            size in 0_usize..=8192,
            alignment_shift in 0_u32..=12,
        ) {
            let alignment = 1_usize << alignment_shift;
            let aligned = AlignedVec::new(size, alignment);
            prop_assert_eq!(aligned.len(), size);
            if size > 0 {
                let ptr = aligned.as_slice().as_ptr() as usize;
                prop_assert_eq!(
                    ptr % alignment, 0,
                    "ptr {:#x} not aligned to {}", ptr, alignment,
                );
            }
        }

        /// AlignedVec from_vec preserves data byte-for-byte.
        #[test]
        fn proptest_aligned_vec_from_vec_preserves_data(
            data in prop::collection::vec(any::<u8>(), 0..=1024),
            alignment_shift in 0_u32..=12,
        ) {
            let alignment = 1_usize << alignment_shift;
            let aligned = AlignedVec::from_vec(data.clone(), alignment);
            prop_assert_eq!(aligned.as_slice(), data.as_slice());
            prop_assert_eq!(aligned.len(), data.len());
        }

        /// AlignedVec into_vec roundtrip preserves data.
        #[test]
        fn proptest_aligned_vec_into_vec_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..=1024),
            alignment_shift in 0_u32..=12,
        ) {
            let alignment = 1_usize << alignment_shift;
            let aligned = AlignedVec::from_vec(data.clone(), alignment);
            let recovered = aligned.into_vec();
            prop_assert_eq!(recovered, data);
        }

        /// BlockBuf CoW semantics: clone_ref shares data, make_mut
        /// triggers copy-on-write, original is preserved.
        #[test]
        fn proptest_block_buf_cow_semantics(
            data in prop::collection::vec(any::<u8>(), 1..=512),
            mutate_byte in any::<u8>(),
        ) {
            let mut buf = BlockBuf::new(data.clone());
            let clone = buf.clone_ref();

            // Clone shares the same data.
            prop_assert_eq!(clone.as_slice(), data.as_slice());

            // Mutate original via make_mut.
            buf.make_mut()[0] = mutate_byte;

            // Clone is unaffected (CoW).
            prop_assert_eq!(clone.as_slice(), data.as_slice());
            prop_assert_eq!(buf.as_slice()[0], mutate_byte);
        }

        /// BlockBuf::zeroed creates an all-zero buffer of the right length.
        #[test]
        fn proptest_block_buf_zeroed(
            len in 0_usize..=8192,
        ) {
            let buf = BlockBuf::zeroed(len);
            prop_assert_eq!(buf.len(), len);
            prop_assert!(buf.as_slice().iter().all(|&b| b == 0));
        }

        /// BlockBuf into_inner roundtrip preserves data.
        #[test]
        fn proptest_block_buf_into_inner_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..=512),
        ) {
            let buf = BlockBuf::new(data.clone());
            prop_assert_eq!(buf.into_inner(), data);
        }

        /// DirtyTracker: mark N blocks, dirty_count matches.
        #[test]
        fn proptest_dirty_tracker_count_matches_marks(
            block_ids in prop::collection::hash_set(0_u64..100, 0..=50),
        ) {
            let mut tracker = DirtyTracker::default();
            for &id in &block_ids {
                tracker.mark_dirty(
                    BlockNumber(id), 4096, TxnId(0), None, DirtyState::InFlight,
                );
            }
            prop_assert_eq!(tracker.dirty_count(), block_ids.len());
            prop_assert_eq!(tracker.dirty_bytes(), block_ids.len() * 4096);
        }

        /// DirtyTracker: clear restores count to zero.
        #[test]
        fn proptest_dirty_tracker_clear_restores_zero(
            block_ids in prop::collection::vec(0_u64..50, 1..=20),
        ) {
            let mut tracker = DirtyTracker::default();
            for &id in &block_ids {
                tracker.mark_dirty(
                    BlockNumber(id), 4096, TxnId(0), None, DirtyState::Committed,
                );
            }
            let unique: HashSet<u64> = block_ids.iter().copied().collect();
            for &id in &unique {
                tracker.clear_dirty_unconditional(BlockNumber(id));
            }
            prop_assert_eq!(tracker.dirty_count(), 0);
            prop_assert_eq!(tracker.dirty_bytes(), 0);
        }

        /// DirtyTracker: oldest_first ordering is FIFO by insertion order.
        #[test]
        fn proptest_dirty_tracker_fifo_ordering(
            block_ids in prop::collection::vec(0_u64..200, 1..=30),
        ) {
            let mut tracker = DirtyTracker::default();
            for &id in &block_ids {
                tracker.mark_dirty(
                    BlockNumber(id), 4096, TxnId(0), None, DirtyState::InFlight,
                );
            }
            // Re-derive insertion order: last occurrence of each unique ID
            // (re-marking moves to end).
            let mut last_seen_order = Vec::new();
            let mut seen_rev = HashSet::new();
            for &id in block_ids.iter().rev() {
                if seen_rev.insert(id) {
                    last_seen_order.push(id);
                }
            }
            last_seen_order.reverse();
            let oldest_first = tracker.dirty_blocks_oldest_first();
            let oldest_ids: Vec<u64> = oldest_first.iter().map(|b| b.0).collect();
            prop_assert_eq!(oldest_ids, last_seen_order);
        }

        /// DirtyTracker: double-mark replaces old entry, count stays same.
        #[test]
        fn proptest_dirty_tracker_double_mark_replaces(
            block_id in 0_u64..100,
            bytes1 in 1_usize..=8192,
            bytes2 in 1_usize..=8192,
        ) {
            let mut tracker = DirtyTracker::default();
            tracker.mark_dirty(
                BlockNumber(block_id), bytes1, TxnId(0), None, DirtyState::InFlight,
            );
            prop_assert_eq!(tracker.dirty_count(), 1);
            prop_assert_eq!(tracker.dirty_bytes(), bytes1);

            tracker.mark_dirty(
                BlockNumber(block_id), bytes2, TxnId(1), None, DirtyState::Committed,
            );
            prop_assert_eq!(tracker.dirty_count(), 1);
            prop_assert_eq!(tracker.dirty_bytes(), bytes2);
        }

        /// MemoryPressure::target_capacity always in [1, max_capacity].
        #[test]
        fn proptest_memory_pressure_target_in_range(
            max_capacity in 1_usize..=10000,
            pressure_idx in 0_u8..=4,
        ) {
            let pressure = match pressure_idx {
                0 => MemoryPressure::None,
                1 => MemoryPressure::Low,
                2 => MemoryPressure::Medium,
                3 => MemoryPressure::High,
                _ => MemoryPressure::Critical,
            };
            let target = pressure.target_capacity(max_capacity);
            prop_assert!(target >= 1, "target {} < 1", target);
            prop_assert!(
                target <= max_capacity,
                "target {} > max {}", target, max_capacity,
            );
        }

        /// CacheMetrics hit_ratio is always in [0.0, 1.0].
        #[test]
        fn proptest_cache_metrics_hit_ratio_bounded(
            hits in 0_u64..=1_000_000,
            misses in 0_u64..=1_000_000,
        ) {
            let metrics = CacheMetrics {
                hits, misses,
                evictions: 0, dirty_flushes: 0,
                t1_len: 0, t2_len: 0, b1_len: 0, b2_len: 0,
                resident: 0, dirty_blocks: 0, dirty_bytes: 0, writeback_queue_depth: 0,
                oldest_dirty_age_ticks: None, capacity: 100, p: 0,
                b1_ghost_hits: 0, b2_ghost_hits: 0,
            };
            let ratio = metrics.hit_ratio();
            prop_assert!((0.0..=1.0).contains(&ratio), "ratio {}", ratio);
        }

        /// CacheMetrics dirty_ratio in [0.0, 1.0] when dirty_blocks <= capacity.
        #[test]
        fn proptest_cache_metrics_dirty_ratio_bounded(
            dirty_blocks in 0_usize..=100,
            capacity in 1_usize..=100,
        ) {
            prop_assume!(dirty_blocks <= capacity);
            let metrics = CacheMetrics {
                hits: 0, misses: 0, evictions: 0, dirty_flushes: 0,
                t1_len: 0, t2_len: 0, b1_len: 0, b2_len: 0,
                resident: 0, dirty_blocks, dirty_bytes: 0, writeback_queue_depth: 0,
                oldest_dirty_age_ticks: None, capacity, p: 0,
                b1_ghost_hits: 0, b2_ghost_hits: 0,
            };
            let ratio = metrics.dirty_ratio();
            prop_assert!((0.0..=1.0).contains(&ratio), "ratio {}", ratio);
        }

        /// normalized_alignment always returns 1 or a power of 2.
        #[test]
        fn proptest_normalized_alignment_power_of_two(
            requested in 0_usize..=65536,
        ) {
            let result = normalized_alignment(requested);
            prop_assert!(
                result == 1 || result.is_power_of_two(),
                "normalized_alignment({}) = {} is not 1 or power of 2",
                requested, result,
            );
            prop_assert!(
                result >= requested || requested <= 1,
                "normalized_alignment({}) = {} is less than requested",
                requested, result,
            );
        }

        /// ARC evictions monotonically increase with access count.
        #[test]
        fn proptest_arc_evictions_monotonic(
            capacity in 1_usize..8,
            accesses in prop::collection::vec(0_u64..64, 1..100),
        ) {
            let mut state = ArcState::new(capacity);
            let mut prev_evictions = 0_u64;
            for &key in &accesses {
                arc_access(&mut state, BlockNumber(key));
                prop_assert!(
                    state.evictions >= prev_evictions,
                    "evictions decreased from {} to {}",
                    prev_evictions, state.evictions,
                );
                prev_evictions = state.evictions;
            }
        }

        /// DirtyTracker state_counts partitions into in_flight + committed == dirty_count.
        #[test]
        fn proptest_dirty_tracker_state_counts_partition(
            ops in proptest::collection::vec(
                (0_u64..32, any::<bool>()),
                1..32,
            ),
        ) {
            let mut tracker = DirtyTracker::default();
            for (i, &(block, committed)) in ops.iter().enumerate() {
                let state = if committed {
                    DirtyState::Committed
                } else {
                    DirtyState::InFlight
                };
                tracker.mark_dirty(
                    BlockNumber(block),
                    8,
                    TxnId(0),
                    if committed { Some(CommitSeq(i as u64)) } else { None },
                    state,
                );
            }
            let (in_flight, committed) = tracker.state_counts();
            prop_assert_eq!(
                in_flight + committed,
                tracker.dirty_count(),
                "state_counts sum ({} + {}) != dirty_count ({})",
                in_flight, committed, tracker.dirty_count(),
            );
        }

        /// DirtyTracker dirty_bytes matches the sum of bytes of all tracked blocks.
        #[test]
        fn proptest_dirty_tracker_bytes_accounting(
            ops in proptest::collection::vec(
                (0_u64..16, 1_usize..256),
                1..32,
            ),
        ) {
            let mut tracker = DirtyTracker::default();
            let mut expected_blocks = HashMap::<u64, usize>::new();
            for &(block, bytes) in &ops {
                tracker.mark_dirty(
                    BlockNumber(block),
                    bytes,
                    TxnId(0),
                    None,
                    DirtyState::Committed,
                );
                expected_blocks.insert(block, bytes);
            }
            let expected_bytes: usize = expected_blocks.values().sum();
            prop_assert_eq!(
                tracker.dirty_bytes(),
                expected_bytes,
                "dirty_bytes mismatch",
            );
        }

        /// DirtyTracker oldest age matches a simple sequence-number model.
        ///
        /// Re-marking the current oldest block can legitimately decrease age
        /// because that block is moved to the newest position.
        #[test]
        fn proptest_dirty_tracker_oldest_age_matches_sequence_model(
            blocks in proptest::collection::vec(0_u64..64, 1..32),
        ) {
            let mut tracker = DirtyTracker::default();
            let mut model_next_seq = 0_u64;
            let mut model_by_block: HashMap<u64, u64> = HashMap::new();

            for &block in &blocks {
                tracker.mark_dirty(
                    BlockNumber(block),
                    8,
                    TxnId(0),
                    None,
                    DirtyState::Committed,
                );

                model_by_block.insert(block, model_next_seq);
                model_next_seq = model_next_seq.saturating_add(1);

                let expected = model_by_block
                    .values()
                    .min()
                    .map(|oldest_seq| model_next_seq.saturating_sub(*oldest_seq));
                prop_assert_eq!(
                    tracker.oldest_dirty_age_ticks(),
                    expected,
                    "oldest age mismatch after marking block {}",
                    block,
                );
            }
        }

        /// FlushDaemonConfig::validate accepts valid configs.
        #[test]
        fn proptest_flush_daemon_config_valid_accepted(
            interval_ms in 1_u64..10_000,
            batch_size in 1_usize..1024,
            reduced_batch_size in 1_usize..256,
            high_wm in 0.01_f64..0.5,
            critical_delta in 0.01_f64..0.5,
        ) {
            let critical_wm = (high_wm + critical_delta).min(1.0);
            // Only test when the constraint actually holds
            prop_assume!(high_wm < critical_wm && critical_wm <= 1.0);
            let config = FlushDaemonConfig {
                interval: Duration::from_millis(interval_ms),
                batch_size,
                budget_poll_quota_threshold: 256,
                reduced_batch_size,
                budget_yield_sleep: Duration::from_millis(10),
                high_watermark: high_wm,
                critical_watermark: critical_wm,
            };
            prop_assert!(config.validate().is_ok(), "valid config rejected");
        }

        /// FlushDaemonConfig::validate rejects zero interval.
        #[test]
        fn proptest_flush_daemon_config_rejects_zero_interval(
            batch_size in 1_usize..256,
        ) {
            let config = FlushDaemonConfig {
                interval: Duration::ZERO,
                batch_size,
                ..FlushDaemonConfig::default()
            };
            prop_assert!(config.validate().is_err());
        }

        /// FlushDaemonConfig::validate rejects invalid watermarks.
        #[test]
        fn proptest_flush_daemon_config_rejects_inverted_watermarks(
            high in 0.5_f64..1.0,
            critical in 0.0_f64..0.5,
        ) {
            // high >= critical should always fail
            prop_assume!(high >= critical);
            let config = FlushDaemonConfig {
                high_watermark: high,
                critical_watermark: critical,
                ..FlushDaemonConfig::default()
            };
            prop_assert!(config.validate().is_err());
        }

        /// MemoryPressure target_capacity ordering:
        /// Critical <= High <= Medium <= Low <= None == max_capacity.
        #[test]
        fn proptest_memory_pressure_ordering(
            max_capacity in 2_usize..1024,
        ) {
            let none = MemoryPressure::None.target_capacity(max_capacity);
            let low = MemoryPressure::Low.target_capacity(max_capacity);
            let med = MemoryPressure::Medium.target_capacity(max_capacity);
            let high = MemoryPressure::High.target_capacity(max_capacity);
            let crit = MemoryPressure::Critical.target_capacity(max_capacity);
            prop_assert!(crit <= high, "Critical {} > High {}", crit, high);
            prop_assert!(high <= med, "High {} > Medium {}", high, med);
            prop_assert!(med <= low, "Medium {} > Low {}", med, low);
            prop_assert!(low <= none, "Low {} > None {}", low, none);
            prop_assert_eq!(none, max_capacity);
        }

        /// ArcCache stage/commit/abort via ArcState internal API:
        /// staged writes are accessible after staging, and abort clears them.
        #[test]
        fn proptest_arc_state_stage_commit_abort(
            blocks in proptest::collection::vec(0_u64..32, 1..8),
            abort in any::<bool>(),
        ) {
            let mut state = ArcState::new(64);
            let txn_id = TxnId(1);
            for &block in &blocks {
                state.stage_txn_write(txn_id, BlockNumber(block), &[0xAA; 8])
                    .expect("stage");
            }

            let taken = state.take_staged_txn(txn_id);
            if abort {
                // Taken set should contain all unique blocks staged
                let unique_blocks: std::collections::BTreeSet<_> = blocks.iter().copied().collect();
                prop_assert_eq!(taken.len(), unique_blocks.len());
                // After take, staging again for same txn should work
                let taken2 = state.take_staged_txn(txn_id);
                prop_assert!(taken2.is_empty());
            } else {
                // Commit path: insert into resident + mark dirty
                for (block, data) in &taken {
                    state.on_miss_or_ghost_hit(*block);
                    state.resident.insert(*block, BlockBuf::new(data.clone()));
                    state.mark_dirty(
                        *block,
                        data.len(),
                        txn_id,
                        Some(CommitSeq(1)),
                        DirtyState::Committed,
                    );
                }
                let unique_blocks: std::collections::BTreeSet<_> = blocks.iter().copied().collect();
                prop_assert_eq!(state.dirty.dirty_count(), unique_blocks.len());
                // All committed blocks should be resident
                for &block in &unique_blocks {
                    prop_assert!(state.resident.contains_key(&BlockNumber(block)));
                }
            }
        }

        /// ArcCache: staged block ownership prevents cross-txn staging.
        #[test]
        fn proptest_arc_state_staged_block_ownership(
            block in 0_u64..64,
        ) {
            let mut state = ArcState::new(64);
            let txn_a = TxnId(1);
            let txn_b = TxnId(2);
            state.stage_txn_write(txn_a, BlockNumber(block), &[0xAA; 8])
                .expect("stage by txn_a");
            // Staging same block by different txn should fail
            let result = state.stage_txn_write(txn_b, BlockNumber(block), &[0xBB; 8]);
            prop_assert!(result.is_err(), "cross-txn staging should fail");
            // Same txn can re-stage (overwrite)
            state.stage_txn_write(txn_a, BlockNumber(block), &[0xCC; 8])
                .expect("re-stage by same txn");
        }
    }

    // ── DirtyTracker unit tests ─────────────────────────────────────────

    #[test]
    fn dirty_tracker_empty_has_no_entries() {
        let tracker = DirtyTracker::default();
        assert_eq!(tracker.dirty_count(), 0);
        assert_eq!(tracker.dirty_bytes(), 0);
        assert!(tracker.oldest_dirty_age_ticks().is_none());
        assert!(tracker.dirty_blocks_oldest_first().is_empty());
        assert!(!tracker.is_dirty(BlockNumber(0)));
        assert!(tracker.entry(BlockNumber(0)).is_none());
        assert_eq!(tracker.state_counts(), (0, 0));
    }

    #[test]
    fn dirty_tracker_mark_and_clear() {
        let mut tracker = DirtyTracker::default();
        tracker.mark_dirty(BlockNumber(5), 4096, TxnId(1), None, DirtyState::InFlight);
        assert!(tracker.is_dirty(BlockNumber(5)));
        assert_eq!(tracker.dirty_count(), 1);
        assert_eq!(tracker.dirty_bytes(), 4096);
        assert_eq!(tracker.state_counts(), (1, 0));

        tracker.clear_dirty_unconditional(BlockNumber(5));
        assert!(!tracker.is_dirty(BlockNumber(5)));
        assert_eq!(tracker.dirty_count(), 0);
        assert_eq!(tracker.dirty_bytes(), 0);
    }

    #[test]
    fn dirty_tracker_clear_absent_block_is_noop() {
        let mut tracker = DirtyTracker::default();
        tracker.clear_dirty_unconditional(BlockNumber(99));
        assert_eq!(tracker.dirty_count(), 0);
    }

    #[test]
    fn dirty_tracker_remark_updates_age_and_bytes() {
        let mut tracker = DirtyTracker::default();
        tracker.mark_dirty(BlockNumber(1), 1024, TxnId(1), None, DirtyState::InFlight);
        tracker.mark_dirty(BlockNumber(2), 2048, TxnId(1), None, DirtyState::InFlight);
        assert_eq!(
            tracker.dirty_blocks_oldest_first(),
            vec![BlockNumber(1), BlockNumber(2)]
        );
        assert_eq!(tracker.dirty_bytes(), 1024 + 2048);

        // Re-mark block 1 with a larger size — moves to newest, updates bytes.
        tracker.mark_dirty(BlockNumber(1), 4096, TxnId(2), None, DirtyState::Committed);
        assert_eq!(
            tracker.dirty_blocks_oldest_first(),
            vec![BlockNumber(2), BlockNumber(1)]
        );
        assert_eq!(tracker.dirty_bytes(), 2048 + 4096);
        assert_eq!(tracker.state_counts(), (1, 1));
    }

    #[test]
    fn dirty_tracker_oldest_age_ticks_reflects_sequence_gap() {
        let mut tracker = DirtyTracker::default();
        tracker.mark_dirty(BlockNumber(0), 512, TxnId(1), None, DirtyState::Committed);
        assert_eq!(tracker.oldest_dirty_age_ticks(), Some(1));

        tracker.mark_dirty(BlockNumber(1), 512, TxnId(1), None, DirtyState::Committed);
        assert_eq!(tracker.oldest_dirty_age_ticks(), Some(2));

        // Clear oldest — age gap shrinks.
        tracker.clear_dirty_unconditional(BlockNumber(0));
        assert_eq!(tracker.oldest_dirty_age_ticks(), Some(1));
    }

    #[test]
    fn dirty_tracker_flushable_entry() {
        let mut tracker = DirtyTracker::default();
        tracker.mark_dirty(
            BlockNumber(7),
            4096,
            TxnId(3),
            Some(CommitSeq(42)),
            DirtyState::Committed,
        );
        let entry = tracker.entry(BlockNumber(7)).expect("entry exists");
        assert!(entry.is_flushable());
        assert_eq!(entry.txn_id, TxnId(3));
        assert_eq!(entry.commit_seq, Some(CommitSeq(42)));

        tracker.mark_dirty(BlockNumber(8), 4096, TxnId(4), None, DirtyState::InFlight);
        let entry = tracker.entry(BlockNumber(8)).expect("entry exists");
        assert!(!entry.is_flushable());
    }

    // ── ARC pressure and capacity trim tests ─────────────────────────────

    #[test]
    fn memory_pressure_critical_reduces_capacity_to_20_percent() {
        assert_eq!(MemoryPressure::Critical.target_capacity(100), 20);
        assert_eq!(MemoryPressure::Critical.target_capacity(10), 2);
        // Clamp to minimum of 1
        assert_eq!(MemoryPressure::Critical.target_capacity(1), 1);
    }

    #[test]
    fn memory_pressure_none_returns_full_capacity() {
        assert_eq!(MemoryPressure::None.target_capacity(100), 100);
        assert_eq!(MemoryPressure::None.target_capacity(1), 1);
    }

    #[cfg(not(feature = "s3fifo"))]
    #[test]
    fn arc_state_pressure_level_shrinks_and_restores() {
        let mut state = ArcState::new(10);
        // Fill cache.
        for i in 0..10_u64 {
            arc_access(&mut state, BlockNumber(i));
        }
        assert_eq!(state.resident_len(), 10);

        // Apply high pressure — target becomes 5.
        state.set_pressure_level(MemoryPressure::High);
        assert_eq!(state.capacity, 5);
        let batch = state.trim_to_capacity();
        assert_eq!(state.resident_len(), 5);
        assert!(batch.evicted_blocks >= 5);

        // Restore — target goes back to 10.
        state.restore_target_capacity();
        assert_eq!(state.capacity, 10);
    }

    #[cfg(not(feature = "s3fifo"))]
    #[test]
    fn arc_state_trim_skips_dirty_blocks() {
        let mut state = ArcState::new(3);
        arc_access(&mut state, BlockNumber(1));
        arc_access(&mut state, BlockNumber(2));
        arc_access(&mut state, BlockNumber(3));
        assert_eq!(state.resident_len(), 3);

        // Mark all blocks dirty — trim cannot evict any.
        for block in [BlockNumber(1), BlockNumber(2), BlockNumber(3)] {
            state
                .dirty
                .mark_dirty(block, 4096, TxnId(1), None, DirtyState::InFlight);
        }
        state.set_target_capacity(1);
        let batch = state.trim_to_capacity();
        assert_eq!(batch.evicted_blocks, 0);
        assert_eq!(state.resident_len(), 3); // All preserved due to dirty.
    }

    // ── Capacity-1 boundary tests ───────────────────────────────────────

    #[cfg(not(feature = "s3fifo"))]
    #[test]
    fn arc_state_capacity_one_evicts_on_new_access() {
        let mut state = ArcState::new(1);
        arc_access(&mut state, BlockNumber(10));
        assert_eq!(state.resident_len(), 1);
        assert!(state.resident.contains_key(&BlockNumber(10)));

        arc_access(&mut state, BlockNumber(20));
        assert_eq!(state.resident_len(), 1);
        assert!(state.resident.contains_key(&BlockNumber(20)));
        assert!(!state.resident.contains_key(&BlockNumber(10)));
    }

    #[cfg(not(feature = "s3fifo"))]
    #[test]
    fn arc_state_capacity_one_hit_promotes_to_t2() {
        let mut state = ArcState::new(1);
        arc_access(&mut state, BlockNumber(42));
        assert_eq!(state.t1.len(), 1);
        assert!(state.t2.is_empty());

        // Second access promotes T1 -> T2.
        arc_access(&mut state, BlockNumber(42));
        assert!(state.t1.is_empty());
        assert_eq!(state.t2.len(), 1);
    }

    // ── AlignedVec edge cases ───────────────────────────────────────────

    #[test]
    fn aligned_vec_zero_len_produces_empty_slice() {
        let v = AlignedVec::new(0, 4096);
        assert_eq!(v.len(), 0);
        assert!(v.is_empty());
        assert!(v.as_slice().is_empty());
    }

    #[test]
    fn aligned_vec_non_power_of_two_rounds_up() {
        let v = AlignedVec::new(100, 3);
        assert_eq!(v.alignment(), 4); // 3 rounds up to 4
        assert_eq!(v.len(), 100);
        assert_eq!((v.as_slice().as_ptr() as usize) % 4, 0);
    }

    #[test]
    fn aligned_vec_from_vec_preserves_data() {
        let data = vec![1_u8, 2, 3, 4, 5];
        let aligned = AlignedVec::from_vec(data, 16);
        assert_eq!(aligned.as_slice(), &[1, 2, 3, 4, 5]);
        assert_eq!((aligned.as_slice().as_ptr() as usize) % 16, 0);
    }

    #[test]
    fn aligned_vec_from_empty_vec() {
        let aligned = AlignedVec::from_vec(Vec::new(), 4096);
        assert!(aligned.is_empty());
        assert_eq!(aligned.len(), 0);
    }

    #[test]
    fn aligned_vec_alignment_one_has_no_padding() {
        let v = AlignedVec::new(10, 1);
        assert_eq!(v.alignment(), 1);
        assert_eq!(v.len(), 10);
    }

    // ── Normalized alignment tests ──────────────────────────────────────

    #[test]
    fn normalized_alignment_zero_returns_one() {
        assert_eq!(normalized_alignment(0), 1);
    }

    #[test]
    fn normalized_alignment_one_returns_one() {
        assert_eq!(normalized_alignment(1), 1);
    }

    #[test]
    fn normalized_alignment_power_of_two_unchanged() {
        assert_eq!(normalized_alignment(2), 2);
        assert_eq!(normalized_alignment(4), 4);
        assert_eq!(normalized_alignment(4096), 4096);
    }

    #[test]
    fn normalized_alignment_non_power_rounds_up() {
        assert_eq!(normalized_alignment(3), 4);
        assert_eq!(normalized_alignment(5), 8);
        assert_eq!(normalized_alignment(1000), 1024);
    }

    // ── BlockBuf edge cases ─────────────────────────────────────────────

    #[test]
    fn block_buf_empty() {
        let buf = BlockBuf::new(Vec::new());
        assert_eq!(buf.len(), 0);
        assert!(buf.as_slice().is_empty());
    }

    #[test]
    fn block_buf_make_mut_cow_semantics() {
        let mut buf = BlockBuf::new(vec![10, 20, 30]);
        let clone1 = buf.clone_ref();
        let clone2 = buf.clone_ref();

        // Mutate via make_mut (triggers COW).
        buf.make_mut()[1] = 99;
        assert_eq!(buf.as_slice(), &[10, 99, 30]);
        assert_eq!(clone1.as_slice(), &[10, 20, 30]); // Unmodified.
        assert_eq!(clone2.as_slice(), &[10, 20, 30]); // Unmodified.
    }

    // ── CacheMetrics computation tests ──────────────────────────────────

    #[test]
    fn cache_metrics_hit_rate_zero_accesses() {
        let metrics = CacheMetrics {
            hits: 0,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
            t1_len: 0,
            t2_len: 0,
            b1_len: 0,
            b2_len: 0,
            resident: 0,
            dirty_blocks: 0,
            dirty_bytes: 0,
            writeback_queue_depth: 0,
            oldest_dirty_age_ticks: None,
            capacity: 10,
            p: 0,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
        };
        assert!(metrics.hit_ratio().abs() < f64::EPSILON);
        assert!(metrics.dirty_ratio().abs() < f64::EPSILON);
    }

    #[test]
    fn cache_metrics_hit_rate_all_hits() {
        let metrics = CacheMetrics {
            hits: 100,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
            t1_len: 5,
            t2_len: 5,
            b1_len: 0,
            b2_len: 0,
            resident: 10,
            dirty_blocks: 0,
            dirty_bytes: 0,
            writeback_queue_depth: 0,
            oldest_dirty_age_ticks: None,
            capacity: 10,
            p: 0,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
        };
        assert!((metrics.hit_ratio() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn cache_metrics_dirty_ratio_full_dirty() {
        let metrics = CacheMetrics {
            hits: 10,
            misses: 0,
            evictions: 0,
            dirty_flushes: 0,
            t1_len: 5,
            t2_len: 5,
            b1_len: 0,
            b2_len: 0,
            resident: 10,
            dirty_blocks: 10,
            dirty_bytes: 40960,
            writeback_queue_depth: 0,
            oldest_dirty_age_ticks: Some(5),
            capacity: 10,
            p: 0,
            b1_ghost_hits: 0,
            b2_ghost_hits: 0,
        };
        assert!((metrics.dirty_ratio() - 1.0).abs() < 1e-12);
    }

    // ── ARC state invariant stress test ────────────────────────────────

    #[cfg(not(feature = "s3fifo"))]
    #[test]
    fn arc_state_scan_then_frequency_pattern_maintains_invariants() {
        let mut state = ArcState::new(8);

        // Sequential scan: access blocks 0..20 once each.
        for i in 0..20_u64 {
            arc_access(&mut state, BlockNumber(i));
        }

        // Now repeatedly access a small hot set.
        for _ in 0..50 {
            for i in 0..4_u64 {
                arc_access(&mut state, BlockNumber(i));
            }
        }

        // Hot blocks should be in T2 (frequency list).
        for i in 0..4_u64 {
            assert!(
                state.t2.contains(&BlockNumber(i)),
                "hot block {i} should be in T2"
            );
        }
        assert!(state.resident_len() <= state.capacity);
    }

    #[cfg(not(feature = "s3fifo"))]
    #[test]
    fn arc_state_ghost_list_bounded_at_capacity() {
        let mut state = ArcState::new(4);
        // Access 20 unique blocks to generate many ghost entries.
        for i in 0..20_u64 {
            arc_access(&mut state, BlockNumber(i));
        }
        // Ghost lists should never exceed capacity.
        assert!(state.b1.len() <= state.capacity);
        assert!(state.b2.len() <= state.capacity);
    }

    // ── CachePressureReport tests ───────────────────────────────────────

    #[test]
    fn cache_pressure_report_zero_state() {
        let state = ArcState::new(10);
        let report = state.pressure_report();
        assert_eq!(report.current_size, 0);
        assert_eq!(report.target_size, 10);
        assert_eq!(report.dirty_count, 0);
        assert!(report.eviction_rate.abs() < f64::EPSILON);
    }

    #[cfg(not(feature = "s3fifo"))]
    #[test]
    fn arc_state_p_target_stays_within_capacity() {
        let mut state = ArcState::new(4);
        // Drive p up by generating B1 ghost hits.
        for round in 0..5_u64 {
            for i in 0..8_u64 {
                arc_access(&mut state, BlockNumber(round * 100 + i));
            }
        }
        assert!(
            state.p <= state.capacity,
            "p={} > capacity={}",
            state.p,
            state.capacity
        );
    }

    /// bd-6owbg — regression guard for the never-hold-both
    /// lock-ordering invariant on `FaultInjector` (rules + log
    /// must NEVER be held simultaneously). Spawns 4 concurrent
    /// workers — fail_on_read registration, check_fault via
    /// read_block, fault_log read, and reset — guarded by a 15s
    /// watchdog that panics with a tagged message if any worker
    /// hangs. Any future regression that nested log.lock() under
    /// rules.lock() would deadlock against a concurrent fault_log
    /// caller and surface here.
    #[test]
    fn fault_injector_concurrent_inject_and_reset_no_hang() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::thread;
        use std::time::{Duration, Instant};

        const INJECTOR_WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(10);

        struct PassThrough;
        impl BlockDevice for PassThrough {
            fn read_block(&self, _cx: &Cx, _block: BlockNumber) -> Result<BlockBuf> {
                Ok(BlockBuf::new(vec![0_u8; 4096]))
            }
            fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
                Ok(())
            }
            fn block_size(&self) -> u32 {
                4096
            }
            fn block_count(&self) -> u64 {
                1024
            }
            fn sync(&self, _cx: &Cx) -> Result<()> {
                Ok(())
            }
        }

        let injector = StdArc::new(FaultInjector::new(PassThrough, 0xCAFE_BABE));
        let cx = Cx::for_testing();
        let cx = StdArc::new(cx);

        let done = StdArc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(15);
        let watchdog_done = StdArc::clone(&done);
        let watchdog = thread::spawn(move || {
            loop {
                if watchdog_done.load(AtomicOrdering::Acquire) {
                    return;
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                thread::sleep(INJECTOR_WATCHDOG_POLL_INTERVAL.min(remaining));
            }
            assert!(
                watchdog_done.load(AtomicOrdering::Acquire),
                "bd-6owbg: FaultInjector lock-ordering watchdog tripped - \
                 inject/reset/log workers did not finish within 15s",
            );
        });

        // Worker A: register faults (acquires rules alone).
        let inj_a = StdArc::clone(&injector);
        let worker_a = thread::spawn(move || {
            for i in 0..64_u64 {
                inj_a.fail_on_read(BlockNumber(i % 16), FaultMode::OneShot);
            }
        });

        // Worker B: trigger faults (acquires rules → drop → log).
        let inj_b = StdArc::clone(&injector);
        let cx_b = StdArc::clone(&cx);
        let worker_b = thread::spawn(move || {
            for i in 0..64_u64 {
                let _ = inj_b.read_block(&cx_b, BlockNumber(i % 16));
            }
        });

        // Worker C: read fault_log (acquires log alone).
        let inj_c = StdArc::clone(&injector);
        let worker_c = thread::spawn(move || {
            for _ in 0..64 {
                let _ = inj_c.fault_log();
            }
        });

        // Worker D: reset (acquires rules + log sequentially).
        let inj_d = StdArc::clone(&injector);
        let worker_d = thread::spawn(move || {
            for _ in 0..16 {
                inj_d.reset();
            }
        });

        worker_a.join().expect("worker A panicked");
        worker_b.join().expect("worker B panicked");
        worker_c.join().expect("worker C panicked");
        worker_d.join().expect("worker D panicked");
        let watchdog_join_started = Instant::now();
        done.store(true, AtomicOrdering::Release);
        watchdog.join().expect("watchdog panicked");
        assert!(
            watchdog_join_started.elapsed() <= INJECTOR_WATCHDOG_POLL_INTERVAL * 25,
            "watchdog should observe completion promptly after workers finish"
        );
    }

    /// bd-6owbg — regression guard for the never-hold-both
    /// lock-ordering invariant on `ThrottleInjector` (config + log
    /// must NEVER be held simultaneously). Same shape as the
    /// FaultInjector test above, with apply_delay (config-then-log)
    /// + update_config + throttle_log + reset workers.
    #[test]
    fn throttle_injector_concurrent_apply_and_reset_no_hang() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::thread;
        use std::time::{Duration, Instant};

        const INJECTOR_WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(10);

        struct PassThrough;
        impl BlockDevice for PassThrough {
            fn read_block(&self, _cx: &Cx, _block: BlockNumber) -> Result<BlockBuf> {
                Ok(BlockBuf::new(vec![0_u8; 4096]))
            }
            fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
                Ok(())
            }
            fn block_size(&self) -> u32 {
                4096
            }
            fn block_count(&self) -> u64 {
                1024
            }
            fn sync(&self, _cx: &Cx) -> Result<()> {
                Ok(())
            }
        }

        // Zero-latency config so apply_delay doesn't actually sleep.
        let config = ThrottleConfig {
            read_latency: Duration::ZERO,
            write_latency: Duration::ZERO,
            bandwidth_bps: 0,
            stall_probability: 0.0,
            stall_duration: Duration::ZERO,
            respect_deadline: false,
        };
        let injector = StdArc::new(ThrottleInjector::new(PassThrough, config, 0xDEAD_BEEF));
        let cx = StdArc::new(Cx::for_testing());

        let done = StdArc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(15);
        let watchdog_done = StdArc::clone(&done);
        let watchdog = thread::spawn(move || {
            loop {
                if watchdog_done.load(AtomicOrdering::Acquire) {
                    return;
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline.saturating_duration_since(now);
                thread::sleep(INJECTOR_WATCHDOG_POLL_INTERVAL.min(remaining));
            }
            assert!(
                watchdog_done.load(AtomicOrdering::Acquire),
                "bd-6owbg: ThrottleInjector lock-ordering watchdog tripped - \
                 apply/update/log/reset workers did not finish within 15s",
            );
        });

        // Worker A: apply_delay via read_block (config → drop → log).
        let inj_a = StdArc::clone(&injector);
        let cx_a = StdArc::clone(&cx);
        let worker_a = thread::spawn(move || {
            for i in 0..64_u64 {
                let _ = inj_a.read_block(&cx_a, BlockNumber(i));
            }
        });

        // Worker B: update_config (acquires config alone).
        let inj_b = StdArc::clone(&injector);
        let worker_b = thread::spawn(move || {
            for _ in 0..32 {
                inj_b.update_config(ThrottleConfig {
                    read_latency: Duration::ZERO,
                    write_latency: Duration::ZERO,
                    bandwidth_bps: 0,
                    stall_probability: 0.0,
                    stall_duration: Duration::ZERO,
                    respect_deadline: false,
                });
            }
        });

        // Worker C: throttle_log (acquires log alone).
        let inj_c = StdArc::clone(&injector);
        let worker_c = thread::spawn(move || {
            for _ in 0..64 {
                let _ = inj_c.throttle_log();
            }
        });

        // Worker D: reset (acquires log alone).
        let inj_d = StdArc::clone(&injector);
        let worker_d = thread::spawn(move || {
            for _ in 0..16 {
                inj_d.reset();
            }
        });

        worker_a.join().expect("worker A panicked");
        worker_b.join().expect("worker B panicked");
        worker_c.join().expect("worker C panicked");
        worker_d.join().expect("worker D panicked");
        let watchdog_join_started = Instant::now();
        done.store(true, AtomicOrdering::Release);
        watchdog.join().expect("watchdog panicked");
        assert!(
            watchdog_join_started.elapsed() <= INJECTOR_WATCHDOG_POLL_INTERVAL * 25,
            "watchdog should observe completion promptly after workers finish"
        );
    }
}
