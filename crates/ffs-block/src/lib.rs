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
    EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, Snapshot, TxnId,
};
#[cfg(feature = "s3fifo")]
use parking_lot::RwLock;
use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};
#[cfg(feature = "s3fifo")]
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::IoSliceMut;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;
#[cfg(feature = "s3fifo")]
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

pub const DEFAULT_BLOCK_ALIGNMENT: usize = 4096;
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
        if (bytes.as_ptr() as usize).is_multiple_of(alignment) {
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
    pub fn from_shared_aligned(bytes: Arc<AlignedVec>) -> Self {
        Self { bytes }
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
    pub fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.bytes, &other.bytes)
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

    /// Returns true when `read_exact_at` leaves `buf` byte-for-byte unchanged
    /// whenever it returns `Err`.
    ///
    /// Callers that must preserve their destination on read failure can skip an
    /// outer staging buffer only when the concrete device advertises this
    /// all-or-nothing contract.
    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        false
    }

    /// Returns true when `read_vectored_exact_at` leaves every destination
    /// buffer byte-for-byte unchanged whenever it returns `Err`.
    fn preserves_read_vectored_destinations_on_error(&self) -> bool {
        false
    }

    /// Read exactly `buf.len()` bytes from `offset` into `buf`.
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()>;

    /// Like [`read_exact_at`](Self::read_exact_at), but the caller does NOT
    /// require the destination to be preserved on error — `buf` may be partially
    /// written when this returns `Err`. Devices that stage small reads solely to
    /// honour the all-or-nothing destination contract can skip that staging (and
    /// its copy) here. Callers use this only when `buf` is a throwaway buffer
    /// that is discarded on failure (e.g. a fresh block buffer read into and then
    /// dropped if the read fails). The default delegates to `read_exact_at`, so
    /// the bytes are identical on success.
    fn read_exact_at_volatile(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        self.read_exact_at(cx, offset, buf)
    }

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
        let total_len = bufs.iter().try_fold(0_u64, |total, buf| {
            let len = u64::try_from(buf.len())
                .map_err(|_| FfsError::Format("read length overflows u64".to_owned()))?;
            total
                .checked_add(len)
                .ok_or_else(|| FfsError::Format("read length overflows u64".to_owned()))
        })?;
        let end = offset
            .0
            .checked_add(total_len)
            .ok_or_else(|| FfsError::Format("read range overflows u64".to_owned()))?;
        if total_len == 0 {
            cx_checkpoint(cx)?;
            return Ok(());
        }
        let len_bytes = self.len_bytes();
        if end > len_bytes {
            return Err(FfsError::Format(format!(
                "read out of bounds: offset={offset} len={total_len} device_len={len_bytes}"
            )));
        }
        let scratch_len = usize::try_from(total_len)
            .map_err(|_| FfsError::Format("read length overflows usize".to_owned()))?;
        let mut read_buf = vec![0_u8; scratch_len];
        let mut next_offset = offset.0;
        let mut copied = 0_usize;
        for buf in bufs.iter() {
            if buf.is_empty() {
                continue;
            }
            let len = u64::try_from(buf.len())
                .map_err(|_| FfsError::Format("read length overflows u64".to_owned()))?;
            let next_copied = copied
                .checked_add(buf.len())
                .ok_or_else(|| FfsError::Format("read length overflows usize".to_owned()))?;
            self.read_exact_at(
                cx,
                ByteOffset(next_offset),
                &mut read_buf[copied..next_copied],
            )?;
            copied = next_copied;
            next_offset = next_offset
                .checked_add(len)
                .ok_or_else(|| FfsError::Format("read range overflows u64".to_owned()))?;
        }
        copied = 0;
        for buf in bufs.iter_mut() {
            let len = buf.len();
            if len == 0 {
                continue;
            }
            let next_copied = copied
                .checked_add(len)
                .ok_or_else(|| FfsError::Format("read length overflows usize".to_owned()))?;
            (**buf).copy_from_slice(&read_buf[copied..next_copied]);
            copied = next_copied;
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
    sync_state: Arc<FileDeviceSyncState>,
}

/// Write/sync epoch pair backing `FileByteDevice`'s clean-sync skip.
///
/// Invariant: `synced_epoch` only ever stores a `write_epoch` value that was
/// read *before* a `sync_all` that then succeeded. Epoch equality in `sync`
/// therefore proves no write syscall has been attempted on this backing file
/// (through any clone of this device) since durability was last established,
/// making the fsync a no-op that can be skipped exactly — the same reasoning
/// kernel ext4 uses to skip the journal commit for an already-clean inode.
/// `write_epoch` starts ahead of `synced_epoch` so the first `sync` after open
/// always issues the syscall, covering writes made through other handles to
/// the same path before or during open (e.g. mount-time journal replay).
///
/// Shared behind `Arc` so `Clone`d devices (which share the `File`) also share
/// the dirty state.
#[derive(Debug)]
struct FileDeviceSyncState {
    /// Advanced after every attempted write syscall (success or failure — a
    /// failed `write_all_at` may have partially written).
    write_epoch: AtomicU64,
    /// The `write_epoch` observed immediately before the last successful
    /// `sync_all`.
    synced_epoch: AtomicU64,
}

/// Whether `FileByteDevice::sync` may skip the `fsync` syscall when no write
/// has been attempted since the last successful sync. Default on; set
/// `FFS_CLEAN_SYNC_SKIP=0` (or `off`/`false`) to force the old unconditional
/// fsync (used to A/B the lever in a single binary). Parsed once.
fn file_device_clean_sync_skip() -> bool {
    use std::sync::OnceLock;
    static SKIP: OnceLock<bool> = OnceLock::new();
    *SKIP.get_or_init(|| {
        !matches!(
            std::env::var("FFS_CLEAN_SYNC_SKIP")
                .ok()
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("0" | "off" | "false")
        )
    })
}

/// Default size at or above which reads skip the per-read staging scratch in
/// `FileByteDevice::read_exact_at` and read straight into the caller buffer.
/// Chosen at the allocator's mmap threshold: below it a scratch `Vec` is served
/// from the freelist with no page faults (cheaper than an extra `fstat`); at or
/// above it the scratch mmaps fresh pages whose first-touch faults dominate.
const FILE_DEVICE_DIRECT_READ_MIN_DEFAULT: usize = 64 * 1024;

/// Max iovec count for the single-`preadv` vectored direct-read fast path. The
/// kernel caps a vectored read at `IOV_MAX` (1024) iovecs; beyond that `preadv`
/// would short-read, so larger buffer arrays fall back to the staged scratch.
const FILE_DEVICE_PREADV_IOV_MAX: usize = 1024;

/// Resolve the direct-read threshold, allowing `FFS_DIRECT_READ_MIN_BYTES` to
/// override the default (read once). Set it to a huge value to force the staged
/// path for every read (used to A/B the lever in a single binary); set it low to
/// widen the direct path. Parsed lazily so the env read is off the hot path.
fn file_device_direct_read_min() -> usize {
    use std::sync::OnceLock;
    static MIN: OnceLock<usize> = OnceLock::new();
    *MIN.get_or_init(|| {
        std::env::var("FFS_DIRECT_READ_MIN_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(FILE_DEVICE_DIRECT_READ_MIN_DEFAULT)
    })
}

/// Read-ahead advice applied to a `FileByteDevice`'s fd at open via
/// `posix_fadvise`, controlled by `FFS_READ_FADVISE` (parsed once).
///
/// The default (`sequential`) declares the dominant access pattern of a
/// bulk-read filesystem so the kernel widens its read-ahead window — a single
/// advisory syscall at open, byte-neutral and inert when the data is already
/// page-cache-resident (the warm tmpfs bench case). It only changes I/O on a
/// COLD read from a real disk, where the kernel's larger prefetch window closes
/// the gap to its own `cat`/readahead path. Settable values:
///   * `sequential` (default) — `POSIX_FADV_SEQUENTIAL` (2x kernel readahead).
///   * `willneed` — eagerly prefetch the whole file at open.
///   * `random` — `POSIX_FADV_RANDOM` (suppress readahead; A/B floor).
///   * `none`/`off` — no advice (pre-lever behavior, for A/B isolation).
fn file_device_open_fadvise() -> Option<nix::fcntl::PosixFadviseAdvice> {
    use nix::fcntl::PosixFadviseAdvice;
    use std::sync::OnceLock;
    static MODE: OnceLock<Option<PosixFadviseAdvice>> = OnceLock::new();
    *MODE.get_or_init(|| {
        match std::env::var("FFS_READ_FADVISE")
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("none" | "off" | "") => None,
            Some("willneed") => Some(PosixFadviseAdvice::POSIX_FADV_WILLNEED),
            Some("random") => Some(PosixFadviseAdvice::POSIX_FADV_RANDOM),
            // Default (unset or "sequential"): declare sequential access.
            _ => Some(PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL),
        }
    })
}

thread_local! {
    /// Per-thread scratch for the small-read staging path (`read_exact_at` on a
    /// sub-`file_device_direct_read_min` read). Reused across reads so a hot
    /// metadata read stream does not allocate and zero-init a fresh buffer that
    /// the positioned read then overwrites in full. Grows only.
    static FILE_READ_STAGING: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
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
        // Declare the access pattern so the kernel sizes its read-ahead window
        // for our bulk reads (cold-read lever; inert when warm). Advisory: any
        // error is ignored — it never affects correctness.
        if let Some(advice) = file_device_open_fadvise() {
            use std::os::unix::io::AsRawFd;
            let _ = nix::fcntl::posix_fadvise(file.as_raw_fd(), 0, 0, advice);
        }
        Ok(Self {
            file: Arc::new(file),
            len,
            writable,
            sync_state: Arc::new(FileDeviceSyncState {
                write_epoch: AtomicU64::new(1),
                synced_epoch: AtomicU64::new(0),
            }),
        })
    }

    #[must_use]
    pub fn file(&self) -> &Arc<File> {
        &self.file
    }

    /// Test-only view of `(write_epoch, synced_epoch)` for the clean-sync
    /// skip invariant.
    #[cfg(test)]
    fn sync_epochs(&self) -> (u64, u64) {
        (
            self.sync_state.write_epoch.load(Ordering::Acquire),
            self.sync_state.synced_epoch.load(Ordering::Acquire),
        )
    }
}

impl ByteDevice for FileByteDevice {
    fn len_bytes(&self) -> u64 {
        self.len
    }

    fn supports_vectored_reads(&self) -> bool {
        true
    }

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        true
    }

    fn preserves_read_vectored_destinations_on_error(&self) -> bool {
        true
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        if buf.is_empty() {
            cx_checkpoint(cx)?;
            return Ok(());
        }
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

        // For a large read, a fresh `vec![0; len]` staging buffer crosses the
        // allocator's mmap threshold, so it mmaps anon pages and pays a
        // first-touch page fault per 4 KiB on the zero-init AND again on the
        // post-read copy — pure overhead that dominates a warm read (measured
        // ~13x on a 1 MiB A/B). Read straight into the caller's buffer instead.
        // A positioned read on a regular file fills the whole buffer in one
        // `pread` when the range is within the live file length, and `pread`
        // writes zero bytes on error, so the only way `buf` could be partially
        // dirtied before an `Err` is the backing file having shrunk below the
        // length cached at `open` (TOCTOU). Guard that rare case with a single
        // length re-check up front so the destination is never touched on a
        // short read — preserving the all-or-nothing contract this device
        // advertises. The extra `fstat` is negligible against a >=64 KiB read.
        //
        // For small reads (e.g. 4 KiB metadata blocks) the staging buffer is
        // served from the allocator's freelist with no page faults and the
        // memset/copy is a few hundred bytes, so the scratch is cheaper than an
        // extra syscall — keep it, which also preserves the destination for
        // free and leaves the hot metadata read path byte-identical.
        if buf.len() >= file_device_direct_read_min() {
            let live_len = self.file.metadata()?.len();
            if end > live_len {
                return Err(FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "short backing read: offset={offset} len={} live_len={live_len}",
                        buf.len()
                    ),
                )));
            }
            self.file.read_exact_at(buf, offset.0)?;
            cx_checkpoint(cx)?;
            return Ok(());
        }

        // Reuse a per-thread staging buffer instead of a fresh `vec![0; n]` on
        // every small read: `read_exact_at` overwrites the whole slice, so the
        // zero-init is pure waste, and a hot metadata read stream would otherwise
        // alloc + memset a scratch buffer per block. The buffer only ever grows
        // (same-size 4 KiB block reads never resize after the first), the read
        // fills exactly `buf.len()` bytes, and `buf` is written only on success —
        // so the all-or-nothing destination contract and the bytes are identical.
        FILE_READ_STAGING.with(|cell| -> Result<()> {
            let mut staging = cell.borrow_mut();
            if staging.len() < buf.len() {
                staging.resize(buf.len(), 0);
            }
            let slot = &mut staging[..buf.len()];
            self.file.read_exact_at(slot, offset.0)?;
            buf.copy_from_slice(slot);
            Ok(())
        })?;
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn read_exact_at_volatile(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        if buf.is_empty() {
            cx_checkpoint(cx)?;
            return Ok(());
        }
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
        // The caller discards `buf` on error, so there is no destination to
        // preserve: read straight into it — no staging buffer, no post-read copy,
        // and no length-recheck fstat. On success the bytes are identical to
        // `read_exact_at`; on a short backing read `buf` may be partially written,
        // which the caller drops.
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
        if total_len == 0 {
            cx_checkpoint(cx)?;
            return Ok(());
        }
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

        // Large vectored read: scatter straight into the caller's buffers with a
        // single positioned `preadv`. This keeps the old syscall count (one),
        // but removes the zeroed staging Vec, first-touch faults, and scatter
        // copy. As in the scalar large-read path, re-check the live file length
        // first so a backing-file shrink fails before partially dirtying any
        // destination slices. Small reads keep the freelist-cheap scratch path.
        if total_len >= file_device_direct_read_min() && bufs.len() <= FILE_DEVICE_PREADV_IOV_MAX {
            let live_len = self.file.metadata()?.len();
            if end > live_len {
                return Err(FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "short backing vectored read: offset={offset} len={total_len} live_len={live_len}"
                    ),
                )));
            }
            let off = i64::try_from(offset.0)
                .map_err(|_| FfsError::Format("read offset overflows i64".to_owned()))?;
            let read = if let [buf] = bufs {
                nix::sys::uio::pread(self.file.as_ref(), buf, off)
            } else {
                nix::sys::uio::preadv(self.file.as_ref(), bufs, off)
            }
            .map_err(std::io::Error::from)
            .map_err(FfsError::Io)?;
            if read != total_len {
                return Err(FfsError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("short vectored read: got {read} of {total_len} bytes"),
                )));
            }
            cx_checkpoint(cx)?;
            return Ok(());
        }

        // Small vectored read: reuse the per-thread staging scratch (same as the
        // scalar small-read path) instead of `vec![0; total_len]` per read — the
        // positioned read overwrites the slot in full, so the zero-init is waste.
        // The caller's `bufs` are scattered into only after the read succeeds, so
        // the all-or-nothing destination contract and the bytes are unchanged.
        FILE_READ_STAGING.with(|cell| -> Result<()> {
            let mut staging = cell.borrow_mut();
            if staging.len() < total_len {
                staging.resize(total_len, 0);
            }
            let slot = &mut staging[..total_len];
            self.file.read_exact_at(slot, offset.0)?;
            let mut copied = 0_usize;
            for buf in bufs {
                let len = buf.len();
                if len == 0 {
                    continue;
                }
                let end = copied
                    .checked_add(len)
                    .ok_or_else(|| FfsError::Format("read length overflows usize".to_owned()))?;
                (**buf).copy_from_slice(&slot[copied..end]);
                copied = end;
            }
            Ok(())
        })?;

        cx_checkpoint(cx)?;
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        if buf.is_empty() {
            cx_checkpoint(cx)?;
            return Ok(());
        }
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

        let write_result = self.file.write_all_at(buf, offset.0);
        // Advance the write epoch before surfacing any error: a failed
        // `write_all_at` may have partially written, so it must dirty the
        // device exactly like a success — `sync` can then never treat a
        // partial write as clean.
        self.sync_state.write_epoch.fetch_add(1, Ordering::Release);
        write_result?;
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;
        let observed = self.sync_state.write_epoch.load(Ordering::Acquire);
        if file_device_clean_sync_skip()
            && observed == self.sync_state.synced_epoch.load(Ordering::Acquire)
        {
            // No write syscall has been attempted through this device (or any
            // clone) since the last successful `sync_all`, so there is nothing
            // new to make durable: POSIX fsync only covers writes completed
            // before the call, and every completed write advanced the epoch
            // before its caller could observe completion. Skipping the syscall
            // saves the storage cache-flush (~400us on this class of host)
            // that dominates no-op durability boundaries (unchanged-directory
            // fsyncdir storms).
            cx_checkpoint(cx)?;
            return Ok(());
        }
        self.file.sync_all()?;
        // Publish at most the pre-sync observation; `fetch_max` keeps a
        // concurrent sync that observed a newer epoch from being regressed.
        self.sync_state
            .synced_epoch
            .fetch_max(observed, Ordering::AcqRel);
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
        let bs = self.block_size() as usize;
        if bs == 0 && !bufs.is_empty() {
            return Err(FfsError::Format(
                "read_contiguous_blocks: block size must be nonzero".to_owned(),
            ));
        }
        let count = u64::try_from(bufs.len())
            .map_err(|_| FfsError::Format("block count does not fit u64".to_owned()))?;
        if let Some(last_delta) = count.checked_sub(1) {
            let last_block = start.0.checked_add(last_delta).ok_or_else(|| {
                FfsError::Format("contiguous read block range overflow".to_owned())
            })?;
            let block_count = self.block_count();
            if last_block >= block_count {
                return Err(FfsError::Format(format!(
                    "block out of range: block={last_block} block_count={block_count}"
                )));
            }
        }
        for (idx, buf) in bufs.iter_mut().enumerate() {
            let delta = u64::try_from(idx)
                .map_err(|_| FfsError::Format("block index does not fit u64".to_owned()))?;
            let block = BlockNumber(start.0.checked_add(delta).ok_or_else(|| {
                FfsError::Format("contiguous read block range overflow".to_owned())
            })?);
            let read = self.read_block(cx, block)?;
            let actual_len = read.as_slice().len();
            if actual_len != bs {
                return Err(FfsError::Format(format!(
                    "read_block returned wrong size: got={actual_len} expected={bs}"
                )));
            }
            *buf = read;
        }
        cx_checkpoint(cx)?;
        Ok(())
    }

    /// Read a contiguous run of `dst.len() / block_size()` blocks starting at
    /// `start` directly into the caller's contiguous `dst` buffer. `dst.len()`
    /// MUST be a multiple of `block_size()`.
    ///
    /// This is the zero-copy counterpart to [`read_contiguous_blocks`]: where
    /// that scatters a run into one `BlockBuf` per block (an allocation per
    /// block) and forces the caller to copy each buffer into its destination,
    /// byte-backed implementations override this to issue ONE ranged device
    /// read straight into `dst` — no per-block buffer allocation and no copy.
    /// The default preserves scalar `read_block` semantics (one read + one copy
    /// per block), so the bytes written into `dst` are identical either way.
    ///
    /// [`read_contiguous_blocks`]: BlockDevice::read_contiguous_blocks
    fn read_contiguous_into(&self, cx: &Cx, start: BlockNumber, dst: &mut [u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        let bs = self.block_size() as usize;
        if bs == 0 || !dst.len().is_multiple_of(bs) {
            return Err(FfsError::Format(
                "read_contiguous_into: dst length must be a multiple of block size".to_owned(),
            ));
        }
        let count = u64::try_from(dst.len() / bs)
            .map_err(|_| FfsError::Format("block count does not fit u64".to_owned()))?;
        if let Some(last_delta) = count.checked_sub(1) {
            let last_block = start.0.checked_add(last_delta).ok_or_else(|| {
                FfsError::Format("contiguous read block range overflow".to_owned())
            })?;
            let block_count = self.block_count();
            if last_block >= block_count {
                return Err(FfsError::Format(format!(
                    "block out of range: block={last_block} block_count={block_count}"
                )));
            }
        }
        for (idx, chunk) in dst.chunks_mut(bs).enumerate() {
            let delta = u64::try_from(idx)
                .map_err(|_| FfsError::Format("block index does not fit u64".to_owned()))?;
            let block = BlockNumber(start.0.checked_add(delta).ok_or_else(|| {
                FfsError::Format("contiguous read block range overflow".to_owned())
            })?);
            let buf = self.read_block(cx, block)?;
            let actual_len = buf.as_slice().len();
            if actual_len != bs {
                return Err(FfsError::Format(format!(
                    "read_block returned wrong size: got={actual_len} expected={bs}"
                )));
            }
            chunk.copy_from_slice(buf.as_slice());
        }
        cx_checkpoint(cx)?;
        Ok(())
    }

    /// Write a block by number. `data.len()` MUST equal `block_size()`.
    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()>;

    /// Read-modify-write one block: read it, hand the mutable block buffer to
    /// `patch`, then write it back. `disjoint_ranges` are the `(offset, len)` byte
    /// ranges `patch` is expected to touch — a hint that the write differs from the
    /// current block ONLY within those ranges (the rest is an unchanged copy of
    /// what was read). An MVCC-backed device uses the hint to read the base AT ITS
    /// TRANSACTION SNAPSHOT and stage the write under a range-scoped merge proof, so
    /// two writers touching DISJOINT ranges of the same block MERGE instead of
    /// first-committer-wins conflicting. The default performs a plain
    /// read-modify-write and ignores the hint — correct for every non-MVCC or
    /// externally-serialized device (the bytes written are identical; the hint is a
    /// pure concurrency optimization). Reading the base and staging the write in one
    /// call is what lets an MVCC device keep them snapshot-consistent, which a
    /// separate `read_block` then `write_block` cannot guarantee under concurrency.
    fn rmw_block(
        &self,
        cx: &Cx,
        block: BlockNumber,
        disjoint_ranges: &[(usize, usize)],
        patch: &mut dyn FnMut(&mut Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        let _ = disjoint_ranges;
        let mut data = self.read_block(cx, block)?.into_inner();
        patch(&mut data)?;
        self.write_block(cx, block, &data)
    }

    /// Read-modify-write one block under a bit-level OR-merge proof, for a
    /// monotone (set-only) allocation bitmap block.
    ///
    /// Like [`Self::rmw_block`] but the staged write is a whole-block bit OR
    /// (`MergeProof::BitmapOr`) rather than a range-scoped overlay: two
    /// concurrent allocators that SET the bits of disjoint blocks in the same
    /// group bitmap block MERGE (`latest | staged`) even though adjacent free
    /// blocks share a bitmap byte, which a byte-range hint cannot express. An
    /// MVCC-backed device reads the base AT ITS TRANSACTION SNAPSHOT and stages
    /// the OR proof; the default performs a plain read-modify-write and is
    /// byte-identical for non-MVCC / externally-serialized devices.
    ///
    /// `patch` MUST only SET bits (allocation). A bit-clear (free) makes the OR
    /// proof invalid and falls back to first-committer-wins, so this must never
    /// be used on the free path.
    fn rmw_block_bitmap_or(
        &self,
        cx: &Cx,
        block: BlockNumber,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        let mut data = self.read_block(cx, block)?.into_inner();
        patch(&mut data)?;
        self.write_block(cx, block, &data)
    }

    /// Read-modify-write one block under a bit-level DELTA merge proof, for a
    /// bitmap block whose concurrent writers both allocate and free.
    ///
    /// The general form of [`Self::rmw_block_bitmap_or`]: it drops that method's
    /// set-only requirement, so `patch` may set bits, clear bits, or both. Two
    /// concurrent writers MERGE (`latest ^ staged ^ base`) as long as they
    /// changed disjoint BITS; changing the same bit still first-committer-wins,
    /// because relative to one shared base that can only be a double-allocation
    /// or a double-free.
    ///
    /// Use this — not `rmw_block_bitmap_or` — for any bitmap whose alloc and free
    /// paths can run concurrently against one block. The ext4 INODE bitmap is
    /// exactly that under the sharded allocator (`create` sets a bit while a
    /// concurrent `unlink` clears another in the same block), and an OR proof
    /// cannot express it in either direction (bd-y2t0r).
    ///
    /// An MVCC-backed device reads the base AT ITS TRANSACTION SNAPSHOT and stages
    /// the delta proof; the default performs a plain read-modify-write and is
    /// byte-identical for non-MVCC / externally-serialized devices.
    fn rmw_block_bitmap_delta(
        &self,
        cx: &Cx,
        block: BlockNumber,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        let mut data = self.read_block(cx, block)?.into_inner();
        patch(&mut data)?;
        self.write_block(cx, block, &data)
    }

    /// The merge common-ancestor for `block` at `snapshot`: the block content as
    /// of `snapshot`, plus the bytes to record as `staged_base` for a
    /// proof-carrying stage into an EXTERNAL, already-begun transaction.
    ///
    /// The base MUST be resolved at THAT transaction's snapshot, not at this
    /// device's own (possibly newer, read-your-writes) view — else a concurrent
    /// writer's bits fold into the staged block and the OR-merge spuriously fails
    /// its disjoint-new check. Returns `(content, base)` where `base` is `Some`
    /// only when the store cannot re-derive the ancestor from its version chain
    /// (i.e. the block has no version at `snapshot` and lives on the raw base
    /// device). The default reads the current block and records no base — a
    /// device with no MVCC overlay is snapshot-invariant and never participates
    /// in a merge.
    fn read_merge_ancestor_at_snapshot(
        &self,
        cx: &Cx,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> Result<(BlockBuf, Option<Vec<u8>>)> {
        let _ = snapshot;
        Ok((self.read_block(cx, block)?, None))
    }

    /// Returns true when `write_contiguous_blocks` collapses a run into fewer
    /// device I/O operations than scalar `write_block` calls.
    fn supports_contiguous_writes(&self) -> bool {
        false
    }

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
        if bs == 0 || !data.len().is_multiple_of(bs) {
            return Err(FfsError::Format(
                "write_contiguous_blocks: data length must be a multiple of block size".to_owned(),
            ));
        }
        let count = u64::try_from(data.len() / bs)
            .map_err(|_| FfsError::Format("block count does not fit u64".to_owned()))?;
        if let Some(last_delta) = count.checked_sub(1) {
            let last_block = start.0.checked_add(last_delta).ok_or_else(|| {
                FfsError::Format("contiguous write block range overflow".to_owned())
            })?;
            let block_count = self.block_count();
            if last_block >= block_count {
                return Err(FfsError::Format(format!(
                    "block out of range: block={last_block} block_count={block_count}"
                )));
            }
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

    fn read_contiguous_into(&self, cx: &Cx, start: BlockNumber, dst: &mut [u8]) -> Result<()> {
        (**self).read_contiguous_into(cx, start, dst)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        (**self).write_block(cx, block, data)
    }

    // The four merge-proof-carrying methods below MUST be forwarded explicitly.
    // Each has a default body that performs a plain read-modify-write, so an
    // `Arc<D>` that inherited those defaults would silently DOWNGRADE every proof
    // to `MergeProof::Unsafe` — the wrapped device's merge implementation is never
    // reached, no error is raised, and the only symptom is first-committer-wins
    // conflicts under concurrency that the proof was added to prevent. That is
    // precisely the failure bd-y2t0r spent a cycle diagnosing, so forwarding is
    // load-bearing rather than tidiness.
    fn rmw_block(
        &self,
        cx: &Cx,
        block: BlockNumber,
        disjoint_ranges: &[(usize, usize)],
        patch: &mut dyn FnMut(&mut Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        (**self).rmw_block(cx, block, disjoint_ranges, patch)
    }

    fn rmw_block_bitmap_or(
        &self,
        cx: &Cx,
        block: BlockNumber,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        (**self).rmw_block_bitmap_or(cx, block, patch)
    }

    fn rmw_block_bitmap_delta(
        &self,
        cx: &Cx,
        block: BlockNumber,
        patch: &mut dyn FnMut(&mut Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        (**self).rmw_block_bitmap_delta(cx, block, patch)
    }

    fn read_merge_ancestor_at_snapshot(
        &self,
        cx: &Cx,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> Result<(BlockBuf, Option<Vec<u8>>)> {
        (**self).read_merge_ancestor_at_snapshot(cx, block, snapshot)
    }

    fn supports_contiguous_writes(&self) -> bool {
        (**self).supports_contiguous_writes()
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
        let block_count = self.block_count();
        if let Some(block) = blocks.iter().copied().find(|block| block.0 >= block_count) {
            return Err(FfsError::Format(format!(
                "block out of range: block={} block_count={block_count}",
                block.0
            )));
        }
        let block_size = self.block_size() as usize;
        if block_size == 0 && !blocks.is_empty() {
            return Err(FfsError::Format(
                "read_vectored: block size must be nonzero".to_owned(),
            ));
        }
        trace!(
            target: "ffs::block::io",
            event = "read_vectored",
            block_count = blocks.len()
        );
        for (block, buf) in blocks.iter().copied().zip(bufs.iter_mut()) {
            let read = self.read_block(cx, block)?;
            let actual_len = read.as_slice().len();
            if actual_len != block_size {
                return Err(FfsError::Format(format!(
                    "read_block returned wrong size: got={actual_len} expected={block_size}"
                )));
            }
            *buf = read;
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
        let block_count = self.block_count();
        if let Some(block) = blocks.iter().copied().find(|block| block.0 >= block_count) {
            return Err(FfsError::Format(format!(
                "block out of range: block={} block_count={block_count}",
                block.0
            )));
        }
        let block_size = self.block_size() as usize;
        if block_size == 0 && !blocks.is_empty() {
            return Err(FfsError::Format(
                "write_vectored: block size must be nonzero".to_owned(),
            ));
        }
        if let Some(buf) = bufs.iter().find(|buf| buf.len() != block_size) {
            return Err(FfsError::Format(format!(
                "write_vectored block size mismatch: got={} expected={block_size}",
                buf.len()
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
        // `buf` is freshly allocated here and dropped if the read fails, so it
        // needs no destination-preservation. The volatile read lets a device that
        // otherwise stages small reads (FileByteDevice) read straight into `buf`,
        // dropping the per-block staging copy on the metadata cache-miss path.
        self.inner
            .read_exact_at_volatile(cx, ByteOffset(offset), buf.make_mut())?;
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
            cx_checkpoint(cx)?;
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

        let total_len = bufs
            .len()
            .checked_mul(block_size)
            .ok_or_else(|| FfsError::Format("contiguous read length overflow".to_owned()))?;
        if self.inner.preserves_read_vectored_destinations_on_error()
            && bufs.iter().all(|buf| buf.len() == block_size)
        {
            let mut slices: Vec<IoSliceMut<'_>> = bufs
                .iter_mut()
                .map(|buf| IoSliceMut::new(buf.make_mut()))
                .collect();
            self.inner
                .read_vectored_exact_at(cx, ByteOffset(offset), &mut slices)?;
            cx_checkpoint(cx)?;
            return Ok(());
        }

        let mut read_buf = vec![0_u8; total_len];
        self.inner
            .read_exact_at(cx, ByteOffset(offset), read_buf.as_mut_slice())?;
        for (buf, chunk) in bufs.iter_mut().zip(read_buf.chunks_exact(block_size)) {
            if buf.len() == block_size {
                buf.make_mut().copy_from_slice(chunk);
            } else {
                *buf = BlockBuf::new(chunk.to_vec());
            }
        }
        cx_checkpoint(cx)?;
        Ok(())
    }

    fn read_contiguous_into(&self, cx: &Cx, start: BlockNumber, dst: &mut [u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        let block_size = usize::try_from(self.block_size)
            .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;
        if block_size == 0 || !dst.len().is_multiple_of(block_size) {
            return Err(FfsError::Format(
                "read_contiguous_into: dst length must be a multiple of block size".to_owned(),
            ));
        }
        if dst.is_empty() {
            cx_checkpoint(cx)?;
            return Ok(());
        }
        let count = (dst.len() / block_size) as u64;
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
        let offset = start
            .0
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(|| FfsError::Format("block offset overflow".to_owned()))?;
        if self.inner.preserves_read_exact_at_destination_on_error() {
            self.inner.read_exact_at(cx, ByteOffset(offset), dst)?;
            cx_checkpoint(cx)?;
            return Ok(());
        }

        let mut read_buf = vec![0_u8; dst.len()];
        self.inner
            .read_exact_at(cx, ByteOffset(offset), read_buf.as_mut_slice())?;
        dst.copy_from_slice(read_buf.as_slice());
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

    fn supports_contiguous_writes(&self) -> bool {
        true
    }

    fn write_contiguous_blocks(&self, cx: &Cx, start: BlockNumber, data: &[u8]) -> Result<()> {
        cx_checkpoint(cx)?;
        let block_size = usize::try_from(self.block_size)
            .map_err(|_| FfsError::Format("block_size does not fit usize".to_owned()))?;
        if block_size == 0 || !data.len().is_multiple_of(block_size) {
            return Err(FfsError::Format(
                "write_contiguous_blocks: data length must be a multiple of block size".to_owned(),
            ));
        }
        if data.is_empty() {
            cx_checkpoint(cx)?;
            return Ok(());
        }
        let count = (data.len() / block_size) as u64;
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
        let offset = start
            .0
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(|| FfsError::Format("block offset overflow".to_owned()))?;
        // One ranged write of the whole contiguous run (one `write_all_at` /
        // `pwrite` instead of one per block). Byte-for-byte identical to the
        // scalar default's per-block writes — block `start + i` lands at byte
        // offset `(start + i) * block_size` either way — but the MVCC flush
        // (bd-ryqep) coalesces dirty runs and relied on this override to avoid
        // N syscalls; without it the byte device silently fell back to scalar.
        // Mirrors `read_contiguous_into`.
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

include!("cache.rs");

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
            assert_eq!(state.resident_recency.len(), state.resident.len());
        }

        for &k in &state.t1 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::T1)));
            assert!(state.resident.contains_key(&k));
            #[cfg(not(feature = "s3fifo"))]
            assert!(matches!(
                state.resident_recency.get(&k),
                Some(ResidentRecency {
                    list: ArcList::T1,
                    ..
                })
            ));
        }
        for &k in &state.t2 {
            assert!(matches!(state.loc.get(&k), Some(ArcList::T2)));
            assert!(state.resident.contains_key(&k));
            #[cfg(not(feature = "s3fifo"))]
            assert!(matches!(
                state.resident_recency.get(&k),
                Some(ResidentRecency {
                    list: ArcList::T2,
                    ..
                })
            ));
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
            let expected_t1_clean: Vec<BlockNumber> = state
                .t1
                .iter()
                .copied()
                .filter(|block| !state.is_dirty(*block))
                .collect();
            let expected_t2_clean: Vec<BlockNumber> = state
                .t2
                .iter()
                .copied()
                .filter(|block| !state.is_dirty(*block))
                .collect();
            let indexed_t1_clean: Vec<BlockNumber> =
                state.clean_t1.iter().map(|entry| entry.block).collect();
            let indexed_t2_clean: Vec<BlockNumber> =
                state.clean_t2.iter().map(|entry| entry.block).collect();
            assert_eq!(indexed_t1_clean, expected_t1_clean);
            assert_eq!(indexed_t2_clean, expected_t2_clean);
            assert_eq!(
                state.oldest_clean_resident(ArcList::T1),
                expected_t1_clean.first().copied()
            );
            assert_eq!(
                state.oldest_clean_resident(ArcList::T2),
                expected_t2_clean.first().copied()
            );
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
        write_count: AtomicUsize,
    }

    impl MemoryByteDevice {
        fn new(len: usize) -> Self {
            Self {
                bytes: Mutex::new(vec![0_u8; len]),
                read_count: AtomicUsize::new(0),
                write_count: AtomicUsize::new(0),
            }
        }

        fn read_count(&self) -> usize {
            self.read_count.load(Ordering::Relaxed)
        }

        fn write_count(&self) -> usize {
            self.write_count.load(Ordering::Relaxed)
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
            self.write_count.fetch_add(1, Ordering::Relaxed);
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
    struct FailingReadByteDevice {
        len: u64,
    }

    impl FailingReadByteDevice {
        fn new(len: u64) -> Self {
            Self { len }
        }
    }

    impl ByteDevice for FailingReadByteDevice {
        fn len_bytes(&self) -> u64 {
            self.len
        }

        fn read_exact_at(&self, _cx: &Cx, _offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
            if let Some(first) = buf.first_mut() {
                *first = 0xEE;
            }
            Err(FfsError::Format("injected byte read failure".to_owned()))
        }

        fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AllOrNothingFailingReadByteDevice {
        len: u64,
        last_read_ptr: Mutex<Option<usize>>,
    }

    impl AllOrNothingFailingReadByteDevice {
        fn new(len: u64) -> Self {
            Self {
                len,
                last_read_ptr: Mutex::new(None),
            }
        }

        fn last_read_ptr(&self) -> Option<usize> {
            *self.last_read_ptr.lock()
        }
    }

    impl ByteDevice for AllOrNothingFailingReadByteDevice {
        fn len_bytes(&self) -> u64 {
            self.len
        }

        fn preserves_read_exact_at_destination_on_error(&self) -> bool {
            true
        }

        fn read_exact_at(&self, _cx: &Cx, _offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
            *self.last_read_ptr.lock() = Some(buf.as_ptr() as usize);
            Err(FfsError::Format(
                "injected all-or-nothing byte read failure".to_owned(),
            ))
        }

        fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TrustedVectoredByteDevice {
        bytes: Mutex<Vec<u8>>,
        fail_read: bool,
        read_exact_count: AtomicUsize,
        read_vectored_count: AtomicUsize,
        last_iovec_ptrs: Mutex<Vec<usize>>,
    }

    impl TrustedVectoredByteDevice {
        fn new(bytes: Vec<u8>, fail_read: bool) -> Self {
            Self {
                bytes: Mutex::new(bytes),
                fail_read,
                read_exact_count: AtomicUsize::new(0),
                read_vectored_count: AtomicUsize::new(0),
                last_iovec_ptrs: Mutex::new(Vec::new()),
            }
        }

        fn read_exact_count(&self) -> usize {
            self.read_exact_count.load(Ordering::Relaxed)
        }

        fn read_vectored_count(&self) -> usize {
            self.read_vectored_count.load(Ordering::Relaxed)
        }

        fn last_iovec_ptrs(&self) -> Vec<usize> {
            self.last_iovec_ptrs.lock().clone()
        }
    }

    impl ByteDevice for TrustedVectoredByteDevice {
        fn len_bytes(&self) -> u64 {
            self.bytes.lock().len() as u64
        }

        fn supports_vectored_reads(&self) -> bool {
            true
        }

        fn preserves_read_vectored_destinations_on_error(&self) -> bool {
            true
        }

        fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
            self.read_exact_count.fetch_add(1, Ordering::Relaxed);
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
            self.read_vectored_count.fetch_add(1, Ordering::Relaxed);
            *self.last_iovec_ptrs.lock() = bufs.iter().map(|buf| buf.as_ptr() as usize).collect();
            if self.fail_read {
                return Err(FfsError::Format(
                    "injected trusted vectored read failure".to_owned(),
                ));
            }

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

        fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ScalarOnlyByteDevice {
        bytes: Mutex<Vec<u8>>,
        read_calls: Mutex<Vec<(ByteOffset, usize)>>,
    }

    impl ScalarOnlyByteDevice {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes: Mutex::new(bytes),
                read_calls: Mutex::new(Vec::new()),
            }
        }

        fn read_calls(&self) -> Vec<(ByteOffset, usize)> {
            self.read_calls.lock().clone()
        }
    }

    impl ByteDevice for ScalarOnlyByteDevice {
        fn len_bytes(&self) -> u64 {
            u64::try_from(self.bytes.lock().len()).unwrap_or(0)
        }

        fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
            self.read_calls.lock().push((offset, buf.len()));
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
    struct FailOnSecondScalarReadByteDevice {
        read_calls: Mutex<Vec<(ByteOffset, usize)>>,
    }

    impl FailOnSecondScalarReadByteDevice {
        fn new() -> Self {
            Self {
                read_calls: Mutex::new(Vec::new()),
            }
        }

        fn read_calls(&self) -> Vec<(ByteOffset, usize)> {
            self.read_calls.lock().clone()
        }
    }

    impl ByteDevice for FailOnSecondScalarReadByteDevice {
        fn len_bytes(&self) -> u64 {
            u64::MAX
        }

        fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
            let is_first_read = {
                let mut read_calls = self.read_calls.lock();
                read_calls.push((offset, buf.len()));
                read_calls.len() == 1
            };
            if is_first_read {
                buf.fill(0x5A);
                return Ok(());
            }
            if let Some(first) = buf.first_mut() {
                *first = 0xEE;
            }
            Err(FfsError::Format(
                "injected second scalar read failure".to_owned(),
            ))
        }

        fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct PermissiveReadByteDevice {
        read_calls: Mutex<Vec<(ByteOffset, usize)>>,
    }

    impl PermissiveReadByteDevice {
        fn new() -> Self {
            Self {
                read_calls: Mutex::new(Vec::new()),
            }
        }

        fn read_calls(&self) -> Vec<(ByteOffset, usize)> {
            self.read_calls.lock().clone()
        }
    }

    impl ByteDevice for PermissiveReadByteDevice {
        fn len_bytes(&self) -> u64 {
            u64::MAX
        }

        fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
            self.read_calls.lock().push((offset, buf.len()));
            buf.fill(0x5A);
            Ok(())
        }

        fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct PermissiveBlockDevice {
        reads: Mutex<Vec<BlockNumber>>,
        writes: Mutex<Vec<BlockNumber>>,
    }

    impl PermissiveBlockDevice {
        fn new() -> Self {
            Self {
                reads: Mutex::new(Vec::new()),
                writes: Mutex::new(Vec::new()),
            }
        }

        fn read_sequence(&self) -> Vec<BlockNumber> {
            self.reads.lock().clone()
        }

        fn write_sequence(&self) -> Vec<BlockNumber> {
            self.writes.lock().clone()
        }
    }

    impl BlockDevice for PermissiveBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.reads.lock().push(block);
            Ok(BlockBuf::new(vec![0x5A; 4]))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, _data: &[u8]) -> Result<()> {
            self.writes.lock().push(block);
            Ok(())
        }

        fn block_size(&self) -> u32 {
            4
        }

        fn block_count(&self) -> u64 {
            u64::MAX
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
    fn byte_block_device_contiguous_blocks_preserves_buffers_on_read_error() {
        let cx = Cx::for_testing();
        let dev = ByteBlockDevice::new(FailingReadByteDevice::new(8), 4).expect("device");
        let mut bufs = [BlockBuf::new(Vec::new()), BlockBuf::new(vec![0xBB; 4])];

        let err = dev
            .read_contiguous_blocks(&cx, BlockNumber(0), &mut bufs)
            .expect_err("backing byte read failure should not mutate caller buffers");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("injected byte read failure")),
            "expected injected byte read Format error, got {err:?}"
        );
        assert!(bufs[0].as_slice().is_empty());
        assert_eq!(bufs[1].as_slice(), &[0xBB; 4]);
    }

    #[test]
    fn byte_block_device_contiguous_into_preserves_dst_on_read_error() {
        let cx = Cx::for_testing();
        let dev = ByteBlockDevice::new(FailingReadByteDevice::new(8), 4).expect("device");
        let mut dst = [0xAA_u8; 8];

        let err = dev
            .read_contiguous_into(&cx, BlockNumber(0), &mut dst)
            .expect_err("backing byte read failure should not mutate destination");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("injected byte read failure")),
            "expected injected byte read Format error, got {err:?}"
        );
        assert_eq!(dst, [0xAA; 8]);
    }

    #[test]
    fn byte_block_device_trusted_contiguous_into_skips_outer_staging_on_error() {
        let cx = Cx::for_testing();
        let dev =
            ByteBlockDevice::new(AllOrNothingFailingReadByteDevice::new(8), 4).expect("device");
        let mut dst = [0xAA_u8; 8];
        let dst_ptr = dst.as_ptr() as usize;

        let err = dev
            .read_contiguous_into(&cx, BlockNumber(0), &mut dst)
            .expect_err("trusted backing read failure should still preserve destination");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("injected all-or-nothing byte read failure")),
            "expected injected all-or-nothing Format error, got {err:?}"
        );
        assert_eq!(dev.inner().last_read_ptr(), Some(dst_ptr));
        assert_eq!(dst, [0xAA; 8]);
    }

    #[test]
    fn byte_block_device_trusted_vectored_contiguous_blocks_reuses_sized_buffers() {
        let cx = Cx::for_testing();
        let mem = TrustedVectoredByteDevice::new(vec![0, 1, 2, 3, 4, 5, 6, 7], false);
        let dev = ByteBlockDevice::new(mem, 4).expect("device");
        let mut bufs = vec![BlockBuf::new(vec![0xAA; 4]), BlockBuf::new(vec![0xBB; 4])];
        let ptrs_before: Vec<usize> = bufs
            .iter()
            .map(|buf| buf.as_slice().as_ptr() as usize)
            .collect();

        dev.read_contiguous_blocks(&cx, BlockNumber(0), &mut bufs)
            .expect("trusted vectored contiguous read");

        assert_eq!(bufs[0].as_slice(), &[0, 1, 2, 3]);
        assert_eq!(bufs[1].as_slice(), &[4, 5, 6, 7]);
        assert_eq!(dev.inner().read_exact_count(), 0);
        assert_eq!(dev.inner().read_vectored_count(), 1);
        assert_eq!(dev.inner().last_iovec_ptrs(), ptrs_before);
        let ptrs_after: Vec<usize> = bufs
            .iter()
            .map(|buf| buf.as_slice().as_ptr() as usize)
            .collect();
        assert_eq!(ptrs_after, ptrs_before);
    }

    #[test]
    fn byte_block_device_trusted_vectored_contiguous_blocks_preserves_buffers_on_error() {
        let cx = Cx::for_testing();
        let mem = TrustedVectoredByteDevice::new(vec![0, 1, 2, 3, 4, 5, 6, 7], true);
        let dev = ByteBlockDevice::new(mem, 4).expect("device");
        let mut bufs = vec![BlockBuf::new(vec![0xAA; 4]), BlockBuf::new(vec![0xBB; 4])];
        let ptrs_before: Vec<usize> = bufs
            .iter()
            .map(|buf| buf.as_slice().as_ptr() as usize)
            .collect();

        let err = dev
            .read_contiguous_blocks(&cx, BlockNumber(0), &mut bufs)
            .expect_err("trusted vectored read failure should preserve buffers");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("injected trusted vectored read failure")),
            "expected trusted vectored Format error, got {err:?}"
        );
        assert_eq!(bufs[0].as_slice(), &[0xAA; 4]);
        assert_eq!(bufs[1].as_slice(), &[0xBB; 4]);
        assert_eq!(dev.inner().read_exact_count(), 0);
        assert_eq!(dev.inner().read_vectored_count(), 1);
        assert_eq!(dev.inner().last_iovec_ptrs(), ptrs_before);
    }

    #[test]
    fn byte_block_device_empty_contiguous_ops_are_noops_at_invalid_start() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(16);
        let dev = ByteBlockDevice::new(mem, 4).expect("device");

        let mut bufs: [BlockBuf; 0] = [];
        dev.read_contiguous_blocks(&cx, BlockNumber(u64::MAX), &mut bufs)
            .expect("empty block-vector read should not bounds-check start");

        let mut dst = [];
        dev.read_contiguous_into(&cx, BlockNumber(u64::MAX), &mut dst)
            .expect("empty contiguous read should not bounds-check start");

        dev.write_contiguous_blocks(&cx, BlockNumber(u64::MAX), &[])
            .expect("empty contiguous write should not bounds-check start");

        assert_eq!(dev.inner().read_count(), 0);
        assert_eq!(dev.inner().write_count(), 0);
    }

    #[test]
    fn default_contiguous_read_rejects_overflow_before_partial_reads() {
        let cx = Cx::for_testing();
        let dev = PermissiveBlockDevice::new();
        let mut bufs = vec![BlockBuf::new(vec![0xAA; 4]), BlockBuf::new(vec![0xBB; 4])];

        let err = dev
            .read_contiguous_blocks(&cx, BlockNumber(u64::MAX), &mut bufs)
            .expect_err("overflowing contiguous read should fail before scalar reads");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("contiguous read block range overflow")),
            "expected contiguous-read overflow Format error, got {err:?}"
        );
        assert!(dev.read_sequence().is_empty());
        assert_eq!(bufs[0].as_slice(), &[0xAA; 4]);
        assert_eq!(bufs[1].as_slice(), &[0xBB; 4]);
    }

    #[test]
    fn default_contiguous_into_rejects_overflow_before_partial_reads() {
        let cx = Cx::for_testing();
        let dev = PermissiveBlockDevice::new();
        let mut dst = [0xAA_u8; 8];

        let err = dev
            .read_contiguous_into(&cx, BlockNumber(u64::MAX), &mut dst)
            .expect_err("overflowing contiguous read should fail before scalar reads");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("contiguous read block range overflow")),
            "expected contiguous-read overflow Format error, got {err:?}"
        );
        assert!(dev.read_sequence().is_empty());
        assert_eq!(dst, [0xAA; 8]);
    }

    #[test]
    fn default_contiguous_write_rejects_overflow_before_partial_writes() {
        let cx = Cx::for_testing();
        let dev = PermissiveBlockDevice::new();

        let err = dev
            .write_contiguous_blocks(&cx, BlockNumber(u64::MAX), &[0xAA; 8])
            .expect_err("overflowing contiguous write should fail before scalar writes");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("contiguous write block range overflow")),
            "expected contiguous-write overflow Format error, got {err:?}"
        );
        assert!(dev.write_sequence().is_empty());
    }

    #[test]
    fn file_byte_device_empty_scalar_read_is_noop() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty-scalar-read.img");
        std::fs::write(&path, [1_u8, 2, 3, 4]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        let mut empty = [];
        dev.read_exact_at(&cx, ByteOffset(4), &mut empty)
            .expect("empty read at EOF is a no-op");
        dev.read_exact_at(&cx, ByteOffset(9), &mut empty)
            .expect("empty read past EOF is a no-op");
    }

    #[test]
    fn file_byte_device_empty_scalar_write_is_noop() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty-scalar-write.img");
        std::fs::write(&path, [1_u8, 2, 3, 4]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        dev.write_all_at(&cx, ByteOffset(4), &[])
            .expect("empty write at EOF is a no-op");
        dev.write_all_at(&cx, ByteOffset(9), &[])
            .expect("empty write past EOF is a no-op");

        assert_eq!(std::fs::read(&path).expect("read file"), [1_u8, 2, 3, 4]);
        assert_eq!(std::fs::metadata(&path).expect("metadata").len(), 4);
    }

    #[test]
    fn file_byte_device_empty_scalar_write_on_read_only_file_is_noop() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty-read-only-write.img");
        std::fs::write(&path, [1_u8, 2, 3, 4]).expect("seed file");
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("read-only file handle");
        let dev = FileByteDevice {
            file: Arc::new(file),
            len: std::fs::metadata(&path).expect("metadata").len(),
            writable: false,
            sync_state: Arc::new(FileDeviceSyncState {
                write_epoch: AtomicU64::new(1),
                synced_epoch: AtomicU64::new(0),
            }),
        };

        dev.write_all_at(&cx, ByteOffset(9), &[])
            .expect("empty write past EOF on read-only file is a no-op");

        assert_eq!(std::fs::read(&path).expect("read file"), [1_u8, 2, 3, 4]);
        assert_eq!(std::fs::metadata(&path).expect("metadata").len(), 4);
    }

    #[test]
    fn file_byte_device_first_sync_always_syncs_then_clean_syncs_skip() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("clean-sync-skip.img");
        std::fs::write(&path, [0_u8; 4096]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        // Fresh device: write epoch starts ahead of synced epoch so the first
        // sync must issue the syscall (covers writes made through other
        // handles to the same path, e.g. mount-time journal replay).
        assert_eq!(dev.sync_epochs(), (1, 0));
        dev.sync(&cx).expect("first sync");
        assert_eq!(dev.sync_epochs(), (1, 1));

        // Clean repeat: epochs already equal, sync stays Ok and publishes no
        // new epoch (the syscall-skip branch).
        dev.sync(&cx).expect("clean sync");
        dev.sync(&cx).expect("clean sync again");
        assert_eq!(dev.sync_epochs(), (1, 1));

        // A write dirties the device; the next sync re-establishes equality.
        dev.write_all_at(&cx, ByteOffset(0), &[7_u8; 512])
            .expect("write");
        assert_eq!(dev.sync_epochs(), (2, 1));
        dev.sync(&cx).expect("post-write sync");
        assert_eq!(dev.sync_epochs(), (2, 2));

        // An empty write returns before the syscall and must not dirty.
        dev.write_all_at(&cx, ByteOffset(0), &[])
            .expect("empty write");
        assert_eq!(dev.sync_epochs(), (2, 2));
    }

    #[test]
    fn file_byte_device_clone_shares_sync_dirty_state() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("clone-sync-state.img");
        std::fs::write(&path, [0_u8; 4096]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");
        let clone = dev.clone();

        dev.sync(&cx).expect("first sync");
        assert_eq!(clone.sync_epochs(), (1, 1));

        // A write through the clone dirties the original too (shared state):
        // its next sync must observe the new epoch.
        clone
            .write_all_at(&cx, ByteOffset(1024), &[3_u8; 128])
            .expect("clone write");
        assert_eq!(dev.sync_epochs(), (2, 1));
        dev.sync(&cx).expect("sync after clone write");
        assert_eq!(clone.sync_epochs(), (2, 2));
    }

    #[test]
    fn file_byte_device_empty_vectored_read_is_noop() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty-vectored-read.img");
        std::fs::write(&path, [1_u8, 2, 3, 4]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        let mut empty_slices: [IoSliceMut<'_>; 0] = [];
        dev.read_vectored_exact_at(&cx, ByteOffset(0), &mut empty_slices)
            .expect("empty iovec read is a no-op");

        let mut zero_len = [];
        let mut zero_len_slices = [IoSliceMut::new(&mut zero_len)];
        dev.read_vectored_exact_at(&cx, ByteOffset(2), &mut zero_len_slices)
            .expect("zero-length iovec read is a no-op");

        let mut past_eof_empty_slices: [IoSliceMut<'_>; 0] = [];
        dev.read_vectored_exact_at(&cx, ByteOffset(9), &mut past_eof_empty_slices)
            .expect("empty iovec read past EOF is a no-op");

        let mut past_eof_zero_len = [];
        let mut past_eof_zero_len_slices = [IoSliceMut::new(&mut past_eof_zero_len)];
        dev.read_vectored_exact_at(&cx, ByteOffset(9), &mut past_eof_zero_len_slices)
            .expect("zero-length iovec read past EOF is a no-op");
    }

    #[test]
    fn file_byte_device_vectored_read_skips_interleaved_zero_length_iovecs() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mixed-vectored-read.img");
        std::fs::write(&path, [10_u8, 11, 12, 13, 14, 15, 16]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        let mut leading = [];
        let mut first = [0_u8; 2];
        let mut middle = [];
        let mut second = [0_u8; 3];
        let mut trailing = [];
        let mut bufs = [
            IoSliceMut::new(&mut leading),
            IoSliceMut::new(&mut first),
            IoSliceMut::new(&mut middle),
            IoSliceMut::new(&mut second),
            IoSliceMut::new(&mut trailing),
        ];

        dev.read_vectored_exact_at(&cx, ByteOffset(1), &mut bufs)
            .expect("mixed zero-length vectored read");

        assert_eq!(first, [11, 12]);
        assert_eq!(second, [13, 14, 15]);
    }

    #[test]
    fn file_byte_device_bounds_errors_have_no_side_effects() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bounds.img");
        std::fs::write(&path, [1_u8, 2, 3, 4]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        let mut scalar = [0xAA_u8; 2];
        let err = dev
            .read_exact_at(&cx, ByteOffset(3), &mut scalar)
            .expect_err("scalar read should reject range before I/O");
        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(scalar, [0xAA; 2]);

        let mut first = [0xBB_u8; 1];
        let mut second = [0xCC_u8; 2];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let err = dev
            .read_vectored_exact_at(&cx, ByteOffset(2), &mut bufs)
            .expect_err("vectored read should reject range before I/O");
        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(first, [0xBB]);
        assert_eq!(second, [0xCC; 2]);

        let err = dev
            .write_all_at(&cx, ByteOffset(3), &[9, 9])
            .expect_err("write should reject range before I/O");
        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(std::fs::read(&path).expect("read file"), [1_u8, 2, 3, 4]);
    }

    #[test]
    fn file_byte_device_scalar_read_preserves_buffer_on_short_read() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("short-scalar-read.img");
        std::fs::write(&path, [1_u8, 2, 3, 4, 5, 6, 7, 8]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate")
            .set_len(4)
            .expect("truncate after device open");

        let mut dst = [0xAA_u8; 8];
        let err = dev
            .read_exact_at(&cx, ByteOffset(0), &mut dst)
            .expect_err("short backing read should fail without mutating caller buffer");

        assert!(
            matches!(err, FfsError::Io(ref io_err)
                if io_err.kind() == std::io::ErrorKind::UnexpectedEof),
            "expected short-read UnexpectedEof, got {err:?}"
        );
        assert_eq!(dst, [0xAA; 8]);
    }

    #[test]
    fn file_byte_device_large_direct_read_preserves_buffer_on_short_read() {
        // Reads >= 64 KiB take the direct (no-scratch) path; verify it still
        // honors the all-or-nothing contract when the backing file shrinks
        // under the device — the up-front length re-check must error before any
        // byte of the destination is touched.
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("short-large-read.img");
        let len = 256 * 1024_usize;
        std::fs::write(&path, vec![0x5A_u8; len]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate")
            .set_len(8 * 1024)
            .expect("truncate after device open");

        let mut dst = vec![0xAA_u8; len];
        let err = dev
            .read_exact_at(&cx, ByteOffset(0), &mut dst)
            .expect_err("short backing read should fail without mutating caller buffer");

        assert!(
            matches!(err, FfsError::Io(ref io_err)
                if io_err.kind() == std::io::ErrorKind::UnexpectedEof),
            "expected short-read UnexpectedEof, got {err:?}"
        );
        assert!(
            dst.iter().all(|&b| b == 0xAA),
            "destination must be preserved"
        );
    }

    #[test]
    fn file_byte_device_large_direct_read_round_trips() {
        // The direct path must still deliver byte-identical data on success.
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("large-read.img");
        let len = 256 * 1024_usize;
        let data: Vec<u8> = (0..len)
            .map(|i| u8::try_from((i * 31 + 7) % 256).expect("byte"))
            .collect();
        std::fs::write(&path, &data).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        let mut dst = vec![0_u8; len];
        dev.read_exact_at(&cx, ByteOffset(0), &mut dst)
            .expect("direct read");
        assert_eq!(dst, data);
    }

    #[test]
    fn file_byte_device_vectored_read_preserves_buffers_on_short_read() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("short-vectored-read.img");
        std::fs::write(&path, [1_u8, 2, 3, 4, 5, 6, 7, 8]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate")
            .set_len(4)
            .expect("truncate after device open");

        let mut first = [0xAA_u8; 3];
        let mut second = [0xBB_u8; 5];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let err = dev
            .read_vectored_exact_at(&cx, ByteOffset(0), &mut bufs)
            .expect_err("short backing read should fail without mutating caller iovecs");

        assert!(
            matches!(err, FfsError::Io(ref io_err)
                if io_err.kind() == std::io::ErrorKind::UnexpectedEof),
            "expected short-read UnexpectedEof, got {err:?}"
        );
        assert_eq!(first, [0xAA; 3]);
        assert_eq!(second, [0xBB; 5]);
    }

    #[test]
    fn file_byte_device_rejects_u64_range_overflow_before_io() {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("range-overflow.img");
        std::fs::write(&path, [1_u8, 2, 3, 4]).expect("seed file");
        let dev = FileByteDevice::open(&path).expect("device");

        let mut scalar = [0xAA_u8; 1];
        let err = dev
            .read_exact_at(&cx, ByteOffset(u64::MAX), &mut scalar)
            .expect_err("scalar read should reject offset+len overflow before I/O");
        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("read range overflows u64")),
            "expected read-range overflow Format error, got {err:?}"
        );
        assert_eq!(scalar, [0xAA]);

        let mut first = [0xBB_u8; 1];
        let mut second = [0xCC_u8; 1];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let err = dev
            .read_vectored_exact_at(&cx, ByteOffset(u64::MAX - 1), &mut bufs)
            .expect_err("vectored read should reject offset+total_len overflow before I/O");
        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("read range overflows u64")),
            "expected read-range overflow Format error, got {err:?}"
        );
        assert_eq!(first, [0xBB]);
        assert_eq!(second, [0xCC]);

        let err = dev
            .write_all_at(&cx, ByteOffset(u64::MAX), &[9])
            .expect_err("write should reject offset+len overflow before I/O");
        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("write range overflows u64")),
            "expected write-range overflow Format error, got {err:?}"
        );
        assert_eq!(std::fs::read(&path).expect("read file"), [1_u8, 2, 3, 4]);
    }

    #[test]
    fn default_vectored_read_skips_zero_length_iovecs() {
        let cx = Cx::for_testing();
        let dev = ScalarOnlyByteDevice::new(vec![10, 11, 12, 13, 14, 15]);

        let mut leading = [];
        let mut middle = [0_u8; 2];
        let mut empty_between = [];
        let mut tail = [0_u8; 1];
        let mut bufs = [
            IoSliceMut::new(&mut leading),
            IoSliceMut::new(&mut middle),
            IoSliceMut::new(&mut empty_between),
            IoSliceMut::new(&mut tail),
        ];

        dev.read_vectored_exact_at(&cx, ByteOffset(1), &mut bufs)
            .expect("default vectored read");

        assert_eq!(middle, [11, 12]);
        assert_eq!(tail, [13]);
        assert_eq!(
            dev.read_calls(),
            vec![(ByteOffset(1), 2), (ByteOffset(3), 1)]
        );
    }

    #[test]
    fn default_vectored_read_preserves_iovecs_when_later_scalar_read_fails() {
        let cx = Cx::for_testing();
        let dev = FailOnSecondScalarReadByteDevice::new();
        let mut first = [0xAA_u8; 2];
        let mut second = [0xBB_u8; 3];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];

        let err = dev
            .read_vectored_exact_at(&cx, ByteOffset(0), &mut bufs)
            .expect_err("later scalar read failure should not mutate caller iovecs");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("injected second scalar read failure")),
            "expected injected scalar-read Format error, got {err:?}"
        );
        assert_eq!(
            dev.read_calls(),
            vec![(ByteOffset(0), 2), (ByteOffset(2), 3)]
        );
        assert_eq!(first, [0xAA; 2]);
        assert_eq!(second, [0xBB; 3]);
    }

    #[test]
    fn default_vectored_read_rejects_overflow_before_partial_reads() {
        let cx = Cx::for_testing();
        let dev = PermissiveReadByteDevice::new();
        let mut first = [0xAA_u8; 2];
        let mut second = [0xBB_u8; 1];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];

        let err = dev
            .read_vectored_exact_at(&cx, ByteOffset(u64::MAX - 1), &mut bufs)
            .expect_err("overflowing vectored read should fail before scalar reads");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("read range overflows u64")),
            "expected read-range overflow Format error, got {err:?}"
        );
        assert!(dev.read_calls().is_empty());
        assert_eq!(first, [0xAA; 2]);
        assert_eq!(second, [0xBB; 1]);
    }

    #[test]
    fn default_vectored_read_rejects_bounds_before_partial_reads() {
        let cx = Cx::for_testing();
        let dev = ScalarOnlyByteDevice::new(vec![10, 11, 12, 13]);
        let mut first = [0xAA_u8; 1];
        let mut second = [0xBB_u8; 2];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];

        let err = dev
            .read_vectored_exact_at(&cx, ByteOffset(2), &mut bufs)
            .expect_err("out-of-bounds vectored read should fail before scalar reads");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("read out of bounds")
                    && message.contains("offset=2")
                    && message.contains("len=3")
                    && message.contains("device_len=4")),
            "expected read-bounds Format error, got {err:?}"
        );
        assert!(dev.read_calls().is_empty());
        assert_eq!(first, [0xAA; 1]);
        assert_eq!(second, [0xBB; 2]);
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
    fn vectored_read_rejects_invalid_later_block_before_partial_reads() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        dev.write_block(&cx, BlockNumber(0), &[0x5A; 4096])
            .expect("seed block");
        let blocks = [BlockNumber(0), BlockNumber(2)];
        let mut reads = [
            BlockBuf::new(vec![0xAA; 4096]),
            BlockBuf::new(vec![0xBB; 4096]),
        ];

        let err = dev
            .read_vectored(&blocks, &mut reads, &cx)
            .expect_err("invalid later block should fail before reads");

        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(reads[0].as_slice(), &[0xAA; 4096]);
        assert_eq!(reads[1].as_slice(), &[0xBB; 4096]);
    }

    #[test]
    fn vectored_write_rejects_invalid_later_block_before_partial_writes() {
        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(4096 * 2);
        let dev = ByteBlockDevice::new(mem, 4096).expect("device");
        let invalid_block_numbers = [BlockNumber(0), BlockNumber(2)];
        let writes = [
            BlockBuf::new(vec![0xAA; 4096]),
            BlockBuf::new(vec![0xBB; 4096]),
        ];

        let err = dev
            .write_vectored(&invalid_block_numbers, &writes, &cx)
            .expect_err("invalid later block should fail before writes");

        assert!(matches!(err, FfsError::Format(_)));
        let first_block_after_failed_write =
            dev.read_block(&cx, BlockNumber(0)).expect("read block 0");
        assert_eq!(first_block_after_failed_write.as_slice(), &[0_u8; 4096]);
    }

    #[derive(Debug)]
    struct ShortReadBlockDevice;

    impl BlockDevice for ShortReadBlockDevice {
        fn read_block(&self, _cx: &Cx, _block: BlockNumber) -> Result<BlockBuf> {
            Ok(BlockBuf::new(vec![0x5A; 2]))
        }

        fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        fn block_size(&self) -> u32 {
            4
        }

        fn block_count(&self) -> u64 {
            1
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn default_vectored_read_rejects_short_block_without_replacing_buffer() {
        let cx = Cx::for_testing();
        let dev = ShortReadBlockDevice;
        let blocks = [BlockNumber(0)];
        let mut bufs = [BlockBuf::new(vec![0xAA; 4])];

        let err = dev
            .read_vectored(&blocks, &mut bufs, &cx)
            .expect_err("short scalar block should fail closed");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("read_block returned wrong size")
                    && message.contains("got=2")
                    && message.contains("expected=4")),
            "expected block-size Format error, got {err:?}"
        );
        assert_eq!(bufs[0].as_slice(), &[0xAA; 4]);
    }

    #[test]
    fn default_contiguous_blocks_rejects_short_block_without_replacing_buffer() {
        let cx = Cx::for_testing();
        let dev = ShortReadBlockDevice;
        let mut bufs = [BlockBuf::new(vec![0xAA; 4])];

        let err = dev
            .read_contiguous_blocks(&cx, BlockNumber(0), &mut bufs)
            .expect_err("short scalar block should fail closed");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("read_block returned wrong size")
                    && message.contains("got=2")
                    && message.contains("expected=4")),
            "expected block-size Format error, got {err:?}"
        );
        assert_eq!(bufs[0].as_slice(), &[0xAA; 4]);
    }

    #[test]
    fn default_contiguous_into_rejects_short_block_without_panic() {
        let cx = Cx::for_testing();
        let dev = ShortReadBlockDevice;
        let mut dst = [0xAA_u8; 4];

        let err = dev
            .read_contiguous_into(&cx, BlockNumber(0), &mut dst)
            .expect_err("short scalar block should fail closed");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("read_block returned wrong size")
                    && message.contains("got=2")
                    && message.contains("expected=4")),
            "expected block-size Format error, got {err:?}"
        );
        assert_eq!(dst, [0xAA; 4]);
    }

    #[derive(Debug, Default)]
    struct RangeCheckedWriteBlockDevice {
        writes: AtomicUsize,
    }

    impl BlockDevice for RangeCheckedWriteBlockDevice {
        fn read_block(&self, _cx: &Cx, _block: BlockNumber) -> Result<BlockBuf> {
            Ok(BlockBuf::new(vec![0_u8; 4]))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            if data.len() != 4 {
                return Err(FfsError::Format(format!(
                    "write size mismatch: got={} expected=4",
                    data.len()
                )));
            }
            if block.0 >= self.block_count() {
                return Err(FfsError::Format(format!(
                    "block out of range: block={} block_count={}",
                    block.0,
                    self.block_count()
                )));
            }
            self.writes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn block_size(&self) -> u32 {
            4
        }

        fn block_count(&self) -> u64 {
            2
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn default_contiguous_write_rejects_later_oob_before_partial_write() {
        let cx = Cx::for_testing();
        let dev = RangeCheckedWriteBlockDevice::default();
        let data = [0xA5_u8; 8];

        let err = dev
            .write_contiguous_blocks(&cx, BlockNumber(1), &data)
            .expect_err("out-of-range later block should fail before writes");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("block out of range")
                    && message.contains("block=2")
                    && message.contains("block_count=2")),
            "expected out-of-range Format error, got {err:?}"
        );
        assert_eq!(dev.writes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn default_vectored_write_rejects_short_buffer_before_partial_write() {
        let cx = Cx::for_testing();
        let dev = RangeCheckedWriteBlockDevice::default();
        let blocks = [BlockNumber(0), BlockNumber(1)];
        let bufs = [BlockBuf::new(vec![0xAA; 4]), BlockBuf::new(vec![0xBB; 2])];

        let err = dev
            .write_vectored(&blocks, &bufs, &cx)
            .expect_err("short later vectored buffer should fail before writes");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("write_vectored block size mismatch")
                    && message.contains("got=2")
                    && message.contains("expected=4")),
            "expected vectored write size Format error, got {err:?}"
        );
        assert_eq!(dev.writes.load(Ordering::Relaxed), 0);
    }

    #[derive(Debug, Default)]
    struct RangeCheckedReadBlockDevice {
        reads: AtomicUsize,
    }

    impl BlockDevice for RangeCheckedReadBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if block.0 >= self.block_count() {
                return Err(FfsError::Format(format!(
                    "block out of range: block={} block_count={}",
                    block.0,
                    self.block_count()
                )));
            }
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(BlockBuf::new(vec![0x5C; 4]))
        }

        fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        fn block_size(&self) -> u32 {
            4
        }

        fn block_count(&self) -> u64 {
            2
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn default_contiguous_blocks_rejects_later_oob_before_partial_read() {
        let cx = Cx::for_testing();
        let dev = RangeCheckedReadBlockDevice::default();
        let mut bufs = [BlockBuf::new(vec![0xAA; 4]), BlockBuf::new(vec![0xBB; 4])];

        let err = dev
            .read_contiguous_blocks(&cx, BlockNumber(1), &mut bufs)
            .expect_err("out-of-range later block should fail before reads");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("block out of range")
                    && message.contains("block=2")
                    && message.contains("block_count=2")),
            "expected out-of-range Format error, got {err:?}"
        );
        assert_eq!(dev.reads.load(Ordering::Relaxed), 0);
        assert_eq!(bufs[0].as_slice(), &[0xAA; 4]);
        assert_eq!(bufs[1].as_slice(), &[0xBB; 4]);
    }

    #[test]
    fn default_contiguous_into_rejects_later_oob_before_partial_read() {
        let cx = Cx::for_testing();
        let dev = RangeCheckedReadBlockDevice::default();
        let mut dst = [0xAA_u8; 8];

        let err = dev
            .read_contiguous_into(&cx, BlockNumber(1), &mut dst)
            .expect_err("out-of-range later block should fail before reads");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("block out of range")
                    && message.contains("block=2")
                    && message.contains("block_count=2")),
            "expected out-of-range Format error, got {err:?}"
        );
        assert_eq!(dev.reads.load(Ordering::Relaxed), 0);
        assert_eq!(dst, [0xAA; 8]);
    }

    #[test]
    fn default_vectored_read_rejects_later_oob_before_partial_read() {
        // bd-d1vrr: a [valid, out-of-range] request must reject in the block-
        // bounds preflight before issuing ANY scalar read_block, leaving both
        // caller buffers untouched (no partial overwrite of the first buffer).
        let cx = Cx::for_testing();
        let dev = RangeCheckedReadBlockDevice::default();
        let blocks = [BlockNumber(0), BlockNumber(2)];
        let mut bufs = [BlockBuf::new(vec![0xAA; 4]), BlockBuf::new(vec![0xBB; 4])];

        let err = dev
            .read_vectored(&blocks, &mut bufs, &cx)
            .expect_err("out-of-range later block should fail before reads");

        assert!(
            matches!(err, FfsError::Format(ref message)
                if message.contains("block out of range")
                    && message.contains("block=2")
                    && message.contains("block_count=2")),
            "expected out-of-range Format error, got {err:?}"
        );
        assert_eq!(dev.reads.load(Ordering::Relaxed), 0);
        assert_eq!(bufs[0].as_slice(), &[0xAA; 4]);
        assert_eq!(bufs[1].as_slice(), &[0xBB; 4]);
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

    #[cfg(feature = "s3fifo")]
    #[test]
    fn arc_cache_explicit_clean_evict_invalidates_fast_residents() {
        const BLOCK_SIZE: u32 = 4096;
        const TARGET: BlockNumber = BlockNumber(0);
        const CACHED_BYTE: u8 = 0xA1;
        const BACKING_BYTE: u8 = 0xB2;

        let cx = Cx::for_testing();
        let mem = MemoryByteDevice::new(BLOCK_SIZE as usize * 4);
        let dev = ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device");
        dev.write_block(&cx, TARGET, &[CACHED_BYTE; BLOCK_SIZE as usize])
            .expect("seed backing block");

        let counted = CountingBlockDevice::new(dev);
        let cache = ArcCache::new(counted, 400).expect("fast-path cache");

        let cold = cache.read_block(&cx, TARGET).expect("cold read");
        assert_eq!(cold.as_slice(), &[CACHED_BYTE; BLOCK_SIZE as usize]);
        assert_eq!(cache.inner().read_count(), 1);

        let global_fast = cache.read_block(&cx, TARGET).expect("global fast read");
        assert_eq!(global_fast.as_slice(), &[CACHED_BYTE; BLOCK_SIZE as usize]);
        assert_eq!(
            cache.inner().read_count(),
            1,
            "global fast resident must bypass the backing device"
        );

        cache
            .inner()
            .inner
            .write_block(&cx, TARGET, &[BACKING_BYTE; BLOCK_SIZE as usize])
            .expect("mutate backing block behind cache");

        let thread_fast = cache.read_block(&cx, TARGET).expect("thread fast read");
        assert_eq!(thread_fast.as_slice(), &[CACHED_BYTE; BLOCK_SIZE as usize]);
        assert_eq!(
            cache.inner().read_count(),
            1,
            "thread-local fast resident must bypass the backing device"
        );

        cache.evict(TARGET);

        let refreshed = cache.read_block(&cx, TARGET).expect("read after eviction");
        assert_eq!(refreshed.as_slice(), &[BACKING_BYTE; BLOCK_SIZE as usize]);
        assert_eq!(
            cache.inner().read_count(),
            2,
            "read after explicit eviction must consult the backing device"
        );
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

    #[cfg(not(feature = "s3fifo"))]
    #[test]
    fn arc_state_clean_index_tracks_dirty_front_across_trim() {
        let mut state = ArcState::new(8);
        for block in 0..8_u64 {
            arc_access(&mut state, BlockNumber(block));
        }

        for block in 0..6_u64 {
            state.mark_dirty(
                BlockNumber(block),
                4096,
                TxnId(block + 1),
                None,
                DirtyState::InFlight,
            );
        }

        assert_eq!(
            state.oldest_clean_resident(ArcList::T1),
            Some(BlockNumber(6))
        );
        assert_eq!(state.oldest_clean_resident(ArcList::T2), None);

        state.set_target_capacity(2);
        let batch = state.trim_to_capacity();
        assert_eq!(batch.evicted_blocks, 2);
        assert_eq!(state.resident_len(), 6);
        assert_eq!(state.oldest_clean_resident(ArcList::T1), None);
        assert_eq!(state.oldest_clean_resident(ArcList::T2), None);

        state.clear_dirty_unconditional(BlockNumber(0));
        assert_eq!(
            state.oldest_clean_resident(ArcList::T1),
            Some(BlockNumber(0))
        );
        assert_eq!(state.oldest_clean_resident(ArcList::T2), None);
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
