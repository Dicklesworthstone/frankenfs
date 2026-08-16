//! Block-level scrub pipeline for detecting corruption signals.
//!
//! The scrub pipeline iterates over blocks in a device, running pluggable
//! validators to detect checksum mismatches, structural invariant violations,
//! and other corruption signals. Findings are collected into a [`ScrubReport`]
//! with per-block detail and summary statistics.
//!
//! # Design
//!
//! The scrub does not interpret filesystem-specific formats directly. Instead,
//! callers provide a [`BlockValidator`] implementation that knows how to check
//! a block's integrity (e.g., ext4 metadata_csum, btrfs csum tree). This keeps
//! the scrub engine format-agnostic while allowing precise corruption detection.
//!
//! # Usage
//!
//! ```text
//! let report = Scrubber::new(&device, &validator)
//!     .scrub_range(&cx, BlockNumber(0), 1000)?;
//! for finding in &report.findings {
//!     eprintln!("block {}: {:?} - {}", finding.block, finding.kind, finding.detail);
//! }
//! ```

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_ondisk::{
    BtrfsHeader, BtrfsSuperblock, Ext4Superblock, verify_btrfs_superblock_checksum,
    verify_btrfs_tree_block_checksum,
};
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, BlockNumber, EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_SIZE, ParseError,
};
use std::fmt;

const SCRUB_READ_BATCH_BLOCKS: usize = 64;

// ── Corruption taxonomy ─────────────────────────────────────────────────────

/// Category of corruption detected during a scrub pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorruptionKind {
    /// Stored checksum does not match computed checksum (CRC32C, BLAKE3, etc.).
    ChecksumMismatch,
    /// A structural field is out of its valid range (e.g., block pointer beyond
    /// device bounds, negative free count, impossible inode size).
    StructuralInvariant,
    /// Magic number or signature bytes are wrong.
    BadMagic,
    /// Block is entirely zeroed when it should contain data.
    UnexpectedZeroes,
    /// Read I/O error (device returned an error for this block).
    IoError,
}

impl fmt::Display for CorruptionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChecksumMismatch => write!(f, "checksum_mismatch"),
            Self::StructuralInvariant => write!(f, "structural_invariant"),
            Self::BadMagic => write!(f, "bad_magic"),
            Self::UnexpectedZeroes => write!(f, "unexpected_zeroes"),
            Self::IoError => write!(f, "io_error"),
        }
    }
}

/// Severity of a scrub finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational — potential issue but not necessarily corruption.
    Info,
    /// Possible corruption that may affect data integrity.
    Warning,
    /// Confirmed corruption that affects data integrity.
    Error,
    /// Critical corruption in metadata essential for filesystem operation
    /// (superblock, group descriptors, journal).
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ── Findings ────────────────────────────────────────────────────────────────

/// A single corruption finding for one block.
#[derive(Debug, Clone)]
pub struct ScrubFinding {
    /// Block where corruption was detected.
    pub block: BlockNumber,
    /// Category of corruption.
    pub kind: CorruptionKind,
    /// How severe the finding is.
    pub severity: Severity,
    /// Human-readable detail (e.g., "CRC32C expected 0xABCD, got 0x1234").
    pub detail: String,
}

impl fmt::Display for ScrubFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "block {} [{}] {}: {}",
            self.block, self.severity, self.kind, self.detail
        )
    }
}

// ── Report ──────────────────────────────────────────────────────────────────

/// Aggregated results from a scrub pass.
#[derive(Debug, Clone)]
pub struct ScrubReport {
    /// All findings, ordered by block number.
    pub findings: Vec<ScrubFinding>,
    /// Total blocks scanned (including clean ones).
    pub blocks_scanned: u64,
    /// Blocks that had at least one finding.
    pub blocks_corrupt: u64,
    /// Blocks that returned I/O errors during read.
    pub blocks_io_error: u64,
}

impl ScrubReport {
    /// True if no corruption was found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Count of findings at or above the given severity.
    #[must_use]
    pub fn count_at_severity(&self, min: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= min).count()
    }
}

impl fmt::Display for ScrubReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scanned {} blocks: {} corrupt, {} io_errors, {} findings",
            self.blocks_scanned,
            self.blocks_corrupt,
            self.blocks_io_error,
            self.findings.len(),
        )
    }
}

// ── Validator trait ─────────────────────────────────────────────────────────

/// Result of validating a single block.
#[derive(Debug)]
pub enum BlockVerdict {
    /// Block passes all checks.
    Clean,
    /// Block has one or more issues.
    Corrupt(Vec<(CorruptionKind, Severity, String)>),
    /// Validator does not know how to check this block (skip it).
    Skip,
}

/// Pluggable block validation strategy.
///
/// Implementations inspect raw block data and return a verdict. The scrub
/// engine calls `validate` for every block in the scan range and collects
/// non-clean verdicts into the report.
pub trait BlockValidator: Send + Sync {
    /// Validate a single block.
    ///
    /// `block` is the block number, `data` is the raw block content.
    /// Implementations should never panic on malformed data — return
    /// `BlockVerdict::Corrupt` with details instead.
    fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict;
}

// ── Scrubber ────────────────────────────────────────────────────────────────

/// Per-chunk scan result: `(findings, blocks_scanned, blocks_corrupt,
/// blocks_io_error)`. The parallel `scrub_range` merges these in block order.
type ChunkScan = (Vec<ScrubFinding>, u64, u64, u64);

/// Block-level scrub engine.
///
/// Iterates over a range of blocks on a [`BlockDevice`], validates each using
/// a [`BlockValidator`], and collects findings into a [`ScrubReport`].
pub struct Scrubber<'a> {
    device: &'a dyn BlockDevice,
    validator: &'a dyn BlockValidator,
}

impl<'a> Scrubber<'a> {
    pub fn new(device: &'a dyn BlockDevice, validator: &'a dyn BlockValidator) -> Self {
        Self { device, validator }
    }

    fn record_verdict(
        findings: &mut Vec<ScrubFinding>,
        blocks_corrupt: &mut u64,
        block: BlockNumber,
        verdict: BlockVerdict,
    ) {
        match verdict {
            BlockVerdict::Clean | BlockVerdict::Skip => {}
            BlockVerdict::Corrupt(issues) => {
                *blocks_corrupt += 1;
                for (kind, severity, detail) in issues {
                    findings.push(ScrubFinding {
                        block,
                        kind,
                        severity,
                        detail,
                    });
                }
            }
        }
    }

    fn record_io_error(
        findings: &mut Vec<ScrubFinding>,
        blocks_corrupt: &mut u64,
        blocks_io_error: &mut u64,
        block: BlockNumber,
        error: &FfsError,
    ) {
        *blocks_corrupt += 1;
        *blocks_io_error += 1;
        findings.push(ScrubFinding {
            block,
            kind: CorruptionKind::IoError,
            severity: Severity::Error,
            detail: format!("read failed: {error}"),
        });
    }

    /// Scrub a range of blocks `[start, start + count)`.
    ///
    /// Returns a report with all findings. Does not panic on I/O errors or
    /// corrupted data — those are recorded as findings.
    ///
    /// The range is partitioned into chunks scanned in parallel across the
    /// rayon pool (bd-tyym4). A whole-device scrub is dominated by the per-batch
    /// device reads; running chunks concurrently overlaps those read latencies
    /// (a blocking read parks its worker, so the overlap is bounded by the pool
    /// size, not the CPU core count — the same I/O-overlap that drives the
    /// read-path levers bd-307e4/bd-strse/bd-yg6tk), and the pure-CPU
    /// per-block validation parallelizes for free. Each chunk scans a disjoint
    /// sub-range with the identical serial batch loop, and the per-chunk reports
    /// are merged in ascending block order, so the findings list and the
    /// scanned/corrupt/io-error counters are byte-identical to a single serial
    /// pass. Checkpoints still occur at the same 256-block cadence measured
    /// from the caller's start block.
    pub fn scrub_range(&self, cx: &Cx, start: BlockNumber, count: u64) -> Result<ScrubReport> {
        use rayon::prelude::{IntoParallelIterator, ParallelIterator};

        let device_blocks = self.device.block_count();
        let end = start.0.saturating_add(count).min(device_blocks);
        if start.0 >= end {
            return Ok(ScrubReport {
                findings: Vec::new(),
                blocks_scanned: 0,
                blocks_corrupt: 0,
                blocks_io_error: 0,
            });
        }
        let total = end - start.0;

        // Partition into ~one chunk per pool thread (not 8) so each chunk spans
        // MANY read batches and its reusable `bufs` pool is actually reused
        // across them. The previous ~8-chunks-per-thread split produced, on a
        // typical image, chunks of exactly one `SCRUB_READ_BATCH_BLOCKS` batch
        // (`total / (threads*8)` fell below the batch floor), so every chunk
        // re-allocated + re-zeroed its read buffers on its first (and only)
        // batch and never reached the fast vectored read path — profiling put
        // ~76% of scrub self-time in buffer alloc/zero/free (memset, AlignedVec,
        // mprotect/madvise), not validation. Targeting one chunk per thread
        // keeps every worker busy (scrub work is uniform per block, so no
        // load-balancing slack is needed) while letting each chunk amortize one
        // buffer-pool allocation over all its batches. Each chunk still covers
        // at least one read batch; a range that fits in a single chunk is
        // scanned inline to skip the rayon fan-out entirely.
        let parallelism = rayon::current_num_threads().max(1) as u64;
        let chunk = (total / parallelism)
            .max(SCRUB_READ_BATCH_BLOCKS as u64)
            .max(1);
        let num_chunks = usize::try_from(total.div_ceil(chunk)).unwrap_or(usize::MAX);

        if num_chunks <= 1 {
            let (findings, blocks_scanned, blocks_corrupt, blocks_io_error) =
                self.scan_subrange(cx, start.0, start.0, end)?;
            return Ok(ScrubReport {
                findings,
                blocks_scanned,
                blocks_corrupt,
                blocks_io_error,
            });
        }

        // `(0..num_chunks)` is an indexed range, so `collect` preserves chunk
        // order; chunks are disjoint and ascending, so concatenating their
        // findings yields the same block order as the serial scan.
        let chunk_results: Vec<Result<ChunkScan>> = (0..num_chunks)
            .into_par_iter()
            .map(|ci| {
                let ci = ci as u64;
                let sub_start = start.0 + ci * chunk;
                let sub_end = (sub_start + chunk).min(end);
                self.scan_subrange(cx, start.0, sub_start, sub_end)
            })
            .collect();

        let mut findings = Vec::new();
        let mut blocks_scanned: u64 = 0;
        let mut blocks_corrupt: u64 = 0;
        let mut blocks_io_error: u64 = 0;
        for result in chunk_results {
            let (chunk_findings, scanned, corrupt, io_error) = result?;
            findings.extend(chunk_findings);
            blocks_scanned += scanned;
            blocks_corrupt += corrupt;
            blocks_io_error += io_error;
        }

        Ok(ScrubReport {
            findings,
            blocks_scanned,
            blocks_corrupt,
            blocks_io_error,
        })
    }

    /// Scan a disjoint sub-range `[sub_start, sub_end)` with the serial
    /// batch-read + validate loop, returning `(findings, scanned, corrupt,
    /// io_error)`. This is the per-chunk unit of work parallelized by
    /// [`Self::scrub_range`]; in isolation it is identical to the previous
    /// single-pass scrub loop.
    fn scan_subrange(
        &self,
        cx: &Cx,
        range_start: u64,
        sub_start: u64,
        sub_end: u64,
    ) -> Result<ChunkScan> {
        let mut findings = Vec::new();
        let mut blocks_scanned: u64 = 0;
        let mut blocks_corrupt: u64 = 0;
        let mut blocks_io_error: u64 = 0;

        // Reused across batches: read_contiguous_blocks fills every buffer
        // (or errors and leaves them unused), so a single allocation that is
        // re-overwritten each batch avoids re-allocating + re-zeroing ~one
        // block per scanned block on the hot scrub loop (bd-xmh5g.7).
        let mut bufs: Vec<BlockBuf> = Vec::new();

        let mut next_block = sub_start;
        while next_block < sub_end {
            if (next_block - range_start).is_multiple_of(256) {
                cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            }

            if !self.device.supports_contiguous_reads() {
                let block = BlockNumber(next_block);
                blocks_scanned += 1;
                match self.device.read_block(cx, block) {
                    Ok(buf) => Self::record_verdict(
                        &mut findings,
                        &mut blocks_corrupt,
                        block,
                        self.validator.validate(block, &buf),
                    ),
                    Err(error) => Self::record_io_error(
                        &mut findings,
                        &mut blocks_corrupt,
                        &mut blocks_io_error,
                        block,
                        &error,
                    ),
                }
                next_block += 1;
                continue;
            }

            let remaining_blocks = sub_end - next_block;
            let remaining = usize::try_from(remaining_blocks).unwrap_or(usize::MAX);
            let batch_len = remaining.min(SCRUB_READ_BATCH_BLOCKS);
            let batch_len_u64 = u64::try_from(batch_len)
                .map_err(|_| FfsError::Format("scrub batch length does not fit u64".to_owned()))?;
            let batch_start = BlockNumber(next_block);
            let batch_end = next_block
                .checked_add(batch_len_u64)
                .ok_or_else(|| FfsError::Format("scrub batch range overflow".to_owned()))?;
            let batch_blocks: Vec<BlockNumber> = (next_block..batch_end).map(BlockNumber).collect();
            // Grow the reusable buffer pool to cover this batch; existing
            // entries keep their block-sized allocations and are reused.
            if bufs.len() < batch_len {
                bufs.resize_with(batch_len, || BlockBuf::new(Vec::new()));
            }

            if self
                .device
                .read_contiguous_blocks(cx, batch_start, &mut bufs[..batch_len])
                .is_ok()
            {
                for (block, buf) in batch_blocks.iter().copied().zip(bufs[..batch_len].iter()) {
                    blocks_scanned += 1;
                    Self::record_verdict(
                        &mut findings,
                        &mut blocks_corrupt,
                        block,
                        self.validator.validate(block, buf),
                    );
                }
            } else {
                for block in batch_blocks {
                    blocks_scanned += 1;
                    match self.device.read_block(cx, block) {
                        Ok(buf) => Self::record_verdict(
                            &mut findings,
                            &mut blocks_corrupt,
                            block,
                            self.validator.validate(block, &buf),
                        ),
                        Err(error) => Self::record_io_error(
                            &mut findings,
                            &mut blocks_corrupt,
                            &mut blocks_io_error,
                            block,
                            &error,
                        ),
                    }
                }
            }

            next_block = batch_end;
        }

        Ok((findings, blocks_scanned, blocks_corrupt, blocks_io_error))
    }

    /// Scrub the entire device.
    pub fn scrub_all(&self, cx: &Cx) -> Result<ScrubReport> {
        self.scrub_range(cx, BlockNumber(0), self.device.block_count())
    }
}

// ── Built-in validators ─────────────────────────────────────────────────────

/// A validator that checks whether a block is entirely zeroed.
///
/// Useful as a baseline or for detecting zeroed-out metadata blocks that
/// should contain data (e.g., superblock backups).
#[derive(Debug, Clone, Copy)]
pub struct ZeroCheckValidator;

fn unexpected_zeroes_issue() -> (CorruptionKind, Severity, String) {
    (
        CorruptionKind::UnexpectedZeroes,
        Severity::Warning,
        "block is entirely zeroed".to_owned(),
    )
}

impl BlockValidator for ZeroCheckValidator {
    fn validate(&self, _block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        if is_all_zero(data.as_slice()) {
            BlockVerdict::Corrupt(vec![unexpected_zeroes_issue()])
        } else {
            BlockVerdict::Clean
        }
    }
}

/// Word-wise all-zeros test: scan `u64` chunks (8× fewer loop iterations than a
/// byte-by-byte `iter().all(|&b| b == 0)`, and the compiler can widen the fold to
/// SIMD) while preserving the same first-non-zero early-exit. Hot on the scrub path
/// where `ZeroCheckValidator::validate` was ~7% self-time re-scanning whole 4 KiB
/// blocks (bd-cc-scrub-zerocheck). Behaviour-identical: true iff every byte is 0.
#[inline]
pub(crate) fn is_all_zero(data: &[u8]) -> bool {
    // OR-reduce 4 u64s (256 bits) per iteration with one early-exit branch. The
    // compiler does not auto-vectorize the single-u64 `.all(== 0)` scan, so this
    // is ~2.1x on the full-scan (all-zero / free block) case with NO regression
    // on the common non-zero data block that exits at word 0 — both are ~1.1 ns
    // (bench `zero_scan_width`). Identical result to the per-word scan.
    let (chunks, chunks_remainder) = data.as_chunks::<32>();
    for block in chunks {
        let w0 = u64::from_ne_bytes(block[0..8].try_into().unwrap());
        let w1 = u64::from_ne_bytes(block[8..16].try_into().unwrap());
        let w2 = u64::from_ne_bytes(block[16..24].try_into().unwrap());
        let w3 = u64::from_ne_bytes(block[24..32].try_into().unwrap());
        if (w0 | w1 | w2 | w3) != 0 {
            return false;
        }
    }
    let (tail_words, tail_bytes) = chunks_remainder.as_chunks::<8>();
    tail_words
        .iter()
        .all(|chunk| u64::from_ne_bytes(*chunk) == 0)
        && tail_bytes.iter().all(|&b| b == 0)
}

/// Validator for the canonical ext4 primary superblock.
///
/// Checks parseability, basic geometry sanity, and metadata checksum integrity
/// (when `METADATA_CSUM` is enabled).
#[derive(Debug, Clone, Copy)]
pub struct Ext4SuperblockValidator {
    block_size: u32,
}

impl Ext4SuperblockValidator {
    #[must_use]
    pub fn new(block_size: u32) -> Self {
        Self { block_size }
    }

    fn target_block_and_offset(self) -> (u64, usize) {
        if self.block_size == 1024 {
            (1, 0)
        } else {
            (0, EXT4_SUPERBLOCK_OFFSET)
        }
    }
}

impl BlockValidator for Ext4SuperblockValidator {
    fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        let (target_block, offset) = self.target_block_and_offset();
        if block.0 != target_block {
            return BlockVerdict::Skip;
        }

        let end = offset.saturating_add(EXT4_SUPERBLOCK_SIZE);
        let Some(region) = data.as_slice().get(offset..end) else {
            return BlockVerdict::Corrupt(vec![(
                CorruptionKind::StructuralInvariant,
                Severity::Critical,
                format!(
                    "ext4 superblock region out of bounds in block {block}: need bytes {offset}..{end}, got {}",
                    data.as_slice().len()
                ),
            )]);
        };

        let sb = match Ext4Superblock::parse_superblock_region(region) {
            Ok(sb) => sb,
            Err(err) => {
                return BlockVerdict::Corrupt(vec![parse_error_issue(
                    "ext4 superblock parse failed",
                    &err,
                )]);
            }
        };

        let mut issues = Vec::new();
        if let Err(err) = sb.validate_geometry() {
            issues.push(parse_error_issue("ext4 superblock geometry invalid", &err));
        }
        if let Err(err) = sb.validate_checksum(region) {
            issues.push(parse_error_issue("ext4 superblock checksum invalid", &err));
        }

        if issues.is_empty() {
            BlockVerdict::Clean
        } else {
            BlockVerdict::Corrupt(issues)
        }
    }
}

/// Validator for the canonical btrfs primary superblock.
///
/// Checks parseability and superblock checksum integrity.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSuperblockValidator {
    /// Precomputed target for the primary superblock and for every mirror the
    /// filesystem is large enough to contain. `validate` runs on EVERY scanned
    /// block, so hoisting the `byte_offset / block_size` division out of the
    /// per-block path (it is a compile-time-opaque method call under `dyn
    /// BlockValidator`, so LLVM cannot lift it) into `new()` leaves the hot path
    /// a handful of block-number compares.
    targets: [Option<SuperblockTarget>; BTRFS_SUPER_MIRROR_OFFSETS.len()],
}

/// Where one superblock copy lives: its block, its offset inside that block, and
/// its absolute byte offset (which a valid copy stores in its own `bytenr`).
#[derive(Debug, Clone, Copy)]
struct SuperblockTarget {
    block: u64,
    offset: usize,
    byte_offset: u64,
}

impl BtrfsSuperblockValidator {
    /// `total_bytes` is the filesystem size taken from the superblock (NOT the
    /// image file size). btrfs writes a superblock mirror only where the
    /// filesystem actually spans it, so a mirror offset beyond `total_bytes` is
    /// legitimately absent and must not be reported.
    #[must_use]
    pub fn new(block_size: u32, total_bytes: u64) -> Self {
        let mut targets = [None; BTRFS_SUPER_MIRROR_OFFSETS.len()];
        if block_size == 0 {
            return Self { targets };
        }
        let block_size = u64::from(block_size);
        for (slot, byte_offset) in targets.iter_mut().zip(BTRFS_SUPER_MIRROR_OFFSETS) {
            // The primary is always a target: it is where the superblock was
            // read from, so its absence is corruption, not a size artifact.
            let is_primary = byte_offset == BTRFS_SUPER_INFO_OFFSET as u64;
            let spanned = byte_offset
                .checked_add(BTRFS_SUPER_INFO_SIZE as u64)
                .is_some_and(|end| end <= total_bytes);
            if is_primary || spanned {
                *slot = Some(SuperblockTarget {
                    block: byte_offset / block_size,
                    offset: usize::try_from(byte_offset % block_size).unwrap_or(0),
                    byte_offset,
                });
            }
        }
        Self { targets }
    }
}

impl BlockValidator for BtrfsSuperblockValidator {
    fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        let Some(target) = self
            .targets
            .iter()
            .flatten()
            .find(|target| target.block == block.0)
        else {
            return BlockVerdict::Skip;
        };
        let offset = target.offset;

        let end = offset.saturating_add(BTRFS_SUPER_INFO_SIZE);
        let Some(region) = data.as_slice().get(offset..end) else {
            return BlockVerdict::Corrupt(vec![(
                CorruptionKind::StructuralInvariant,
                Severity::Critical,
                format!(
                    "btrfs superblock region out of bounds in block {block}: need bytes {offset}..{end}, got {}",
                    data.as_slice().len()
                ),
            )]);
        };

        let mut issues = Vec::new();
        match BtrfsSuperblock::parse_superblock_region(region) {
            Ok(superblock) => {
                // Unlike a tree block's `bytenr` (a chunk-mapped LOGICAL address
                // — see bd-5vb36), a superblock copy stores its own PHYSICAL byte
                // offset, so this comparison is well-founded: the primary holds
                // 65536, the 64 MiB mirror holds 67108864, and so on.
                if superblock.bytenr != target.byte_offset {
                    issues.push((
                        CorruptionKind::StructuralInvariant,
                        Severity::Critical,
                        format!(
                            "btrfs superblock bytenr {} does not match its own offset {}",
                            superblock.bytenr, target.byte_offset
                        ),
                    ));
                }
            }
            Err(err) => issues.push(parse_error_issue("btrfs superblock parse failed", &err)),
        }
        if let Err(err) = verify_btrfs_superblock_checksum(region) {
            issues.push(parse_error_issue("btrfs superblock checksum invalid", &err));
        }

        if issues.is_empty() {
            BlockVerdict::Clean
        } else {
            BlockVerdict::Corrupt(issues)
        }
    }
}

/// Validator for btrfs tree block metadata integrity.
///
/// Applies to blocks that look like btrfs tree blocks for the current
/// filesystem (`fsid` match). For candidate blocks, validates header geometry
/// and tree-block checksum.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsTreeBlockValidator {
    fsid: [u8; 16],
    csum_type: u16,
    /// Precomputed block numbers of the superblock and its mirrors. `validate`
    /// runs on EVERY scanned block and checked `BTRFS_SUPER_INFO_OFFSET /
    /// block_size` per call (a division, uninlinable under `dyn
    /// BlockValidator`); hoisting it into `new()` leaves the hot path a handful
    /// of block-number compares.
    superblock_blocks: [u64; BTRFS_SUPER_MIRROR_OFFSETS.len()],
}

/// Byte offsets btrfs reserves for the superblock and its mirrors.
///
/// A tree block never lives at one of these, so [`BtrfsTreeBlockValidator`]
/// skips them all. That matters to a *physical* scrub because a superblock
/// carries its `fsid` at `0x20..0x30` — exactly where a tree block does — so the
/// cheap `fsid` pre-check would otherwise misclassify a backup superblock as a
/// tree block and checksum the whole block instead of the 4096-byte superblock
/// region, yielding a spurious `ChecksumMismatch` (bd-scrub-btrfs-false-corrupt).
///
/// [`BtrfsSuperblockValidator`] instead validates each of these *as a
/// superblock*, but only where the filesystem's `total_bytes` actually spans the
/// offset — btrfs writes a mirror only when the device covers it (bd-xqzgy).
const BTRFS_SUPER_MIRROR_OFFSETS: [u64; 3] = [
    BTRFS_SUPER_INFO_OFFSET as u64, // 64 KiB — primary
    0x0400_0000,                    // 64 MiB
    0x40_0000_0000,                 // 256 GiB
];

impl BtrfsTreeBlockValidator {
    #[must_use]
    pub fn new(block_size: u32, fsid: [u8; 16], csum_type: u16) -> Self {
        let mut superblock_blocks = [0_u64; BTRFS_SUPER_MIRROR_OFFSETS.len()];
        if block_size != 0 {
            for (slot, offset) in superblock_blocks.iter_mut().zip(BTRFS_SUPER_MIRROR_OFFSETS) {
                *slot = offset / u64::from(block_size);
            }
        }
        Self {
            fsid,
            csum_type,
            superblock_blocks,
        }
    }
}

impl BlockValidator for BtrfsTreeBlockValidator {
    fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        // Skip the superblock and every mirror: btrfs reserves those offsets, so
        // no tree block lives there, and a superblock's `fsid` sits at the same
        // `0x20..0x30` a tree block's does — without this the `fsid` pre-check
        // below misclassifies a backup superblock as a tree block and checksums
        // the whole block instead of its 4096-byte superblock region.
        if self.superblock_blocks.contains(&block.0) {
            return BlockVerdict::Skip;
        }

        let slice = data.as_slice();

        // Cheap fsid pre-check before the full header parse. Only blocks whose
        // fsid (16 bytes at offset 0x20) matches THIS filesystem are btrfs
        // metadata candidates; the vast majority of a device (data + free
        // blocks) will not match, and on a data-heavy image the ZeroCheck ahead
        // of this validator early-exits at the first non-zero byte, leaving the
        // ~64-byte header copy + field parse as the dominant per-block cost. A
        // 16-byte fsid compare skips that parse for every non-metadata block.
        // Behaviour-identical: `parse_from_block` also rejects on fsid mismatch,
        // and a slice too short for the fsid (< 0x30) already parsed to Skip.
        if slice.get(0x20..0x30) != Some(&self.fsid[..]) {
            return BlockVerdict::Skip;
        }

        let Ok(header) = BtrfsHeader::parse_from_block(slice) else {
            return BlockVerdict::Skip;
        };

        // fsid already confirmed above; retained for defence in depth (the parse
        // re-reads the same bytes, so this is always true here).
        if header.fsid != self.fsid {
            return BlockVerdict::Skip;
        }

        // No `expected_bytenr`: `header.bytenr` is a btrfs **logical** address,
        // resolved to a physical offset through the chunk tree, whereas this is a
        // *physical* whole-image scrub that only knows `block * block_size`. The
        // two coincide only under an identity chunk map, so comparing them flags
        // every valid tree block on a real image (measured: a constant -8 MiB
        // delta across independent blocks on btr_571421.img — the chunk mapping,
        // not corruption). See bd-5vb36.
        //
        // Nothing is lost. The btrfs metadata checksum covers bytes `0x20..`,
        // which includes `bytenr` at `0x30..0x38`, so a *corrupted* bytenr still
        // fails `verify_btrfs_tree_block_checksum` below. The equality check was
        // only ever a *placement* check, and placement is unverifiable without
        // the chunk map. `header.validate` still enforces the map-independent
        // structural invariants (`level <= BTRFS_MAX_LEVEL`, `nritems` fits the
        // block).
        let mut issues = Vec::new();
        if let Err(err) = header.validate(slice.len(), None) {
            issues.push(parse_error_issue("btrfs tree header invalid", &err));
        }
        if let Err(err) = verify_btrfs_tree_block_checksum(slice, self.csum_type) {
            issues.push(parse_error_issue("btrfs tree block checksum invalid", &err));
        }

        if issues.is_empty() {
            BlockVerdict::Clean
        } else {
            BlockVerdict::Corrupt(issues)
        }
    }
}

fn parse_error_issue(prefix: &str, err: &ParseError) -> (CorruptionKind, Severity, String) {
    let (kind, severity) = match err {
        ParseError::InvalidMagic { .. } => (CorruptionKind::BadMagic, Severity::Critical),
        ParseError::InvalidField { field, .. }
            if field.contains("checksum") || field.contains("csum") =>
        {
            (CorruptionKind::ChecksumMismatch, Severity::Critical)
        }
        ParseError::InsufficientData { .. }
        | ParseError::InvalidField { .. }
        | ParseError::IntegerConversion { .. } => {
            (CorruptionKind::StructuralInvariant, Severity::Critical)
        }
    };
    (kind, severity, format!("{prefix}: {err}"))
}

/// A composite validator that runs multiple validators and merges their findings.
pub struct CompositeValidator {
    validators: Vec<Box<dyn BlockValidator>>,
}

impl CompositeValidator {
    #[must_use]
    pub fn new(validators: Vec<Box<dyn BlockValidator>>) -> Self {
        Self { validators }
    }
}

impl BlockValidator for CompositeValidator {
    fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        let mut all_issues = Vec::new();
        let mut any_checked = false;

        for v in &self.validators {
            match v.validate(block, data) {
                BlockVerdict::Clean => {
                    any_checked = true;
                }
                BlockVerdict::Corrupt(issues) => {
                    any_checked = true;
                    all_issues.extend(issues);
                }
                BlockVerdict::Skip => {}
            }
        }

        if all_issues.is_empty() {
            if any_checked {
                BlockVerdict::Clean
            } else {
                BlockVerdict::Skip
            }
        } else {
            BlockVerdict::Corrupt(all_issues)
        }
    }
}

/// Monomorphic btrfs scrub validator.
///
/// Fuses the canonical btrfs configuration (`BtrfsSuperblock` +
/// `BtrfsTreeBlock`) into one concrete type that **short-circuits the common
/// non-metadata block** instead of materialising two `BlockVerdict`s and merging
/// them like `CompositeValidator` does.
///
/// On a real image the vast majority of scanned blocks are non-superblock and
/// have a non-matching `fsid` — for those, both composite validators return
/// `Skip` with no real parse work, yet `CompositeValidator` still pays a
/// `dyn`-indirect call each, two enum returns, and a merge loop per block. This
/// type does the cheap gating inline (a 16-byte `fsid` compare gated on the
/// superblock block number) and returns `Clean` directly for that common case,
/// only falling through to the real superblock / tree-block validators for the
/// rare metadata candidate (the superblock block, or a block whose `fsid`
/// matches this filesystem).
///
/// Report-equivalent to the composite by construction: the fast path is taken
/// only when both metadata validators would have `Skip`ped, and `Skip` vs
/// `Clean` is indistinguishable to [`Scrubber::record_verdict`]. Every other
/// block runs the exact same sub-validator logic and merge.
///
/// It deliberately runs no blind all-zero check: unallocated space is
/// legitimately zeroed, and a whole-image scrub has no allocation map to tell
/// free blocks from wrongly-zeroed metadata (bd-scrub-btrfs-false-corrupt).
///
/// Measured ~3.5x faster than the equivalent `CompositeValidator` on a data-heavy
/// block set (bench `scrub_composite_mono`).
#[derive(Debug, Clone, Copy)]
pub struct BtrfsScrubValidator {
    superblock: BtrfsSuperblockValidator,
    tree_block: BtrfsTreeBlockValidator,
    /// Precomputed block numbers of the superblock and its mirrors (the blocks
    /// both metadata validators special-case). Used by the inline fast-path gate.
    superblock_blocks: [u64; BTRFS_SUPER_MIRROR_OFFSETS.len()],
    /// This filesystem's `fsid` — the tree-block validator's Skip key.
    fsid: [u8; 16],
}

impl BtrfsScrubValidator {
    /// `total_bytes` is the filesystem size from the superblock; it decides which
    /// superblock mirrors are expected to exist. See [`BtrfsSuperblockValidator::new`].
    #[must_use]
    pub fn new(block_size: u32, fsid: [u8; 16], csum_type: u16, total_bytes: u64) -> Self {
        let mut superblock_blocks = [0_u64; BTRFS_SUPER_MIRROR_OFFSETS.len()];
        if block_size != 0 {
            for (slot, offset) in superblock_blocks.iter_mut().zip(BTRFS_SUPER_MIRROR_OFFSETS) {
                *slot = offset / u64::from(block_size);
            }
        }
        Self {
            superblock: BtrfsSuperblockValidator::new(block_size, total_bytes),
            tree_block: BtrfsTreeBlockValidator::new(block_size, fsid, csum_type),
            superblock_blocks,
            fsid,
        }
    }

    /// Cold path: reproduce `CompositeValidator`'s run-both-and-merge exactly
    /// for the rare metadata-candidate block.
    #[cold]
    #[inline(never)]
    fn validate_metadata(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        let mut all_issues = Vec::new();
        for verdict in [
            self.superblock.validate(block, data),
            self.tree_block.validate(block, data),
        ] {
            match verdict {
                BlockVerdict::Clean | BlockVerdict::Skip => {}
                BlockVerdict::Corrupt(issues) => all_issues.extend(issues),
            }
        }
        if all_issues.is_empty() {
            BlockVerdict::Clean
        } else {
            BlockVerdict::Corrupt(all_issues)
        }
    }
}

impl BlockValidator for BtrfsScrubValidator {
    fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        let slice = data.as_slice();

        // Fast path: a block that is neither a superblock/mirror block nor an
        // fsid-matching tree-block candidate is `Skip`ped by BOTH metadata
        // validators → verdict Clean.
        // (`BtrfsSuperblockValidator` Skips when the block is not one of its
        // targets; `BtrfsTreeBlockValidator` Skips on any superblock mirror block
        // or on fsid mismatch — mirrored here without any dyn call or enum
        // materialisation.)
        //
        // The mirror blocks must be gated on the BLOCK NUMBER, not the fsid: a
        // superblock copy that was wrongly zeroed has no fsid to match, so an
        // fsid-only gate would short-circuit it to Clean and never validate it.
        //
        // This deliberately does NOT run a blind all-zero check. Unallocated
        // space is legitimately all zeroes, and a whole-image scrub has no
        // allocation map to distinguish "free" from "metadata that was wrongly
        // zeroed". Flagging every zero block made `blocks_corrupt` meaningless
        // (99.9% on a valid, kernel-mountable image) and poisoned the repair
        // autopilot's Beta posterior, which is fed `blocks_corrupt`. A zeroed
        // *superblock* is still caught below: it is reached by block number, and
        // `BtrfsSuperblockValidator` rejects it on the failed magic/parse.
        // `ZeroCheckValidator` remains available for scoped, known-metadata use.
        if !self.superblock_blocks.contains(&block.0)
            && slice.get(0x20..0x30) != Some(&self.fsid[..])
        {
            return BlockVerdict::Clean;
        }

        // Cold: metadata candidate — run the real validators and merge.
        self.validate_metadata(block, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_block::BlockBuf;
    use ffs_ondisk::{Ext4IncompatFeatures, Ext4RoCompatFeatures};
    use ffs_types::EXT4_SB_CHECKSUM_OFFSET;
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ── Test block device ───────────────────────────────────────────────

    #[derive(Debug)]
    struct MemBlockDevice {
        blocks: RwLock<HashMap<BlockNumber, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
    }

    impl MemBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: RwLock::new(HashMap::new()),
                block_size,
                block_count,
            }
        }

        fn write(&self, block: BlockNumber, data: Vec<u8>) {
            self.blocks.write().insert(block, data);
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            let bs = self.block_size as usize;
            let data = self
                .blocks
                .read()
                .get(&block)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; bs]);
            Ok(BlockBuf::new(data))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.blocks.write().insert(block, data.to_vec());
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

    /// Block device that returns I/O errors for specific blocks.
    #[derive(Debug)]
    struct FaultyBlockDevice {
        inner: MemBlockDevice,
        faulty_blocks: Vec<BlockNumber>,
    }

    impl FaultyBlockDevice {
        fn new(inner: MemBlockDevice, faulty_blocks: Vec<BlockNumber>) -> Self {
            Self {
                inner,
                faulty_blocks,
            }
        }
    }

    impl BlockDevice for FaultyBlockDevice {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if self.faulty_blocks.contains(&block) {
                Err(FfsError::Io(std::io::Error::other(format!(
                    "simulated I/O error at block {}",
                    block.0
                ))))
            } else {
                self.inner.read_block(cx, block)
            }
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

    #[derive(Debug)]
    struct BatchCountingBlockDevice {
        inner: MemBlockDevice,
        batch_reads: AtomicUsize,
        scalar_reads: AtomicUsize,
        fail_batches: bool,
    }

    impl BatchCountingBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                inner: MemBlockDevice::new(block_size, block_count),
                batch_reads: AtomicUsize::new(0),
                scalar_reads: AtomicUsize::new(0),
                fail_batches: false,
            }
        }

        fn with_failing_batches(mut self) -> Self {
            self.fail_batches = true;
            self
        }

        fn write(&self, block: BlockNumber, data: Vec<u8>) {
            self.inner.write(block, data);
        }

        fn batch_read_count(&self) -> usize {
            self.batch_reads.load(Ordering::Relaxed)
        }

        fn scalar_read_count(&self) -> usize {
            self.scalar_reads.load(Ordering::Relaxed)
        }
    }

    impl BlockDevice for BatchCountingBlockDevice {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.scalar_reads.fetch_add(1, Ordering::Relaxed);
            self.inner.read_block(cx, block)
        }

        fn supports_contiguous_reads(&self) -> bool {
            true
        }

        fn read_contiguous_blocks(
            &self,
            cx: &Cx,
            start: BlockNumber,
            bufs: &mut [BlockBuf],
        ) -> Result<()> {
            self.batch_reads.fetch_add(1, Ordering::Relaxed);
            if self.fail_batches {
                return Err(FfsError::Io(std::io::Error::other(
                    "simulated batch read failure",
                )));
            }
            for (idx, buf) in bufs.iter_mut().enumerate() {
                let delta = u64::try_from(idx)
                    .map_err(|_| FfsError::Format("batch index overflow".into()))?;
                let block = BlockNumber(
                    start
                        .0
                        .checked_add(delta)
                        .ok_or_else(|| FfsError::Format("batch range overflow".into()))?,
                );
                *buf = self.inner.read_block(cx, block)?;
            }
            Ok(())
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

    fn test_cx() -> Cx {
        Cx::for_testing()
    }

    // ── Test validator: CRC32C of block data stored in first 4 bytes ────

    /// A simple validator that checks a CRC32C stored in the first 4 bytes
    /// of each block against the computed CRC of the remaining bytes.
    struct Crc32cBlockValidator;

    impl BlockValidator for Crc32cBlockValidator {
        fn validate(&self, _block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
            let slice = data.as_slice();
            if slice.len() < 4 {
                return BlockVerdict::Skip;
            }
            let stored = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
            let computed = crc32c::crc32c(&slice[4..]);
            if stored == computed {
                BlockVerdict::Clean
            } else {
                BlockVerdict::Corrupt(vec![(
                    CorruptionKind::ChecksumMismatch,
                    Severity::Error,
                    format!("CRC32C expected {stored:#010x}, got {computed:#010x}"),
                )])
            }
        }
    }

    /// Create a block with CRC32C in first 4 bytes, payload in remainder.
    fn make_checksummed_block(block_size: u32, payload_byte: u8) -> Vec<u8> {
        let bs = block_size as usize;
        let mut block = vec![0_u8; bs];
        // Fill payload area (bytes 4..)
        for b in &mut block[4..] {
            *b = payload_byte;
        }
        // Compute and store CRC32C of payload
        let crc = crc32c::crc32c(&block[4..]);
        block[..4].copy_from_slice(&crc.to_le_bytes());
        block
    }

    fn make_valid_ext4_superblock_region() -> [u8; EXT4_SUPERBLOCK_SIZE] {
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes()); // magic
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // 4KiB blocks
        sb[0x1C..0x20].copy_from_slice(&2_u32.to_le_bytes()); // 4KiB clusters
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_count_lo
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
        sb[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_per_group
        sb[0x24..0x28].copy_from_slice(&32768_u32.to_le_bytes()); // clusters_per_group
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_per_group
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
        let incompat =
            (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0).to_le_bytes();
        sb[0x60..0x64].copy_from_slice(&incompat);
        sb[0x64..0x68].copy_from_slice(&Ext4RoCompatFeatures::METADATA_CSUM.0.to_le_bytes());
        sb[0x175] = 1; // checksum_type=crc32c

        let checksum = ffs_ondisk::ext4_chksum(!0_u32, &sb[..EXT4_SB_CHECKSUM_OFFSET]);
        sb[EXT4_SB_CHECKSUM_OFFSET..EXT4_SB_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&checksum.to_le_bytes());
        sb
    }

    /// Filesystem size of the 8-block × 16 KiB devices these tests build. Too
    /// small to span any superblock mirror, so only the primary is a target.
    const TEST_FS_BYTES: u64 = 8 * 16384;

    fn make_valid_btrfs_superblock_region() -> Vec<u8> {
        make_valid_btrfs_superblock_region_at(BTRFS_SUPER_INFO_OFFSET as u64)
    }

    /// A valid superblock copy that lives at `bytenr` (each btrfs superblock copy
    /// records its own physical byte offset).
    fn make_valid_btrfs_superblock_region_at(bytenr: u64) -> Vec<u8> {
        let mut sb = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        sb[0x40..0x48].copy_from_slice(&ffs_types::BTRFS_MAGIC.to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&1_u64.to_le_bytes()); // generation
        sb[0x50..0x58].copy_from_slice(&4096_u64.to_le_bytes()); // root
        sb[0x58..0x60].copy_from_slice(&8192_u64.to_le_bytes()); // chunk_root
        sb[0x70..0x78].copy_from_slice(&1_000_000_u64.to_le_bytes()); // total_bytes
        sb[0x78..0x80].copy_from_slice(&123_456_u64.to_le_bytes()); // bytes_used
        sb[0x80..0x88].copy_from_slice(&6_u64.to_le_bytes()); // root_dir_objectid
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes()); // num_devices
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes()); // sectorsize
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes()); // nodesize
        sb[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes()); // stripesize
        sb[0xC4..0xC6].copy_from_slice(&0_u16.to_le_bytes()); // csum_type=CRC32C
        let csum = crc32c::crc32c(&sb[0x20..BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&csum.to_le_bytes());
        sb
    }

    fn make_valid_btrfs_tree_block(block_size: usize, fsid: [u8; 16], bytenr: u64) -> Vec<u8> {
        let mut block = vec![0_u8; block_size];
        block[0x20..0x30].copy_from_slice(&fsid); // fsid
        block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes()); // bytenr
        block[0x50..0x58].copy_from_slice(&1_u64.to_le_bytes()); // generation
        block[0x58..0x60].copy_from_slice(&5_u64.to_le_bytes()); // owner (tree id)
        block[0x60..0x64].copy_from_slice(&0_u32.to_le_bytes()); // nritems
        block[0x64] = 0; // leaf level

        let csum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
        block
    }

    // ── Tests ───────────────────────────────────────────────────────────

    #[test]
    fn clean_device_produces_clean_report() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 16);
        // Write valid checksummed blocks
        for i in 0..16 {
            dev.write(BlockNumber(i), make_checksummed_block(4096, 0xAA));
        }

        let report = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert!(report.is_clean());
        assert_eq!(report.blocks_scanned, 16);
        assert_eq!(report.blocks_corrupt, 0);
        assert_eq!(report.blocks_io_error, 0);
    }

    #[test]
    fn bit_flip_detected_deterministically() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 16);
        // Write valid checksummed blocks
        for i in 0..16 {
            dev.write(BlockNumber(i), make_checksummed_block(4096, 0xBB));
        }
        // Inject bit flip in block 7 (flip a bit in the payload area)
        let mut corrupted = make_checksummed_block(4096, 0xBB);
        corrupted[100] ^= 0x01; // flip one bit
        dev.write(BlockNumber(7), corrupted);

        let report = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert!(!report.is_clean());
        assert_eq!(report.blocks_scanned, 16);
        assert_eq!(report.blocks_corrupt, 1);
        assert_eq!(report.findings.len(), 1);

        let finding = &report.findings[0];
        assert_eq!(finding.block, BlockNumber(7));
        assert_eq!(finding.kind, CorruptionKind::ChecksumMismatch);
        assert_eq!(finding.severity, Severity::Error);
        assert!(finding.detail.contains("CRC32C"));

        // Run again — deterministic
        let report2 = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_all(&cx)
            .expect("second scrub should succeed");
        assert_eq!(report2.findings.len(), 1);
        assert_eq!(report2.findings[0].block, BlockNumber(7));
    }

    #[test]
    fn multiple_corrupt_blocks() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 32);
        for i in 0..32 {
            dev.write(BlockNumber(i), make_checksummed_block(4096, 0xCC));
        }
        // Corrupt blocks 3, 15, 31
        for &b in &[3, 15, 31] {
            let mut data = make_checksummed_block(4096, 0xCC);
            data[200] ^= 0xFF;
            dev.write(BlockNumber(b), data);
        }

        let report = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert_eq!(report.blocks_corrupt, 3);
        assert_eq!(report.findings.len(), 3);
        let corrupt_blocks: Vec<u64> = report.findings.iter().map(|f| f.block.0).collect();
        assert_eq!(corrupt_blocks, vec![3, 15, 31]);
    }

    #[test]
    fn io_error_recorded_as_finding() {
        let cx = test_cx();
        let inner = MemBlockDevice::new(4096, 16);
        for i in 0..16 {
            inner.write(BlockNumber(i), make_checksummed_block(4096, 0xDD));
        }
        let dev = FaultyBlockDevice::new(inner, vec![BlockNumber(5), BlockNumber(10)]);

        let report = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert_eq!(report.blocks_scanned, 16);
        assert_eq!(report.blocks_corrupt, 2);
        assert_eq!(report.blocks_io_error, 2);
        let io_findings: Vec<&ScrubFinding> = report
            .findings
            .iter()
            .filter(|f| f.kind == CorruptionKind::IoError)
            .collect();
        assert_eq!(io_findings.len(), 2);
        assert_eq!(io_findings[0].block, BlockNumber(5));
        assert_eq!(io_findings[1].block, BlockNumber(10));
    }

    #[test]
    fn scrub_range_respects_bounds() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 100);
        // Write valid blocks
        for i in 0..100 {
            dev.write(BlockNumber(i), make_checksummed_block(4096, 0xEE));
        }
        // Corrupt block 50
        let mut bad = make_checksummed_block(4096, 0xEE);
        bad[500] ^= 0x80;
        dev.write(BlockNumber(50), bad);

        // Scrub only blocks 0..10 — should be clean
        let report = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_range(&cx, BlockNumber(0), 10)
            .expect("scrub should succeed");
        assert!(report.is_clean());
        assert_eq!(report.blocks_scanned, 10);

        // Scrub blocks 45..55 — should find block 50
        let report = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_range(&cx, BlockNumber(45), 10)
            .expect("scrub should succeed");
        assert_eq!(report.blocks_corrupt, 1);
        assert_eq!(report.findings[0].block, BlockNumber(50));
    }

    #[test]
    fn scrub_range_clamps_to_device_size() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 8);
        for i in 0..8 {
            dev.write(BlockNumber(i), make_checksummed_block(4096, 0xFF));
        }

        // Request more blocks than exist
        let report = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_range(&cx, BlockNumber(0), 1000)
            .expect("scrub should succeed");
        assert_eq!(report.blocks_scanned, 8);
        assert!(report.is_clean());
    }

    #[test]
    fn scrub_range_uses_contiguous_read_batches() {
        let cx = test_cx();
        let dev = BatchCountingBlockDevice::new(4096, 130);
        for i in 0..130 {
            dev.write(BlockNumber(i), make_checksummed_block(4096, 0x42));
        }

        let report = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert!(report.is_clean());
        assert_eq!(report.blocks_scanned, 130);
        assert_eq!(dev.batch_read_count(), 3);
        assert_eq!(dev.scalar_read_count(), 0);
    }

    #[test]
    fn scrub_range_falls_back_to_scalar_reads_after_batch_error() {
        let cx = test_cx();
        let dev = BatchCountingBlockDevice::new(4096, 4).with_failing_batches();
        for i in 0..4 {
            dev.write(BlockNumber(i), make_checksummed_block(4096, 0x24));
        }

        let report = Scrubber::new(&dev, &Crc32cBlockValidator)
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert!(report.is_clean());
        assert_eq!(report.blocks_scanned, 4);
        assert_eq!(dev.batch_read_count(), 1);
        assert_eq!(dev.scalar_read_count(), 4);
    }

    #[test]
    fn ext4_superblock_validator_accepts_valid_primary_superblock() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 8);
        let mut block0 = vec![0_u8; 4096];
        let sb = make_valid_ext4_superblock_region();
        block0[1024..2048].copy_from_slice(&sb);
        dev.write(BlockNumber(0), block0);

        let report = Scrubber::new(&dev, &Ext4SuperblockValidator::new(4096))
            .scrub_all(&cx)
            .expect("scrub should succeed");
        assert!(report.is_clean());
    }

    #[test]
    fn ext4_superblock_validator_detects_checksum_corruption() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 8);
        let mut block0 = vec![0_u8; 4096];
        let mut sb = make_valid_ext4_superblock_region();
        sb[0x50] ^= 0x01; // invalidate checksum without touching checksum field
        block0[1024..2048].copy_from_slice(&sb);
        dev.write(BlockNumber(0), block0);

        let report = Scrubber::new(&dev, &Ext4SuperblockValidator::new(4096))
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert_eq!(report.blocks_corrupt, 1);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.block, BlockNumber(0));
        assert_eq!(finding.kind, CorruptionKind::ChecksumMismatch);
    }

    #[test]
    fn ext4_superblock_validator_handles_1k_block_layout() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(1024, 4);
        let mut sb = make_valid_ext4_superblock_region();
        sb[0x18..0x1C].copy_from_slice(&0_u32.to_le_bytes()); // log_block_size=0 -> 1KiB
        sb[0x1C..0x20].copy_from_slice(&0_u32.to_le_bytes()); // log_cluster_size=0 -> 1KiB
        sb[0x14..0x18].copy_from_slice(&1_u32.to_le_bytes()); // first_data_block=1 for 1KiB
        sb[0x20..0x24].copy_from_slice(&8192_u32.to_le_bytes()); // blocks_per_group
        sb[0x24..0x28].copy_from_slice(&8192_u32.to_le_bytes()); // clusters_per_group
        sb[0x04..0x08].copy_from_slice(&8193_u32.to_le_bytes()); // blocks_count_lo
        let checksum = ffs_ondisk::ext4_chksum(!0_u32, &sb[..EXT4_SB_CHECKSUM_OFFSET]);
        sb[EXT4_SB_CHECKSUM_OFFSET..EXT4_SB_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&checksum.to_le_bytes());
        dev.write(BlockNumber(1), sb.to_vec());

        let report = Scrubber::new(&dev, &Ext4SuperblockValidator::new(1024))
            .scrub_all(&cx)
            .expect("scrub should succeed");
        assert!(
            report.is_clean(),
            "unexpected findings: {:?}",
            report.findings
        );
    }

    #[test]
    fn btrfs_superblock_validator_accepts_valid_superblock() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(16384, 8);
        let mut block4 = vec![0_u8; 16384];
        let sb = make_valid_btrfs_superblock_region();
        block4[..BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);
        dev.write(BlockNumber(4), block4);

        let report = Scrubber::new(&dev, &BtrfsSuperblockValidator::new(16384, TEST_FS_BYTES))
            .scrub_all(&cx)
            .expect("scrub should succeed");
        assert!(report.is_clean());
    }

    #[test]
    fn btrfs_superblock_validator_detects_checksum_corruption() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(16384, 8);
        let mut block4 = vec![0_u8; 16384];
        let mut sb = make_valid_btrfs_superblock_region();
        sb[0x50] ^= 0x01;
        block4[..BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);
        dev.write(BlockNumber(4), block4);

        let report = Scrubber::new(&dev, &BtrfsSuperblockValidator::new(16384, TEST_FS_BYTES))
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert_eq!(report.blocks_corrupt, 1);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.block, BlockNumber(4));
        assert_eq!(finding.kind, CorruptionKind::ChecksumMismatch);
    }

    #[test]
    fn btrfs_tree_block_validator_accepts_valid_tree_block() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(16384, 8);

        let fsid = [0x11_u8; 16];
        let mut sb = make_valid_btrfs_superblock_region();
        sb[0x20..0x30].copy_from_slice(&fsid);
        let sb_csum = crc32c::crc32c(&sb[0x20..BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&sb_csum.to_le_bytes());

        let mut block4 = vec![0_u8; 16384];
        block4[..BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);
        dev.write(BlockNumber(4), block4);

        let block5_bytenr = 5_u64 * 16384_u64;
        let tree_block = make_valid_btrfs_tree_block(16384, fsid, block5_bytenr);
        dev.write(BlockNumber(5), tree_block);

        let report = Scrubber::new(
            &dev,
            &CompositeValidator::new(vec![
                Box::new(BtrfsSuperblockValidator::new(16384, TEST_FS_BYTES)),
                Box::new(BtrfsTreeBlockValidator::new(16384, fsid, 0)),
            ]),
        )
        .scrub_all(&cx)
        .expect("scrub should succeed");
        assert!(
            report.is_clean(),
            "unexpected findings: {:?}",
            report.findings
        );
    }

    #[test]
    fn btrfs_scrub_validator_matches_composite_on_fast_and_metadata_paths() {
        let fsid = [0x11_u8; 16];
        let dev = MemBlockDevice::new(16384, 8);

        let mut foreign_data = vec![0x55_u8; 16384];
        foreign_data[0x20..0x30].copy_from_slice(&[0x22_u8; 16]);
        dev.write(BlockNumber(0), foreign_data);

        // Block 1 stays all zeroes: unallocated space, must produce no finding.
        // Block 4 stays all zeroes too, but is the btrfs superblock block;
        // the optimized validator must still run metadata validators there.

        let block5_bytenr = 5_u64 * 16384_u64;
        dev.write(
            BlockNumber(5),
            make_valid_btrfs_tree_block(16384, fsid, block5_bytenr),
        );

        let block6_bytenr = 6_u64 * 16384_u64;
        let mut corrupt_tree = make_valid_btrfs_tree_block(16384, fsid, block6_bytenr);
        corrupt_tree[0x80] ^= 0x01;
        dev.write(BlockNumber(6), corrupt_tree);

        let composite = CompositeValidator::new(vec![
            Box::new(BtrfsSuperblockValidator::new(16384, TEST_FS_BYTES)),
            Box::new(BtrfsTreeBlockValidator::new(16384, fsid, 0)),
        ]);
        let optimized = BtrfsScrubValidator::new(16384, fsid, 0, TEST_FS_BYTES);

        let composite_report = Scrubber::new(&dev, &composite)
            .scrub_all(&test_cx())
            .expect("composite scrub should succeed");
        let optimized_report = Scrubber::new(&dev, &optimized)
            .scrub_all(&test_cx())
            .expect("optimized scrub should succeed");

        let signature = |report: &ScrubReport| {
            report
                .findings
                .iter()
                .map(|finding| (finding.block, finding.kind, finding.severity))
                .collect::<Vec<_>>()
        };

        assert_eq!(
            optimized_report.blocks_scanned,
            composite_report.blocks_scanned
        );
        assert_eq!(
            optimized_report.blocks_corrupt,
            composite_report.blocks_corrupt
        );
        assert_eq!(signature(&optimized_report), signature(&composite_report));
        assert!(
            optimized_report
                .findings
                .iter()
                .any(|finding| finding.block == BlockNumber(4)
                    && finding.kind != CorruptionKind::UnexpectedZeroes),
            "zeroed superblock candidate must retain metadata-validator findings"
        );
    }

    #[test]
    fn btrfs_tree_block_validator_detects_checksum_corruption() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(16384, 8);
        let fsid = [0x22_u8; 16];

        let block5_bytenr = 5_u64 * 16384_u64;
        let mut tree_block = make_valid_btrfs_tree_block(16384, fsid, block5_bytenr);
        tree_block[0x80] ^= 0x01;
        dev.write(BlockNumber(5), tree_block);

        let report = Scrubber::new(&dev, &BtrfsTreeBlockValidator::new(16384, fsid, 0))
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert_eq!(report.blocks_corrupt, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].block, BlockNumber(5));
        assert_eq!(report.findings[0].kind, CorruptionKind::ChecksumMismatch);
    }

    #[test]
    fn btrfs_tree_block_validator_skips_foreign_fsid_blocks() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(16384, 8);

        let block5_bytenr = 5_u64 * 16384_u64;
        let mut tree_block = make_valid_btrfs_tree_block(16384, [0x33_u8; 16], block5_bytenr);
        tree_block[0x80] ^= 0x01; // invalidate checksum, but fsid won't match validator
        dev.write(BlockNumber(5), tree_block);

        let report = Scrubber::new(&dev, &BtrfsTreeBlockValidator::new(16384, [0x44_u8; 16], 0))
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert!(report.is_clean());
    }

    #[test]
    fn btrfs_scrub_validator_matches_composite_on_representative_blocks() {
        let fsid = [0x55_u8; 16];
        let block_size = 16384_u32;
        let block_size_usize = block_size as usize;
        let superblock = BlockNumber(4);
        let tree = BlockNumber(5);
        let foreign = BlockNumber(6);
        let zero = BlockNumber(7);

        let mut sb = make_valid_btrfs_superblock_region();
        sb[0x20..0x30].copy_from_slice(&fsid);
        let sb_csum = crc32c::crc32c(&sb[0x20..BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&sb_csum.to_le_bytes());
        let mut sb_block = vec![0_u8; block_size_usize];
        sb_block[..BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);

        let tree_bytenr = tree.0 * u64::from(block_size);
        let tree_block = make_valid_btrfs_tree_block(block_size_usize, fsid, tree_bytenr);

        let mut foreign_block = make_valid_btrfs_tree_block(
            block_size_usize,
            [0x66_u8; 16],
            foreign.0 * u64::from(block_size),
        );
        foreign_block[0x80] ^= 0x01;

        let zero_block = vec![0_u8; block_size_usize];

        let composite = CompositeValidator::new(vec![
            Box::new(BtrfsSuperblockValidator::new(block_size, TEST_FS_BYTES)),
            Box::new(BtrfsTreeBlockValidator::new(block_size, fsid, 0)),
        ]);
        let mono = BtrfsScrubValidator::new(block_size, fsid, 0, TEST_FS_BYTES);

        for (block, data) in [
            (superblock, sb_block),
            (tree, tree_block),
            (foreign, foreign_block),
            (zero, zero_block),
        ] {
            let buf = BlockBuf::new(data);
            let composite_verdict = composite.validate(block, &buf);
            let mono_verdict = mono.validate(block, &buf);
            assert_eq!(
                verdict_signature(&composite_verdict),
                verdict_signature(&mono_verdict),
                "concrete btrfs scrub validator must match composite at block {block}",
            );
        }
    }

    /// Build an 8-block btrfs device: a valid superblock at block 4 (the
    /// `BTRFS_SUPER_INFO_OFFSET / 16384` block) and a valid tree block at 5.
    /// Blocks 0-3, 6, 7 stay all-zero — i.e. unallocated free space.
    fn sparse_valid_btrfs_device(block_size: u32, fsid: [u8; 16]) -> MemBlockDevice {
        let block_size_usize = block_size as usize;
        let dev = MemBlockDevice::new(block_size, 8);

        let mut sb = make_valid_btrfs_superblock_region();
        sb[0x20..0x30].copy_from_slice(&fsid);
        let sb_csum = crc32c::crc32c(&sb[0x20..BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&sb_csum.to_le_bytes());
        let mut sb_block = vec![0_u8; block_size_usize];
        sb_block[..BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);
        dev.write(BlockNumber(4), sb_block);

        dev.write(
            BlockNumber(5),
            make_valid_btrfs_tree_block(block_size_usize, fsid, 5 * u64::from(block_size)),
        );
        dev
    }

    /// Regression (bd-scrub-btrfs-false-corrupt): a btrfs backup superblock must
    /// not be validated as a tree block. It carries its `fsid` at `0x20..0x30`,
    /// exactly where a tree block does, so the cheap `fsid` pre-check used to
    /// misclassify it and checksum the whole 16 KiB block instead of the
    /// 4096-byte superblock region — a spurious `ChecksumMismatch` on block 4096
    /// (the 64 MiB mirror) of every real btrfs image.
    #[test]
    fn btrfs_tree_block_validator_skips_superblock_mirrors() {
        let fsid = [0x55_u8; 16];
        let validator = BtrfsTreeBlockValidator::new(16384, fsid, 0);

        // Shaped like a real backup superblock: fsid at 0x20, btrfs magic at 0x40.
        let mut block = vec![0_u8; 16384];
        block[0x20..0x30].copy_from_slice(&fsid);
        block[0x40..0x48].copy_from_slice(b"_BHRfS_M");
        let buf = BlockBuf::new(block);

        // 64 KiB / 64 MiB / 256 GiB mirrors at a 16 KiB block size.
        for mirror_block in [4_u64, 4096, 16_777_216] {
            assert!(
                matches!(
                    validator.validate(BlockNumber(mirror_block), &buf),
                    BlockVerdict::Skip
                ),
                "superblock mirror at block {mirror_block} must be skipped by the tree-block validator",
            );
        }
    }

    /// A 16 KiB block holding a superblock copy for `bytenr` at its start.
    fn mirror_block_at(bytenr: u64) -> Vec<u8> {
        let mut block = vec![0_u8; 16384];
        block[..BTRFS_SUPER_INFO_SIZE]
            .copy_from_slice(&make_valid_btrfs_superblock_region_at(bytenr));
        block
    }

    /// Issues carried by a `Corrupt` verdict; empty for `Clean`/`Skip`, so callers
    /// assert non-emptiness with a message instead of panicking.
    fn corrupt_issues(verdict: BlockVerdict) -> Vec<(CorruptionKind, Severity, String)> {
        match verdict {
            BlockVerdict::Corrupt(issues) => issues,
            BlockVerdict::Clean | BlockVerdict::Skip => Vec::new(),
        }
    }

    /// A filesystem large enough to span the 64 MiB mirror but not the 256 GiB one.
    const ONE_GIB: u64 = 1 << 30;
    /// Block number of the 64 MiB mirror at a 16 KiB block size.
    const MIRROR_64MIB_BLOCK: u64 = 0x0400_0000 / 16384;

    /// bd-xqzgy: a valid backup superblock is now VALIDATED as a superblock
    /// (previously it was skipped outright, so a corrupt one went unreported).
    #[test]
    fn btrfs_superblock_validator_accepts_valid_backup_mirror() {
        let validator = BtrfsSuperblockValidator::new(16384, ONE_GIB);
        let buf = BlockBuf::new(mirror_block_at(0x0400_0000));

        assert!(matches!(
            validator.validate(BlockNumber(MIRROR_64MIB_BLOCK), &buf),
            BlockVerdict::Clean
        ));
    }

    /// bd-xqzgy: the detection the skip was costing us — a corrupt backup
    /// superblock is now reported instead of silently ignored.
    #[test]
    fn btrfs_superblock_validator_detects_corrupt_backup_mirror() {
        let validator = BtrfsSuperblockValidator::new(16384, ONE_GIB);

        let mut block = mirror_block_at(0x0400_0000);
        block[0x100] ^= 0x01; // inside the checksummed region
        let buf = BlockBuf::new(block);

        let issues = corrupt_issues(validator.validate(BlockNumber(MIRROR_64MIB_BLOCK), &buf));
        assert!(
            !issues.is_empty(),
            "a corrupt backup superblock must be reported"
        );
        assert!(
            issues
                .iter()
                .any(|(kind, _, _)| *kind == CorruptionKind::ChecksumMismatch)
        );
    }

    /// bd-xqzgy: a superblock copy records its OWN physical offset in `bytenr`
    /// (unlike a tree block's chunk-mapped logical bytenr, see bd-5vb36), so a
    /// mirror carrying the primary's bytenr is structurally wrong. Checksum is
    /// recomputed, so only the bytenr check can catch this.
    #[test]
    fn btrfs_superblock_validator_detects_mirror_with_wrong_bytenr() {
        let validator = BtrfsSuperblockValidator::new(16384, ONE_GIB);
        // A well-formed, correctly-checksummed superblock — but it claims to live
        // at the primary offset while sitting at the 64 MiB mirror.
        let buf = BlockBuf::new(mirror_block_at(BTRFS_SUPER_INFO_OFFSET as u64));

        let issues = corrupt_issues(validator.validate(BlockNumber(MIRROR_64MIB_BLOCK), &buf));
        assert!(
            !issues.is_empty(),
            "a mirror whose bytenr is not its own offset must be reported"
        );
        assert!(
            issues
                .iter()
                .any(|(kind, _, _)| *kind == CorruptionKind::StructuralInvariant)
        );
    }

    /// bd-xqzgy: btrfs writes a mirror only where the filesystem spans it, so a
    /// mirror offset beyond `total_bytes` is legitimately absent and must be
    /// skipped — not reported. (Measured: `btr2_572550.img` is a 2 GiB file whose
    /// 64 MiB region is all-zero because it holds no filesystem at all.)
    #[test]
    fn btrfs_superblock_validator_skips_mirror_outside_filesystem() {
        // 32 MiB filesystem: the 64 MiB mirror was never written.
        let validator = BtrfsSuperblockValidator::new(16384, 32 * 1024 * 1024);
        let buf = BlockBuf::new(vec![0_u8; 16384]);

        assert!(matches!(
            validator.validate(BlockNumber(MIRROR_64MIB_BLOCK), &buf),
            BlockVerdict::Skip
        ));
    }

    /// The fused validator must reach a wrongly-ZEROED mirror. Its `fsid` is
    /// zeroes, so an fsid-only fast-path gate would short-circuit it to `Clean`
    /// and never validate it; the gate keys on the block number instead.
    #[test]
    fn btrfs_scrub_validator_reports_zeroed_backup_mirror() {
        let fsid = [0x55_u8; 16];
        let validator = BtrfsScrubValidator::new(16384, fsid, 0, ONE_GIB);
        let buf = BlockBuf::new(vec![0_u8; 16384]); // mirror expected, but zeroed

        let issues = corrupt_issues(validator.validate(BlockNumber(MIRROR_64MIB_BLOCK), &buf));
        assert!(
            !issues.is_empty(),
            "an expected-but-zeroed backup superblock must be reported"
        );
        assert!(
            issues
                .iter()
                .all(|(_, severity, _)| *severity >= Severity::Error)
        );
    }

    /// Regression (bd-5vb36): a valid tree block whose logical `bytenr` differs
    /// from its physical offset must scrub Clean. That is the *normal* case — the
    /// chunk tree maps logical→physical — yet the validator used to compare
    /// `header.bytenr` against `block * block_size` and flag every such block
    /// `StructuralInvariant`/Critical.
    #[test]
    fn btrfs_tree_block_valid_under_non_identity_chunk_map() {
        let fsid = [0x55_u8; 16];
        let dev = MemBlockDevice::new(16384, 8);

        // Physical block 5, but the chunk map places it 8 MiB up in logical space
        // (the exact shape measured on btr_571421.img).
        let logical = 5 * 16384_u64 + 8 * 1024 * 1024;
        dev.write(
            BlockNumber(5),
            make_valid_btrfs_tree_block(16384, fsid, logical),
        );

        let report = Scrubber::new(&dev, &BtrfsTreeBlockValidator::new(16384, fsid, 0))
            .scrub_all(&test_cx())
            .expect("scrub should succeed");

        assert_eq!(
            report.blocks_corrupt, 0,
            "a chunk-mapped tree block is not corruption: {:?}",
            report.findings
        );
    }

    /// The counterpart guarantee for bd-5vb36: dropping the `bytenr` equality
    /// check loses no detection, because the metadata checksum covers bytes
    /// `0x20..` — which includes `bytenr` at `0x30..0x38`. A tampered `bytenr`
    /// therefore still fails the checksum.
    #[test]
    fn btrfs_tree_block_corrupted_bytenr_is_caught_by_checksum() {
        let fsid = [0x55_u8; 16];
        let dev = MemBlockDevice::new(16384, 8);

        let mut block = make_valid_btrfs_tree_block(16384, fsid, 5 * 16384);
        block[0x30] ^= 0x01; // flip a bytenr byte AFTER the checksum was computed
        dev.write(BlockNumber(5), block);

        let report = Scrubber::new(&dev, &BtrfsTreeBlockValidator::new(16384, fsid, 0))
            .scrub_all(&test_cx())
            .expect("scrub should succeed");

        assert_eq!(report.blocks_corrupt, 1);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == CorruptionKind::ChecksumMismatch),
            "a tampered bytenr must still be caught by the checksum: {:?}",
            report.findings
        );
    }

    /// Regression (bd-scrub-btrfs-false-corrupt): a valid image whose free space
    /// is all zeroes must scrub clean. Before the fix a blind `ZeroCheck` flagged
    /// every unallocated block, reporting 99.9% of a healthy image as "corrupt"
    /// and poisoning the repair autopilot's posterior (fed `blocks_corrupt`).
    #[test]
    fn btrfs_scrub_does_not_flag_unallocated_zero_blocks() {
        let fsid = [0x55_u8; 16];
        let dev = sparse_valid_btrfs_device(16384, fsid);

        let report = Scrubber::new(
            &dev,
            &BtrfsScrubValidator::new(16384, fsid, 0, TEST_FS_BYTES),
        )
        .scrub_all(&test_cx())
        .expect("scrub should succeed");

        assert_eq!(report.blocks_scanned, 8);
        assert_eq!(
            report.blocks_corrupt, 0,
            "unallocated zero blocks must not be reported as corruption: {:?}",
            report.findings
        );
        assert!(report.is_clean(), "findings: {:?}", report.findings);
    }

    /// The counterpart guarantee: dropping the blind `ZeroCheck` must not lose
    /// the one detection it legitimately provided. A zeroed superblock is still
    /// caught, because `BtrfsSuperblockValidator` rejects the failed magic/parse.
    #[test]
    fn btrfs_scrub_still_detects_zeroed_superblock() {
        let fsid = [0x55_u8; 16];
        // Every block all-zero, including block 4 (the superblock block).
        let dev = MemBlockDevice::new(16384, 8);

        let report = Scrubber::new(
            &dev,
            &BtrfsScrubValidator::new(16384, fsid, 0, TEST_FS_BYTES),
        )
        .scrub_all(&test_cx())
        .expect("scrub should succeed");

        assert_eq!(
            report.blocks_corrupt, 1,
            "exactly the zeroed superblock block is corrupt: {:?}",
            report.findings
        );
        assert!(!report.findings.is_empty());
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.block == BlockNumber(4) && f.severity >= Severity::Error),
            "zeroed superblock must be reported at error+ severity on block 4: {:?}",
            report.findings
        );
    }

    /// Signature at the granularity the scrub report actually observes.
    ///
    /// `Scrubber::record_verdict` treats `Skip` and `Clean` identically (neither
    /// yields a finding nor increments `blocks_corrupt`), so they collapse to the
    /// same signature here. They differ only in whether *any* validator claimed
    /// the block: the fused `BtrfsScrubValidator` answers `Clean` for a block it
    /// short-circuits, while `CompositeValidator` answers `Skip` when every
    /// member skipped. That distinction is invisible to the report.
    fn verdict_signature(verdict: &BlockVerdict) -> (u8, Vec<(CorruptionKind, Severity)>) {
        match verdict {
            BlockVerdict::Skip | BlockVerdict::Clean => (0, Vec::new()),
            BlockVerdict::Corrupt(issues) => (
                1,
                issues
                    .iter()
                    .map(|(kind, severity, _)| (*kind, *severity))
                    .collect(),
            ),
        }
    }

    #[test]
    fn zero_check_validator_detects_zeroed_blocks() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 4);
        // Block 0 and 2 have data, block 1 and 3 are all-zeroes (default)
        dev.write(BlockNumber(0), vec![1; 4096]);
        dev.write(BlockNumber(2), vec![2; 4096]);

        let report = Scrubber::new(&dev, &ZeroCheckValidator)
            .scrub_all(&cx)
            .expect("scrub should succeed");

        assert_eq!(report.blocks_corrupt, 2);
        let zeroed: Vec<u64> = report.findings.iter().map(|f| f.block.0).collect();
        assert_eq!(zeroed, vec![1, 3]);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.kind == CorruptionKind::UnexpectedZeroes)
        );
    }

    #[test]
    fn composite_validator_merges_findings() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 4);
        // Block 0: all zeroes (caught by zero-check) + bad CRC (caught by crc32c check)
        // Block 1: valid checksummed, non-zero (clean for both)
        dev.write(BlockNumber(1), make_checksummed_block(4096, 0x42));

        let composite = CompositeValidator::new(vec![
            Box::new(ZeroCheckValidator),
            Box::new(Crc32cBlockValidator),
        ]);

        let report = Scrubber::new(&dev, &composite)
            .scrub_all(&cx)
            .expect("scrub should succeed");

        // Block 0 should have findings from both validators (zeroed + bad crc)
        let block_0_findings: Vec<&ScrubFinding> = report
            .findings
            .iter()
            .filter(|f| f.block == BlockNumber(0))
            .collect();
        assert!(block_0_findings.len() >= 2);

        let kinds: Vec<CorruptionKind> = block_0_findings.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&CorruptionKind::UnexpectedZeroes));
        assert!(kinds.contains(&CorruptionKind::ChecksumMismatch));
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn count_at_severity_filters_correctly() {
        let report = ScrubReport {
            findings: vec![
                ScrubFinding {
                    block: BlockNumber(0),
                    kind: CorruptionKind::UnexpectedZeroes,
                    severity: Severity::Warning,
                    detail: "zeroed".into(),
                },
                ScrubFinding {
                    block: BlockNumber(1),
                    kind: CorruptionKind::ChecksumMismatch,
                    severity: Severity::Error,
                    detail: "bad crc".into(),
                },
                ScrubFinding {
                    block: BlockNumber(2),
                    kind: CorruptionKind::BadMagic,
                    severity: Severity::Critical,
                    detail: "bad magic".into(),
                },
            ],
            blocks_scanned: 10,
            blocks_corrupt: 3,
            blocks_io_error: 0,
        };

        assert_eq!(report.count_at_severity(Severity::Info), 3);
        assert_eq!(report.count_at_severity(Severity::Warning), 3);
        assert_eq!(report.count_at_severity(Severity::Error), 2);
        assert_eq!(report.count_at_severity(Severity::Critical), 1);
    }

    #[test]
    fn display_formatting() {
        let finding = ScrubFinding {
            block: BlockNumber(42),
            kind: CorruptionKind::ChecksumMismatch,
            severity: Severity::Error,
            detail: "CRC32C expected 0xDEAD, got 0xBEEF".into(),
        };
        assert_eq!(
            finding.to_string(),
            "block 42 [error] checksum_mismatch: CRC32C expected 0xDEAD, got 0xBEEF"
        );

        let report = ScrubReport {
            findings: vec![finding],
            blocks_scanned: 100,
            blocks_corrupt: 1,
            blocks_io_error: 0,
        };
        assert_eq!(
            report.to_string(),
            "scanned 100 blocks: 1 corrupt, 0 io_errors, 1 findings"
        );
    }

    #[test]
    fn scrub_report_human_output_snapshot() {
        use std::fmt::Write as _;

        let report = ScrubReport {
            findings: vec![
                ScrubFinding {
                    block: BlockNumber(7),
                    kind: CorruptionKind::ChecksumMismatch,
                    severity: Severity::Error,
                    detail: "CRC32C expected 0x5a17beef, got 0x1cedcafe".into(),
                },
                ScrubFinding {
                    block: BlockNumber(9),
                    kind: CorruptionKind::UnexpectedZeroes,
                    severity: Severity::Warning,
                    detail: "block payload is entirely zeroed".into(),
                },
                ScrubFinding {
                    block: BlockNumber(12),
                    kind: CorruptionKind::BadMagic,
                    severity: Severity::Critical,
                    detail: "expected ext4 magic 0xef53".into(),
                },
            ],
            blocks_scanned: 64,
            blocks_corrupt: 3,
            blocks_io_error: 1,
        };

        let mut rendered = report.to_string();
        for finding in &report.findings {
            writeln!(&mut rendered).expect("write to String cannot fail");
            write!(&mut rendered, "{finding}").expect("write to String cannot fail");
        }

        insta::assert_snapshot!("scrub_report_human_output", rendered);
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn corruption_kind_display_all_variants() {
        assert_eq!(
            CorruptionKind::ChecksumMismatch.to_string(),
            "checksum_mismatch"
        );
        assert_eq!(
            CorruptionKind::StructuralInvariant.to_string(),
            "structural_invariant"
        );
        assert_eq!(CorruptionKind::BadMagic.to_string(), "bad_magic");
        assert_eq!(
            CorruptionKind::UnexpectedZeroes.to_string(),
            "unexpected_zeroes"
        );
        assert_eq!(CorruptionKind::IoError.to_string(), "io_error");
    }

    #[test]
    fn severity_display_all_variants() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Error.to_string(), "error");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn scrub_report_empty_is_clean() {
        let report = ScrubReport {
            findings: vec![],
            blocks_scanned: 0,
            blocks_corrupt: 0,
            blocks_io_error: 0,
        };
        assert!(report.is_clean());
        assert_eq!(report.count_at_severity(Severity::Info), 0);
    }

    #[test]
    fn corruption_kind_hash_consistent() {
        use std::collections::HashSet;
        let set: HashSet<CorruptionKind> = [
            CorruptionKind::ChecksumMismatch,
            CorruptionKind::ChecksumMismatch,
            CorruptionKind::BadMagic,
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn severity_hash_consistent() {
        use std::collections::HashSet;
        let set: HashSet<Severity> = [Severity::Info, Severity::Info, Severity::Critical]
            .into_iter()
            .collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn scrub_finding_display_includes_all_parts() {
        let finding = ScrubFinding {
            block: BlockNumber(999),
            kind: CorruptionKind::BadMagic,
            severity: Severity::Critical,
            detail: "expected 0xEF53".into(),
        };
        assert_eq!(
            finding.to_string(),
            "block 999 [critical] bad_magic: expected 0xEF53"
        );
    }

    #[test]
    fn scrub_report_display_with_io_errors() {
        let report = ScrubReport {
            findings: vec![],
            blocks_scanned: 50,
            blocks_corrupt: 0,
            blocks_io_error: 3,
        };
        assert_eq!(
            report.to_string(),
            "scanned 50 blocks: 0 corrupt, 3 io_errors, 0 findings"
        );
    }

    #[test]
    fn severity_total_ordering_equality() {
        assert_eq!(
            Severity::Info.cmp(&Severity::Info),
            std::cmp::Ordering::Equal
        );
        assert!(Severity::Critical >= Severity::Info);
    }

    #[test]
    fn corruption_kind_copy_semantics() {
        let a = CorruptionKind::IoError;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    struct AlwaysCorruptValidator;
    impl BlockValidator for AlwaysCorruptValidator {
        fn validate(&self, _block: BlockNumber, _data: &BlockBuf) -> BlockVerdict {
            BlockVerdict::Corrupt(vec![(
                CorruptionKind::StructuralInvariant,
                Severity::Error,
                "always corrupt".to_owned(),
            )])
        }
    }

    #[test]
    fn scrub_does_not_panic_on_corrupted_data() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096, 8);

        // Write various garbage patterns
        dev.write(BlockNumber(0), vec![0xFF; 4096]); // all 0xFF
        dev.write(BlockNumber(1), vec![0x00; 4096]); // all zeroes
        dev.write(BlockNumber(2), vec![0xDE, 0xAD]); // short (but MemBlockDevice pads)
        dev.write(BlockNumber(3), (0..=255).cycle().take(4096).collect()); // ramp pattern

        let report = Scrubber::new(&dev, &AlwaysCorruptValidator)
            .scrub_all(&cx)
            .expect("scrub must not panic");
        assert_eq!(report.blocks_scanned, 8);
        assert_eq!(report.blocks_corrupt, 8);
        assert_eq!(report.findings.len(), 8);
    }
}
