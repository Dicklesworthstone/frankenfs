#![forbid(unsafe_code)]

pub mod compression;
pub mod crash_matrix;
pub mod demo;
pub mod persist;
pub mod rcu;
pub mod sharded;
pub mod wal;
pub mod wal_replay;
pub mod wal_writer;

use asupersync::Cx;
pub use compression::{CompressionAlgo, CompressionPolicy};
use compression::{CompressionStats, VersionData};
use crossbeam_epoch as epoch;
use ffs_block::{BlockBuf, BlockDevice, FlushPinToken, MvccFlushLifecycle};
use ffs_error::{FfsError, Result as FfsResult};
pub use ffs_repair::evidence::TxnAbortReason;
use ffs_repair::evidence::{
    ContentionSampleDetail, EvidenceRecord, MergeAppliedDetail, MergeProofCheckedDetail,
    MergeRejectedDetail, PolicySwitchedDetail, SerializationConflictDetail,
    TransactionCommitDetail, TxnAbortedDetail,
};
use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use parking_lot::{Mutex, RwLock};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use smallvec::{SmallVec, smallvec};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

fn saturating_increment_atomic(counter: &AtomicU64, ordering: Ordering) -> u64 {
    loop {
        if let Ok(previous) = counter.fetch_update(ordering, Ordering::Relaxed, |current| {
            Some(current.saturating_add(1))
        }) {
            return previous.saturating_add(1);
        }
        std::hint::spin_loop();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVersion {
    pub block: BlockNumber,
    pub commit_seq: CommitSeq,
    pub writer: TxnId,
    pub data: VersionData,
}

impl BlockVersion {
    /// Convenience: get inline bytes if this is a Full version.
    #[must_use]
    pub fn bytes_inline(&self) -> Option<&[u8]> {
        match &self.data {
            VersionData::Full(bytes) => Some(bytes.as_slice()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalBlockVersion {
    pub logical: BlockNumber,
    pub physical: BlockNumber,
    pub commit_seq: CommitSeq,
    pub writer: TxnId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct CowRewriteIntent {
    old_physical: Option<BlockNumber>,
    new_physical: BlockNumber,
}

pub trait CowAllocator {
    /// Allocate a new physical block for a COW write.
    fn alloc_cow(&self, hint: Option<BlockNumber>, cx: &Cx) -> FfsResult<BlockNumber>;

    /// Mark a block as deferrable until the given commit is no longer visible.
    fn defer_free(&self, block: BlockNumber, commit_seq: CommitSeq);

    /// Free all deferred blocks eligible at `watermark`.
    fn gc_free(&self, watermark: CommitSeq, cx: &Cx) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeByteRange {
    pub start: usize,
    pub len: usize,
}

pub type MergeByteRanges = SmallVec<[MergeByteRange; 1]>;

impl MergeByteRange {
    #[must_use]
    pub const fn new(start: usize, len: usize) -> Self {
        Self { start, len }
    }

    #[must_use]
    const fn end(self) -> usize {
        self.start.saturating_add(self.len)
    }

    #[must_use]
    const fn overlaps(self, other: Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

/// Byte-level merge algorithm selected by a [`MergeProof`].
///
/// The public proof labels are semantic/diagnostic labels. They intentionally
/// collapse to two same-block merge mechanisms plus one non-merge outcome:
/// append-only concatenation, range overlay, or FCW fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeProofMechanism {
    /// No same-block merge is attempted; FCW remains the decision boundary.
    NoSameBlockMerge,
    /// Preserve the snapshot prefix and append the staged suffix to `latest`.
    AppendOnly,
    /// Overlay declared byte ranges after validating that both writers touched
    /// disjoint regions.
    RangeOverlay,
    /// Bit-level OR of a monotone (set-only) allocation-bitmap block.
    ///
    /// Two allocators that SET the bits of disjoint blocks merge to `latest |
    /// staged`, even when their bits share a byte (a byte-range overlay cannot
    /// express this). Valid only when neither writer cleared a base bit.
    BitmapOr,
}

/// Evidence label used when a same-block FCW conflict might be mergeable.
///
/// `AppendOnly` is its own executable mechanism. `IndependentKeys`,
/// `NonOverlappingExtents`, and `TimestampOnlyInode` are not separate byte
/// algorithms; they all route through the same range-overlay validator after
/// the caller has established the family-specific semantic preconditions.
/// `Unsafe` and `DisjointBlocks` deliberately do not merge same-block
/// conflicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MergeProof {
    #[default]
    Unsafe,
    DisjointBlocks,
    AppendOnly {
        base_len: usize,
    },
    IndependentKeys {
        touched_ranges: MergeByteRanges,
    },
    NonOverlappingExtents {
        touched_ranges: MergeByteRanges,
    },
    TimestampOnlyInode {
        touched_ranges: MergeByteRanges,
    },
    /// Bit-level OR merge for a monotone (set-only) allocation-bitmap block.
    ///
    /// A block/inode bitmap packs 8 allocation bits per byte. Two concurrent
    /// allocators in the same group each SET the bits of the disjoint blocks
    /// they claimed, but adjacent free blocks share a byte, so an
    /// [`Self::IndependentKeys`] byte-range proof cannot express the merge — the
    /// writers overlap at the *byte* level while their *bits* are disjoint. This
    /// proof merges them as `latest | staged` after validating that both writers
    /// only SET bits relative to `base` (a *free* clears bits, so it fails this
    /// validation and falls back to FCW — hence the proof is only ever staged on
    /// the allocation path) and that their newly-set bits are disjoint (two
    /// writers setting the same new bit is a real double-allocation that must
    /// abort, not merge). Carries no ranges: the algorithm is whole-block.
    BitmapOr,
}

impl MergeProof {
    #[must_use]
    pub fn independent_key_range(start: usize, len: usize) -> Self {
        Self::IndependentKeys {
            touched_ranges: smallvec![MergeByteRange::new(start, len)],
        }
    }

    /// `IndependentKeys` proof over a set of `(start, len)` byte ranges — the
    /// multi-range form of [`Self::independent_key_range`]. Used for a block whose
    /// concurrent writers each touch a distinct fixed-size record slot (e.g. one
    /// group descriptor within the shared GDT block), so disjoint-slot writers
    /// merge instead of first-committer-wins conflicting.
    #[must_use]
    pub fn independent_keys(ranges: &[(usize, usize)]) -> Self {
        Self::IndependentKeys {
            touched_ranges: ranges
                .iter()
                .map(|&(start, len)| MergeByteRange::new(start, len))
                .collect(),
        }
    }

    #[must_use]
    pub fn non_overlapping_extent_range(start: usize, len: usize) -> Self {
        Self::NonOverlappingExtents {
            touched_ranges: smallvec![MergeByteRange::new(start, len)],
        }
    }

    #[must_use]
    pub fn timestamp_only_inode_range(start: usize, len: usize) -> Self {
        Self::TimestampOnlyInode {
            touched_ranges: smallvec![MergeByteRange::new(start, len)],
        }
    }

    #[must_use]
    pub fn mechanism(&self) -> MergeProofMechanism {
        match self {
            Self::Unsafe | Self::DisjointBlocks => MergeProofMechanism::NoSameBlockMerge,
            Self::AppendOnly { .. } => MergeProofMechanism::AppendOnly,
            Self::IndependentKeys { .. }
            | Self::NonOverlappingExtents { .. }
            | Self::TimestampOnlyInode { .. } => MergeProofMechanism::RangeOverlay,
            Self::BitmapOr => MergeProofMechanism::BitmapOr,
        }
    }

    /// Whether [`Self::merge_bytes`] would succeed for these inputs, WITHOUT
    /// allocating or building the merged block.
    ///
    /// The FCW *preflight* conflict check only needs a yes/no answer. Building
    /// the merged buffer there (then discarding it and rebuilding it at install
    /// time) wastes a block-sized allocation + copy per conflicting block on the
    /// contended commit path, under the shard lock. `merge_valid(..) ==
    /// merge_bytes(..).is_some()` by construction: both run the identical
    /// validators; only `merge_bytes` additionally materializes the output.
    pub(crate) fn merge_valid(&self, base: &[u8], latest: &[u8], staged: &[u8]) -> bool {
        match self {
            Self::Unsafe | Self::DisjointBlocks => false,
            Self::AppendOnly { base_len } => {
                append_only_merge_valid(*base_len, base, latest, staged)
            }
            Self::IndependentKeys { touched_ranges }
            | Self::NonOverlappingExtents { touched_ranges }
            | Self::TimestampOnlyInode { touched_ranges } => {
                merge_non_overlapping_ranges_valid(touched_ranges, base, latest, staged, self)
            }
            Self::BitmapOr => bitmap_or_merge_valid(base, latest, staged),
        }
    }

    pub(crate) fn merge_bytes(&self, base: &[u8], latest: &[u8], staged: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Unsafe | Self::DisjointBlocks => None,
            Self::AppendOnly { base_len } => {
                if !append_only_merge_valid(*base_len, base, latest, staged) {
                    return None;
                }
                let mut merged = latest.to_vec();
                merged.extend_from_slice(&staged[*base_len..]);
                Some(merged)
            }
            Self::IndependentKeys { touched_ranges }
            | Self::NonOverlappingExtents { touched_ranges }
            | Self::TimestampOnlyInode { touched_ranges } => {
                merge_non_overlapping_ranges(touched_ranges, base, latest, staged, self)
            }
            Self::BitmapOr => {
                if !bitmap_or_merge_valid(base, latest, staged) {
                    return None;
                }
                // Validity guarantees equal lengths and set-only writers, so the
                // byte-wise OR `latest | staged` reconstructs every allocation:
                // `base | latest_new | staged_new`, with no spurious bit.
                let mut merged = latest.to_vec();
                for (m, &s) in merged.iter_mut().zip(staged.iter()) {
                    *m |= s;
                }
                Some(merged)
            }
        }
    }
}

/// Validate an `AppendOnly` merge (base_len bounds + unchanged common prefix)
/// without building the merged block. Shared by `merge_valid` (preflight) and
/// `merge_bytes` (install) so the two can never diverge.
fn append_only_merge_valid(base_len: usize, base: &[u8], latest: &[u8], staged: &[u8]) -> bool {
    if base_len > base.len() || base_len > latest.len() || base_len > staged.len() {
        warn!(
            target: "ffs::mvcc::merge",
            proof = "AppendOnly",
            base_len,
            actual_base = base.len(),
            actual_latest = latest.len(),
            actual_staged = staged.len(),
            "merge_proof_rejected: base_len exceeds buffer size"
        );
        return false;
    }
    let prefix = &base[..base_len];
    if latest[..base_len] != *prefix || staged[..base_len] != *prefix {
        warn!(
            target: "ffs::mvcc::merge",
            proof = "AppendOnly",
            base_len,
            "merge_proof_rejected: prefix mismatch (base region was modified)"
        );
        return false;
    }
    true
}

/// Extract the variant name from a `MergeProof` for diagnostic logging.
fn merge_proof_variant_name(proof: &MergeProof) -> &'static str {
    match proof {
        MergeProof::Unsafe => "Unsafe",
        MergeProof::DisjointBlocks => "DisjointBlocks",
        MergeProof::AppendOnly { .. } => "AppendOnly",
        MergeProof::IndependentKeys { .. } => "IndependentKeys",
        MergeProof::NonOverlappingExtents { .. } => "NonOverlappingExtents",
        MergeProof::TimestampOnlyInode { .. } => "TimestampOnlyInode",
        MergeProof::BitmapOr => "BitmapOr",
    }
}

/// Validate a bit-level OR merge for a monotone (set-only) allocation-bitmap
/// block WITHOUT building the merged block.
///
/// Returns `true` iff [`MergeProof::merge_bytes`] would produce the byte-OR
/// `latest | staged`. Shared by `merge_valid` (preflight) and `merge_bytes`
/// (install) so the yes/no decision can never diverge from the materialized
/// output.
///
/// The three preconditions (all bit-level, hence uncatchable by a byte-range
/// proof):
///
/// - **Equal length** across base/latest/staged — a bitmap block is fixed-size.
/// - **Set-only** for both writers: neither cleared a bit set in `base`
///   (`base & !latest == 0` and `base & !staged == 0`). A *free* clears bits, so
///   a free operation fails here and falls back to FCW; the proof is therefore
///   only ever staged on the allocation (bit-set) path.
/// - **Disjoint new bits**: the bits each writer newly set are disjoint
///   (`(latest & !base) & (staged & !base) == 0`). Overlap means both writers
///   allocated the SAME block to different owners — a real double-allocation
///   that MUST abort so the loser retries, not silently merge.
///
/// Under those preconditions `latest | staged == base | latest_new |
/// staged_new`: every writer's allocation survives and no spurious bit appears.
fn bitmap_or_merge_valid(base: &[u8], latest: &[u8], staged: &[u8]) -> bool {
    if latest.len() != base.len() || staged.len() != base.len() {
        warn!(
            target: "ffs::mvcc::merge",
            proof = "BitmapOr",
            base_len = base.len(),
            latest_len = latest.len(),
            staged_len = staged.len(),
            "merge_proof_rejected: buffer length mismatch"
        );
        return false;
    }
    for ((&b, &l), &s) in base.iter().zip(latest.iter()).zip(staged.iter()) {
        // Set-only: a bit set in `base` must remain set in both writers.
        if (b & !l) != 0 || (b & !s) != 0 {
            warn!(
                target: "ffs::mvcc::merge",
                proof = "BitmapOr",
                "merge_proof_rejected: a writer cleared a base bit (not a set-only bitmap merge)"
            );
            return false;
        }
        // Disjoint new bits: both writers setting the same fresh bit is a real
        // double-allocation of one block, which must abort rather than merge.
        if ((l & !b) & (s & !b)) != 0 {
            warn!(
                target: "ffs::mvcc::merge",
                proof = "BitmapOr",
                "merge_proof_rejected: writers set the same new bit (double-allocation)"
            );
            return false;
        }
    }
    true
}

/// Validate a range-overlay merge (`IndependentKeys` / `NonOverlappingExtents`
/// / `TimestampOnlyInode`) WITHOUT building the merged block. Returns `true`
/// iff [`merge_non_overlapping_ranges`] would return `Some`. Shared by
/// `merge_valid` (preflight) and `merge_non_overlapping_ranges` (install) so the
/// yes/no decision can never diverge from the materialized output.
fn merge_non_overlapping_ranges_valid(
    touched_ranges: &[MergeByteRange],
    base: &[u8],
    latest: &[u8],
    staged: &[u8],
    proof: &MergeProof,
) -> bool {
    let variant = merge_proof_variant_name(proof);
    if latest.len() != base.len() || staged.len() != base.len() {
        warn!(
            target: "ffs::mvcc::merge",
            proof_variant = %variant,
            base_len = base.len(),
            latest_len = latest.len(),
            staged_len = staged.len(),
            "merge_proof_rejected: buffer length mismatch"
        );
        return false;
    }
    if !ranges_are_pairwise_disjoint(touched_ranges) {
        warn!(
            target: "ffs::mvcc::merge",
            proof_variant = %variant,
            range_count = touched_ranges.len(),
            "merge_proof_rejected: touched ranges overlap"
        );
        return false;
    }

    // Every declared range must fit within the block before we slice it.
    for range in touched_ranges {
        if range.end() > base.len() {
            warn!(
                target: "ffs::mvcc::merge",
                proof_variant = %variant,
                range_start = range.start,
                range_end = range.end(),
                base_len = base.len(),
                "merge_proof_rejected: range exceeds block size"
            );
            return false;
        }
    }

    // Strict validation: if the staged block modified ANYTHING outside the
    // declared touched_ranges, the proof is invalid and we must abort. This is
    // exactly `base`-with-staged-ranges-overlaid == `staged`, i.e. `staged`
    // matches `base` in the *complement* of the touched ranges. Comparing the
    // complement gaps directly avoids materializing a full-block `expected`
    // buffer (one block-sized allocation + copy) on the contended merge path,
    // which runs under the shard lock. The ranges are pairwise disjoint
    // (checked above); sort by start so the gaps between them are well-formed
    // (`ordered` is a stack SmallVec for the common single-range case).
    let mut ordered: MergeByteRanges = touched_ranges.iter().copied().collect();
    ordered.sort_unstable_by_key(|range| range.start);
    let mut cursor = 0usize;
    for range in &ordered {
        if staged[cursor..range.start] != base[cursor..range.start] {
            warn!(
                target: "ffs::mvcc::merge",
                proof_variant = %variant,
                range_count = touched_ranges.len(),
                "merge_proof_rejected: staged block modified bytes outside declared touched_ranges"
            );
            return false;
        }
        cursor = range.end();
    }
    if staged[cursor..] != base[cursor..] {
        warn!(
            target: "ffs::mvcc::merge",
            proof_variant = %variant,
            range_count = touched_ranges.len(),
            "merge_proof_rejected: staged block modified bytes outside declared touched_ranges"
        );
        return false;
    }

    // True conflict: `latest` must not have modified any declared range vs base.
    for range in touched_ranges {
        if latest[range.start..range.end()] != base[range.start..range.end()] {
            warn!(
                target: "ffs::mvcc::merge",
                proof_variant = %variant,
                range_start = range.start,
                range_end = range.end(),
                "merge_proof_rejected: latest version modified the same byte range (true conflict)"
            );
            return false;
        }
    }
    true
}

fn merge_non_overlapping_ranges(
    touched_ranges: &[MergeByteRange],
    base: &[u8],
    latest: &[u8],
    staged: &[u8],
    proof: &MergeProof,
) -> Option<Vec<u8>> {
    if !merge_non_overlapping_ranges_valid(touched_ranges, base, latest, staged, proof) {
        return None;
    }
    let mut merged = latest.to_vec();
    for range in touched_ranges {
        merged[range.start..range.end()].copy_from_slice(&staged[range.start..range.end()]);
    }
    Some(merged)
}

fn ranges_are_pairwise_disjoint(touched_ranges: &[MergeByteRange]) -> bool {
    touched_ranges.iter().enumerate().all(|(idx, left)| {
        touched_ranges[idx + 1..]
            .iter()
            .all(|right| !left.overlaps(*right))
    })
}

/// Index of the newest version with `commit_seq <= visible_high`, or `None` if
/// no version is visible at that snapshot.
///
/// Version chains are maintained in ascending `commit_seq` order (commits append
/// monotonically increasing sequences and pruning only trims the front), so
/// `commit_seq <= visible_high` is monotonic across the slice. This checks the
/// newest version first — O(1) for the common case of a reader at or near the
/// latest snapshot, identical to the prior reverse scan's best case — and
/// otherwise binary-searches in O(log n) instead of the previous O(n) reverse
/// linear scan. The returned index is identical to
/// `versions.iter().rposition(|v| v.commit_seq <= visible_high)` for any
/// ascending-ordered chain.
#[inline]
pub(crate) fn newest_visible_index(
    versions: &[BlockVersion],
    visible_high: CommitSeq,
) -> Option<usize> {
    newest_visible_index_by(versions, visible_high, |version| version.commit_seq)
}

/// Generic core of [`newest_visible_index`] over any ascending-by-`commit_seq`
/// slice. Checks the newest element first (O(1) for readers at/near the latest
/// snapshot) and otherwise binary-searches in O(log n). Used for both logical
/// `BlockVersion` chains and physical `PhysicalBlockVersion` chains so a
/// long-running reader holding the watermark down (which prevents the chain
/// from being trimmed) does not pay an O(n) reverse linear scan per read.
#[inline]
pub(crate) fn newest_visible_index_by<T>(
    versions: &[T],
    visible_high: CommitSeq,
    commit_seq: impl Fn(&T) -> CommitSeq,
) -> Option<usize> {
    let last = versions.len().checked_sub(1)?;
    if commit_seq(&versions[last]) <= visible_high {
        return Some(last);
    }
    versions
        .partition_point(|version| commit_seq(version) <= visible_high)
        .checked_sub(1)
}

pub(crate) fn resolve_version_bytes_cow_at_or_before(
    versions: &[BlockVersion],
    visible_high: CommitSeq,
) -> Option<std::borrow::Cow<'_, [u8]>> {
    let idx = newest_visible_index(versions, visible_high)?;
    compression::resolve_data_with(versions, idx, |version| &version.data)
}

pub(crate) fn resolve_version_bytes_at_or_before(
    versions: &[BlockVersion],
    visible_high: CommitSeq,
) -> Option<Vec<u8>> {
    resolve_version_bytes_cow_at_or_before(versions, visible_high).map(std::borrow::Cow::into_owned)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedWrite {
    pub(crate) bytes: Vec<u8>,
    pub(crate) merge_proof: MergeProof,
    /// The block's content at this transaction's snapshot, as read during the
    /// staging RMW, recorded ONLY when the store held no version for the block
    /// (a first write to a freshly-allocated block, read straight from the base
    /// device). The conflict-merge base is normally recovered from the version
    /// chain via `version_bytes_at`, but a brand-new block that two transactions
    /// concurrently write disjoint ranges of has NO version at their shared
    /// snapshot, so the chain yields an empty base and the range-overlay merge
    /// would spuriously reject on a length mismatch. This preserves the exact
    /// common-ancestor bytes both writers RMW'd from so the merge is sound
    /// (bd-bhh0i: freshly-allocated inode-table / GDT block under parallel
    /// create). `None` for non-RMW writes and for writes over an existing
    /// version (where `version_bytes_at` already returns the correct base).
    pub(crate) base: Option<Vec<u8>>,
}

type StagedWrites = SmallVec<[(BlockNumber, StagedWrite); 4]>;

fn staged_write_pos(
    staged_writes: &[(BlockNumber, StagedWrite)],
    block: BlockNumber,
) -> Result<usize, usize> {
    staged_writes.binary_search_by_key(&block, |(candidate, _)| *candidate)
}

#[derive(Clone, Copy)]
pub struct WriteSet<'a> {
    staged_writes: &'a [(BlockNumber, StagedWrite)],
}

impl<'a> WriteSet<'a> {
    #[must_use]
    pub fn len(self) -> usize {
        self.staged_writes.len()
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.staged_writes.is_empty()
    }

    #[must_use]
    pub fn contains_key(self, block: &BlockNumber) -> bool {
        staged_write_pos(self.staged_writes, *block).is_ok()
    }

    #[must_use]
    pub fn keys(self) -> impl DoubleEndedIterator<Item = &'a BlockNumber> + ExactSizeIterator + 'a {
        self.staged_writes.iter().map(|(block, _)| block)
    }

    #[must_use]
    fn key_span(self) -> Option<(BlockNumber, BlockNumber)> {
        Some((self.staged_writes.first()?.0, self.staged_writes.last()?.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub id: TxnId,
    pub snapshot: Snapshot,
    staged_writes: StagedWrites,
    /// Blocks read during the transaction's lifetime.  Each entry maps
    /// the block to the `CommitSeq` of the version that was read (or
    /// `CommitSeq(0)` if the block had no version at that snapshot).
    ///
    /// Populated by `record_read`.  Used by SSI conflict detection.
    reads: BTreeMap<BlockNumber, CommitSeq>,
    /// COW rewrite metadata for logical blocks staged in this transaction.
    ///
    /// This tracks the newly allocated physical location and the physical
    /// location that will become free after commit.
    cow_writes: BTreeMap<BlockNumber, CowRewriteIntent>,
    /// Newly allocated physical blocks superseded by a later write in the
    /// same transaction. These blocks never became visible and should be
    /// deferred for freeing on commit.
    cow_orphans: BTreeSet<BlockNumber>,
}

#[derive(Serialize, Deserialize)]
struct TransactionSerde {
    id: TxnId,
    snapshot: Snapshot,
    writes: BTreeMap<BlockNumber, Vec<u8>>,
    #[serde(default)]
    merge_proofs: BTreeMap<BlockNumber, MergeProof>,
    reads: BTreeMap<BlockNumber, CommitSeq>,
    cow_writes: BTreeMap<BlockNumber, CowRewriteIntent>,
    cow_orphans: BTreeSet<BlockNumber>,
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let writes = self
            .staged_writes
            .iter()
            .map(|(block, staged)| (*block, staged.bytes.clone()))
            .collect();
        let merge_proofs = self
            .staged_writes
            .iter()
            .map(|(block, staged)| (*block, staged.merge_proof.clone()))
            .collect();
        TransactionSerde {
            id: self.id,
            snapshot: self.snapshot,
            writes,
            merge_proofs,
            reads: self.reads.clone(),
            cow_writes: self.cow_writes.clone(),
            cow_orphans: self.cow_orphans.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut helper = TransactionSerde::deserialize(deserializer)?;
        let staged_writes = helper
            .writes
            .into_iter()
            .map(|(block, bytes)| {
                let merge_proof = helper.merge_proofs.remove(&block).unwrap_or_default();
                (
                    block,
                    StagedWrite {
                        bytes,
                        merge_proof,
                        base: None,
                    },
                )
            })
            .collect();
        Ok(Self {
            id: helper.id,
            snapshot: helper.snapshot,
            staged_writes,
            reads: helper.reads,
            cow_writes: helper.cow_writes,
            cow_orphans: helper.cow_orphans,
        })
    }
}

impl Transaction {
    /// Create a new transaction at the given snapshot.
    #[must_use]
    pub(crate) fn new(id: TxnId, snapshot: Snapshot) -> Self {
        Self {
            id,
            snapshot,
            staged_writes: StagedWrites::new(),
            reads: BTreeMap::new(),
            cow_writes: BTreeMap::new(),
            cow_orphans: BTreeSet::new(),
        }
    }

    /// The transaction's unique ID.
    #[must_use]
    pub fn id(&self) -> TxnId {
        self.id
    }

    /// The snapshot this transaction reads at.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    pub fn stage_write(&mut self, block: BlockNumber, bytes: Vec<u8>) {
        self.stage_write_with_proof(block, bytes, MergeProof::Unsafe);
    }

    pub fn stage_write_with_proof(
        &mut self,
        block: BlockNumber,
        bytes: Vec<u8>,
        merge_proof: MergeProof,
    ) {
        self.insert_staged_write(
            block,
            StagedWrite {
                bytes,
                merge_proof,
                base: None,
            },
        );
    }

    /// Stage a write together with the block's pre-modification base bytes at
    /// this transaction's snapshot. `base` must be `Some` exactly when the RMW
    /// read the block from the base device because the store held no version at
    /// the snapshot; it supplies the range-overlay merge's common ancestor for a
    /// freshly-allocated block that has no version chain (bd-bhh0i). Passing
    /// `None` is identical to [`stage_write_with_proof`](Self::stage_write_with_proof).
    pub fn stage_write_with_proof_and_base(
        &mut self,
        block: BlockNumber,
        bytes: Vec<u8>,
        merge_proof: MergeProof,
        base: Option<Vec<u8>>,
    ) {
        self.insert_staged_write(
            block,
            StagedWrite {
                bytes,
                merge_proof,
                base,
            },
        );
    }

    fn insert_staged_write(&mut self, block: BlockNumber, staged: StagedWrite) {
        match staged_write_pos(&self.staged_writes, block) {
            Ok(idx) => self.staged_writes[idx] = (block, staged),
            Err(idx) => self.staged_writes.insert(idx, (block, staged)),
        }
    }

    fn stage_cow_rewrite(
        &mut self,
        logical: BlockNumber,
        old_physical: Option<BlockNumber>,
        new_physical: BlockNumber,
        bytes: Vec<u8>,
    ) {
        if let Some(previous) = self.cow_writes.insert(
            logical,
            CowRewriteIntent {
                old_physical,
                new_physical,
            },
        ) {
            self.cow_orphans.insert(previous.new_physical);
            trace!(
                txn_id = self.id.0,
                logical = logical.0,
                orphan_physical = previous.new_physical.0,
                "cow_orphan_staged_for_free"
            );
        }
        self.insert_staged_write(
            logical,
            StagedWrite {
                bytes,
                merge_proof: MergeProof::Unsafe,
                base: None,
            },
        );
    }

    #[must_use]
    pub fn staged_write(&self, block: BlockNumber) -> Option<&[u8]> {
        let idx = staged_write_pos(&self.staged_writes, block).ok()?;
        Some(self.staged_writes[idx].1.bytes.as_slice())
    }

    /// The RMW base bytes recorded for `block` (see [`StagedWrite::base`]).
    /// `Some` only when this transaction's staging RMW read the block from the
    /// base device because no version existed at its snapshot — the merge's
    /// common-ancestor fallback for a freshly-allocated block (bd-bhh0i).
    #[must_use]
    pub(crate) fn staged_base(&self, block: BlockNumber) -> Option<&[u8]> {
        let idx = staged_write_pos(&self.staged_writes, block).ok()?;
        self.staged_writes[idx].1.base.as_deref()
    }

    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.staged_writes.len()
    }

    /// Record that `block` was read at version `version_seq`.
    ///
    /// This is required for SSI conflict detection.  When using FCW-only
    /// mode this is a no-op — reads are not tracked and the `reads` map
    /// stays empty.
    ///
    /// Only the *first* read of a given block is recorded (the version
    /// seen at the transaction's snapshot).  Subsequent reads of the same
    /// block are no-ops.
    pub fn record_read(&mut self, block: BlockNumber, version_seq: CommitSeq) {
        use std::collections::btree_map::Entry;
        if let Entry::Vacant(e) = self.reads.entry(block) {
            e.insert(version_seq);
            trace!(
                target: "ffs::ssi",
                block_num = block.0,
                version_seen = version_seq.0,
                txn_id = self.id.0,
                read_set_size = self.reads.len(),
                "read_set_add"
            );
        }
    }

    /// The set of blocks this transaction has read (and their version).
    #[must_use]
    pub fn read_set(&self) -> &BTreeMap<BlockNumber, CommitSeq> {
        &self.reads
    }

    /// The set of blocks this transaction will write.
    #[must_use]
    pub fn write_set(&self) -> WriteSet<'_> {
        WriteSet {
            staged_writes: &self.staged_writes,
        }
    }

    #[must_use]
    pub fn merge_proof(&self, block: BlockNumber) -> Option<&MergeProof> {
        let idx = staged_write_pos(&self.staged_writes, block).ok()?;
        Some(&self.staged_writes[idx].1.merge_proof)
    }

    pub(crate) fn into_staged_writes(self) -> StagedWrites {
        assert!(
            self.cow_writes.is_empty(),
            "COW writes silently dropped by into_staged_writes"
        );
        assert!(
            self.cow_orphans.is_empty(),
            "COW orphans silently dropped by into_staged_writes"
        );
        self.staged_writes
    }

    #[must_use]
    pub fn staged_physical(&self, block: BlockNumber) -> Option<BlockNumber> {
        self.cow_writes.get(&block).map(|w| w.new_physical)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitError {
    #[error(
        "first-committer-wins conflict on block {block}: snapshot={snapshot:?}, observed={observed:?}"
    )]
    Conflict {
        block: BlockNumber,
        snapshot: CommitSeq,
        observed: CommitSeq,
    },
    #[error(
        "SSI: two-edge dangerous structure detected via block {pivot_block} \
         (this txn read it at {read_version:?}, concurrent txn {concurrent_txn:?} wrote it at {write_version:?})"
    )]
    SsiConflict {
        pivot_block: BlockNumber,
        read_version: CommitSeq,
        write_version: CommitSeq,
        concurrent_txn: TxnId,
    },
    #[error(
        "version chain backpressure on block {block}: len={chain_len}, cap={cap}, critical={critical_len}, watermark={watermark:?}"
    )]
    ChainBackpressure {
        block: BlockNumber,
        chain_len: usize,
        cap: usize,
        critical_len: usize,
        watermark: CommitSeq,
    },
    #[error("commit durability failure: {detail}")]
    DurabilityFailure { detail: String },
}

pub(crate) fn validate_transaction_id(txn_id: TxnId) -> Result<(), CommitError> {
    if txn_id.0 == 0 || txn_id.0 == u64::MAX {
        return Err(CommitError::DurabilityFailure {
            detail: format!("invalid transaction id {}", txn_id.0),
        });
    }
    Ok(())
}

/// Record of a committed transaction kept for SSI antidependency checking.
#[derive(Debug, Clone)]
pub(crate) struct CommittedTxnRecord {
    pub(crate) txn_id: TxnId,
    pub(crate) commit_seq: CommitSeq,
    pub(crate) snapshot: Snapshot,
    pub(crate) write_set: BTreeSet<BlockNumber>,
    pub(crate) read_set: BTreeMap<BlockNumber, CommitSeq>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SsiRwEdge {
    pub(crate) reader_txn: TxnId,
    pub(crate) writer_txn: TxnId,
    pub(crate) block: BlockNumber,
    pub(crate) read_version: CommitSeq,
    pub(crate) reader_snapshot_high: CommitSeq,
    pub(crate) write_version: CommitSeq,
}

/// Two adjacent rw-antidependencies with the committing transaction as pivot.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SsiDangerousStructure {
    pub(crate) incoming: SsiRwEdge,
    pub(crate) outgoing: SsiRwEdge,
}

impl SsiDangerousStructure {
    #[must_use]
    pub(crate) fn to_commit_error(self) -> CommitError {
        CommitError::SsiConflict {
            pivot_block: self.outgoing.block,
            read_version: self.outgoing.read_version,
            write_version: self.outgoing.write_version,
            concurrent_txn: self.outgoing.writer_txn,
        }
    }

    pub(crate) fn emit_logs(self, pivot_txn: TxnId) {
        debug!(
            target: "ffs::ssi",
            txn_id = pivot_txn.0,
            incoming_reader_txn = self.incoming.reader_txn.0,
            incoming_block = self.incoming.block.0,
            incoming_read_version = self.incoming.read_version.0,
            incoming_reader_snapshot_high = self.incoming.reader_snapshot_high.0,
            outgoing_writer_txn = self.outgoing.writer_txn.0,
            outgoing_block = self.outgoing.block.0,
            outgoing_read_version = self.outgoing.read_version.0,
            outgoing_reader_snapshot_high = self.outgoing.reader_snapshot_high.0,
            outgoing_write_version = self.outgoing.write_version.0,
            cycle = %format_args!(
                "T{} -rw[block {}]-> T{} -rw[block {}]-> T{}",
                self.incoming.reader_txn.0,
                self.incoming.block.0,
                pivot_txn.0,
                self.outgoing.block.0,
                self.outgoing.writer_txn.0
            ),
            "ssi_two_edge_dangerous_structure"
        );
        warn!(
            target: "ffs::ssi",
            txn_id = pivot_txn.0,
            incoming_reader_txn = self.incoming.reader_txn.0,
            incoming_block = self.incoming.block.0,
            incoming_reader_snapshot_high = self.incoming.reader_snapshot_high.0,
            outgoing_writer_txn = self.outgoing.writer_txn.0,
            outgoing_block = self.outgoing.block.0,
            outgoing_reader_snapshot_high = self.outgoing.reader_snapshot_high.0,
            conflict_type = "two_edge_dangerous_structure",
            action = "abort",
            "ssi_conflict"
        );
        warn!(
            target: "ffs::mvcc::evidence",
            event = "txn_aborted",
            txn_id = pivot_txn.0,
            reason = "ssi_cycle",
            incoming_reader_txn = self.incoming.reader_txn.0,
            incoming_block = self.incoming.block.0,
            incoming_reader_snapshot_high = self.incoming.reader_snapshot_high.0,
            outgoing_writer_txn = self.outgoing.writer_txn.0,
            outgoing_block = self.outgoing.block.0,
            outgoing_reader_snapshot_high = self.outgoing.reader_snapshot_high.0,
            read_version = self.outgoing.read_version.0,
            write_version = self.outgoing.write_version.0
        );
    }
}

fn btree_map_key_span<V>(map: &BTreeMap<BlockNumber, V>) -> Option<(BlockNumber, BlockNumber)> {
    Some((*map.first_key_value()?.0, *map.last_key_value()?.0))
}

fn btree_set_key_span(set: &BTreeSet<BlockNumber>) -> Option<(BlockNumber, BlockNumber)> {
    Some((*set.first()?, *set.last()?))
}

fn key_in_span(key: BlockNumber, span: (BlockNumber, BlockNumber)) -> bool {
    span.0 <= key && key <= span.1
}

fn ssi_incoming_edge(txn: &Transaction, record: &CommittedTxnRecord) -> Option<SsiRwEdge> {
    // rw-antidependency: a block the committed txn READ and we WRITE. This is a
    // set intersection of `record.read_set` and our `write_set`. Both are sorted
    // (BTreeMap), so iterating EITHER in order and taking the first match yields
    // the identical block — the minimum of the intersection. Iterate the SMALLER
    // set so the cost is O(min(|read_set|, |write_set|)) rather than always
    // O(|read_set|); read-heavy transactions have large read sets but write few.
    let read_set = &record.read_set;
    let write_set = txn.write_set();
    let mk = |block, read_version| SsiRwEdge {
        reader_txn: record.txn_id,
        writer_txn: txn.id(),
        block,
        read_version,
        reader_snapshot_high: record.snapshot.high,
        write_version: CommitSeq(0),
    };
    if write_set.len() < read_set.len() {
        let read_span = btree_map_key_span(read_set)?;
        write_set.keys().find_map(|&block| {
            if key_in_span(block, read_span) {
                read_set.get(&block).map(|&rv| mk(block, rv))
            } else {
                None
            }
        })
    } else {
        let write_span = write_set.key_span()?;
        read_set.iter().find_map(|(&block, &rv)| {
            (key_in_span(block, write_span) && write_set.contains_key(&block))
                .then(|| mk(block, rv))
        })
    }
}

fn ssi_outgoing_edge(txn: &Transaction, record: &CommittedTxnRecord) -> Option<SsiRwEdge> {
    // Mirror of `ssi_incoming_edge`: a block we READ and the committed txn WROTE.
    // Intersection of our `read_set` (BTreeMap) and `record.write_set` (BTreeSet),
    // both sorted — iterate the smaller, identical first-match (min of intersection).
    let read_set = txn.read_set();
    let write_set = &record.write_set;
    let mk = |block, read_version| SsiRwEdge {
        reader_txn: txn.id(),
        writer_txn: record.txn_id,
        block,
        read_version,
        reader_snapshot_high: txn.snapshot().high,
        write_version: record.commit_seq,
    };
    if write_set.len() < read_set.len() {
        let read_span = btree_map_key_span(read_set)?;
        write_set.iter().find_map(|&block| {
            if key_in_span(block, read_span) {
                read_set.get(&block).map(|&rv| mk(block, rv))
            } else {
                None
            }
        })
    } else {
        let write_span = btree_set_key_span(write_set)?;
        read_set.iter().find_map(|(&block, &rv)| {
            (key_in_span(block, write_span) && write_set.contains(&block)).then(|| mk(block, rv))
        })
    }
}

pub(crate) fn detect_ssi_dangerous_structure<'a>(
    txn: &Transaction,
    records: impl IntoIterator<Item = &'a CommittedTxnRecord>,
) -> (u64, Option<SsiDangerousStructure>) {
    if txn.write_set().is_empty() {
        return (0, None);
    }

    let mut checks_performed = 0_u64;
    let mut incoming = None;
    let mut outgoing = None;

    for record in records {
        if record.commit_seq <= txn.snapshot().high {
            continue;
        }
        checks_performed = checks_performed.saturating_add(1);

        if incoming.is_none() {
            incoming = ssi_incoming_edge(txn, record);
        }
        if outgoing.is_none() {
            outgoing = ssi_outgoing_edge(txn, record);
        }

        if let (Some(incoming), Some(outgoing)) = (incoming, outgoing) {
            return (
                checks_performed,
                Some(SsiDangerousStructure { incoming, outgoing }),
            );
        }
    }

    (checks_performed, None)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbrVersionStats {
    pub retired_versions: u64,
    pub reclaimed_versions: u64,
}

impl EbrVersionStats {
    #[must_use]
    pub fn pending_versions(self) -> u64 {
        self.retired_versions
            .saturating_sub(self.reclaimed_versions)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVersionStats {
    pub tracked_blocks: usize,
    pub max_chain_length: usize,
    pub chains_over_cap: usize,
    pub chains_over_critical: usize,
    pub chain_cap: Option<usize>,
    pub critical_chain_length: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOutcomeStats {
    pub aborted_transactions: u64,
    pub ssi_conflicts: u64,
}

/// Conflict resolution policy governing how MVCC commit handles FCW conflicts.
///
/// - `Strict`: Pure first-committer-wins.  Any conflict aborts the later writer.
/// - `SafeMerge`: When a [`MergeProof`] is available and validates, the conflicting
///   writes are merged.  Falls back to abort when no proof exists.
/// - `Adaptive`: Automatically selects between `Strict` and `SafeMerge` based on
///   observed contention metrics and an expected-loss decision rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConflictPolicy {
    /// Pure FCW — any block-level conflict aborts the later writer.
    Strict,
    /// Merge when a valid [`MergeProof`] exists; abort otherwise.
    #[default]
    SafeMerge,
    /// Runtime-tunable: selects between `Strict` and `SafeMerge` per commit
    /// based on observed contention and expected-loss calculation.
    Adaptive,
}

/// Parameters for the expected-loss decision model used by [`ConflictPolicy::Adaptive`].
///
/// The adaptive policy selects the strategy with the lowest expected loss:
///
/// ```text
/// E[loss] = P(corruption) * severity + P(unnecessary_abort) * abort_cost
/// ```
///
/// `SafeMerge` has lower `P(unnecessary_abort)` but higher `P(corruption)` because
/// a buggy merge proof could silently corrupt data.  `Strict` has zero corruption
/// risk but wastes throughput under high contention with safe-mergeable workloads.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AdaptivePolicyConfig {
    /// Cost multiplier for a data corruption event (must-not-happen severity).
    /// Default: 1000.0 — corruption is catastrophic.
    pub corruption_severity: f64,
    /// Cost multiplier for an unnecessary transaction abort.
    /// Default: 1.0 — aborts are annoying but recoverable.
    pub abort_cost: f64,
    /// Baseline probability of corruption from a merge-proof bug.
    /// Default: 1e-6 — merge proofs are heavily tested, but non-zero risk.
    pub base_corruption_probability: f64,
    /// EMA smoothing factor for contention metrics (0..1, higher = more responsive).
    /// Default: 0.1 — smooth out noise while tracking trends.
    pub ema_alpha: f64,
    /// Minimum number of commits observed before adaptive kicks in.
    /// Below this, the policy falls back to `SafeMerge`.
    /// Default: 50 (increased from 20 to provide more statistically credible
    /// evidence before policy switching; 20 commits yields <2.3 effective
    /// Bayesian samples which is insufficient for reliable decision-making).
    pub warmup_commits: u64,
    /// Hysteresis ratio for policy switching.  The adaptive selector will only
    /// switch away from the *current* policy when the alternative's expected
    /// loss is better by at least this multiplicative factor.
    ///
    /// A value of 1.0 disables hysteresis (switch on any improvement).
    /// Default: 1.5 — require a 50 % improvement before switching, preventing
    /// rapid oscillation near the decision boundary.
    pub hysteresis_ratio: f64,
}

impl Default for AdaptivePolicyConfig {
    fn default() -> Self {
        Self {
            corruption_severity: 1000.0,
            abort_cost: 1.0,
            base_corruption_probability: 1e-6,
            ema_alpha: 0.1,
            warmup_commits: 50,
            hysteresis_ratio: 1.5,
        }
    }
}

/// Exponential moving average contention metrics tracked per [`MvccStore`].
///
/// Updated on every commit attempt (success or abort).  Used by
/// [`ConflictPolicy::Adaptive`] to drive the expected-loss calculation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ContentionMetrics {
    /// EMA of conflicts per commit (0.0 = no conflicts, 1.0 = every commit conflicts).
    pub conflict_rate: f64,
    /// EMA of successful merges per conflict (0.0 = merges always fail, 1.0 = always succeed).
    pub merge_success_rate: f64,
    /// EMA of aborts per commit (0.0 = no aborts, 1.0 = every commit aborts).
    pub abort_rate: f64,
    /// Total commits observed (for warmup gating).
    pub total_commits: u64,
    /// Total conflicts observed.
    pub total_conflicts: u64,
    /// Total successful merges observed.
    pub total_merges: u64,
    /// Total aborts observed.
    pub total_aborts: u64,
    /// The last policy selected by the adaptive selector, used for hysteresis.
    /// `None` until the first adaptive selection after warmup.
    pub last_selected: Option<ConflictPolicy>,
}

impl Default for ContentionMetrics {
    fn default() -> Self {
        Self {
            conflict_rate: 0.0,
            merge_success_rate: 1.0,
            abort_rate: 0.0,
            total_commits: 0,
            total_conflicts: 0,
            total_merges: 0,
            total_aborts: 0,
            last_selected: None,
        }
    }
}

impl ContentionMetrics {
    /// Update metrics after a commit attempt.
    ///
    /// - `had_conflict`: true if any block in the write set had a version newer
    ///   than the transaction's snapshot.
    /// - `merge_succeeded`: true if the conflict was resolved via merge proof
    ///   (only meaningful when `had_conflict` is true).
    /// - `aborted`: true if the commit was aborted.
    pub fn record_commit(
        &mut self,
        alpha: f64,
        had_conflict: bool,
        merge_succeeded: bool,
        aborted: bool,
    ) {
        self.total_commits = self.total_commits.saturating_add(1);
        let decay = 1.0 - alpha;
        let conflict_sample = if had_conflict { 1.0 } else { 0.0 };
        self.conflict_rate = decay.mul_add(self.conflict_rate, conflict_sample * alpha);

        if had_conflict {
            self.total_conflicts = self.total_conflicts.saturating_add(1);
            let merge_sample = if merge_succeeded { 1.0 } else { 0.0 };
            self.merge_success_rate = decay.mul_add(self.merge_success_rate, merge_sample * alpha);
            if merge_succeeded {
                self.total_merges = self.total_merges.saturating_add(1);
            }
        }

        if aborted {
            self.total_aborts = self.total_aborts.saturating_add(1);
        }
        let abort_sample = if aborted { 1.0 } else { 0.0 };
        self.abort_rate = decay.mul_add(self.abort_rate, abort_sample * alpha);
    }

    /// Compute the expected loss for `Strict` policy given current metrics.
    ///
    /// Strict never corrupts (`P(corruption) = 0`) but aborts every conflict:
    /// `E[loss] = conflict_rate * abort_cost`
    #[must_use]
    pub fn expected_loss_strict(&self, config: &AdaptivePolicyConfig) -> f64 {
        self.conflict_rate * config.abort_cost
    }

    /// Compute the expected loss for `SafeMerge` policy given current metrics.
    ///
    /// SafeMerge has a small corruption risk but avoids most aborts:
    /// `E[loss] = P(corruption) * severity + (conflict_rate * (1 - merge_success_rate)) * abort_cost`
    #[must_use]
    pub fn expected_loss_safe_merge(&self, config: &AdaptivePolicyConfig) -> f64 {
        let corruption_loss = config.base_corruption_probability * config.corruption_severity;
        let residual_abort_rate = self.conflict_rate * (1.0 - self.merge_success_rate);
        corruption_loss + residual_abort_rate * config.abort_cost
    }

    /// Select the conflict resolution strategy with the lowest expected loss,
    /// applying hysteresis to prevent rapid oscillation near the decision boundary.
    ///
    /// The selector only switches away from the current policy when the
    /// alternative's expected loss is better by at least
    /// [`AdaptivePolicyConfig::hysteresis_ratio`].  This prevents limit-cycle
    /// oscillation when the two policies have similar expected loss.
    ///
    /// Returns `SafeMerge` during the warmup period.
    #[must_use]
    pub fn select_policy(&self, config: &AdaptivePolicyConfig) -> ConflictPolicy {
        if self.total_commits < config.warmup_commits {
            return ConflictPolicy::SafeMerge;
        }
        let loss_strict = self.expected_loss_strict(config);
        let loss_merge = self.expected_loss_safe_merge(config);

        // Apply hysteresis: the *challenger* must beat the *incumbent* by the
        // hysteresis ratio.  On the very first selection after warmup
        // (`last_selected` is `None`), no hysteresis is applied.
        let raw_winner = if loss_strict <= loss_merge {
            ConflictPolicy::Strict
        } else {
            ConflictPolicy::SafeMerge
        };

        let selected = match self.last_selected {
            Some(incumbent) if incumbent != raw_winner => {
                // Challenger must beat incumbent by the hysteresis ratio.
                let (incumbent_loss, challenger_loss) = if incumbent == ConflictPolicy::Strict {
                    (loss_strict, loss_merge)
                } else {
                    (loss_merge, loss_strict)
                };
                if challenger_loss * config.hysteresis_ratio < incumbent_loss {
                    raw_winner // Challenger wins convincingly
                } else {
                    incumbent // Stick with incumbent
                }
            }
            _ => raw_winner, // First selection or same policy: no hysteresis needed
        };

        trace!(
            target: "ffs::mvcc::adaptive",
            loss_strict,
            loss_merge,
            conflict_rate = self.conflict_rate,
            merge_success_rate = self.merge_success_rate,
            abort_rate = self.abort_rate,
            total_commits = self.total_commits,
            hysteresis_ratio = config.hysteresis_ratio,
            ?selected,
            ?raw_winner,
            incumbent = ?self.last_selected,
            "adaptive_policy_selection"
        );

        selected
    }
}

const DEFAULT_RUNTIME_HISTOGRAM_BOUNDS: [u64; 12] = [
    1, 5, 10, 50, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 1_000_000,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeHistogramBucket {
    pub le: u64,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeHistogramSnapshot {
    pub buckets: Vec<RuntimeHistogramBucket>,
    pub inf_count: u64,
    pub sum: u64,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MvccRuntimeMetricsSnapshot {
    pub active_snapshots: usize,
    pub commit_rate: f64,
    pub conflict_rate: f64,
    pub abort_rate: f64,
    pub version_chain_max_length: usize,
    pub prune_throughput: f64,
    pub commit_attempts_total: u64,
    pub commit_successes_total: u64,
    pub conflicts_total: u64,
    pub aborts_total: u64,
    pub pruned_versions_total: u64,
    pub commit_latency_us: RuntimeHistogramSnapshot,
    pub conflict_resolution_latency_us: RuntimeHistogramSnapshot,
}

#[derive(Debug, Clone)]
struct RuntimeHistogram {
    bounds: Vec<u64>,
    counts: Vec<u64>,
    sum: u64,
    count: u64,
}

impl Default for RuntimeHistogram {
    fn default() -> Self {
        Self::with_bounds(&DEFAULT_RUNTIME_HISTOGRAM_BOUNDS)
    }
}

impl RuntimeHistogram {
    fn with_bounds(bounds: &[u64]) -> Self {
        Self {
            bounds: bounds.to_vec(),
            counts: vec![0; bounds.len() + 1],
            sum: 0,
            count: 0,
        }
    }

    fn observe(&mut self, value: u64) {
        let idx = self.bounds.partition_point(|&bound| bound < value);
        self.counts[idx] = self.counts[idx].saturating_add(1);
        self.sum = self.sum.saturating_add(value);
        self.count = self.count.saturating_add(1);
    }

    fn snapshot(&self) -> RuntimeHistogramSnapshot {
        RuntimeHistogramSnapshot {
            buckets: self
                .bounds
                .iter()
                .enumerate()
                .map(|(idx, &bound)| RuntimeHistogramBucket {
                    le: bound,
                    count: self.counts[idx],
                })
                .collect(),
            inf_count: self.counts[self.bounds.len()],
            sum: self.sum,
            count: self.count,
        }
    }
}

#[derive(Debug, Clone)]
struct MvccRuntimeMetricsState {
    started_at: Instant,
    commit_attempts_total: u64,
    commit_successes_total: u64,
    conflicts_total: u64,
    aborts_total: u64,
    pruned_versions_total: u64,
    commit_latency_us: RuntimeHistogram,
    conflict_resolution_latency_us: RuntimeHistogram,
}

impl Default for MvccRuntimeMetricsState {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            commit_attempts_total: 0,
            commit_successes_total: 0,
            conflicts_total: 0,
            aborts_total: 0,
            pruned_versions_total: 0,
            commit_latency_us: RuntimeHistogram::default(),
            conflict_resolution_latency_us: RuntimeHistogram::default(),
        }
    }
}

impl MvccRuntimeMetricsState {
    fn record_commit_attempt(&mut self) {
        self.commit_attempts_total = self.commit_attempts_total.saturating_add(1);
    }

    fn record_commit_success(&mut self, latency_us: u64) {
        self.commit_successes_total = self.commit_successes_total.saturating_add(1);
        self.commit_latency_us.observe(latency_us);
    }

    fn record_commit_abort(&mut self, error: &CommitError) {
        self.aborts_total = self.aborts_total.saturating_add(1);
        if matches!(
            error,
            CommitError::Conflict { .. } | CommitError::SsiConflict { .. }
        ) {
            self.conflicts_total = self.conflicts_total.saturating_add(1);
        }
    }

    fn record_conflict_resolution_latency(&mut self, latency_us: u64) {
        self.conflict_resolution_latency_us.observe(latency_us);
    }

    fn record_versions_pruned(&mut self, count: usize) {
        self.pruned_versions_total = self
            .pruned_versions_total
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
    }

    fn snapshot(
        &self,
        active_snapshots: usize,
        version_chain_max_length: usize,
    ) -> MvccRuntimeMetricsSnapshot {
        let elapsed_secs = self.started_at.elapsed().as_secs_f64();
        let safe_elapsed_secs = elapsed_secs.max(f64::EPSILON);
        let commit_attempts = self.commit_attempts_total as f64;
        MvccRuntimeMetricsSnapshot {
            active_snapshots,
            commit_rate: self.commit_successes_total as f64 / safe_elapsed_secs,
            conflict_rate: if self.commit_attempts_total == 0 {
                0.0
            } else {
                self.conflicts_total as f64 / commit_attempts
            },
            abort_rate: if self.commit_attempts_total == 0 {
                0.0
            } else {
                self.aborts_total as f64 / commit_attempts
            },
            version_chain_max_length,
            prune_throughput: self.pruned_versions_total as f64 / safe_elapsed_secs,
            commit_attempts_total: self.commit_attempts_total,
            commit_successes_total: self.commit_successes_total,
            conflicts_total: self.conflicts_total,
            aborts_total: self.aborts_total,
            pruned_versions_total: self.pruned_versions_total,
            commit_latency_us: self.commit_latency_us.snapshot(),
            conflict_resolution_latency_us: self.conflict_resolution_latency_us.snapshot(),
        }
    }
}

/// Budget-driven controls for MVCC version GC batches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcBackpressureConfig {
    /// Poll quota threshold below which GC skips the current batch.
    pub min_poll_quota: u32,
    /// Sleep duration used when a GC batch is throttled.
    pub throttle_sleep: Duration,
}

impl Default for GcBackpressureConfig {
    fn default() -> Self {
        Self {
            min_poll_quota: 256,
            throttle_sleep: Duration::from_millis(10),
        }
    }
}

fn sleep_for_gc_throttle(cx: &Cx, duration: Duration) {
    if duration.is_zero() || cx.checkpoint().is_err() {
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

        std::thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
        if cx.checkpoint().is_err() {
            return;
        }
    }
}

#[derive(Debug, Clone)]
struct EbrVersionReclaimer {
    collector: Arc<epoch::Collector>,
    retired_versions: Arc<AtomicU64>,
    reclaimed_versions: Arc<AtomicU64>,
}

impl Default for EbrVersionReclaimer {
    fn default() -> Self {
        Self {
            collector: Arc::new(epoch::Collector::new()),
            retired_versions: Arc::new(AtomicU64::new(0)),
            reclaimed_versions: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl EbrVersionReclaimer {
    fn retire_versions(&self, retired: Vec<BlockVersion>) {
        if retired.is_empty() {
            return;
        }
        let handle = self.collector.register();
        let guard = handle.pin();
        for version in retired {
            saturating_increment_atomic(self.retired_versions.as_ref(), Ordering::Relaxed);
            let reclaimed = Arc::clone(&self.reclaimed_versions);
            guard.defer(move || {
                drop(version);
                saturating_increment_atomic(reclaimed.as_ref(), Ordering::Relaxed);
            });
        }
    }

    fn collect(&self) {
        let passes = usize::try_from(self.stats().pending_versions().clamp(1, 8)).unwrap_or(8);
        for _ in 0..passes {
            let handle = self.collector.register();
            handle.pin().flush();
            if self.stats().pending_versions() == 0 {
                break;
            }
            std::thread::yield_now();
        }
    }

    fn collect_with_budget(&self, cx: &Cx, min_poll_quota: u32) -> bool {
        let passes = usize::try_from(self.stats().pending_versions().clamp(1, 8)).unwrap_or(8);
        let mut collected_any = false;
        for _ in 0..passes {
            let budget = cx.budget();
            if budget.is_exhausted() || budget.poll_quota <= min_poll_quota {
                break;
            }
            if cx.checkpoint().is_err() {
                break;
            }

            let handle = self.collector.register();
            handle.pin().flush();
            collected_any = true;
            if self.stats().pending_versions() == 0 {
                break;
            }
            std::thread::yield_now();
        }
        collected_any
    }

    fn stats(&self) -> EbrVersionStats {
        EbrVersionStats {
            retired_versions: self.retired_versions.load(Ordering::Relaxed),
            reclaimed_versions: self.reclaimed_versions.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
struct MvccEvidenceSink {
    file: Arc<Mutex<File>>,
}

impl MvccEvidenceSink {
    fn open(path: &Path) -> FfsResult<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    fn append(&self, record: &EvidenceRecord, txn_id: u64) {
        let start = Instant::now();
        let append_result = {
            let mut file = self.file.lock();
            serde_json::to_writer(&mut *file, record)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
                .and_then(|()| file.write_all(b"\n"))
                .and_then(|()| file.flush())
        };
        if let Err(error) = append_result {
            warn!(
                target: "ffs::mvcc::evidence",
                event = "evidence_append_failed",
                txn_id,
                error = %error
            );
            return;
        }

        trace!(
            target: "ffs::mvcc::evidence",
            event = "evidence_entry_written",
            entry_type = ?record.event_type,
            txn_id
        );
        let flush_duration_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        debug!(
            target: "ffs::mvcc::evidence",
            event = "evidence_ledger_flush",
            entries_buffered = 1_u64,
            flush_duration_us
        );
    }
}

#[derive(Debug, Clone)]
pub struct MvccStore {
    pub(crate) next_txn: u64,
    pub(crate) next_commit: u64,
    pub(crate) versions: FxHashMap<BlockNumber, Vec<BlockVersion>>,
    pub(crate) physical_versions: FxHashMap<BlockNumber, Vec<PhysicalBlockVersion>>,
    /// Active snapshots: each entry is a `CommitSeq` from which a reader is
    /// still potentially reading.  The set uses a `BTreeMap` so that the
    /// minimum (oldest active snapshot) can be obtained in O(log n).
    ///
    /// Callers **must** pair every `register_snapshot` with a corresponding
    /// `release_snapshot` to avoid preventing GC indefinitely.
    ///
    /// NOTE: For new code, prefer using [`SnapshotRegistry`] + [`SnapshotHandle`]
    /// which provide thread-safe RAII lifecycle management decoupled from the
    /// version store lock.  These inline methods are retained for backward
    /// compatibility and for use in single-threaded / test contexts.
    active_snapshots: BTreeMap<CommitSeq, u64>,
    /// Device-references whose snapshot was force-aged-out by chain-pressure
    /// relief (`force_advance_oldest_snapshot`) while still held by a live
    /// inline reader. Each such forced advance consumes one ref that no real
    /// `release_snapshot` will provide via `active_snapshots`; recording it
    /// here lets the eventual reader Drop release succeed instead of tripping
    /// the unregistered-release invariant, while genuine double-frees (absent
    /// from both maps) still return `false`.
    force_advanced_releases: BTreeMap<CommitSeq, u64>,
    /// Recent committed transactions retained for SSI antidependency
    /// checking.  Pruned by `prune_ssi_log`.
    pub(crate) ssi_log: Vec<CommittedTxnRecord>,
    /// Version chain compression policy.
    compression_policy: CompressionPolicy,
    /// Epoch-based reclaimer for retired logical block versions.
    ebr_reclaimer: EbrVersionReclaimer,
    /// Optional append-only evidence sink for transaction decisions.
    evidence_sink: Option<MvccEvidenceSink>,
    /// Whether the most recent GC batch was throttled by budget pressure.
    gc_throttled: bool,
    /// Total number of aborted transactions since store creation.
    aborted_transactions: u64,
    /// Total number of SSI conflicts observed since store creation.
    ssi_conflicts: u64,
    /// Conflict resolution policy (Strict / SafeMerge / Adaptive).
    conflict_policy: ConflictPolicy,
    /// Configuration for the adaptive expected-loss decision model.
    adaptive_config: AdaptivePolicyConfig,
    /// Runtime contention metrics tracked via EMA.
    contention_metrics: ContentionMetrics,
    /// JSON-exportable runtime counters/histograms for observability.
    runtime_metrics: MvccRuntimeMetricsState,
}

impl Default for MvccStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MvccStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_txn: 1,
            next_commit: 1,
            versions: FxHashMap::default(),
            physical_versions: FxHashMap::default(),
            active_snapshots: BTreeMap::new(),
            force_advanced_releases: BTreeMap::new(),
            ssi_log: Vec::new(),
            compression_policy: CompressionPolicy::default(),
            ebr_reclaimer: EbrVersionReclaimer::default(),
            evidence_sink: None,
            gc_throttled: false,
            aborted_transactions: 0,
            ssi_conflicts: 0,
            conflict_policy: ConflictPolicy::default(),
            adaptive_config: AdaptivePolicyConfig::default(),
            contention_metrics: ContentionMetrics::default(),
            runtime_metrics: MvccRuntimeMetricsState::default(),
        }
    }

    /// Create a store with a custom compression policy.
    #[must_use]
    pub fn with_compression_policy(policy: CompressionPolicy) -> Self {
        Self {
            compression_policy: policy,
            ..Self::new()
        }
    }

    /// Set the conflict resolution policy.
    pub fn set_conflict_policy(&mut self, policy: ConflictPolicy) {
        self.conflict_policy = policy;
    }

    /// Set the adaptive policy configuration.
    pub fn set_adaptive_config(&mut self, config: AdaptivePolicyConfig) {
        self.adaptive_config = config;
    }

    /// Returns the current conflict policy.
    #[must_use]
    pub fn conflict_policy(&self) -> ConflictPolicy {
        self.conflict_policy
    }

    /// Returns the current contention metrics.
    #[must_use]
    pub fn contention_metrics(&self) -> &ContentionMetrics {
        &self.contention_metrics
    }

    /// Returns the adaptive policy configuration.
    #[must_use]
    pub fn adaptive_config(&self) -> &AdaptivePolicyConfig {
        &self.adaptive_config
    }

    /// The effective policy for the next commit: resolves `Adaptive` to a
    /// concrete `Strict` or `SafeMerge` based on current contention metrics.
    #[must_use]
    pub fn effective_policy(&self) -> ConflictPolicy {
        match self.conflict_policy {
            ConflictPolicy::Adaptive => {
                self.contention_metrics.select_policy(&self.adaptive_config)
            }
            other => other,
        }
    }

    /// Enable append-only evidence recording to a JSONL ledger path.
    ///
    /// Evidence events are best-effort: MVCC commit/abort semantics are never
    /// blocked by ledger I/O errors.
    ///
    /// # Errors
    ///
    /// Returns an error if the ledger file cannot be opened for append.
    pub fn enable_evidence_ledger(&mut self, path: impl AsRef<Path>) -> FfsResult<()> {
        self.evidence_sink = Some(MvccEvidenceSink::open(path.as_ref())?);
        Ok(())
    }

    /// Disable evidence recording.
    pub fn disable_evidence_ledger(&mut self) {
        self.evidence_sink = None;
    }

    /// Returns the current compression policy.
    #[must_use]
    pub fn compression_policy(&self) -> &CompressionPolicy {
        &self.compression_policy
    }

    /// Compute compression statistics across all version chains.
    #[must_use]
    pub fn compression_stats(&self) -> CompressionStats {
        let mut stats = CompressionStats::default();
        for versions in self.versions.values() {
            for (idx, version) in versions.iter().enumerate() {
                match &version.data {
                    VersionData::Full(bytes) => {
                        stats.full_versions += 1;
                        stats.bytes_stored += bytes.len();
                    }
                    VersionData::Zstd(bytes) | VersionData::Brotli(bytes) => {
                        stats.full_versions += 1;
                        stats.bytes_stored += bytes.len();
                    }
                    VersionData::Identical => {
                        stats.identical_versions += 1;
                        // Estimate bytes saved: use the resolved data size
                        if let Some(bytes) =
                            compression::resolve_data_with(versions, idx, |v| &v.data)
                        {
                            stats.bytes_saved += bytes.len();
                        }
                    }
                }
            }
        }
        stats
    }

    /// Epoch-based retirement/reclamation counters for logical block versions.
    #[must_use]
    pub fn ebr_stats(&self) -> EbrVersionStats {
        self.ebr_reclaimer.stats()
    }

    /// Best-effort collection pass for deferred version reclamation.
    pub fn ebr_collect(&self) {
        self.ebr_reclaimer.collect();
    }

    /// Run one budget-aware MVCC GC batch.
    ///
    /// Returns `Some(watermark)` when pruning/collection ran, or `None` when
    /// the batch was skipped due to tight budget.
    pub fn run_gc_batch(&mut self, cx: &Cx, config: GcBackpressureConfig) -> Option<CommitSeq> {
        let budget = cx.budget();
        let budget_remaining = budget.poll_quota;
        let budget_throttled = budget.is_exhausted() || budget_remaining <= config.min_poll_quota;
        if budget_throttled {
            debug!(
                target: "ffs::mvcc::gc",
                daemon_name = "mvcc_gc",
                budget_remaining,
                yield_duration_ms = config.throttle_sleep.as_millis(),
                "daemon_throttled"
            );
            self.gc_throttled = true;
            sleep_for_gc_throttle(cx, config.throttle_sleep);
            return None;
        }

        if self.gc_throttled {
            debug!(
                target: "ffs::mvcc::gc",
                daemon_name = "mvcc_gc",
                new_budget = budget_remaining,
                "daemon_resumed"
            );
            self.gc_throttled = false;
        }

        let watermark = self.prune_safe();
        let collected = self
            .ebr_reclaimer
            .collect_with_budget(cx, config.min_poll_quota);
        if !collected && self.ebr_reclaimer.stats().pending_versions() > 0 {
            debug!(
                target: "ffs::mvcc::gc",
                daemon_name = "mvcc_gc",
                budget_remaining = cx.budget().poll_quota,
                yield_duration_ms = config.throttle_sleep.as_millis(),
                "daemon_throttled"
            );
            self.gc_throttled = true;
            sleep_for_gc_throttle(cx, config.throttle_sleep);
        }
        Some(watermark)
    }

    /// Chain-length monitoring snapshot for logical block versions.
    #[must_use]
    pub fn block_version_stats(&self) -> BlockVersionStats {
        let tracked_blocks = self.versions.len();
        let max_chain_length = self.versions.values().map(Vec::len).max().unwrap_or(0);
        let chain_cap = self.compression_policy.max_chain_length;
        let critical_chain_length = chain_cap.map(Self::critical_chain_len);

        let mut chains_over_cap = 0_usize;
        let mut chains_over_critical = 0_usize;
        if let Some(cap) = chain_cap {
            let critical = Self::critical_chain_len(cap);
            for chain in self.versions.values() {
                chains_over_cap += usize::from(chain.len() > cap);
                chains_over_critical += usize::from(chain.len() >= critical);
            }
        }

        BlockVersionStats {
            tracked_blocks,
            max_chain_length,
            chains_over_cap,
            chains_over_critical,
            chain_cap,
            critical_chain_length,
        }
    }

    /// Monotonic transaction outcome counters since store creation.
    #[must_use]
    pub fn transaction_outcome_stats(&self) -> TransactionOutcomeStats {
        TransactionOutcomeStats {
            aborted_transactions: self.aborted_transactions,
            ssi_conflicts: self.ssi_conflicts,
        }
    }

    /// JSON-friendly runtime metrics export for MVCC health/performance.
    #[must_use]
    pub fn runtime_metrics(&self) -> MvccRuntimeMetricsSnapshot {
        self.runtime_metrics.snapshot(
            self.active_snapshot_count(),
            self.block_version_stats().max_chain_length,
        )
    }

    fn critical_chain_len(max_len: usize) -> usize {
        let cap = max_len.max(1);
        cap.saturating_mul(4).max(cap.saturating_add(1))
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Snapshot {
        let high = self.next_commit.saturating_sub(1);
        Snapshot {
            high: CommitSeq(high),
        }
    }

    pub fn begin(&mut self) -> Transaction {
        let txn = Transaction {
            id: TxnId(self.next_txn),
            snapshot: self.current_snapshot(),
            staged_writes: StagedWrites::new(),
            reads: BTreeMap::new(),
            cow_writes: BTreeMap::new(),
            cow_orphans: BTreeSet::new(),
        };
        self.next_txn = self.next_txn.saturating_add(1);
        txn
    }

    /// Explicitly abort a transaction and emit an evidence entry.
    ///
    /// Aborting is a metadata operation: no versions are installed and staged
    /// writes are dropped when `txn` goes out of scope.
    pub fn abort(&mut self, txn: Transaction, reason: TxnAbortReason, detail: Option<String>) {
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        drop(txn);
        self.emit_txn_aborted(TxnAbortedDetail {
            txn_id,
            reason,
            detail,
            read_set_size,
            write_set_size,
        });
    }

    /// Explicitly abort a transaction and free any physical blocks allocated for it.
    pub fn abort_with_cow_allocator(
        &mut self,
        txn: Transaction,
        reason: TxnAbortReason,
        detail: Option<String>,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) {
        for intent in txn.cow_writes.values() {
            allocator.defer_free(intent.new_physical, CommitSeq(0));
        }
        for orphan in &txn.cow_orphans {
            allocator.defer_free(*orphan, CommitSeq(0));
        }
        let _ = self.gc_cow_blocks(allocator, cx);
        self.abort(txn, reason, detail);
    }

    pub fn commit(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.commit_fcw_internal(txn) {
            Ok((commit_seq, _)) => {
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, _txn)) => {
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    pub fn commit_with_cow_allocator(
        &mut self,
        txn: Transaction,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.commit_fcw_internal(txn) {
            Ok((commit_seq, deferred)) => {
                for block in deferred {
                    trace!(block = block.0, commit_seq = commit_seq.0, "cow_defer_free");
                    allocator.defer_free(block, commit_seq);
                }
                let _ = self.gc_cow_blocks(allocator, cx);
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, txn)) => {
                for intent in txn.cow_writes.values() {
                    allocator.defer_free(intent.new_physical, CommitSeq(0));
                }
                for orphan in txn.cow_orphans {
                    allocator.defer_free(orphan, CommitSeq(0));
                }
                let _ = self.gc_cow_blocks(allocator, cx);
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    /// Validate FCW + chain-pressure constraints without making versions visible.
    ///
    /// Callers should hold the same `MvccStore` write lock between this preflight
    /// and a subsequent [`Self::commit_fcw_prechecked`] call.
    pub fn preflight_commit_fcw(&mut self, txn: &Transaction) -> Result<(), CommitError> {
        self.preflight_fcw(txn)
    }

    /// Commit a transaction that has already passed FCW preflight checks.
    ///
    /// This avoids a second conflict check when an external durability phase
    /// (for example, journal I/O) must run between validation and visibility.
    ///
    /// # Errors
    ///
    /// Returns `CommitError` if the commit sequence is exhausted or if the
    /// prechecked commit fails while installing versions.
    pub fn commit_fcw_prechecked(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.apply_fcw_commit(txn) {
            Ok((commit_seq, deferred)) => {
                debug_assert!(
                    deferred.is_empty(),
                    "commit_fcw_prechecked silently drops deferred COW frees"
                );
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, _txn)) => {
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    pub fn resolved_writes_for_commit(
        &self,
        txn: &Transaction,
    ) -> Result<Vec<(BlockNumber, Vec<u8>)>, CommitError> {
        txn.write_set()
            .keys()
            .copied()
            .map(|block| {
                self.resolved_write_bytes(txn, block)
                    .map(|bytes| (block, bytes))
            })
            .collect()
    }

    /// Commit with Serializable Snapshot Isolation (SSI) enforcement.
    ///
    /// This extends FCW with rw-antidependency tracking. A transaction aborts
    /// only when it is the pivot of a two-edge dangerous structure:
    ///
    /// 1. A concurrent transaction read a block this transaction writes.
    /// 2. This transaction read a block that a concurrent transaction wrote
    ///    after this transaction's snapshot.
    ///
    /// A single rw-antidependency edge remains serializable by itself and does
    /// not trigger an SSI abort. Read-only transactions never trigger SSI
    /// aborts.
    pub fn commit_ssi(&mut self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.commit_ssi_internal(txn) {
            Ok((commit_seq, deferred)) => {
                debug_assert!(
                    deferred.is_empty(),
                    "commit_ssi silently drops deferred COW frees"
                );
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, _txn)) => {
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    pub fn commit_ssi_with_cow_allocator(
        &mut self,
        txn: Transaction,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) -> Result<CommitSeq, CommitError> {
        let started = Instant::now();
        let txn_id = txn.id().0;
        let read_set_size = txn.read_set().len();
        let write_set_size = txn.pending_writes();
        self.runtime_metrics.record_commit_attempt();
        match self.commit_ssi_internal(txn) {
            Ok((commit_seq, deferred)) => {
                for block in deferred {
                    trace!(block = block.0, commit_seq = commit_seq.0, "cow_defer_free");
                    allocator.defer_free(block, commit_seq);
                }
                let _ = self.gc_cow_blocks(allocator, cx);
                self.emit_transaction_commit(txn_id, commit_seq, write_set_size, started);
                Ok(commit_seq)
            }
            Err((error, txn)) => {
                for intent in txn.cow_writes.values() {
                    allocator.defer_free(intent.new_physical, CommitSeq(0));
                }
                for orphan in txn.cow_orphans {
                    allocator.defer_free(orphan, CommitSeq(0));
                }
                let _ = self.gc_cow_blocks(allocator, cx);
                self.record_commit_abort(txn_id, read_set_size, write_set_size, &error);
                Err(error)
            }
        }
    }

    fn record_commit_abort(
        &mut self,
        txn_id: u64,
        read_set_size: usize,
        write_set_size: usize,
        error: &CommitError,
    ) {
        self.runtime_metrics.record_commit_abort(error);
        match error {
            CommitError::Conflict { .. } => self.emit_txn_aborted(TxnAbortedDetail {
                txn_id,
                reason: TxnAbortReason::FcwConflict,
                detail: Some(error.to_string()),
                read_set_size,
                write_set_size,
            }),
            CommitError::SsiConflict { concurrent_txn, .. } => {
                self.emit_txn_aborted(TxnAbortedDetail {
                    txn_id,
                    reason: TxnAbortReason::SsiCycle,
                    detail: Some(error.to_string()),
                    read_set_size,
                    write_set_size,
                });
                self.emit_serialization_conflict(
                    txn_id,
                    Some(concurrent_txn.0),
                    "two_edge_rw_antidependency_cycle",
                );
            }
            CommitError::ChainBackpressure { .. } => self.emit_txn_aborted(TxnAbortedDetail {
                txn_id,
                reason: TxnAbortReason::Timeout,
                detail: Some(error.to_string()),
                read_set_size,
                write_set_size,
            }),
            CommitError::DurabilityFailure { .. } => self.emit_txn_aborted(TxnAbortedDetail {
                txn_id,
                reason: TxnAbortReason::DurabilityFailure,
                detail: Some(error.to_string()),
                read_set_size,
                write_set_size,
            }),
        }
    }

    fn emit_transaction_commit(
        &mut self,
        txn_id: u64,
        commit_seq: CommitSeq,
        write_set_size: usize,
        started: Instant,
    ) {
        let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.runtime_metrics.record_commit_success(duration_us);
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::transaction_commit(TransactionCommitDetail {
                txn_id,
                commit_seq: commit_seq.0,
                write_set_size,
                duration_us,
            }),
            txn_id,
        );
    }

    fn emit_txn_aborted(&mut self, detail: TxnAbortedDetail) {
        self.aborted_transactions = self.aborted_transactions.saturating_add(1);
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        let txn_id = detail.txn_id;
        sink.append(&EvidenceRecord::txn_aborted(detail), txn_id);
    }

    fn emit_serialization_conflict(
        &mut self,
        txn_id: u64,
        conflicting_txn: Option<u64>,
        conflict_type: &str,
    ) {
        self.ssi_conflicts = self.ssi_conflicts.saturating_add(1);
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::serialization_conflict(SerializationConflictDetail {
                txn_id,
                conflicting_txn,
                conflict_type: conflict_type.to_owned(),
            }),
            txn_id,
        );
    }

    // ── Merge evidence emission helpers ────────────────────────────────────

    fn emit_merge_proof_checked(
        &self,
        txn_id: u64,
        block_id: u64,
        proof_variant: &str,
        valid: bool,
        rejection_reason: Option<&str>,
    ) {
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::merge_proof_checked(MergeProofCheckedDetail {
                txn_id,
                block_id,
                proof_variant: proof_variant.to_owned(),
                valid,
                rejection_reason: rejection_reason.map(str::to_owned),
            }),
            txn_id,
        );
    }

    fn emit_merge_applied(
        &self,
        txn_id: u64,
        merged_block_count: usize,
        combined_write_set_bytes: usize,
        proof_variant: &str,
    ) {
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::merge_applied(MergeAppliedDetail {
                txn_id,
                merged_block_count,
                combined_write_set_bytes,
                proof_variant: proof_variant.to_owned(),
            }),
            txn_id,
        );
    }

    fn emit_merge_rejected(&self, txn_id: u64, block_id: u64, proof_variant: &str, reason: &str) {
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::merge_rejected(MergeRejectedDetail {
                txn_id,
                block_id,
                proof_variant: proof_variant.to_owned(),
                reason: reason.to_owned(),
            }),
            txn_id,
        );
    }

    fn maybe_emit_policy_switch(&self, prev_effective: ConflictPolicy) {
        let new_effective = self.effective_policy();
        if prev_effective == new_effective {
            return;
        }
        let loss_strict = self
            .contention_metrics
            .expected_loss_strict(&self.adaptive_config);
        let loss_merge = self
            .contention_metrics
            .expected_loss_safe_merge(&self.adaptive_config);
        // Positive delta = the new policy is cheaper than the old one.
        let loss_old = match prev_effective {
            ConflictPolicy::Strict => loss_strict,
            _ => loss_merge,
        };
        let loss_new = match new_effective {
            ConflictPolicy::Strict => loss_strict,
            _ => loss_merge,
        };
        let delta = loss_old - loss_new;

        info!(
            target: "ffs::mvcc::merge",
            event = "mvcc_policy_switched",
            from_policy = ?prev_effective,
            to_policy = ?new_effective,
            expected_loss_delta = delta,
            trigger = "contention_rate_change",
        );
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::policy_switched(PolicySwitchedDetail {
                from_policy: format!("{prev_effective:?}"),
                to_policy: format!("{new_effective:?}"),
                expected_loss_delta: delta,
                trigger_reason: "contention_rate_change".to_owned(),
            }),
            0,
        );
    }

    fn emit_contention_sample(&self) {
        let m = &self.contention_metrics;
        let effective = self.effective_policy();
        info!(
            target: "ffs::mvcc::merge",
            event = "mvcc_contention_sample",
            conflict_rate = m.conflict_rate,
            merge_success_rate = m.merge_success_rate,
            abort_rate = m.abort_rate,
            total_commits = m.total_commits,
            total_conflicts = m.total_conflicts,
            total_merges = m.total_merges,
            total_aborts = m.total_aborts,
            effective_policy = ?effective,
        );
        let Some(sink) = &self.evidence_sink else {
            return;
        };
        sink.append(
            &EvidenceRecord::contention_sample(ContentionSampleDetail {
                conflict_rate: m.conflict_rate,
                merge_success_rate: m.merge_success_rate,
                abort_rate: m.abort_rate,
                total_commits: m.total_commits,
                total_conflicts: m.total_conflicts,
                total_merges: m.total_merges,
                total_aborts: m.total_aborts,
                effective_policy: format!("{effective:?}"),
            }),
            0,
        );
    }

    #[allow(clippy::result_large_err)]
    fn commit_fcw_internal(
        &mut self,
        txn: Transaction,
    ) -> Result<(CommitSeq, Vec<BlockNumber>), (CommitError, Transaction)> {
        if let Err(error) = self.preflight_fcw(&txn) {
            return Err((error, txn));
        }
        self.apply_fcw_commit(txn)
    }

    fn version_bytes_at(
        &self,
        block: BlockNumber,
        visible_high: CommitSeq,
    ) -> Option<std::borrow::Cow<'_, [u8]>> {
        // Conflict-merge only reads these bytes (`merge_bytes(&base, &latest, ..)`),
        // so return a borrow for the common uncompressed `Full` version instead of
        // cloning it into a fresh Vec; compressed versions still own their
        // decompressed bytes. Byte-identical; `&Cow` deref-coerces to `&[u8]`.
        self.versions.get(&block).and_then(|versions| {
            let idx = newest_visible_index(versions, visible_high)?;
            compression::resolve_data_with(versions, idx, |v| &v.data)
        })
    }

    fn resolved_write_bytes(
        &self,
        txn: &Transaction,
        block: BlockNumber,
    ) -> Result<Vec<u8>, CommitError> {
        self.resolved_write_bytes_with_policy(txn, block, self.effective_policy())
    }

    fn resolved_write_bytes_with_policy(
        &self,
        txn: &Transaction,
        block: BlockNumber,
        effective: ConflictPolicy,
    ) -> Result<Vec<u8>, CommitError> {
        let staged = txn
            .staged_write(block)
            .ok_or_else(|| CommitError::DurabilityFailure {
                detail: format!("write_set keys must have staged bytes: {block:?}"),
            })?;
        let observed = self.latest_commit_seq(block);
        if observed <= txn.snapshot.high {
            return Ok(staged.to_vec());
        }
        if effective == ConflictPolicy::Strict {
            return Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed,
            });
        }

        let proof = txn.merge_proof(block).cloned().unwrap_or_default();
        let base = self
            .version_bytes_at(block, txn.snapshot.high)
            .or_else(|| txn.staged_base(block).map(std::borrow::Cow::Borrowed))
            .unwrap_or_default();
        let latest = self.version_bytes_at(block, observed).unwrap_or_default();
        proof
            .merge_bytes(&base, &latest, staged)
            .ok_or(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed,
            })
    }

    /// Preflight validity check mirroring [`Self::resolved_write_bytes_with_policy`]
    /// but returning only a yes/no answer, WITHOUT building the merged block.
    /// The FCW preflight discards the merged bytes (it merely gates the commit);
    /// the install path (`resolved_write_bytes`) rebuilds them. Skipping the
    /// merged-output allocation here removes one block-sized alloc + copy per
    /// conflicting block on the contended commit path. Equivalent to
    /// `resolved_write_bytes_with_policy(..).is_ok()` by construction
    /// (`merge_valid == merge_bytes(..).is_some()`).
    fn resolved_write_valid_with_policy(
        &self,
        txn: &Transaction,
        block: BlockNumber,
        effective: ConflictPolicy,
    ) -> Result<(), CommitError> {
        let staged = txn
            .staged_write(block)
            .ok_or_else(|| CommitError::DurabilityFailure {
                detail: format!("write_set keys must have staged bytes: {block:?}"),
            })?;
        let observed = self.latest_commit_seq(block);
        if observed <= txn.snapshot.high {
            return Ok(());
        }
        if effective == ConflictPolicy::Strict {
            return Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed,
            });
        }

        let proof = txn.merge_proof(block).cloned().unwrap_or_default();
        let base = self
            .version_bytes_at(block, txn.snapshot.high)
            .or_else(|| txn.staged_base(block).map(std::borrow::Cow::Borrowed))
            .unwrap_or_default();
        let latest = self.version_bytes_at(block, observed).unwrap_or_default();
        if proof.merge_valid(&base, &latest, staged) {
            Ok(())
        } else {
            Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed,
            })
        }
    }

    /// Extract the short variant name from a `MergeProof`'s debug representation.
    fn merge_proof_variant_name(proof: &MergeProof) -> String {
        merge_proof_variant_name(proof).to_owned()
    }

    /// Handle a single block-level conflict during FCW preflight.
    ///
    /// Returns `Ok((variant, bytes_len))` if the conflict was resolved via
    /// merge, `Err` if the commit should be aborted.
    fn preflight_resolve_block_conflict(
        &self,
        txn: &Transaction,
        block: BlockNumber,
        latest: CommitSeq,
        effective: ConflictPolicy,
    ) -> Result<(String, usize), CommitError> {
        let proof = txn.merge_proof(block).cloned().unwrap_or_default();
        let variant = Self::merge_proof_variant_name(&proof);

        if effective == ConflictPolicy::Strict {
            self.emit_merge_check_and_reject(
                txn.id.0,
                block.0,
                &variant,
                "strict_policy_rejects_all_merges",
                "strict_fcw_conflict",
            );
            return Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed: latest,
            });
        }

        if self
            .resolved_write_valid_with_policy(txn, block, effective)
            .is_ok()
        {
            let bytes_len = txn.staged_write(block).map_or(0, <[u8]>::len);
            info!(
                target: "ffs::mvcc::merge",
                event = "mvcc_merge_proof_checked",
                txn_id = txn.id.0, block = block.0,
                proof_variant = %variant, valid = true,
            );
            self.emit_merge_proof_checked(txn.id.0, block.0, &variant, true, None);
            Ok((variant, bytes_len))
        } else {
            self.emit_merge_check_and_reject(
                txn.id.0,
                block.0,
                &variant,
                "merge_bytes_returned_none",
                "merge_validation_failed",
            );
            Err(CommitError::Conflict {
                block,
                snapshot: txn.snapshot.high,
                observed: latest,
            })
        }
    }

    /// Emit both a merge-proof-checked (invalid) and merge-rejected event.
    fn emit_merge_check_and_reject(
        &self,
        txn_id: u64,
        block_id: u64,
        variant: &str,
        check_reason: &str,
        reject_reason: &str,
    ) {
        info!(
            target: "ffs::mvcc::merge",
            event = "mvcc_merge_proof_checked",
            txn_id, block = block_id,
            proof_variant = %variant, valid = false,
            reason = %check_reason,
        );
        self.emit_merge_proof_checked(txn_id, block_id, variant, false, Some(check_reason));
        info!(
            target: "ffs::mvcc::merge",
            event = "mvcc_merge_rejected",
            txn_id, block = block_id,
            proof_variant = %variant,
            reason = %reject_reason,
        );
        self.emit_merge_rejected(txn_id, block_id, variant, reject_reason);
    }

    fn preflight_fcw(&mut self, txn: &Transaction) -> Result<(), CommitError> {
        validate_transaction_id(txn.id())?;

        let chain_cap = self.compression_policy.max_chain_length;
        let prev_effective = self.effective_policy();
        // Only Adaptive consumes the contention metrics (`effective_policy` reads
        // them to select a strategy; no production caller reads them otherwise).
        // Under a fixed policy (default SafeMerge) the per-commit `record_commit` +
        // `select_policy` (2-3x/commit under Adaptive) + policy-switch/sample
        // emissions are dead CPU — skip them. Sibling of the sharded-store gate
        // (73174f5b). Merge telemetry (`mvcc_merge_applied`) stays ungated since
        // merges also occur under SafeMerge.
        let record_metrics = matches!(self.conflict_policy, ConflictPolicy::Adaptive);
        let mut had_conflict = false;
        let mut merge_succeeded = false;
        let mut merged_block_count: usize = 0;
        let mut combined_write_bytes: usize = 0;
        let mut merge_variants: BTreeSet<String> = BTreeSet::new();

        for &block in txn.write_set().keys() {
            let latest = self.latest_commit_seq(block);
            if latest > txn.snapshot.high {
                had_conflict = true;
                let resolution_started = Instant::now();
                let resolution =
                    self.preflight_resolve_block_conflict(txn, block, latest, prev_effective);
                let resolution_latency_us =
                    u64::try_from(resolution_started.elapsed().as_micros()).unwrap_or(u64::MAX);
                self.runtime_metrics
                    .record_conflict_resolution_latency(resolution_latency_us);
                match resolution {
                    Ok((variant, bytes_len)) => {
                        merge_succeeded = true;
                        merged_block_count += 1;
                        combined_write_bytes += bytes_len;
                        merge_variants.insert(variant);
                    }
                    Err(err) => {
                        if record_metrics {
                            self.contention_metrics.record_commit(
                                self.adaptive_config.ema_alpha,
                                true,
                                false,
                                true,
                            );
                            self.contention_metrics.last_selected =
                                Some(self.contention_metrics.select_policy(&self.adaptive_config));
                            self.maybe_emit_policy_switch(prev_effective);
                        }
                        return Err(err);
                    }
                }
            }
            if let Some(cap) = chain_cap {
                if let Err(err) = self.enforce_chain_pressure(txn.id, block, cap) {
                    // Chain backpressure abort — still record the commit attempt.
                    if record_metrics {
                        self.contention_metrics.record_commit(
                            self.adaptive_config.ema_alpha,
                            had_conflict,
                            merge_succeeded,
                            true,
                        );
                        self.contention_metrics.last_selected =
                            Some(self.contention_metrics.select_policy(&self.adaptive_config));
                    }
                    return Err(err);
                }
            }
        }

        // Record successful preflight (no abort).
        if record_metrics {
            self.contention_metrics.record_commit(
                self.adaptive_config.ema_alpha,
                had_conflict,
                merge_succeeded,
                false,
            );
            // Update hysteresis state so the next select_policy call has a stable incumbent.
            self.contention_metrics.last_selected =
                Some(self.contention_metrics.select_policy(&self.adaptive_config));
        }

        // mvcc_merge_applied — emit after successful merge commit preflight.
        if merged_block_count > 0 {
            let variants_joined: String = merge_variants.into_iter().collect::<Vec<_>>().join("+");
            info!(
                target: "ffs::mvcc::merge",
                event = "mvcc_merge_applied",
                txn_id = txn.id.0,
                merged_block_count,
                combined_write_set_bytes = combined_write_bytes,
                proof_variant = %variants_joined,
            );
            self.emit_merge_applied(
                txn.id.0,
                merged_block_count,
                combined_write_bytes,
                &variants_joined,
            );
        }

        if record_metrics {
            self.maybe_emit_policy_switch(prev_effective);

            // Periodic contention sample (every 100 commits).
            if self.contention_metrics.total_commits % 100 == 0
                && self.contention_metrics.total_commits > 0
            {
                self.emit_contention_sample();
            }
        }

        Ok(())
    }

    fn next_commit_seq(&mut self) -> Result<CommitSeq, CommitError> {
        let current = self.next_commit;
        let Some(next) = current.checked_add(1) else {
            return Err(CommitError::DurabilityFailure {
                detail: format!("commit sequence exhausted at {current}"),
            });
        };
        self.next_commit = next;
        Ok(CommitSeq(current))
    }

    #[allow(clippy::result_large_err)]
    fn apply_fcw_commit(
        &mut self,
        txn: Transaction,
    ) -> Result<(CommitSeq, Vec<BlockNumber>), (CommitError, Transaction)> {
        if let Err(error) = validate_transaction_id(txn.id()) {
            return Err((error, txn));
        }

        // Resolve conflicts before moving staged writes out of the transaction.
        // The common no-conflict path stays borrow-only until the commit is
        // known to succeed, so aborts still return the original transaction
        // while successful commits can move owned staged bytes into storage.
        let snapshot_high = txn.snapshot.high;
        let effective = self.effective_policy();
        let mut merged_writes = BTreeMap::new();
        for (block, staged) in &txn.staged_writes {
            let block = *block;
            let observed = self.latest_commit_seq(block);
            if observed <= snapshot_high {
                continue;
            }
            if effective == ConflictPolicy::Strict {
                return Err((
                    CommitError::Conflict {
                        block,
                        snapshot: snapshot_high,
                        observed,
                    },
                    txn,
                ));
            }

            let base = self
                .version_bytes_at(block, snapshot_high)
                .unwrap_or_default();
            let latest = self.version_bytes_at(block, observed).unwrap_or_default();
            match staged
                .merge_proof
                .merge_bytes(&base, &latest, &staged.bytes)
            {
                Some(merged) => {
                    merged_writes.insert(block, merged);
                }
                None => {
                    return Err((
                        CommitError::Conflict {
                            block,
                            snapshot: snapshot_high,
                            observed,
                        },
                        txn,
                    ));
                }
            }
        }

        let commit_seq = match self.next_commit_seq() {
            Ok(seq) => seq,
            Err(error) => return Err((error, txn)),
        };
        let chain_cap = self.compression_policy.max_chain_length;
        let Transaction {
            id: txn_id,
            staged_writes,
            cow_writes,
            cow_orphans,
            ..
        } = txn;
        let dedup_enabled = self.compression_policy.dedup_identical;
        let store_full = matches!(self.compression_policy.algo, CompressionAlgo::None);

        for (block, staged) in staged_writes {
            let version_bytes = merged_writes.remove(&block).unwrap_or(staged.bytes);
            // Move the owned bytes straight into `Full` for the no-compression
            // store (the prior path re-`to_vec`d them in `compress_data`). Dedup
            // and non-`None` compression keep their existing output.
            let version_data =
                if dedup_enabled && self.is_identical_to_latest(block, &version_bytes) {
                    VersionData::Identical
                } else if store_full {
                    VersionData::full(version_bytes)
                } else {
                    self.compress_data(&version_bytes)
                };

            self.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn_id,
                data: version_data,
            });

            if let Some(intent) = cow_writes.get(&block) {
                self.physical_versions
                    .entry(block)
                    .or_default()
                    .push(PhysicalBlockVersion {
                        logical: block,
                        physical: intent.new_physical,
                        commit_seq,
                        writer: txn_id,
                    });
            }

            if let Some(cap) = chain_cap {
                self.enforce_chain_cap(block, cap);
                self.enforce_physical_chain_cap(block, cap);
            }
        }
        debug_assert!(merged_writes.is_empty());

        let deferred = Self::collect_cow_deferred_frees(&cow_writes, cow_orphans);
        Ok((commit_seq, deferred))
    }

    /// Whether `bytes` is byte-identical to the latest committed version of
    /// `block` — the dedup-`Identical` predicate, factored out of `maybe_dedup`
    /// so the commit apply path can test it without re-`to_vec`ing the data.
    fn is_identical_to_latest(&self, block: BlockNumber, bytes: &[u8]) -> bool {
        let Some(versions) = self.versions.get(&block) else {
            return false;
        };
        if versions.is_empty() {
            return false;
        }
        compression::resolve_data_with(versions, versions.len() - 1, |v| &v.data)
            .is_some_and(|existing| existing.as_ref() == bytes)
    }

    #[inline]
    fn merged_writes_after_preflight(
        &self,
        txn: &Transaction,
    ) -> Result<BTreeMap<BlockNumber, Vec<u8>>, CommitError> {
        let snapshot_high = txn.snapshot.high;
        let effective = self.effective_policy();
        let mut merged_writes = BTreeMap::new();
        for (block, staged) in &txn.staged_writes {
            let block = *block;
            let observed = self.latest_commit_seq(block);
            if observed <= snapshot_high {
                continue;
            }
            if effective == ConflictPolicy::Strict {
                return Err(CommitError::Conflict {
                    block,
                    snapshot: snapshot_high,
                    observed,
                });
            }

            let base = self
                .version_bytes_at(block, snapshot_high)
                .unwrap_or_default();
            let latest = self.version_bytes_at(block, observed).unwrap_or_default();
            let Some(merged) = staged
                .merge_proof
                .merge_bytes(&base, &latest, &staged.bytes)
            else {
                return Err(CommitError::Conflict {
                    block,
                    snapshot: snapshot_high,
                    observed,
                });
            };
            merged_writes.insert(block, merged);
        }
        Ok(merged_writes)
    }

    #[allow(clippy::result_large_err)]
    fn commit_ssi_internal(
        &mut self,
        txn: Transaction,
    ) -> Result<(CommitSeq, Vec<BlockNumber>), (CommitError, Transaction)> {
        if let Err(error) = self.preflight_fcw(&txn) {
            return Err((error, txn));
        }

        // Step 2: SSI two-edge rw-antidependency check.
        let checks_performed = match self.validate_ssi_read_set(&txn) {
            Ok(count) => count,
            Err(e) => return Err((e, txn)),
        };

        let mut merged_writes = match self.merged_writes_after_preflight(&txn) {
            Ok(writes) => writes,
            Err(error) => return Err((error, txn)),
        };

        let commit_seq = match self.next_commit_seq() {
            Ok(seq) => seq,
            Err(error) => return Err((error, txn)),
        };

        let Transaction {
            id: txn_id,
            snapshot,
            staged_writes,
            reads,
            cow_writes,
            cow_orphans,
        } = txn;
        let dedup_enabled = self.compression_policy.dedup_identical;
        let store_full = matches!(self.compression_policy.algo, CompressionAlgo::None);
        let write_keys: BTreeSet<BlockNumber> =
            staged_writes.iter().map(|(block, _)| *block).collect();

        for (block, staged) in staged_writes {
            let version_bytes = merged_writes.remove(&block).unwrap_or(staged.bytes);
            let version_data =
                if dedup_enabled && self.is_identical_to_latest(block, &version_bytes) {
                    trace!(
                        block = block.0,
                        bytes_saved = version_bytes.len(),
                        "version_dedup: identical to previous"
                    );
                    VersionData::Identical
                } else if store_full {
                    VersionData::full(version_bytes)
                } else {
                    self.compress_data(&version_bytes)
                };

            self.versions.entry(block).or_default().push(BlockVersion {
                block,
                commit_seq,
                writer: txn_id,
                data: version_data,
            });

            if let Some(intent) = cow_writes.get(&block) {
                self.physical_versions
                    .entry(block)
                    .or_default()
                    .push(PhysicalBlockVersion {
                        logical: block,
                        physical: intent.new_physical,
                        commit_seq,
                        writer: txn_id,
                    });
            }

            if let Some(cap) = self.compression_policy.max_chain_length {
                self.enforce_chain_cap(block, cap);
                self.enforce_physical_chain_cap(block, cap);
            }
        }
        debug_assert!(merged_writes.is_empty());

        let read_set_size = reads.len();
        let write_set_size = write_keys.len();
        self.ssi_log.push(CommittedTxnRecord {
            txn_id,
            commit_seq,
            snapshot,
            write_set: write_keys,
            read_set: reads,
        });

        info!(
            target: "ffs::ssi",
            txn_id = txn_id.0,
            read_set_size,
            write_set_size,
            checks_performed,
            commit_seq = commit_seq.0,
            "ssi_commit_validated"
        );

        let deferred = Self::collect_cow_deferred_frees(&cow_writes, cow_orphans);
        Ok((commit_seq, deferred))
    }

    /// Check if `new_bytes` are identical to the latest version for `block`.
    /// If so, return `VersionData::Identical` (dedup); otherwise `VersionData::Full` or compressed.
    pub(crate) fn maybe_dedup(&self, block: BlockNumber, new_bytes: &[u8]) -> VersionData {
        if let Some(versions) = self.versions.get(&block) {
            if !versions.is_empty() {
                // Resolve the latest version's data (might itself be Identical).
                if let Some(existing) =
                    compression::resolve_data_with(versions, versions.len() - 1, |v| &v.data)
                {
                    if existing.as_ref() == new_bytes {
                        trace!(
                            block = block.0,
                            chain_len = versions.len(),
                            bytes_saved = new_bytes.len(),
                            "version_dedup: identical to previous"
                        );
                        return VersionData::Identical;
                    }
                }
            }
        }
        self.compress_data(new_bytes)
    }

    pub(crate) fn compress_data(&self, new_bytes: &[u8]) -> VersionData {
        match self.compression_policy.algo {
            compression::CompressionAlgo::None => VersionData::full(new_bytes.to_vec()),
            compression::CompressionAlgo::Zstd { level } => {
                if let Ok(compressed) = zstd::encode_all(new_bytes, level)
                    && compressed.len() < new_bytes.len()
                {
                    return VersionData::Zstd(compressed);
                }
                VersionData::full(new_bytes.to_vec())
            }
            compression::CompressionAlgo::Brotli { level } => {
                let mut compressed = Vec::new();
                #[allow(clippy::cast_possible_wrap)]
                let params = brotli::enc::BrotliEncoderParams {
                    quality: level as i32,
                    ..Default::default()
                };
                let mut reader = new_bytes;
                if brotli::BrotliCompress(&mut reader, &mut compressed, &params).is_ok()
                    && compressed.len() < new_bytes.len()
                {
                    return VersionData::Brotli(compressed);
                }
                VersionData::full(new_bytes.to_vec())
            }
        }
    }

    /// Advance the internal transaction and commit counters so the next
    /// allocated IDs are at least `last_commit + 1` and `last_txn + 1`.
    ///
    /// Used during checkpoint / WAL replay to restore counter state.
    pub(crate) fn advance_counters(&mut self, last_commit: u64, last_txn: u64) {
        self.next_commit = self.next_commit.max(last_commit.saturating_add(1));
        self.next_txn = self.next_txn.max(last_txn.saturating_add(1));
    }

    /// Insert pre-built version chains for a block during checkpoint loading.
    pub(crate) fn insert_versions(&mut self, block: BlockNumber, versions: Vec<BlockVersion>) {
        self.versions.entry(block).or_default().extend(versions);
    }

    fn validate_ssi_read_set(&self, txn: &Transaction) -> Result<u64, CommitError> {
        let records = self
            .ssi_log
            .iter()
            .rev()
            .take_while(|record| record.commit_seq > txn.snapshot.high);
        let (checks_performed, dangerous_structure) = detect_ssi_dangerous_structure(txn, records);

        if let Some(dangerous_structure) = dangerous_structure {
            dangerous_structure.emit_logs(txn.id);
            return Err(dangerous_structure.to_commit_error());
        }

        trace!(
            target: "ffs::ssi",
            txn_id = txn.id.0,
            read_set_size = txn.reads.len(),
            write_set_size = txn.staged_writes.len(),
            checks_performed,
            "ssi_two_edge_check_clean"
        );
        Ok(checks_performed)
    }

    fn force_advance_oldest_snapshot(&mut self) -> Option<(CommitSeq, u64)> {
        let oldest = self.active_snapshots.keys().next().copied()?;
        let refs = self.active_snapshots.get_mut(&oldest)?;
        // This consumes one live device-reference without a real Drop: in both
        // branches `active_snapshots` ends up one short of the live inline
        // readers at `oldest`. Record the forced release so the eventual reader
        // Drop's `release_snapshot` succeeds (the invariant is "every register
        // is matched by a release OR a forced advance"), not so a genuine
        // double-free escapes detection.
        *self.force_advanced_releases.entry(oldest).or_insert(0) += 1;
        if *refs > 1 {
            *refs -= 1;
            return Some((oldest, *refs));
        }
        self.active_snapshots.remove(&oldest);
        Some((oldest, 0))
    }

    fn chain_trim_blocked_by_snapshot(&self, block: BlockNumber, watermark: CommitSeq) -> bool {
        self.versions
            .get(&block)
            .is_some_and(|versions| versions.len() > 1 && versions[1].commit_seq > watermark)
    }

    fn enforce_chain_pressure(
        &mut self,
        txn_id: TxnId,
        block: BlockNumber,
        max_len: usize,
    ) -> Result<(), CommitError> {
        let chain_len = self.versions.get(&block).map_or(0, Vec::len);
        if chain_len == 0 {
            return Ok(());
        }
        let max_len = max_len.max(1);
        let critical_len = Self::critical_chain_len(max_len);
        if chain_len < critical_len {
            return Ok(());
        }

        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        if !self.chain_trim_blocked_by_snapshot(block, watermark) {
            return Ok(());
        }

        warn!(
            target: "ffs::mvcc::gc",
            block = block.0,
            chain_len,
            cap = max_len,
            critical_len,
            watermark = watermark.0,
            "chain_pressure_snapshot_blocking"
        );

        if let Some((forced_snapshot, remaining_refs)) = self.force_advance_oldest_snapshot() {
            let new_watermark = self
                .watermark()
                .unwrap_or_else(|| self.current_snapshot().high);
            info!(
                target: "ffs::mvcc::gc",
                block = block.0,
                forced_snapshot = forced_snapshot.0,
                remaining_refs,
                new_watermark = new_watermark.0,
                "chain_pressure_force_advance_oldest_snapshot"
            );
            // Same O(tracked_blocks) evidence-only scan as the release_snapshot
            // path — gate on a real `enabled!` check so it never runs when the
            // evidence target is disabled (a lazy field expr is insufficient
            // under the dynamic EnvFilter; see the note in `release_snapshot`).
            // Gated at DEBUG, not INFO: the default `info` filter must NOT pay
            // this per-commit O(tracked_blocks) scan (it was ~46% of delete CPU
            // under the default filter). Enable explicitly with
            // `RUST_LOG=ffs::mvcc::evidence=debug` for the diagnostic.
            if tracing::enabled!(target: "ffs::mvcc::evidence", tracing::Level::DEBUG) {
                debug!(
                    target: "ffs::mvcc::evidence",
                    event = "snapshot_advanced",
                    old_commit_seq = forced_snapshot.0,
                    new_commit_seq = new_watermark.0,
                    versions_eligible = self.versions_eligible_at_watermark(new_watermark),
                    trigger = "chain_pressure"
                );
            }
            if !self.chain_trim_blocked_by_snapshot(block, new_watermark) {
                return Ok(());
            }
        }

        error!(
            target: "ffs::mvcc::gc",
            block = block.0,
            chain_len,
            cap = max_len,
            critical_len,
            watermark = watermark.0,
            "chain_backpressure_reject"
        );
        warn!(
            target: "ffs::mvcc::evidence",
            event = "txn_aborted",
            txn_id = txn_id.0,
            reason = "timeout",
            block = block.0,
            chain_len,
            cap = max_len,
            watermark = watermark.0
        );
        Err(CommitError::ChainBackpressure {
            block,
            chain_len,
            cap: max_len,
            critical_len,
            watermark,
        })
    }

    /// Enforce chain length cap for a block by pruning the oldest versions.
    ///
    /// Pruning is watermark-aware: versions are only dropped when doing so
    /// cannot break visibility for any active snapshot.
    fn enforce_chain_cap(&mut self, block: BlockNumber, max_len: usize) {
        let max_len = max_len.max(1);
        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        let retired = self
            .versions
            .get_mut(&block)
            .map_or_else(Vec::new, |versions| {
                let (trimmed, retired_versions) =
                    Self::trim_block_chain_to_cap(versions, max_len, watermark);
                if trimmed > 0 {
                    trace!(
                        block = block.0,
                        watermark = watermark.0,
                        trimmed,
                        remaining = versions.len(),
                        "chain_cap_enforced"
                    );
                } else if versions.len() > max_len {
                    debug!(
                        target: "ffs::mvcc::gc",
                        block = block.0,
                        watermark = watermark.0,
                        cap = max_len,
                        current_len = versions.len(),
                        "chain_cap_pending_snapshot_release"
                    );
                }
                retired_versions
            });
        if !retired.is_empty() {
            self.ebr_reclaimer.retire_versions(retired);
        }
    }

    /// Enforce chain cap for physical versions using the same watermark-safe
    /// rule as logical versions.
    fn enforce_physical_chain_cap(&mut self, block: BlockNumber, max_len: usize) {
        let max_len = max_len.max(1);
        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        if let Some(versions) = self.physical_versions.get_mut(&block) {
            let trimmed = Self::trim_physical_chain_to_cap(versions, max_len, watermark);
            if trimmed > 0 {
                trace!(
                    block = block.0,
                    watermark = watermark.0,
                    trimmed,
                    remaining = versions.len(),
                    "physical_chain_cap_enforced"
                );
            }
        }
    }

    fn trim_block_chain_to_cap(
        versions: &mut Vec<BlockVersion>,
        max_len: usize,
        watermark: CommitSeq,
    ) -> (usize, Vec<BlockVersion>) {
        let mut trim = 0_usize;
        while versions.len().saturating_sub(trim) > max_len {
            let next = trim + 1;
            if next >= versions.len() || versions[next].commit_seq > watermark {
                break;
            }
            trim += 1;
        }
        let retired = if trim > 0 {
            Self::make_chain_head_full(versions, trim);
            versions.drain(0..trim).collect()
        } else {
            Vec::new()
        };
        (trim, retired)
    }

    fn trim_physical_chain_to_cap(
        versions: &mut Vec<PhysicalBlockVersion>,
        max_len: usize,
        watermark: CommitSeq,
    ) -> usize {
        let mut trim = 0_usize;
        while versions.len().saturating_sub(trim) > max_len {
            let next = trim + 1;
            if next >= versions.len() || versions[next].commit_seq > watermark {
                break;
            }
            trim += 1;
        }
        if trim > 0 {
            versions.drain(0..trim);
        }
        trim
    }

    fn make_chain_head_full(versions: &mut [BlockVersion], keep_from: usize) {
        if keep_from < versions.len() && versions[keep_from].data.is_identical() {
            if let Some(full_data) =
                compression::resolve_data_with(versions, keep_from, |v| &v.data)
            {
                let full_data = full_data.into_owned();
                versions[keep_from].data = VersionData::full(full_data);
            }
        }
    }

    fn versions_eligible_at_watermark(&self, watermark: CommitSeq) -> u64 {
        self.versions
            .values()
            .map(|versions| {
                if versions.len() <= 1 {
                    return 0_u64;
                }
                let mut trim = 0_usize;
                while trim + 1 < versions.len() && versions[trim + 1].commit_seq <= watermark {
                    trim += 1;
                }
                u64::try_from(trim).unwrap_or(u64::MAX)
            })
            .sum()
    }

    fn collect_cow_deferred_frees(
        cow_writes: &BTreeMap<BlockNumber, CowRewriteIntent>,
        mut cow_orphans: BTreeSet<BlockNumber>,
    ) -> Vec<BlockNumber> {
        for intent in cow_writes.values() {
            if let Some(old_physical) = intent.old_physical
                && old_physical != intent.new_physical
            {
                cow_orphans.insert(old_physical);
            }
        }
        cow_orphans.into_iter().collect()
    }

    /// Prune SSI log entries older than `watermark`.
    ///
    /// Once no active transaction has a snapshot older than `watermark`,
    /// those log entries can no longer participate in antidependency
    /// detection and can be safely removed.
    pub fn prune_ssi_log(&mut self, watermark: CommitSeq) {
        self.ssi_log.retain(|r| r.commit_seq > watermark);
    }

    #[must_use]
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        self.versions
            .get(&block)
            .and_then(|v| v.last())
            .map_or(CommitSeq(0), |v| v.commit_seq)
    }

    #[must_use]
    pub fn read_visible(
        &self,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<std::borrow::Cow<'_, [u8]>> {
        self.versions.get(&block).and_then(|versions| {
            let idx = newest_visible_index(versions, snapshot.high)?;
            compression::resolve_data_with(versions, idx, |v| &v.data)
        })
    }

    #[must_use]
    pub fn read_visible_block_buf(
        &self,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<BlockBuf> {
        self.versions.get(&block).and_then(|versions| {
            let idx = newest_visible_index(versions, snapshot.high)?;
            compression::resolve_block_buf_with(versions, idx, |v| &v.data)
        })
    }

    #[must_use]
    pub fn read_visible_physical(
        &self,
        logical: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<BlockNumber> {
        if let Some(versions) = self.physical_versions.get(&logical)
            && let Some(idx) =
                newest_visible_index_by(versions, snapshot.high, |version| version.commit_seq)
        {
            return Some(versions[idx].physical);
        }
        self.read_visible(logical, snapshot).map(|_| logical)
    }

    #[must_use]
    pub fn latest_physical_block(&self, logical: BlockNumber) -> Option<BlockNumber> {
        self.read_visible_physical(logical, self.current_snapshot())
    }

    pub fn write_cow(
        &self,
        logical: BlockNumber,
        data: &[u8],
        txn: &mut Transaction,
        allocator: &dyn CowAllocator,
        cx: &Cx,
    ) -> FfsResult<BlockNumber> {
        let committed_old = txn
            .cow_writes
            .get(&logical)
            .and_then(|intent| intent.old_physical)
            .or_else(|| self.read_visible_physical(logical, txn.snapshot));
        let allocation_hint = txn
            .cow_writes
            .get(&logical)
            .map(|intent| intent.new_physical)
            .or(committed_old);
        let new_physical = allocator.alloc_cow(allocation_hint, cx)?;
        trace!(
            txn_id = txn.id.0,
            logical = logical.0,
            old_physical = committed_old.map(|b| b.0),
            new_physical = new_physical.0,
            "cow_allocation"
        );
        txn.stage_cow_rewrite(logical, committed_old, new_physical, data.to_vec());
        Ok(new_physical)
    }

    pub fn gc_cow_blocks(&self, allocator: &dyn CowAllocator, cx: &Cx) -> usize {
        let watermark = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        let freed = allocator.gc_free(watermark, cx);
        debug!(watermark = watermark.0, freed_blocks = freed, "cow_gc");
        freed
    }

    /// Flush all committed block versions to the underlying device.
    ///
    /// For each block that has committed versions in the MVCC store, this
    /// writes the latest version visible at the current snapshot to the
    /// base device.  This materialises in-memory MVCC data to persistent
    /// storage, which is required for write durability (e.g. `fsync`,
    /// unmount).
    ///
    /// Returns the number of blocks flushed.
    pub fn flush_to_device<D: BlockDevice>(&self, cx: &Cx, device: &D) -> FfsResult<usize> {
        self.flush_to_device_after(cx, device, CommitSeq(0))
            .map(|(flushed, _)| flushed)
    }

    /// Flush versions committed after `flushed_through` and return the snapshot
    /// through which the device is durable.
    ///
    /// The caller must serialize calls and advance its watermark only after this
    /// method succeeds. Keeping that cursor at the filesystem/device boundary
    /// lets the public [`Self::flush_to_device`] retain its full-checkpoint
    /// semantics for callers that supply unrelated devices.
    pub fn flush_to_device_after<D: BlockDevice>(
        &self,
        cx: &Cx,
        device: &D,
        flushed_through: CommitSeq,
    ) -> FfsResult<(usize, CommitSeq)> {
        let snapshot = self.current_snapshot();
        if snapshot.high <= flushed_through {
            return Ok((0, snapshot.high));
        }
        let mut flushed = 0usize;

        // `versions` is an FxHashMap (bd-mvccmap: O(1) commit/read entry vs the
        // old BTreeMap's O(log N)), so collect + sort the blocks here to restore
        // ASCENDING order before coalescing — flush is once per sync, so this one
        // O(N log N) sort is amortized over many O(1) per-op commits. Then
        // coalesce maximal runs of contiguous blocks and write each run with a
        // single `write_contiguous_blocks` (one ranged device write) instead of
        // one `write_block` per block. Bytes/locations identical to the scalar
        // path (bd-ryqep), so the on-disk state is unchanged.
        let mut run_start: Option<BlockNumber> = None;
        let mut run_next: u64 = 0; // next block number that would continue the run
        let mut run_buf: Vec<u8> = Vec::new();

        let mut sorted_versions: Vec<(&BlockNumber, &Vec<BlockVersion>)> =
            self.versions.iter().collect();
        sorted_versions.sort_unstable_by_key(|(block, _)| **block);
        for (block, versions) in sorted_versions {
            // Binary-search the newest visible version instead of an O(n) reverse
            // linear scan; identical index for an ascending-ordered chain.
            let Some(idx) = newest_visible_index(versions, snapshot.high) else {
                continue;
            };
            if versions[idx].commit_seq <= flushed_through {
                continue;
            }
            let Some(data) = compression::resolve_data_with(versions, idx, |v| &v.data) else {
                continue;
            };

            let continues_run = run_start.is_some() && block.0 == run_next;
            if !continues_run {
                if let Some(start) = run_start.take() {
                    device.write_contiguous_blocks(cx, start, &run_buf)?;
                    run_buf.clear();
                }
                run_start = Some(*block);
            }
            run_buf.extend_from_slice(&data);
            run_next = block.0.saturating_add(1);
            flushed += 1;
        }
        if let Some(start) = run_start.take() {
            device.write_contiguous_blocks(cx, start, &run_buf)?;
        }

        if flushed > 0 {
            device.sync(cx)?;
            debug!(flushed_blocks = flushed, "mvcc_flush_to_device");
        }
        Ok((flushed, snapshot.high))
    }

    pub fn prune_versions_older_than(&mut self, watermark: CommitSeq) {
        let mut retired_versions = Vec::new();
        let active_snapshot_count = self.active_snapshot_count();
        for (block, versions) in &mut self.versions {
            if versions.len() <= 1 {
                continue;
            }

            let mut keep_from = 0_usize;
            while keep_from + 1 < versions.len() {
                if versions[keep_from + 1].commit_seq <= watermark {
                    keep_from += 1;
                } else {
                    break;
                }
            }

            if keep_from > 0 {
                Self::make_chain_head_full(versions, keep_from);
                retired_versions.extend(versions.drain(0..keep_from));
                let oldest_retained_commit_seq =
                    versions.first().map_or(watermark.0, |v| v.commit_seq.0);
                info!(
                    target: "ffs::mvcc::evidence",
                    event = "version_gc",
                    block_id = block.0,
                    versions_freed = u64::try_from(keep_from).unwrap_or(u64::MAX),
                    oldest_retained_commit_seq
                );
            } else if versions.len() > 1 {
                let next_commit_seq = versions[1].commit_seq;
                if next_commit_seq > watermark {
                    debug!(
                        target: "ffs::mvcc::gc",
                        event = "gc_skip_pinned_version",
                        block_id = block.0,
                        blocked_commit_seq = next_commit_seq.0,
                        epoch_id = watermark.0,
                        pinned_by = "active_snapshot_watermark",
                        active_snapshot_count
                    );
                }
            }
        }
        if !retired_versions.is_empty() {
            self.runtime_metrics
                .record_versions_pruned(retired_versions.len());
            self.ebr_reclaimer.retire_versions(retired_versions);
        }

        for versions in self.physical_versions.values_mut() {
            if versions.len() <= 1 {
                continue;
            }

            let mut keep_from = 0_usize;
            while keep_from + 1 < versions.len() {
                if versions[keep_from + 1].commit_seq <= watermark {
                    keep_from += 1;
                } else {
                    break;
                }
            }

            if keep_from > 0 {
                versions.drain(0..keep_from);
            }
        }
    }

    // ── Watermark / active snapshot tracking ───────────────────────────

    /// Register a snapshot as active.  This prevents `prune_safe` from
    /// removing versions that this snapshot might still need.
    ///
    /// Multiple registrations of the same `CommitSeq` are ref-counted;
    /// each must be paired with a corresponding `release_snapshot`.
    pub fn register_snapshot(&mut self, snapshot: Snapshot) {
        let count = self.active_snapshots.entry(snapshot.high).or_insert(0);
        *count = count.saturating_add(1);
        trace!(
            commit_seq = snapshot.high.0,
            ref_count_after = *count,
            "snapshot_acquire (inline)"
        );
    }

    /// Release a previously registered snapshot.  When the last reference
    /// at a given `CommitSeq` is released, that sequence is no longer
    /// considered active and versions below it become eligible for pruning.
    ///
    /// Returns `true` if the snapshot was still registered, `false` if it
    /// was already fully released (a logic error by the caller, but not
    /// fatal).
    pub fn release_snapshot(&mut self, snapshot: Snapshot) -> bool {
        let old_watermark = self.watermark();
        if let Some(count) = self.active_snapshots.get_mut(&snapshot.high) {
            *count = count.saturating_sub(1);
            let count_after = *count;
            if count_after == 0 {
                self.active_snapshots.remove(&snapshot.high);
                debug!(
                    commit_seq = snapshot.high.0,
                    "snapshot_final_release (inline): ref_count reached 0"
                );
            } else {
                trace!(
                    commit_seq = snapshot.high.0,
                    ref_count_after = count_after,
                    "snapshot_release (inline)"
                );
            }
            if let Some(old_commit_seq) = old_watermark.map(|wm| wm.0) {
                let new_watermark = self
                    .watermark()
                    .unwrap_or_else(|| self.current_snapshot().high);
                // `versions_eligible_at_watermark` is an O(tracked_blocks) scan
                // of every version chain, and it feeds ONLY this evidence log
                // field. It MUST be skipped when the evidence target is
                // disabled. A lazy `info!` field expression is NOT enough: the
                // `fmt`+`EnvFilter` subscriber registers the callsite as
                // `Interest::sometimes`, so tracing evaluates the field then
                // filters at runtime — the full scan still ran on EVERY write
                // commit (71% of write-path self-time; ~5x slower 4 KiB writes).
                // Gate on a real runtime `enabled!` check so the scan only runs
                // when a subscriber will actually record the event. Gated at
                // DEBUG, not INFO: the default `info` filter must NOT pay this
                // per-commit O(tracked_blocks) scan (it dominated write- and
                // delete-commit CPU under the default filter). Enable with
                // `RUST_LOG=ffs::mvcc::evidence=debug` for the diagnostic.
                if new_watermark.0 > old_commit_seq
                    && tracing::enabled!(target: "ffs::mvcc::evidence", tracing::Level::DEBUG)
                {
                    debug!(
                        target: "ffs::mvcc::evidence",
                        event = "snapshot_advanced",
                        old_commit_seq,
                        new_commit_seq = new_watermark.0,
                        versions_eligible = self.versions_eligible_at_watermark(new_watermark),
                        trigger = "release_snapshot"
                    );
                }
            }
            true
        } else if let Some(pending) = self.force_advanced_releases.get_mut(&snapshot.high) {
            // The snapshot was force-aged-out by chain-pressure relief while
            // this reader still held it; this Drop is the expected late
            // release, not a double-free.
            *pending -= 1;
            if *pending == 0 {
                self.force_advanced_releases.remove(&snapshot.high);
            }
            trace!(
                commit_seq = snapshot.high.0,
                "snapshot_release (inline): matched a prior chain-pressure force-advance"
            );
            true
        } else {
            error!(
                commit_seq = snapshot.high.0,
                "ref_count_underflow (inline): release called on unregistered snapshot"
            );
            false
        }
    }

    /// The oldest active snapshot, or `None` if no snapshots are
    /// registered.
    ///
    /// This is the **safe watermark**: pruning versions with
    /// `commit_seq < watermark` will not break any active reader.
    #[must_use]
    pub fn watermark(&self) -> Option<CommitSeq> {
        self.active_snapshots.keys().next().copied()
    }

    /// Number of currently active (registered) snapshots.
    #[must_use]
    pub fn active_snapshot_count(&self) -> usize {
        self.active_snapshots
            .values()
            .fold(0_usize, |total, count| {
                total.saturating_add(usize::try_from(*count).unwrap_or(usize::MAX))
            })
    }

    /// Prune versions that are no longer needed by any active snapshot.
    ///
    /// Equivalent to `prune_versions_older_than(watermark)` where
    /// `watermark` is the oldest active snapshot.  If no snapshots are
    /// registered, prunes up to the current commit sequence (i.e., keeps
    /// only the latest version per block).
    ///
    /// Returns the watermark that was used.
    pub fn prune_safe(&mut self) -> CommitSeq {
        let wm = self
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        // `version_count()` is an O(tracked_blocks) scan, and it runs TWICE here
        // (before + after) ONLY to compute `freed`/`remaining` for the debug
        // trace below. Same disabled-log O(N) antipattern as the per-commit scan
        // fixed in the write path (b1619f0b): gate both scans behind a real
        // `enabled!` check so they never run when the gc logs are off (a lazy
        // field expr is insufficient under the dynamic EnvFilter). Enabling
        // TRACE implies DEBUG, so the DEBUG check covers both branches. The
        // actual pruning (`prune_versions_older_than`) always runs.
        let log_counts = tracing::enabled!(tracing::Level::DEBUG);
        let old_count = if log_counts { self.version_count() } else { 0 };
        self.prune_versions_older_than(wm);
        if log_counts {
            let new_count = self.version_count();
            let freed = old_count.saturating_sub(new_count);
            if freed > 0 {
                debug!(
                    watermark = wm.0,
                    versions_freed = freed,
                    versions_remaining = new_count,
                    "watermark_advance: pruned old versions"
                );
            } else {
                trace!(
                    watermark = wm.0,
                    versions_count = new_count,
                    "gc_eligible: no versions to prune"
                );
            }
        }
        if !self.active_snapshots.is_empty() {
            trace!(
                active_snapshots = self.active_snapshot_count(),
                oldest_active = ?self.watermark(),
                "gc_blocked: active snapshots prevent full pruning"
            );
        }
        wm
    }

    /// Total number of block versions stored across all blocks.
    #[must_use]
    pub fn version_count(&self) -> usize {
        self.versions.values().map(Vec::len).sum()
    }

    /// Number of distinct blocks that have at least one version.
    #[must_use]
    pub fn block_count_versioned(&self) -> usize {
        self.versions.len()
    }
}

// ── SnapshotRegistry: thread-safe, standalone snapshot lifecycle ──────────────

/// Thread-safe snapshot registry for managing active snapshot lifetimes.
///
/// This is decoupled from `MvccStore` so that FUSE request handlers can
/// acquire/release snapshots without holding the version-store lock.
/// Snapshot operations only contend on the registry's internal lock.
///
/// # Lock-ordering invariant (bd-7esyh)
///
/// `SnapshotRegistry` holds two `parking_lot::RwLock`es —
/// `active: RwLock<BTreeMap<CommitSeq, u64>>` (lock-rank 0) and
/// `oldest_registered_at: RwLock<Option<Instant>>` (lock-rank 1).
/// The order is **`active` → `oldest_registered_at`**. All methods
/// comply:
///
/// | Method            | active                | oldest_registered_at | Notes                              |
/// |-------------------|-----------------------|----------------------|------------------------------------|
/// | `register`        | W (held across)       | R then W (nested)    | nested under active is intentional |
/// | `release`         | W → drop → -          | W (only after drop)  | active dropped before oldest taken |
/// | `check_stalls`    | R (via `watermark`)   | R (drops first)      | oldest read+dropped, then active   |
/// | `watermark`       | R                     | -                    | leaf                               |
/// | `distinct_count`  | R                     | -                    | leaf                               |
/// | `acquired_total` / `released_total` | -       | -                    | atomic-only                        |
///
/// **Any new method that acquires `oldest_registered_at` BEFORE
/// `active` would deadlock against `register()` running
/// concurrently.** Specifically, `register()` deliberately nests
/// `oldest_registered_at.read()/.write()` inside `active.write()`
/// to keep the watermark timestamp atomically consistent with the
/// active set; an inverse path elsewhere would form an AB-BA cycle.
///
/// The `snapshot_registry_concurrent_register_release_check_stalls_no_hang`
/// regression test exercises this contract under contention with a
/// watchdog timeout.
#[derive(Debug)]
pub struct SnapshotRegistry {
    /// Active snapshot ref counts. **Lock-rank 0** — must be acquired
    /// before `oldest_registered_at`. `register` nests
    /// `oldest_registered_at` reads/writes inside `active.write()`;
    /// `release` always drops `active` before touching
    /// `oldest_registered_at`.
    active: RwLock<BTreeMap<CommitSeq, u64>>,
    /// Timestamp of the oldest currently active snapshot registration.
    /// Used for stall detection. **Lock-rank 1** — must be acquired
    /// AFTER `active` (or alone for read+drop pattern in
    /// `check_stalls`). Never acquire `active` while holding this lock.
    oldest_registered_at: RwLock<Option<Instant>>,
    /// Duration threshold beyond which a stalled watermark is logged.
    stall_threshold_secs: u64,
    // Counters for metrics (monotonic).
    acquired_total: std::sync::atomic::AtomicU64,
    released_total: std::sync::atomic::AtomicU64,
    /// Lock-free watermark for GC — updated on register/release,
    /// readable without acquiring any lock.
    atomic_watermark: rcu::AtomicWatermark,
}

impl Default for SnapshotRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotRegistry {
    /// Create a new empty registry with the default stall threshold (60s).
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: RwLock::new(BTreeMap::new()),
            oldest_registered_at: RwLock::new(None),
            stall_threshold_secs: 60,
            acquired_total: std::sync::atomic::AtomicU64::new(0),
            released_total: std::sync::atomic::AtomicU64::new(0),
            atomic_watermark: rcu::AtomicWatermark::new(),
        }
    }

    /// Create a registry with a custom stall threshold.
    #[must_use]
    pub fn with_stall_threshold(stall_threshold_secs: u64) -> Self {
        Self {
            stall_threshold_secs,
            ..Self::new()
        }
    }

    /// Acquire a snapshot handle from an `Arc<SnapshotRegistry>`.
    ///
    /// The snapshot is registered as active and will prevent GC of versions
    /// at or after this commit sequence until the returned handle is dropped.
    pub fn acquire(this: &Arc<Self>, snapshot: Snapshot) -> SnapshotHandle {
        this.register(snapshot);
        SnapshotHandle {
            snapshot,
            registry: Arc::clone(this),
        }
    }

    /// Register a snapshot as active (increment ref count).
    pub fn register(&self, snapshot: Snapshot) {
        let mut active = self.active.write();
        let count = active.entry(snapshot.high).or_insert(0);
        *count = count.saturating_add(1);
        let count_after = *count;

        // Track oldest registration time.
        if active.len() == 1 || self.oldest_registered_at.read().is_none() {
            *self.oldest_registered_at.write() = Some(Instant::now());
        }

        // Update atomic watermark (lock-free GC reads).
        if let Some(&min_seq) = active.keys().next() {
            self.atomic_watermark.store(min_seq.0);
        }
        drop(active);

        saturating_increment_atomic(&self.acquired_total, Ordering::Relaxed);

        trace!(
            commit_seq = snapshot.high.0,
            ref_count_after = count_after,
            "snapshot_acquire"
        );
    }

    /// Release a previously registered snapshot (decrement ref count).
    ///
    /// Returns `true` if the snapshot was still registered, `false` if
    /// it was already fully released (caller bug, but not fatal).
    pub fn release(&self, snapshot: Snapshot) -> bool {
        let mut active = self.active.write();
        let Some(mut count_after) = active.get(&snapshot.high).copied() else {
            error!(
                commit_seq = snapshot.high.0,
                "ref_count_underflow: release called on unregistered snapshot"
            );
            return false;
        };

        let was_oldest = active.keys().next().copied() == Some(snapshot.high);
        let mut clear_oldest = false;
        let mut reset_oldest = false;
        count_after = count_after.saturating_sub(1);
        if count_after == 0 {
            active.remove(&snapshot.high);
            debug!(
                commit_seq = snapshot.high.0,
                "snapshot_final_release: ref_count reached 0"
            );
            if active.is_empty() {
                clear_oldest = true;
            } else if was_oldest {
                reset_oldest = true;
            }
        } else {
            active.insert(snapshot.high, count_after);
            trace!(
                commit_seq = snapshot.high.0,
                ref_count_after = count_after,
                "snapshot_release"
            );
        }

        // Update atomic watermark (lock-free GC reads).
        if let Some(&min_seq) = active.keys().next() {
            self.atomic_watermark.store(min_seq.0);
        } else {
            self.atomic_watermark.clear();
        }
        drop(active);
        if clear_oldest {
            *self.oldest_registered_at.write() = None;
        } else if reset_oldest {
            // Reset to now — imprecise but avoids tracking per-snapshot times.
            *self.oldest_registered_at.write() = Some(Instant::now());
        }

        saturating_increment_atomic(&self.released_total, Ordering::Relaxed);
        true
    }

    /// The oldest active snapshot (safe GC watermark), or `None` if empty.
    ///
    /// This acquires a brief read lock on the active set for an authoritative
    /// answer. For lock-free (possibly slightly stale) reads, use
    /// [`watermark_lockfree`](Self::watermark_lockfree).
    #[must_use]
    pub fn watermark(&self) -> Option<CommitSeq> {
        self.active.read().keys().next().copied()
    }

    /// Execute a closure while holding the registry's read lock, passing
    /// the current watermark. This prevents concurrent `register()` calls
    /// from inserting a snapshot below the watermark during pruning.
    #[allow(clippy::significant_drop_tightening)]
    pub fn watermark_under_guard<R>(&self, f: impl FnOnce(Option<CommitSeq>) -> R) -> R {
        let active = self.active.read();
        let wm = active.keys().next().copied();
        // Intentionally hold `active` (read lock) during `f` to prevent
        // concurrent snapshot registration below the watermark.
        f(wm)
    }

    /// Lock-free watermark query via RCU-style atomic.
    ///
    /// Returns the oldest active snapshot commit sequence, or `None` if no
    /// snapshots are registered. This reads an atomic integer — no lock
    /// acquisition, no atomic increment on the reader path.
    ///
    /// The value may be very slightly stale if a concurrent register/release
    /// is in progress, but it is always conservative: the returned watermark
    /// is never *newer* than the true minimum, so GC decisions based on it
    /// are always safe (may keep versions slightly longer, never too short).
    #[inline]
    #[must_use]
    pub fn watermark_lockfree(&self) -> Option<CommitSeq> {
        self.atomic_watermark.load().map(CommitSeq)
    }

    /// Total number of active snapshot references (counting duplicates).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.read().values().fold(0_usize, |total, count| {
            total.saturating_add(usize::try_from(*count).unwrap_or(usize::MAX))
        })
    }

    /// Number of distinct commit sequences with active snapshots.
    #[must_use]
    pub fn distinct_count(&self) -> usize {
        self.active.read().len()
    }

    /// Check for stalled watermark and log if threshold exceeded.
    ///
    /// Returns `Some(stall_duration_secs)` if stalled, `None` otherwise.
    pub fn check_stalls(&self) -> Option<u64> {
        let oldest = *self.oldest_registered_at.read();
        if let (Some(registered_at), Some(wm)) = (oldest, self.watermark()) {
            let elapsed = registered_at.elapsed().as_secs();
            if elapsed >= self.stall_threshold_secs {
                info!(
                    current_watermark = wm.0,
                    oldest_active = wm.0,
                    stall_duration_secs = elapsed,
                    "watermark_stall: oldest active snapshot held for > {}s",
                    self.stall_threshold_secs
                );
                return Some(elapsed);
            }
        }
        None
    }

    /// Total snapshots acquired since creation (monotonic counter).
    #[must_use]
    pub fn acquired_total(&self) -> u64 {
        self.acquired_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total snapshots released since creation (monotonic counter).
    #[must_use]
    pub fn released_total(&self) -> u64 {
        self.released_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// RAII handle that releases a snapshot when dropped.
///
/// Acquire via [`SnapshotRegistry::acquire`].  The snapshot remains
/// active (preventing GC of versions at or after its commit sequence)
/// until this handle is dropped.  Panic-safe: `Drop` is always called.
#[derive(Debug)]
pub struct SnapshotHandle {
    snapshot: Snapshot,
    registry: Arc<SnapshotRegistry>,
}

impl SnapshotHandle {
    /// The snapshot this handle protects.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// Reference to the underlying registry.
    #[must_use]
    pub fn registry(&self) -> &Arc<SnapshotRegistry> {
        &self.registry
    }
}

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        let released = self.registry.release(self.snapshot);
        debug_assert!(
            released,
            "SnapshotHandle: snapshot was not registered or already released: {:?}",
            self.snapshot
        );
    }
}

/// Flush lifecycle that pins MVCC snapshots while dirty cache blocks are flushed.
///
/// The pin is held for the full lifetime of [`FlushPinToken`], preventing
/// `prune_safe` / `prune_versions_older_than` from reclaiming versions that the
/// in-flight flush still references.
#[derive(Debug, Clone)]
pub struct StoreBackedMvccFlushLifecycle {
    store: Arc<RwLock<MvccStore>>,
    active_flush_pins: Arc<AtomicU64>,
    acquired_flush_pins: Arc<AtomicU64>,
    released_flush_pins: Arc<AtomicU64>,
}

impl StoreBackedMvccFlushLifecycle {
    #[must_use]
    pub fn new(store: Arc<RwLock<MvccStore>>) -> Self {
        Self {
            store,
            active_flush_pins: Arc::new(AtomicU64::new(0)),
            acquired_flush_pins: Arc::new(AtomicU64::new(0)),
            released_flush_pins: Arc::new(AtomicU64::new(0)),
        }
    }

    #[must_use]
    pub fn store(&self) -> &Arc<RwLock<MvccStore>> {
        &self.store
    }

    #[must_use]
    pub fn active_flush_pins(&self) -> u64 {
        self.active_flush_pins.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn acquired_flush_pins(&self) -> u64 {
        self.acquired_flush_pins.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn released_flush_pins(&self) -> u64 {
        self.released_flush_pins.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct StoreBackedFlushPin {
    store: Arc<RwLock<MvccStore>>,
    snapshot: Snapshot,
    block: BlockNumber,
    commit_seq: CommitSeq,
    pin_id: u64,
    active_flush_pins: Arc<AtomicU64>,
    released_flush_pins: Arc<AtomicU64>,
}

impl Drop for StoreBackedFlushPin {
    fn drop(&mut self) {
        let released = self.store.write().release_snapshot(self.snapshot);
        if !released {
            warn!(
                target: "ffs::mvcc::flush",
                event = "flush_epoch_guard_release_underflow",
                block_id = self.block.0,
                epoch_id = self.commit_seq.0,
                flush_pin_id = self.pin_id
            );
        }

        if self
            .active_flush_pins
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_sub(1)
            })
            .is_err()
        {
            warn!(
                target: "ffs::mvcc::flush",
                event = "flush_epoch_guard_active_counter_underflow",
                block_id = self.block.0,
                epoch_id = self.commit_seq.0,
                flush_pin_id = self.pin_id
            );
        }

        saturating_increment_atomic(&self.released_flush_pins, Ordering::Relaxed);
        trace!(
            target: "ffs::mvcc::flush",
            event = "flush_epoch_guard_released",
            block_id = self.block.0,
            epoch_id = self.commit_seq.0,
            flush_pin_id = self.pin_id,
            blocks_flushed = 1_u64
        );
    }
}

impl MvccFlushLifecycle for StoreBackedMvccFlushLifecycle {
    fn pin_for_flush(&self, block: BlockNumber, commit_seq: CommitSeq) -> FfsResult<FlushPinToken> {
        if commit_seq == CommitSeq(0) {
            return Ok(FlushPinToken::noop());
        }

        let snapshot = Snapshot { high: commit_seq };
        self.store.write().register_snapshot(snapshot);

        saturating_increment_atomic(&self.active_flush_pins, Ordering::SeqCst);
        let pin_id = saturating_increment_atomic(&self.acquired_flush_pins, Ordering::Relaxed);
        trace!(
            target: "ffs::mvcc::flush",
            event = "flush_epoch_guard_acquired",
            block_id = block.0,
            epoch_id = commit_seq.0,
            flush_pin_id = pin_id
        );

        Ok(FlushPinToken::new(StoreBackedFlushPin {
            store: Arc::clone(&self.store),
            snapshot,
            block,
            commit_seq,
            pin_id,
            active_flush_pins: Arc::clone(&self.active_flush_pins),
            released_flush_pins: Arc::clone(&self.released_flush_pins),
        }))
    }

    fn mark_persisted(&self, block: BlockNumber, commit_seq: CommitSeq) -> FfsResult<()> {
        trace!(
            target: "ffs::mvcc::flush",
            event = "flush_mark_persisted",
            block_id = block.0,
            epoch_id = commit_seq.0
        );
        Ok(())
    }
}

/// Snapshot-aware block device wrapper.
///
/// Reads check the `MvccStore` for a version visible at the configured
/// snapshot before falling back to the base device.  Writes stage data
/// into the version store immediately (write-through to the base device
/// is deferred to commit time).
///
/// # Concurrency
///
/// The `MvccStore` is behind a `parking_lot::RwLock`:
/// - **Reads** acquire a shared (`read`) lock — many concurrent readers.
/// - **Writes/commits** acquire an exclusive (`write`) lock.
/// - The base device read (fallback path) happens **outside** the lock.
///
/// Snapshot ownership mode for `MvccBlockDevice`.
///
/// Either the device manages its snapshot via the `MvccStore`'s inline
/// tracking (legacy) or via a standalone [`SnapshotHandle`] (preferred).
#[derive(Debug)]
enum SnapshotOwnership {
    /// Snapshot registered on MvccStore; released in Drop.
    Inline { snapshot: Snapshot },
    /// Snapshot managed by a SnapshotHandle (RAII, auto-released on drop).
    Handle { handle: SnapshotHandle },
    /// Snapshot NOT registered on the store (bd-eflng). Used by read-only
    /// adapters where no writes occur, so no version is ever pruned and the
    /// active-snapshot ref-counting is pure overhead. Registering/releasing it
    /// would take the store *write* lock on every adapter construction/drop,
    /// serializing concurrent readers. Drop does nothing.
    Unregistered { snapshot: Snapshot },
}

#[derive(Debug)]
pub struct MvccBlockDevice<D: BlockDevice> {
    base: D,
    store: Arc<RwLock<MvccStore>>,
    ownership: SnapshotOwnership,
    /// When true, reads resolve at the store's *current* committed snapshot
    /// rather than the construction-time snapshot. This gives read-your-writes
    /// to a no-transaction adapter whose own `write_block` commits advance the
    /// store (each `write_block` begins+commits a single-block txn at a higher
    /// seq). Without it, a write followed by a read of the same block through
    /// one adapter instance returns stale data, because the read stays pinned
    /// to the older construction-time snapshot — the bug behind bd-vdi91
    /// (failed-mkdir / rename-over-existing leaving a stale block-bitmap csum).
    /// Fixed-snapshot readers (historical/isolation views) leave this false.
    read_your_writes: bool,
}

impl<D: BlockDevice> MvccBlockDevice<D> {
    /// Create a new MVCC block device at a given snapshot.
    ///
    /// The `store` is shared across all devices/transactions that
    /// participate in the same MVCC group.  The snapshot is tracked
    /// via `MvccStore`'s inline active_snapshots.
    pub fn new(base: D, store: Arc<RwLock<MvccStore>>, snapshot: Snapshot) -> Self {
        store.write().register_snapshot(snapshot);
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Inline { snapshot },
            read_your_writes: false,
        }
    }

    /// Construct a read-only adapter that does NOT register its snapshot on the
    /// store (bd-eflng). Safe only for immutable/read-only filesystem views:
    /// registration exists to hold back version pruning for live readers, but
    /// with no writers nothing is ever pruned, and no MVCC overlay version can
    /// become visible. Reads therefore go straight to the base device instead of
    /// taking a store read lock for a guaranteed-miss overlay probe.
    #[must_use]
    pub fn new_unregistered(base: D, store: Arc<RwLock<MvccStore>>, snapshot: Snapshot) -> Self {
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Unregistered { snapshot },
            read_your_writes: false,
        }
    }

    /// Resolve reads at the store's current committed snapshot instead of the
    /// construction-time snapshot, giving a no-transaction adapter
    /// read-your-writes across its own `write_block` commits. See the
    /// `read_your_writes` field docs (bd-vdi91).
    #[must_use]
    pub fn with_read_your_writes(mut self) -> Self {
        self.read_your_writes = true;
        self
    }

    /// Create a new MVCC block device using a [`SnapshotRegistry`] for
    /// lifecycle management.
    ///
    /// The snapshot is tracked via the registry's RAII handle, which
    /// decouples snapshot lifecycle from the version-store lock.
    pub fn with_registry(
        base: D,
        store: Arc<RwLock<MvccStore>>,
        snapshot: Snapshot,
        registry: &Arc<SnapshotRegistry>,
    ) -> Self {
        let handle = SnapshotRegistry::acquire(registry, snapshot);
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Handle { handle },
            read_your_writes: false,
        }
    }

    /// The construction-time snapshot this device was created at.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        match &self.ownership {
            SnapshotOwnership::Inline { snapshot }
            | SnapshotOwnership::Unregistered { snapshot } => *snapshot,
            SnapshotOwnership::Handle { handle } => handle.snapshot(),
        }
    }

    /// The snapshot reads actually resolve at: the store's current committed
    /// snapshot when `read_your_writes` is set, else the construction-time one.
    fn read_snapshot(&self) -> Snapshot {
        if self.read_your_writes {
            self.store.read().current_snapshot()
        } else {
            self.snapshot()
        }
    }

    /// Unregistered devices are used only for immutable/read-only filesystem
    /// views: no writer can create MVCC overlay versions, so every overlay probe
    /// is a guaranteed miss. Treat that mode as a direct base-device view.
    fn reads_base_directly(&self) -> bool {
        matches!(&self.ownership, SnapshotOwnership::Unregistered { .. }) && !self.read_your_writes
    }

    /// Shared reference to the MVCC store.
    #[must_use]
    pub fn store(&self) -> &Arc<RwLock<MvccStore>> {
        &self.store
    }

    /// Reference to the underlying base device.
    #[must_use]
    pub fn base(&self) -> &D {
        &self.base
    }
}

impl<D: BlockDevice> Drop for MvccBlockDevice<D> {
    fn drop(&mut self) {
        match &self.ownership {
            SnapshotOwnership::Inline { snapshot } => {
                let released = self.store.write().release_snapshot(*snapshot);
                debug_assert!(
                    released,
                    "mvcc snapshot was not registered or already released: {snapshot:?}"
                );
            }
            SnapshotOwnership::Unregistered { .. } | SnapshotOwnership::Handle { .. } => {
                // No inline registration was acquired here.
            }
        }
    }
}

impl<D: BlockDevice> BlockDevice for MvccBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
        if self.reads_base_directly() {
            return self.base.read_block(cx, block);
        }

        let snap = self.read_snapshot();
        // Check version store first (shared lock, no I/O).
        {
            let guard = self.store.read();
            if let Some(buf) = guard.read_visible_block_buf(block, snap) {
                // Full uncompressed versions now share the stored aligned block
                // buffer (`Arc::clone`), while compressed versions still
                // materialize exactly the decompressed bytes into a fresh buffer.
                return Ok(buf);
            }
        }
        // Fall back to base device (no lock held).
        self.base.read_block(cx, block)
    }

    fn supports_contiguous_reads(&self) -> bool {
        self.base.supports_contiguous_reads()
    }

    fn read_contiguous_blocks(
        &self,
        cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> ffs_error::Result<()> {
        if bufs.is_empty() {
            return Ok(());
        }

        let count = u64::try_from(bufs.len())
            .map_err(|_| FfsError::Format("block count does not fit u64".to_owned()))?;
        start
            .0
            .checked_add(count)
            .ok_or_else(|| FfsError::Format("block range overflow".to_owned()))?;
        if self.reads_base_directly() {
            return self.base.read_contiguous_blocks(cx, start, bufs);
        }
        let snap = self.read_snapshot();

        // Single pass under one read guard at a single snapshot: capture the
        // bytes of MVCC-visible blocks and leave the rest as base gaps. No
        // device I/O is performed while the lock is held. Using one snapshot for
        // the whole range (rather than re-fetching per block as the prior
        // per-block `read_block` loop did) also keeps the contiguous read
        // internally consistent under `read_your_writes`.
        let mut visible: Vec<Option<BlockBuf>> = Vec::with_capacity(bufs.len());
        let mut any_visible = false;
        {
            let guard = self.store.read();
            for delta in 0..count {
                let block = BlockNumber(start.0 + delta);
                match guard.read_visible_block_buf(block, snap) {
                    Some(buf) => {
                        visible.push(Some(buf));
                        any_visible = true;
                    }
                    None => visible.push(None),
                }
            }
        }

        // Fast path: nothing overlaid by MVCC — one ranged base read, unchanged.
        if !any_visible {
            return self.base.read_contiguous_blocks(cx, start, bufs);
        }

        // Fill visible blocks from the captured bytes and coalesce maximal runs
        // of base-resident gap blocks into ranged base reads — restoring
        // vectored I/O for the gaps instead of one scalar `read_block` per gap
        // block. Per-block bytes are identical to the prior path.
        let mut idx = 0usize;
        while idx < bufs.len() {
            if let Some(buf) = visible[idx].take() {
                bufs[idx] = buf;
                idx += 1;
                continue;
            }
            let run_start = idx;
            while idx < bufs.len() && visible[idx].is_none() {
                idx += 1;
            }
            let run_block_start = BlockNumber(start.0 + run_start as u64);
            self.base
                .read_contiguous_blocks(cx, run_block_start, &mut bufs[run_start..idx])?;
        }
        Ok(())
    }

    fn read_contiguous_into(
        &self,
        cx: &Cx,
        start: BlockNumber,
        dst: &mut [u8],
    ) -> ffs_error::Result<()> {
        let bs = self.block_size() as usize;
        if bs == 0 || dst.len() % bs != 0 {
            return Err(FfsError::Format(
                "read_contiguous_into: dst length must be a multiple of block size".to_owned(),
            ));
        }
        if dst.is_empty() {
            return Ok(());
        }
        let count = dst.len() / bs;
        let count_u64 = u64::try_from(count)
            .map_err(|_| FfsError::Format("block range exceeds u64".to_owned()))?;
        start
            .0
            .checked_add(count_u64)
            .ok_or_else(|| FfsError::Format("block range overflow".to_owned()))?;
        if self.reads_base_directly() {
            return self.base.read_contiguous_into(cx, start, dst);
        }
        let snap = self.read_snapshot();

        // Capture MVCC-visible blocks once under a single read guard at one
        // snapshot (mirrors `read_contiguous_blocks`), then read the remaining
        // base-resident gaps directly into the matching `dst` sub-slices.
        let mut visible: Vec<Option<BlockBuf>> = Vec::with_capacity(count);
        let mut any_visible = false;
        {
            let guard = self.store.read();
            for delta in 0..count_u64 {
                let block = BlockNumber(start.0 + delta);
                match guard.read_visible_block_buf(block, snap) {
                    Some(buf) => {
                        visible.push(Some(buf));
                        any_visible = true;
                    }
                    None => visible.push(None),
                }
            }
        }

        // Fast path: nothing overlaid — one ranged base read straight into dst.
        if !any_visible {
            return self.base.read_contiguous_into(cx, start, dst);
        }

        let n = count;
        let mut idx = 0usize;
        while idx < n {
            if let Some(buf) = visible[idx].take() {
                dst[idx * bs..(idx + 1) * bs].copy_from_slice(buf.as_slice());
                idx += 1;
                continue;
            }
            let run_start = idx;
            while idx < n && visible[idx].is_none() {
                idx += 1;
            }
            let run_start_u64 = u64::try_from(run_start)
                .map_err(|_| FfsError::Format("block range exceeds u64".to_owned()))?;
            let run_block_start = BlockNumber(start.0 + run_start_u64);
            self.base.read_contiguous_into(
                cx,
                run_block_start,
                &mut dst[run_start * bs..idx * bs],
            )?;
        }
        Ok(())
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
        if self.reads_base_directly() {
            return Err(FfsError::UnsupportedFeature(
                "unregistered MVCC block device is read-only".to_owned(),
            ));
        }

        // Stage into a new single-block transaction and commit immediately.
        // For batched writes, callers should use the MvccStore API directly.
        let mut guard = self.store.write();
        let mut txn = guard.begin();
        txn.stage_write(block, data.to_vec());
        guard
            .commit(txn)
            .map_err(|e| FfsError::Format(e.to_string()))?;
        drop(guard);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.base.block_size()
    }

    fn block_count(&self) -> u64 {
        self.base.block_count()
    }

    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.base.sync(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::atomic::AtomicBool;

    /// Isomorphism + golden proof that the binary-search visibility lookup
    /// (`newest_visible_index_by`, now used by `read_visible_physical` and
    /// `flush_to_device`) returns the byte-identical index to the prior O(n)
    /// reverse linear scan (`rposition`/`.rev().find`) for every ascending
    /// chain and every snapshot. Drives 5000 random ascending chains and pins
    /// an FNV-1a digest of the per-case result.
    #[test]
    fn newest_visible_index_by_matches_reverse_scan_iso() {
        // Reference: the prior reverse linear scan over an ascending chain.
        fn reference(seqs: &[u64], high: u64) -> Option<usize> {
            seqs.iter().rposition(|&s| s <= high)
        }

        let mut state: u64 = 0x0123_4567_89ab_cdef;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 33
        };

        let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
        let fold = |x: u64, d: &mut u64| {
            *d ^= x;
            *d = d.wrapping_mul(0x0000_0100_0000_01b3);
        };

        for _ in 0..5000 {
            // Build a strictly-ascending commit_seq chain of length 0..=128.
            let n = (next() % 129) as usize;
            let mut seqs = Vec::with_capacity(n);
            let mut cur = 0_u64;
            for _ in 0..n {
                cur += 1 + (next() % 5);
                seqs.push(cur);
            }
            let high = next() % (cur + 4); // span below, within, and above the chain
            let bin = newest_visible_index_by(&seqs, CommitSeq(high), |s| CommitSeq(*s));
            let reff = reference(&seqs, high);
            assert_eq!(
                bin, reff,
                "binary != reverse-scan for chain {seqs:?} high {high}"
            );
            fold(bin.map_or(u64::MAX, |i| i as u64), &mut digest);
            fold(high, &mut digest);
        }
        assert_eq!(
            digest, 17_052_713_067_055_689_022,
            "golden visibility-index digest changed"
        );
    }

    /// Simple in-memory block device for testing `MvccBlockDevice`.
    #[derive(Debug)]
    struct MemBlockDevice {
        blocks: parking_lot::RwLock<HashMap<BlockNumber, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
    }

    impl MemBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: parking_lot::RwLock::new(HashMap::new()),
                block_size,
                block_count,
            }
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
            let bs = usize::try_from(self.block_size)
                .map_err(|_| FfsError::Format("block_size overflow".to_owned()))?;
            let data = self
                .blocks
                .read()
                .get(&block)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; bs]);
            Ok(BlockBuf::new(data))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
            self.blocks.write().insert(block, data.to_vec());
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            self.block_count
        }

        fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
            Ok(())
        }
    }

    fn test_cx() -> Cx {
        Cx::for_testing()
    }

    const SNAPSHOT_REGISTRY_WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(10);

    fn spawn_snapshot_registry_watchdog(
        stop: Arc<AtomicBool>,
        workers_complete: Arc<AtomicBool>,
        timeout: Duration,
    ) -> std::thread::JoinHandle<bool> {
        std::thread::spawn(move || {
            let deadline = Instant::now() + timeout;
            loop {
                if workers_complete.load(Ordering::Acquire) {
                    return false;
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let sleep_for = deadline
                    .saturating_duration_since(now)
                    .min(SNAPSHOT_REGISTRY_WATCHDOG_POLL_INTERVAL);
                std::thread::sleep(sleep_for);
            }
            stop.store(true, Ordering::Release);
            true
        })
    }

    fn seed_block(store: &mut MvccStore, block: BlockNumber, bytes: &[u8]) {
        let mut txn = store.begin();
        txn.stage_write(block, bytes.to_vec());
        store.commit(txn).expect("seed commit");
    }

    /// Device that records each `write_contiguous_blocks` run (and any scalar
    /// `write_block`) so a test can prove the flush coalesces contiguous runs.
    #[derive(Debug)]
    struct RunCountingDevice {
        block_size: u32,
        block_count: u64,
        blocks: parking_lot::RwLock<HashMap<BlockNumber, Vec<u8>>>,
        run_lengths: parking_lot::RwLock<Vec<usize>>,
        scalar_writes: std::sync::atomic::AtomicUsize,
    }

    impl RunCountingDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                block_size,
                block_count,
                blocks: parking_lot::RwLock::new(HashMap::new()),
                run_lengths: parking_lot::RwLock::new(Vec::new()),
                scalar_writes: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl BlockDevice for RunCountingDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
            let bs = self.block_size as usize;
            Ok(BlockBuf::new(
                self.blocks
                    .read()
                    .get(&block)
                    .cloned()
                    .unwrap_or_else(|| vec![0_u8; bs]),
            ))
        }
        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
            self.scalar_writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.blocks.write().insert(block, data.to_vec());
            Ok(())
        }
        #[allow(clippy::significant_drop_tightening)]
        fn write_contiguous_blocks(
            &self,
            _cx: &Cx,
            start: BlockNumber,
            data: &[u8],
        ) -> ffs_error::Result<()> {
            let bs = self.block_size as usize;
            let n = data.len() / bs;
            self.run_lengths.write().push(n);
            let mut blocks = self.blocks.write();
            for i in 0..n {
                blocks.insert(
                    BlockNumber(start.0 + i as u64),
                    data[i * bs..(i + 1) * bs].to_vec(),
                );
            }
            Ok(())
        }
        fn block_size(&self) -> u32 {
            self.block_size
        }
        fn block_count(&self) -> u64 {
            self.block_count
        }
        fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn flush_to_device_coalesces_contiguous_blocks_bd_ryqep() {
        const BS: u32 = 4096;
        let cx = test_cx();
        let mut store = MvccStore::new();
        // Four contiguous dirty blocks (10..14) plus a separated one (20).
        for b in 10..14_u64 {
            seed_block(
                &mut store,
                BlockNumber(b),
                &vec![u8::try_from(b).unwrap(); BS as usize],
            );
        }
        seed_block(&mut store, BlockNumber(20), &vec![0xAB; BS as usize]);

        let dev = RunCountingDevice::new(BS, 64);
        let flushed = store.flush_to_device(&cx, &dev).unwrap();
        assert_eq!(flushed, 5, "all five dirty blocks flushed");

        // SCORE (bd-ryqep): the four contiguous blocks become ONE ranged write
        // (run length 4); block 20 is its own run. Two batched writes, zero
        // scalar per-block writes — vs five scalar writes pre-coalescing.
        assert_eq!(
            *dev.run_lengths.read(),
            vec![4, 1],
            "contiguous run of 4 coalesced; separated block is its own run"
        );
        assert_eq!(
            dev.scalar_writes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "flush uses write_contiguous_blocks, not scalar write_block"
        );

        // ISOMORPHISM: every block's bytes landed at the right location.
        for b in 10..14_u64 {
            assert_eq!(
                *dev.blocks.read().get(&BlockNumber(b)).unwrap(),
                vec![u8::try_from(b).unwrap(); BS as usize]
            );
        }
        assert_eq!(
            *dev.blocks.read().get(&BlockNumber(20)).unwrap(),
            vec![0xAB; BS as usize]
        );
    }

    #[test]
    fn incremental_flush_writes_only_versions_after_watermark() {
        const BS: u32 = 4096;
        let cx = test_cx();
        let mut store = MvccStore::new();
        seed_block(&mut store, BlockNumber(10), &vec![0x10; BS as usize]);
        seed_block(&mut store, BlockNumber(11), &vec![0x11; BS as usize]);

        let dev = RunCountingDevice::new(BS, 64);
        let (initial_flushed, initial_through) = store
            .flush_to_device_after(&cx, &dev, CommitSeq(0))
            .unwrap();
        assert_eq!(initial_flushed, 2);

        seed_block(&mut store, BlockNumber(11), &vec![0xBB; BS as usize]);
        seed_block(&mut store, BlockNumber(20), &vec![0xCC; BS as usize]);
        let (incremental_flushed, incremental_through) = store
            .flush_to_device_after(&cx, &dev, initial_through)
            .unwrap();
        assert_eq!(incremental_flushed, 2);
        assert!(incremental_through > initial_through);

        let blocks = dev.blocks.read();
        assert_eq!(
            blocks.get(&BlockNumber(10)).unwrap(),
            &vec![0x10; BS as usize],
            "unchanged durable block must remain byte-identical"
        );
        assert_eq!(
            blocks.get(&BlockNumber(11)).unwrap(),
            &vec![0xBB; BS as usize]
        );
        assert_eq!(
            blocks.get(&BlockNumber(20)).unwrap(),
            &vec![0xCC; BS as usize]
        );
        drop(blocks);

        let (repeat_flushed, repeat_through) = store
            .flush_to_device_after(&cx, &dev, incremental_through)
            .unwrap();
        assert_eq!(repeat_flushed, 0, "published watermark is idempotent");
        assert_eq!(repeat_through, incremental_through);

        let unrelated = RunCountingDevice::new(BS, 64);
        assert_eq!(
            store.flush_to_device(&cx, &unrelated).unwrap(),
            3,
            "public full-checkpoint API must not inherit another device's cursor"
        );
    }

    /// Base device that counts scalar `read_block` calls and records each
    /// `read_contiguous_blocks` run length, to prove the MVCC contiguous read
    /// coalesces base-resident gaps into ranged reads.
    #[derive(Debug)]
    struct ReadRunCountingDevice {
        block_size: u32,
        block_count: u64,
        blocks: parking_lot::RwLock<HashMap<BlockNumber, Vec<u8>>>,
        scalar_reads: std::sync::atomic::AtomicUsize,
        ranged_runs: parking_lot::RwLock<Vec<usize>>,
    }

    impl ReadRunCountingDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                block_size,
                block_count,
                blocks: parking_lot::RwLock::new(HashMap::new()),
                scalar_reads: std::sync::atomic::AtomicUsize::new(0),
                ranged_runs: parking_lot::RwLock::new(Vec::new()),
            }
        }
        fn reset(&self) {
            self.scalar_reads
                .store(0, std::sync::atomic::Ordering::SeqCst);
            self.ranged_runs.write().clear();
        }
        fn one(&self, block: BlockNumber) -> Vec<u8> {
            let bs = self.block_size as usize;
            self.blocks
                .read()
                .get(&block)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; bs])
        }
    }

    impl BlockDevice for ReadRunCountingDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
            self.scalar_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(BlockBuf::new(self.one(block)))
        }
        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
            self.blocks.write().insert(block, data.to_vec());
            Ok(())
        }
        fn supports_contiguous_reads(&self) -> bool {
            true
        }
        fn read_contiguous_blocks(
            &self,
            _cx: &Cx,
            start: BlockNumber,
            bufs: &mut [BlockBuf],
        ) -> ffs_error::Result<()> {
            self.ranged_runs.write().push(bufs.len());
            for (i, buf) in bufs.iter_mut().enumerate() {
                *buf = BlockBuf::new(self.one(BlockNumber(start.0 + i as u64)));
            }
            Ok(())
        }
        fn read_contiguous_into(
            &self,
            _cx: &Cx,
            start: BlockNumber,
            dst: &mut [u8],
        ) -> ffs_error::Result<()> {
            let bs = self.block_size as usize;
            if bs == 0 || dst.len() % bs != 0 {
                return Err(ffs_error::FfsError::Format(
                    "test read_contiguous_into requires whole blocks".to_owned(),
                ));
            }
            self.ranged_runs.write().push(dst.len() / bs);
            for (i, chunk) in dst.chunks_mut(bs).enumerate() {
                chunk.copy_from_slice(&self.one(BlockNumber(start.0 + i as u64)));
            }
            Ok(())
        }
        fn block_size(&self) -> u32 {
            self.block_size
        }
        fn block_count(&self) -> u64 {
            self.block_count
        }
        fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
            Ok(())
        }
    }

    /// Isomorphism + Score proof for the MVCC contiguous-read batching lever:
    /// when MVCC overlays only some blocks of a contiguous range, the prior
    /// per-block `read_block` loop issued one SCALAR base read per gap block.
    /// The single-pass coalescing path issues one RANGED base read per maximal
    /// gap run, with byte-identical per-block results.
    #[test]
    fn mvcc_contiguous_read_coalesces_base_gaps_score() {
        use sha2::{Digest, Sha256};
        const BS: u32 = 512;
        const N: u64 = 64;
        const OVERLAY: u64 = 32; // single MVCC-overlaid block, splitting the range
        let cx = test_cx();

        let base = ReadRunCountingDevice::new(BS, N);
        for b in 0..N {
            base.write_block(
                &cx,
                BlockNumber(b),
                &vec![u8::try_from(b % 251).unwrap(); BS as usize],
            )
            .expect("seed base");
        }

        // Overlay exactly one block in the MVCC store with distinct bytes.
        let store = Arc::new(RwLock::new(MvccStore::new()));
        seed_block(
            &mut store.write(),
            BlockNumber(OVERLAY),
            &vec![0xEE; BS as usize],
        );
        let snap = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);

        // Reference (prior behavior): per-block read_block over the range.
        let old_bufs: Vec<BlockBuf> = (0..N)
            .map(|i| dev.read_block(&cx, BlockNumber(i)).expect("read"))
            .collect();
        let old_scalar = dev
            .base()
            .scalar_reads
            .load(std::sync::atomic::Ordering::SeqCst);

        // New: single contiguous read.
        dev.base().reset();
        let mut new_bufs: Vec<BlockBuf> = (0..N)
            .map(|_| BlockBuf::new(vec![0_u8; BS as usize]))
            .collect();
        dev.read_contiguous_blocks(&cx, BlockNumber(0), &mut new_bufs)
            .expect("contiguous read");
        let new_ranged = dev.base().ranged_runs.read().len();
        let new_scalar = dev
            .base()
            .scalar_reads
            .load(std::sync::atomic::Ordering::SeqCst);

        // ISOMORPHISM: byte-identical per-block, including the overlaid block.
        for i in 0..new_bufs.len() {
            assert_eq!(
                old_bufs[i].as_slice(),
                new_bufs[i].as_slice(),
                "block {i} bytes diverged"
            );
        }
        let overlay_idx = usize::try_from(OVERLAY).expect("overlay index fits usize");
        assert_eq!(new_bufs[overlay_idx].as_slice(), &[0xEE; BS as usize]);

        // GOLDEN: sha256 over the concatenated contiguous-read output.
        let mut hasher = Sha256::new();
        for buf in &new_bufs {
            hasher.update(buf.as_slice());
        }
        let golden = hex_lower(&hasher.finalize());
        assert_eq!(
            golden, "6631d26c4e6e0d7f6f0414c59844ae2afcca85b291177918dabba0ccf8fbd9ca",
            "golden contiguous-read digest changed"
        );

        // SCORE: 63 scalar base reads (one per gap block) → 2 ranged reads
        // (the gap runs either side of the overlaid block).
        assert_eq!(
            old_scalar, 63,
            "prior path: one scalar base read per gap block"
        );
        assert_eq!(new_ranged, 2, "two maximal gap runs around the overlay");
        assert_eq!(new_scalar, 0, "no scalar base reads on the coalesced path");
        let read_op_ratio = old_scalar as f64 / new_ranged as f64;
        assert!(
            read_op_ratio >= 2.0,
            "Score {read_op_ratio} must clear 2.0 (got {old_scalar} -> {new_ranged})"
        );
    }

    #[test]
    fn mvcc_contiguous_read_into_coalesces_base_gaps_score() {
        use sha2::{Digest, Sha256};
        const BS: u32 = 512;
        const N: u64 = 64;
        const OVERLAY: u64 = 32;
        let cx = test_cx();
        let block_count = usize::try_from(N).expect("test block count fits usize");
        let block_size = BS as usize;

        let base = ReadRunCountingDevice::new(BS, N);
        for b in 0..N {
            base.write_block(
                &cx,
                BlockNumber(b),
                &vec![u8::try_from(b % 251).unwrap(); block_size],
            )
            .expect("seed base");
        }

        let store = Arc::new(RwLock::new(MvccStore::new()));
        seed_block(
            &mut store.write(),
            BlockNumber(OVERLAY),
            &vec![0xEE; block_size],
        );
        let snap = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);

        let old_bufs: Vec<BlockBuf> = (0..N)
            .map(|i| dev.read_block(&cx, BlockNumber(i)).expect("read"))
            .collect();
        let old_scalar = dev
            .base()
            .scalar_reads
            .load(std::sync::atomic::Ordering::SeqCst);

        dev.base().reset();
        let mut out = vec![0_u8; block_count * block_size];
        dev.read_contiguous_into(&cx, BlockNumber(0), &mut out)
            .expect("contiguous read into");
        let new_ranged = dev.base().ranged_runs.read().len();
        let new_scalar = dev
            .base()
            .scalar_reads
            .load(std::sync::atomic::Ordering::SeqCst);

        for (i, expected) in old_bufs.iter().enumerate() {
            let start = i * block_size;
            assert_eq!(
                expected.as_slice(),
                &out[start..start + block_size],
                "block {i} bytes diverged"
            );
        }
        let overlay_start =
            usize::try_from(OVERLAY).expect("overlay index fits usize") * block_size;
        assert_eq!(
            &out[overlay_start..overlay_start + block_size],
            &[0xEE; BS as usize]
        );

        let mut hasher = Sha256::new();
        hasher.update(&out);
        let golden = hex_lower(&hasher.finalize());
        assert_eq!(
            golden, "6631d26c4e6e0d7f6f0414c59844ae2afcca85b291177918dabba0ccf8fbd9ca",
            "golden contiguous-read-into digest changed"
        );

        assert_eq!(
            old_scalar, 63,
            "prior path: one scalar base read per gap block"
        );
        assert_eq!(new_ranged, 2, "two maximal gap runs around the overlay");
        assert_eq!(new_scalar, 0, "no scalar base reads on the coalesced path");
    }

    fn hex_lower(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn append_only_proof(base_len: usize) -> MergeProof {
        MergeProof::AppendOnly { base_len }
    }

    fn independent_range_proof(start: usize, len: usize) -> MergeProof {
        MergeProof::independent_key_range(start, len)
    }

    #[derive(Debug)]
    struct TestCowAllocator {
        next_block: std::sync::atomic::AtomicU64,
        allocated: parking_lot::Mutex<Vec<BlockNumber>>,
        deferred: parking_lot::Mutex<Vec<(BlockNumber, CommitSeq)>>,
        freed: parking_lot::Mutex<Vec<BlockNumber>>,
    }

    impl TestCowAllocator {
        fn new(start: u64) -> Self {
            Self {
                next_block: std::sync::atomic::AtomicU64::new(start),
                allocated: parking_lot::Mutex::new(Vec::new()),
                deferred: parking_lot::Mutex::new(Vec::new()),
                freed: parking_lot::Mutex::new(Vec::new()),
            }
        }

        fn allocated_blocks(&self) -> Vec<BlockNumber> {
            self.allocated.lock().clone()
        }

        fn freed_blocks(&self) -> Vec<BlockNumber> {
            self.freed.lock().clone()
        }
    }

    impl CowAllocator for TestCowAllocator {
        fn alloc_cow(&self, _hint: Option<BlockNumber>, _cx: &Cx) -> FfsResult<BlockNumber> {
            let next = self
                .next_block
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let block = BlockNumber(next);
            self.allocated.lock().push(block);
            Ok(block)
        }

        fn defer_free(&self, block: BlockNumber, commit_seq: CommitSeq) {
            self.deferred.lock().push((block, commit_seq));
        }

        fn gc_free(&self, watermark: CommitSeq, _cx: &Cx) -> usize {
            let mut deferred = self.deferred.lock();
            let mut still_deferred = Vec::with_capacity(deferred.len());
            let mut newly_freed = Vec::new();
            for (block, retire_seq) in deferred.drain(..) {
                if retire_seq <= watermark {
                    newly_freed.push(block);
                } else {
                    still_deferred.push((block, retire_seq));
                }
            }
            *deferred = still_deferred;
            drop(deferred);
            let freed_count = newly_freed.len();
            self.freed.lock().extend(newly_freed);
            freed_count
        }
    }

    #[test]
    fn visibility_and_fcw_conflict() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(7), vec![1, 2, 3]);
        t2.stage_write(BlockNumber(7), vec![9, 9, 9]);

        let c1 = store.commit(t1).expect("t1 commit");
        assert_eq!(c1, CommitSeq(1));

        let err = store.commit(t2).expect_err("t2 should conflict");
        assert!(
            matches!(err, CommitError::Conflict { block, .. } if block == BlockNumber(7)),
            "expected FCW conflict on block 7, got {err:?}"
        );
    }

    #[test]
    fn ranges_are_pairwise_disjoint_detects_overlap() {
        let r = MergeByteRange::new;
        // Disjoint, non-touching ranges.
        assert!(ranges_are_pairwise_disjoint(&[r(0, 4), r(10, 4), r(20, 4)]));
        // Adjacent half-open ranges [0,4) and [4,8) do not overlap.
        assert!(ranges_are_pairwise_disjoint(&[r(0, 4), r(4, 4)]));
        // An overlapping pair is rejected.
        assert!(!ranges_are_pairwise_disjoint(&[r(0, 5), r(4, 4)]));
        // Overlap between non-adjacent entries (first and third) is still caught.
        assert!(!ranges_are_pairwise_disjoint(&[
            r(0, 100),
            r(200, 4),
            r(50, 4)
        ]));
        // Empty and single-range inputs are trivially disjoint.
        assert!(ranges_are_pairwise_disjoint(&[]));
        assert!(ranges_are_pairwise_disjoint(&[r(0, 4)]));
    }

    #[test]
    fn merge_non_overlapping_ranges_overlays_disjoint_and_rejects_conflicts() {
        let r = MergeByteRange::new;
        let proof = MergeProof::default(); // label only
        let base = vec![0_u8; 8];

        // Clean 3-way merge: latest changed [4,8), staged changed declared [0,4).
        let mut latest = base.clone();
        latest[4..8].copy_from_slice(&[9, 9, 9, 9]);
        let mut staged = base.clone();
        staged[0..4].copy_from_slice(&[1, 2, 3, 4]);
        let merged = merge_non_overlapping_ranges(&[r(0, 4)], &base, &latest, &staged, &proof)
            .expect("disjoint writers merge");
        assert_eq!(merged, vec![1, 2, 3, 4, 9, 9, 9, 9]);

        // Size mismatch is rejected.
        assert!(
            merge_non_overlapping_ranges(&[r(0, 4)], &base, &base[..4], &staged, &proof).is_none()
        );
        // Overlapping touched ranges are rejected.
        assert!(
            merge_non_overlapping_ranges(&[r(0, 5), r(4, 4)], &base, &latest, &staged, &proof)
                .is_none()
        );
        // A range exceeding the block is rejected.
        assert!(
            merge_non_overlapping_ranges(&[r(4, 8)], &base, &latest, &staged, &proof).is_none()
        );

        // Integrity: staged modified a byte OUTSIDE the declared range -> rejected.
        let mut sneaky = staged.clone();
        sneaky[7] = 42;
        assert!(
            merge_non_overlapping_ranges(&[r(0, 4)], &base, &latest, &sneaky, &proof).is_none()
        );

        // True conflict: latest also modified the declared range -> rejected.
        let mut latest_conflict = base.clone();
        latest_conflict[0..4].copy_from_slice(&[5, 5, 5, 5]);
        assert!(
            merge_non_overlapping_ranges(&[r(0, 4)], &base, &latest_conflict, &staged, &proof)
                .is_none()
        );
    }

    #[test]
    fn merge_non_overlapping_ranges_handles_multiple_unsorted_ranges() {
        let r = MergeByteRange::new;
        let proof = MergeProof::default();
        // 16-byte block; staged touches two declared ranges given OUT OF ORDER
        // ([8,12) then [0,4)) — exercises the complement-gap sort path.
        let base = vec![0_u8; 16];
        let mut latest = base.clone();
        latest[4..8].copy_from_slice(&[7, 7, 7, 7]); // latest touches a gap range
        let mut staged = base.clone();
        staged[0..4].copy_from_slice(&[1, 2, 3, 4]);
        staged[8..12].copy_from_slice(&[5, 6, 7, 8]);

        let merged =
            merge_non_overlapping_ranges(&[r(8, 4), r(0, 4)], &base, &latest, &staged, &proof)
                .expect("two disjoint declared ranges merge");
        let mut expect = base.clone();
        expect[0..4].copy_from_slice(&[1, 2, 3, 4]);
        expect[4..8].copy_from_slice(&[7, 7, 7, 7]);
        expect[8..12].copy_from_slice(&[5, 6, 7, 8]);
        assert_eq!(merged, expect);

        // A byte modified in a complement gap BETWEEN two declared ranges is
        // caught (staged touched byte 6, outside both declared ranges).
        let mut sneaky = staged.clone();
        sneaky[6] = 42;
        assert!(
            merge_non_overlapping_ranges(&[r(8, 4), r(0, 4)], &base, &latest, &sneaky, &proof)
                .is_none()
        );
        // A byte modified in the trailing complement (after the last range) is caught.
        let mut trailing = staged.clone();
        trailing[15] = 99;
        assert!(
            merge_non_overlapping_ranges(&[r(8, 4), r(0, 4)], &base, &latest, &trailing, &proof)
                .is_none()
        );
    }

    #[test]
    fn merge_valid_matches_merge_bytes_is_some() {
        let base = vec![0_u8; 8];
        let mut latest = base.clone();
        latest[4..8].copy_from_slice(&[9, 9, 9, 9]);
        let mut staged = base.clone();
        staged[0..4].copy_from_slice(&[1, 2, 3, 4]);
        let mut staged_sneaky = staged.clone();
        staged_sneaky[7] = 42; // modified outside declared range
        let mut latest_conflict = base.clone();
        latest_conflict[0..4].copy_from_slice(&[5, 5, 5, 5]); // true conflict

        // (proof, base, latest, staged) cases spanning every decision branch.
        let ap = MergeProof::AppendOnly { base_len: 1 };
        let ind = MergeProof::independent_key_range(0, 4);
        let cases: Vec<(MergeProof, &[u8], &[u8], &[u8])> = vec![
            (MergeProof::Unsafe, &base, &latest, &staged),
            (MergeProof::DisjointBlocks, &base, &latest, &staged),
            (ind.clone(), &base, &latest, &staged), // clean merge
            (ind.clone(), &base, &latest, &staged_sneaky), // outside-range reject
            (ind.clone(), &base, &latest_conflict, &staged), // true-conflict reject
            (ind.clone(), &base, &base[..4], &staged), // size mismatch reject
            (
                MergeProof::non_overlapping_extent_range(0, 5),
                &base,
                &latest,
                &staged,
            ), // overlaps latest range? no; still valid check
            (ap.clone(), b"abc", b"abcX", b"abcY"), // append clean
            (ap.clone(), b"abc", b"Xbc!", b"abcY"), // append prefix reject
            (
                MergeProof::AppendOnly { base_len: 10 },
                b"abc",
                b"abcX",
                b"abcY",
            ), // oversized base_len
            (MergeProof::BitmapOr, &base, &latest, &staged), // disjoint-byte set-only merge
            // Crux: disjoint BITS that share a byte — valid OR merge.
            (
                MergeProof::BitmapOr,
                &[0b0000_0001][..],
                &[0b0000_0011][..],
                &[0b0000_0101][..],
            ),
            // A writer cleared a base bit (a free) — reject, falls back to FCW.
            (
                MergeProof::BitmapOr,
                &[0b0000_0011][..],
                &[0b0000_0001][..],
                &[0b0000_0011][..],
            ),
            // Both writers set the SAME new bit — double-allocation, reject.
            (
                MergeProof::BitmapOr,
                &[0b0000_0000][..],
                &[0b0000_0010][..],
                &[0b0000_0010][..],
            ),
            // Length mismatch — reject.
            (MergeProof::BitmapOr, &base, &base[..4], &staged),
        ];
        for (i, (proof, b, l, s)) in cases.iter().enumerate() {
            assert_eq!(
                proof.merge_valid(b, l, s),
                proof.merge_bytes(b, l, s).is_some(),
                "case {i}: merge_valid disagrees with merge_bytes().is_some() for {proof:?}"
            );
        }
    }

    #[test]
    fn merge_bytes_append_only_rejects_oversized_base_and_prefix_changes() {
        let base = b"abc".to_vec();
        let proof = MergeProof::AppendOnly { base_len: 3 };

        // Clean append: both writers extended the common prefix "abc"; the merge
        // keeps latest and concatenates staged's suffix.
        assert_eq!(
            proof
                .merge_bytes(&base, b"abcX", b"abcY")
                .expect("append-only merge"),
            b"abcXY"
        );

        // base_len larger than a buffer is rejected.
        assert!(
            MergeProof::AppendOnly { base_len: 10 }
                .merge_bytes(&base, b"abcX", b"abcY")
                .is_none()
        );

        // A modified snapshot prefix (not a pure append) is rejected on either side.
        assert!(proof.merge_bytes(&base, b"Xbc!", b"abcY").is_none());
        assert!(proof.merge_bytes(&base, b"abcX", b"Zbc!").is_none());
    }

    #[test]
    fn merge_proof_unsafe_rejects_merge() {
        let merged = MergeProof::Unsafe.merge_bytes(&[0], &[0, 1], &[0, 2]);
        assert!(merged.is_none(), "unsafe proof must fall back to FCW");
    }

    #[test]
    fn merge_proof_disjoint_blocks_rejects_same_block_merge() {
        let merged = MergeProof::DisjointBlocks.merge_bytes(&[0], &[0, 1], &[0, 2]);
        assert!(
            merged.is_none(),
            "disjoint-block proof is not valid for same-block FCW resolution"
        );
    }

    #[test]
    fn stage_write_records_unsafe_merge_proof_by_default() {
        let mut store = MvccStore::new();
        let block = BlockNumber(6);
        let mut txn = store.begin();

        txn.stage_write(block, vec![1, 2, 3]);
        assert_eq!(
            txn.merge_proof(block),
            Some(&MergeProof::Unsafe),
            "plain stage_write must not silently attach bench-only merge evidence"
        );

        txn.stage_write_with_proof(block, vec![1, 2, 3, 4], append_only_proof(3));
        assert_eq!(
            txn.merge_proof(block),
            Some(&MergeProof::AppendOnly { base_len: 3 }),
            "explicit callers must still be able to supply executable merge evidence"
        );
    }

    #[test]
    fn merge_proof_mechanism_collapses_labels_to_two_merge_algorithms() {
        let cases = vec![
            (MergeProof::Unsafe, MergeProofMechanism::NoSameBlockMerge),
            (
                MergeProof::DisjointBlocks,
                MergeProofMechanism::NoSameBlockMerge,
            ),
            (
                MergeProof::AppendOnly { base_len: 4 },
                MergeProofMechanism::AppendOnly,
            ),
            (
                MergeProof::independent_key_range(2, 2),
                MergeProofMechanism::RangeOverlay,
            ),
            (
                MergeProof::non_overlapping_extent_range(2, 2),
                MergeProofMechanism::RangeOverlay,
            ),
            (
                MergeProof::timestamp_only_inode_range(2, 2),
                MergeProofMechanism::RangeOverlay,
            ),
            (MergeProof::BitmapOr, MergeProofMechanism::BitmapOr),
        ];

        for (proof, mechanism) in cases {
            assert_eq!(proof.mechanism(), mechanism, "proof label {proof:?}");
        }
    }

    #[test]
    fn bitmap_or_merges_disjoint_bits_sharing_a_byte() {
        // Two allocators claim different blocks whose bitmap bits live in the
        // SAME byte — the case a byte-range (IndependentKeys) proof cannot
        // express. base=block 0 already allocated; `latest` also took block 1,
        // `staged` also took block 2. The merge must keep all three bits.
        let base = vec![0b0000_0001_u8, 0x00];
        let latest = vec![0b0000_0011_u8, 0x00]; // + block 1
        let staged = vec![0b0000_0101_u8, 0x00]; // + block 2
        let merged = MergeProof::BitmapOr
            .merge_bytes(&base, &latest, &staged)
            .expect("disjoint bits sharing a byte must OR-merge");
        assert_eq!(merged, vec![0b0000_0111_u8, 0x00]);
    }

    #[test]
    fn bitmap_or_rejects_a_cleared_base_bit() {
        // `latest` FREED block 0 (cleared its bit). A free is not a set-only
        // bitmap merge — must fall back to FCW so the concurrent set is not lost.
        let base = vec![0b0000_0011_u8];
        let latest = vec![0b0000_0001_u8]; // cleared bit 1
        let staged = vec![0b0000_0111_u8]; // set bit 2
        assert!(
            MergeProof::BitmapOr
                .merge_bytes(&base, &latest, &staged)
                .is_none(),
            "a bit-clear (free) must reject the OR merge"
        );
        // Symmetric: staged clears a base bit.
        assert!(
            MergeProof::BitmapOr
                .merge_bytes(&base, &[0b0000_0111_u8], &[0b0000_0001_u8])
                .is_none()
        );
    }

    #[test]
    fn bitmap_or_rejects_double_allocation_of_the_same_bit() {
        // Both writers newly SET bit 3 of the same byte: they handed the same
        // block to two owners. The merge must abort (loser retries), never
        // silently coalesce the double-allocation.
        let base = vec![0b0000_0001_u8];
        let latest = vec![0b0000_1001_u8]; // + bit 3
        let staged = vec![0b0000_1001_u8]; // + bit 3 (same!)
        assert!(
            MergeProof::BitmapOr
                .merge_bytes(&base, &latest, &staged)
                .is_none(),
            "two writers setting the same new bit is a double-allocation; must reject"
        );
    }

    #[test]
    fn bitmap_or_rejects_length_mismatch() {
        assert!(
            MergeProof::BitmapOr
                .merge_bytes(&[0, 0, 0, 0], &[0, 1], &[0, 0, 0, 2])
                .is_none()
        );
    }

    #[test]
    fn bitmap_or_resolves_concurrent_same_block_alloc_via_store_commit() {
        // End-to-end: two transactions each allocate a disjoint bit of a freshly
        // seeded bitmap block, stage a BitmapOr proof, and the second commit must
        // MERGE against the first instead of first-committer-wins aborting.
        let mut store = MvccStore::new();
        let block = BlockNumber(65); // group-0 block bitmap, the BUG-4 block
        seed_block(&mut store, block, &[0b0000_0001_u8, 0x00]); // block 0 reserved

        let mut first = store.begin();
        let mut second = store.begin();
        first.stage_write_with_proof(block, vec![0b0000_0011_u8, 0x00], MergeProof::BitmapOr);
        second.stage_write_with_proof(block, vec![0b0000_0101_u8, 0x00], MergeProof::BitmapOr);

        store.commit(first).expect("first alloc commit");
        let resolved = store
            .resolved_writes_for_commit(&second)
            .expect("BitmapOr proof must resolve the concurrent same-block alloc");
        assert_eq!(
            resolved,
            vec![(block, vec![0b0000_0111_u8, 0x00])],
            "both allocations must survive the OR merge"
        );
    }

    #[test]
    fn range_overlay_labels_share_the_same_byte_algorithm() {
        let proofs = vec![
            MergeProof::independent_key_range(2, 2),
            MergeProof::non_overlapping_extent_range(2, 2),
            MergeProof::timestamp_only_inode_range(2, 2),
        ];

        for proof in proofs {
            let merged = proof
                .merge_bytes(&[0, 0, 0, 0], &[9, 9, 0, 0], &[0, 0, 5, 5])
                .expect("range-overlay proof should merge disjoint byte ranges");
            assert_eq!(merged, vec![9, 9, 5, 5], "proof label {proof:?}");
        }
    }

    #[test]
    fn range_overlay_labels_reject_undeclared_byte_changes() {
        let proofs = vec![
            MergeProof::independent_key_range(2, 2),
            MergeProof::non_overlapping_extent_range(2, 2),
            MergeProof::timestamp_only_inode_range(2, 2),
        ];

        for proof in proofs {
            assert!(
                proof
                    .merge_bytes(&[0, 0, 0, 0], &[9, 9, 0, 0], &[0, 7, 5, 5])
                    .is_none(),
                "proof label {proof:?} must reject changes outside touched_ranges"
            );
        }
    }

    #[test]
    fn merge_proof_inline_ranges_preserve_serde_golden_bd_6tooy() {
        use sha2::{Digest, Sha256};

        let proofs = vec![
            MergeProof::independent_key_range(0, 2),
            MergeProof::non_overlapping_extent_range(2, 2),
            MergeProof::timestamp_only_inode_range(1, 1),
        ];
        let json = serde_json::to_string(&proofs).expect("serialize proof golden");
        let digest = hex_lower(&Sha256::digest(json.as_bytes()));
        println!("bd_6tooy_merge_proof_serde_sha256={digest}");

        assert_eq!(
            json,
            r#"[{"IndependentKeys":{"touched_ranges":[{"start":0,"len":2}]}},{"NonOverlappingExtents":{"touched_ranges":[{"start":2,"len":2}]}},{"TimestampOnlyInode":{"touched_ranges":[{"start":1,"len":1}]}}]"#,
            "inline range storage must preserve the prior Vec-backed serde shape"
        );
        assert_eq!(
            digest, "e3a0f052016fa83985a7b1968c06b0d21589999a1e441915fff89c2d8c88a324",
            "golden SHA changed for merge proof range serialization"
        );
    }

    #[test]
    fn validate_transaction_id_rejects_reserved_ids() {
        // Ordinary ids validate.
        assert!(validate_transaction_id(TxnId(1)).is_ok());
        assert!(validate_transaction_id(TxnId(u64::MAX - 1)).is_ok());
        // 0 (uninitialized / no-transaction) and u64::MAX (sentinel) are reserved.
        assert!(validate_transaction_id(TxnId(0)).is_err());
        assert!(validate_transaction_id(TxnId(u64::MAX)).is_err());
    }

    #[test]
    fn resolved_writes_for_commit_returns_merged_bytes_for_append_only_proof() {
        let mut store = MvccStore::new();
        let block = BlockNumber(7);
        seed_block(&mut store, block, &[0]);

        let mut first = store.begin();
        let mut second = store.begin();

        first.stage_write_with_proof(block, vec![0, 1], append_only_proof(1));
        second.stage_write_with_proof(block, vec![0, 2], append_only_proof(1));

        store.commit(first).expect("first append commit");

        let resolved = store
            .resolved_writes_for_commit(&second)
            .expect("append-only proof should resolve");
        assert_eq!(resolved, vec![(block, vec![0, 1, 2])]);
    }

    #[test]
    fn resolved_writes_for_commit_honors_strict_policy() {
        let mut store = MvccStore::new();
        store.set_conflict_policy(ConflictPolicy::Strict);
        let block = BlockNumber(7);
        seed_block(&mut store, block, &[0]);

        let mut first = store.begin();
        let mut second = store.begin();

        first.stage_write_with_proof(block, vec![0, 1], append_only_proof(1));
        second.stage_write_with_proof(block, vec![0, 2], append_only_proof(1));

        store.commit(first).expect("first append commit");

        let err = store
            .resolved_writes_for_commit(&second)
            .expect_err("strict policy must reject mergeable same-block conflicts");
        assert!(
            matches!(err, CommitError::Conflict { block: b, .. } if b == block),
            "expected strict FCW conflict, got {err:?}"
        );
    }

    #[test]
    fn commit_ssi_move_through_preserves_full_bytes_and_golden_bd_9m1g4() {
        use sha2::{Digest, Sha256};

        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: None,
            algo: CompressionAlgo::None,
        });
        let block_a = BlockNumber(31);
        let block_b = BlockNumber(32);
        let bytes_a = vec![0xA5; 16];
        let bytes_b = vec![0x5A; 8];

        let mut txn = store.begin();
        txn.stage_write(block_a, bytes_a.clone());
        txn.stage_write(block_b, bytes_b.clone());

        let commit_seq = store.commit_ssi(txn).expect("SSI commit");
        assert_eq!(commit_seq, CommitSeq(1));

        let chain_a = store.versions.get(&block_a).expect("block_a chain");
        let chain_b = store.versions.get(&block_b).expect("block_b chain");
        let VersionData::Full(stored_a) = &chain_a[0].data else {
            panic!("block_a should store full bytes");
        };
        let VersionData::Full(stored_b) = &chain_b[0].data else {
            panic!("block_b should store full bytes");
        };
        assert_eq!(stored_a.as_slice(), bytes_a.as_slice());
        assert_eq!(stored_b.as_slice(), bytes_b.as_slice());

        let record = store.ssi_log.last().expect("SSI record");
        assert_eq!(record.read_set.len(), 0);
        assert_eq!(record.write_set, BTreeSet::from([block_a, block_b]));

        let mut hasher = Sha256::new();
        hasher.update(commit_seq.0.to_le_bytes());
        for (block, bytes) in [
            (block_a, stored_a.as_slice()),
            (block_b, stored_b.as_slice()),
        ] {
            hasher.update(block.0.to_le_bytes());
            let len = u64::try_from(bytes.len()).expect("test bytes length fits u64");
            hasher.update(len.to_le_bytes());
            hasher.update(bytes);
        }
        let read_set_len =
            u64::try_from(record.read_set.len()).expect("test read-set length fits u64");
        hasher.update(read_set_len.to_le_bytes());
        for block in &record.write_set {
            hasher.update(block.0.to_le_bytes());
        }
        let golden = hex_lower(&hasher.finalize());
        assert_eq!(
            golden, "dc236d4739346b0642de6982db3bf2afee6019b1f4637fd65699f7a8e6e984be",
            "SSI move-through golden digest changed"
        );
    }

    #[test]
    fn commit_ssi_move_through_preserves_append_only_merge_bd_9m1g4() {
        let mut store = MvccStore::new();
        let block = BlockNumber(33);
        seed_block(&mut store, block, &[0]);

        let mut first = store.begin();
        let mut second = store.begin();
        first.stage_write_with_proof(block, vec![0, 1], append_only_proof(1));
        second.stage_write_with_proof(block, vec![0, 2], append_only_proof(1));

        store.commit_ssi(first).expect("first append");
        store.commit_ssi(second).expect("second append merges");

        let snapshot = store.current_snapshot();
        let visible = store.read_visible(block, snapshot).expect("visible bytes");
        assert_eq!(visible.as_ref(), &[0, 1, 2]);

        let chain = store.versions.get(&block).expect("block chain");
        let VersionData::Full(stored) = &chain[2].data else {
            panic!("merged SSI append should store full bytes");
        };
        assert_eq!(stored.as_slice(), &[0, 1, 2]);
    }

    #[test]
    fn commit_ssi_move_through_returns_original_txn_on_fcw_conflict_bd_9m1g4() {
        let mut store = MvccStore::new();
        store.set_conflict_policy(ConflictPolicy::Strict);
        let block = BlockNumber(34);
        seed_block(&mut store, block, &[0]);

        let mut first = store.begin();
        let mut second = store.begin();
        first.stage_write(block, vec![0, 1]);
        second.stage_write(block, vec![0, 2]);

        store.commit_ssi(first).expect("first write");

        let (err, returned) = store
            .commit_ssi_internal(second)
            .expect_err("strict FCW conflict");
        assert!(
            matches!(err, CommitError::Conflict { block: b, .. } if b == block),
            "expected strict FCW conflict, got {err:?}"
        );
        assert_eq!(returned.pending_writes(), 1);
        assert_eq!(returned.staged_write(block), Some(&[0, 2][..]));

        let snapshot = store.current_snapshot();
        let visible = store.read_visible(block, snapshot).expect("visible bytes");
        assert_eq!(visible.as_ref(), &[0, 1]);
    }

    #[test]
    fn apply_fcw_commit_returns_original_writes_on_conflict_bd_csfbv() {
        let mut store = MvccStore::new();
        store.set_conflict_policy(ConflictPolicy::Strict);
        let block = BlockNumber(8);
        seed_block(&mut store, block, &[0]);

        let mut first = store.begin();
        let mut second = store.begin();
        first.stage_write(block, vec![0, 1]);
        second.stage_write(block, vec![0, 2]);

        store.commit(first).expect("first write commits");

        let (err, returned) = store
            .commit_fcw_internal(second)
            .expect_err("strict policy must reject stale write");
        assert!(
            matches!(err, CommitError::Conflict { block: b, .. } if b == block),
            "expected strict FCW conflict, got {err:?}"
        );
        assert_eq!(returned.pending_writes(), 1);
        assert_eq!(returned.staged_write(block), Some(&[0, 2][..]));
    }

    #[test]
    fn fcw_append_only_merge_proof_allows_same_block_commit() {
        let mut store = MvccStore::new();
        let block = BlockNumber(11);
        seed_block(&mut store, block, &[0]);

        let mut first = store.begin();
        let mut second = store.begin();

        first.stage_write_with_proof(block, vec![0, 1], append_only_proof(1));
        second.stage_write_with_proof(block, vec![0, 2], append_only_proof(1));

        store.commit(first).expect("first append commit");
        store
            .commit(second)
            .expect("second append should merge instead of conflicting");

        let latest = store.current_snapshot();
        let visible = store.read_visible(block, latest).expect("latest bytes");
        assert_eq!(visible.as_ref(), &[0, 1, 2]);
    }

    #[test]
    fn fcw_independent_range_merge_proof_allows_same_block_commit() {
        let mut store = MvccStore::new();
        let block = BlockNumber(12);
        seed_block(&mut store, block, &[0, 0, 0, 0]);

        let mut first = store.begin();
        let mut second = store.begin();

        first.stage_write_with_proof(block, vec![1, 1, 0, 0], independent_range_proof(0, 2));
        second.stage_write_with_proof(block, vec![0, 0, 2, 2], independent_range_proof(2, 2));

        store.commit(first).expect("first range commit");
        store
            .commit(second)
            .expect("disjoint ranges should merge instead of conflicting");

        let latest = store.current_snapshot();
        let visible = store.read_visible(block, latest).expect("latest bytes");
        assert_eq!(visible.as_ref(), &[1, 1, 2, 2]);
    }

    #[test]
    fn hundred_same_snapshot_append_only_writers_all_commit_without_chain_cap() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy::dedup_only());
        let block = BlockNumber(13);
        seed_block(&mut store, block, &[0]);

        let mut txns = Vec::new();
        for value in 1_u8..=100 {
            let mut txn = store.begin();
            txn.stage_write_with_proof(block, vec![0, value], append_only_proof(1));
            txns.push(txn);
        }

        for txn in txns {
            store
                .commit(txn)
                .expect("append-only writers should merge cleanly");
        }

        let latest = store.current_snapshot();
        let visible = store.read_visible(block, latest).expect("latest bytes");
        let mut expected = vec![0];
        expected.extend(1_u8..=100);
        assert_eq!(visible.as_ref(), expected.as_slice());
    }

    #[test]
    fn hundred_same_snapshot_unsafe_writers_only_first_commits() {
        let mut store = MvccStore::new();
        let block = BlockNumber(14);

        let mut txns = Vec::new();
        for value in 1_u8..=100 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![value]);
            txns.push(txn);
        }

        let mut successes = 0usize;
        let mut failures = 0usize;
        for txn in txns {
            match store.commit(txn) {
                Ok(_) => successes += 1,
                Err(err) => {
                    assert!(
                        matches!(&err, CommitError::Conflict { .. }),
                        "unexpected commit error: {err:?}"
                    );
                    failures += 1;
                }
            }
        }

        assert_eq!(successes, 1, "exactly one unsafe writer should commit");
        assert_eq!(failures, 99, "remaining unsafe writers should conflict");

        let latest = store.current_snapshot();
        let visible = store.read_visible(block, latest).expect("latest bytes");
        assert_eq!(visible.as_ref(), &[1]);
    }

    #[test]
    fn read_snapshot_visibility() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(1), vec![1]);
        let _ = store.commit(t1).expect("commit t1");

        let snap = store.current_snapshot();

        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(1), vec![2]);
        let _ = store.commit(t2).expect("commit t2");

        let visible = store
            .read_visible(BlockNumber(1), snap)
            .expect("visible data at snap");
        assert_eq!(visible.as_ref(), &[1]);
    }

    #[test]
    fn cow_write_allocates_new_physical_block() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let allocator = TestCowAllocator::new(1_000);
        let logical = BlockNumber(7);

        let mut txn = store.begin();
        let new_physical = store
            .write_cow(logical, &[0xAB; 8], &mut txn, &allocator, &cx)
            .expect("cow allocation");
        assert_ne!(new_physical, logical);
        assert_eq!(txn.staged_physical(logical), Some(new_physical));

        let commit_seq = store
            .commit_with_cow_allocator(txn, &allocator, &cx)
            .expect("cow commit");
        assert_eq!(commit_seq, CommitSeq(1));

        let latest = store.current_snapshot();
        assert_eq!(
            store.read_visible(logical, latest).unwrap().as_ref(),
            &[0xAB; 8]
        );
        assert_eq!(store.latest_physical_block(logical), Some(new_physical));
        assert!(allocator.freed_blocks().is_empty());
    }

    #[test]
    fn cow_preserves_old_snapshot_and_gc_frees_after_release() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let allocator = TestCowAllocator::new(2_000);
        let logical = BlockNumber(13);

        let mut seed = store.begin();
        seed.stage_write(logical, vec![0x11; 4]);
        store.commit(seed).expect("seed commit");

        let old_snapshot = store.current_snapshot();
        store.register_snapshot(old_snapshot);

        let mut txn = store.begin();
        let new_physical = store
            .write_cow(logical, &[0x22; 4], &mut txn, &allocator, &cx)
            .expect("cow allocation");
        store
            .commit_with_cow_allocator(txn, &allocator, &cx)
            .expect("cow commit");

        assert_eq!(
            store.read_visible(logical, old_snapshot).unwrap().as_ref(),
            &[0x11; 4]
        );
        assert_eq!(
            store.read_visible_physical(logical, old_snapshot),
            Some(logical)
        );
        assert_eq!(store.latest_physical_block(logical), Some(new_physical));
        assert!(allocator.freed_blocks().is_empty());

        assert!(store.release_snapshot(old_snapshot));
        let freed_now = store.gc_cow_blocks(&allocator, &cx);
        assert_eq!(freed_now, 1);
        assert_eq!(allocator.freed_blocks(), vec![logical]);
    }

    #[test]
    fn cow_hundred_rewrites_produce_unique_physical_blocks() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let allocator = TestCowAllocator::new(3_000);
        let logical = BlockNumber(99);
        let mut seen = BTreeSet::new();

        for i in 0_u8..100_u8 {
            let mut txn = store.begin();
            let physical = store
                .write_cow(logical, &[i], &mut txn, &allocator, &cx)
                .expect("cow allocation");
            assert!(seen.insert(physical), "physical block was reused");
            store
                .commit_with_cow_allocator(txn, &allocator, &cx)
                .expect("cow commit");
        }

        assert_eq!(seen.len(), 100);
        assert_eq!(allocator.allocated_blocks().len(), 100);
        assert_eq!(
            store.latest_physical_block(logical),
            allocator.allocated_blocks().last().copied()
        );
    }

    #[test]
    fn cow_gc_reclaims_all_deferred_blocks_after_snapshot_release() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let allocator = TestCowAllocator::new(4_000);
        let logical = BlockNumber(17);

        let mut seed = store.begin();
        seed.stage_write(logical, vec![0xAA; 2]);
        store.commit(seed).expect("seed commit");

        let held_snapshot = store.current_snapshot();
        store.register_snapshot(held_snapshot);

        for i in 0_u8..5_u8 {
            let mut txn = store.begin();
            store
                .write_cow(logical, &[i; 2], &mut txn, &allocator, &cx)
                .expect("cow allocation");
            store
                .commit_with_cow_allocator(txn, &allocator, &cx)
                .expect("cow commit");
        }

        assert!(allocator.freed_blocks().is_empty());

        assert!(store.release_snapshot(held_snapshot));
        let freed_now = store.gc_cow_blocks(&allocator, &cx);
        assert_eq!(freed_now, 5);

        let freed_set: BTreeSet<BlockNumber> = allocator.freed_blocks().into_iter().collect();
        assert_eq!(freed_set.len(), 5);
        assert!(freed_set.contains(&logical));
    }

    // ── MvccBlockDevice tests ────────────────────────────────────────────

    #[test]
    fn mvcc_device_read_falls_back_to_base() {
        let cx = test_cx();
        let base = MemBlockDevice::new(512, 16);
        // Pre-populate block 3 in base device.
        base.write_block(&cx, BlockNumber(3), &[0xAB; 512])
            .expect("base write");

        let store = Arc::new(RwLock::new(MvccStore::new()));
        let snap = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, store, snap);

        let buf = dev.read_block(&cx, BlockNumber(3)).expect("read block 3");
        assert_eq!(buf.as_slice(), &[0xAB; 512]);
    }

    #[test]
    fn unregistered_mvcc_device_is_direct_read_only_view_bd_xmh5g_416() {
        let cx = test_cx();
        let block = BlockNumber(3);
        let base = MemBlockDevice::new(512, 16);
        base.write_block(&cx, block, &[0xAB; 512])
            .expect("seed base");

        let store = Arc::new(RwLock::new(MvccStore::new()));
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(block, vec![0xCD; 512]);
            guard.commit(txn).expect("seed overlay");
        }
        let snap = store.read().current_snapshot();
        let dev = MvccBlockDevice::new_unregistered(base, Arc::clone(&store), snap);

        let buf = dev.read_block(&cx, block).expect("direct read-only read");
        assert_eq!(
            buf.as_slice(),
            &[0xAB; 512],
            "unregistered/read-only mode must bypass MVCC overlay probes"
        );

        let err = dev
            .write_block(&cx, block, &[0xEF; 512])
            .expect_err("unregistered mode is a read-only base-device view");
        assert!(
            matches!(err, FfsError::UnsupportedFeature(_)),
            "unexpected error kind: {err:?}"
        );
    }

    #[test]
    fn mvcc_device_read_shares_uncompressed_full_version_buffer_bd_xmh5g_394() {
        let cx = test_cx();
        let block = BlockNumber(4);
        let store = Arc::new(RwLock::new(MvccStore::new()));
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(block, vec![0xCD; 512]);
            guard.commit(txn).expect("commit");
        }

        let snap = store.read().current_snapshot();
        let shared = {
            let guard = store.read();
            let versions = guard.versions.get(&block).expect("block chain");
            let VersionData::Full(shared) = &versions[0].data else {
                panic!("uncompressed commit should store shared full bytes");
            };
            let shared = Arc::clone(shared);
            drop(guard);
            shared
        };
        let stored = BlockBuf::from_shared_aligned(shared);

        let base = MemBlockDevice::new(512, 16);
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);
        let read = dev.read_block(&cx, block).expect("read");

        assert_eq!(read.as_slice(), &[0xCD; 512]);
        assert!(
            read.shares_storage_with(&stored),
            "uncompressed MVCC read_block should share VersionData::Full storage"
        );
    }

    #[test]
    fn force_advanced_inline_snapshot_drop_does_not_trip_release_invariant() {
        // Regression for bd-6oolk: chain-pressure relief
        // (force_advance_oldest_snapshot) can age a snapshot out of
        // active_snapshots while a live inline MvccBlockDevice still holds it.
        // The device's Drop must then release cleanly (matching the recorded
        // forced advance) rather than tripping the unregistered-release
        // debug_assert. Surfaced by a >4 MiB e2compr double-indirect write
        // (ffs-core compressed_write_reaching_double_indirect_roundtrips_ext4).
        let base = MemBlockDevice::new(512, 16);
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let snap = store.read().current_snapshot();
        // Live inline reader holds `snap` (register_snapshot via ::new).
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);
        assert_eq!(store.read().active_snapshot_count(), 1);

        // Force the oldest snapshot out from under the live reader.
        let advanced = store.write().force_advance_oldest_snapshot();
        assert!(advanced.is_some(), "expected an oldest snapshot to advance");
        assert_eq!(
            store.read().active_snapshot_count(),
            0,
            "forced advance should remove the sole snapshot ref"
        );

        // Dropping the live reader must not panic on the release invariant,
        // and must drain the recorded forced-release credit.
        drop(dev);

        // A genuinely-unregistered release still reports false (invariant
        // detection preserved): the forced credit was consumed by the Drop.
        assert!(
            !store.write().release_snapshot(snap),
            "no forced-release credit should remain after the matching Drop"
        );
    }

    #[test]
    fn mvcc_device_write_visible_to_reader_at_later_snapshot() {
        let cx = test_cx();
        let base = MemBlockDevice::new(512, 16);
        let store = Arc::new(RwLock::new(MvccStore::new()));

        let snap1 = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap1);

        // Write via the MVCC device.
        dev.write_block(&cx, BlockNumber(5), &[0xFF; 512])
            .expect("mvcc write");

        // A new snapshot taken after the write should see it.
        let snap2 = store.read().current_snapshot();
        let base2 = MemBlockDevice::new(512, 16);
        let dev2 = MvccBlockDevice::new(base2, Arc::clone(&store), snap2);

        let buf = dev2.read_block(&cx, BlockNumber(5)).expect("read block 5");
        assert_eq!(buf.as_slice(), &[0xFF; 512]);
    }

    #[test]
    fn mvcc_device_snapshot_isolation() {
        let cx = test_cx();
        let store = Arc::new(RwLock::new(MvccStore::new()));

        // Commit a version via the store directly.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(BlockNumber(1), vec![1; 512]);
            guard.commit(txn).expect("commit v1");
        }

        // Capture snapshot after v1.
        let snap_after_v1 = store.read().current_snapshot();

        // Commit a second version.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(BlockNumber(1), vec![2; 512]);
            guard.commit(txn).expect("commit v2");
        }

        // Device at snap_after_v1 should see v1, not v2.
        let base = MemBlockDevice::new(512, 16);
        let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap_after_v1);
        let buf = dev.read_block(&cx, BlockNumber(1)).expect("read");
        assert_eq!(buf.as_slice(), &[1; 512]);

        // Device at latest snapshot should see v2.
        let snap_after_v2 = store.read().current_snapshot();
        let base2 = MemBlockDevice::new(512, 16);
        let dev2 = MvccBlockDevice::new(base2, Arc::clone(&store), snap_after_v2);
        let buf2 = dev2.read_block(&cx, BlockNumber(1)).expect("read v2");
        assert_eq!(buf2.as_slice(), &[2; 512]);
    }

    #[test]
    fn mvcc_device_delegates_block_size_and_count() {
        let base = MemBlockDevice::new(4096, 128);
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let snap = store.read().current_snapshot();
        let dev = MvccBlockDevice::new(base, store, snap);

        assert_eq!(dev.block_size(), 4096);
        assert_eq!(dev.block_count(), 128);
    }

    #[test]
    fn mvcc_device_registers_and_releases_snapshot_lifetime() {
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let snap = store.read().current_snapshot();
        assert_eq!(store.read().active_snapshot_count(), 0);

        {
            let base = MemBlockDevice::new(512, 4);
            let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);
            assert_eq!(dev.snapshot(), snap);
            assert_eq!(store.read().active_snapshot_count(), 1);
        }

        assert_eq!(store.read().active_snapshot_count(), 0);
    }

    // ── Deterministic concurrency tests (bd-hrv) ─────────────────────────
    //
    // These tests encode MVCC invariants under controlled interleavings:
    //   1. Snapshot visibility — readers see only committed versions ≤ snap.
    //   2. First-committer-wins (FCW) — concurrent writers conflict correctly.
    //   3. No lost updates — every committed write is observable.
    //
    // The tests are deterministic: each constructs a specific interleaving
    // order rather than relying on thread scheduling, making them non-flaky.

    /// Invariant: snapshot visibility across a chain of commits.
    ///
    /// bd-bw90c isolation: a block committed by an earlier txn, then read +
    /// RMW'd multiple times within a LATER txn (each a full-block overwrite
    /// staged with MergeProof::DisjointBlocks — exactly what the e2compr
    /// indirect-pointer writes do across sequential chunked writes). The final
    /// committed bytes must read back verbatim; the corruption symptom is an
    /// intermediate full-block write (here slot 2 = 2113) being dropped.
    #[test]
    fn disjoint_proof_repeated_full_overwrite_after_prior_commit_roundtrips() {
        let mut store = MvccStore::new();
        let block = BlockNumber(2101);

        // Tx1 (chunk 1): commit a block with its first two u32 slots set.
        let mut base = vec![0u8; 16];
        base[0..4].copy_from_slice(&100u32.to_le_bytes());
        base[4..8].copy_from_slice(&101u32.to_le_bytes());
        let mut t1 = store.begin();
        t1.stage_write_with_proof(block, base, MergeProof::DisjointBlocks);
        store.commit(t1).expect("t1 commit");

        // Tx2 (chunk 2): read the committed block, then RMW it twice in one txn.
        let snap1 = store.current_snapshot();
        let mut cur = store
            .read_visible(block, snap1)
            .expect("base visible")
            .into_owned();
        let mut t2 = store.begin();
        cur[8..12].copy_from_slice(&2113u32.to_le_bytes()); // slot 2 (data ptr)
        t2.stage_write_with_proof(block, cur, MergeProof::DisjointBlocks);
        let mut cur2 = t2.staged_write(block).expect("staged").to_vec();
        cur2[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // slot 3 (sentinel)
        t2.stage_write_with_proof(block, cur2, MergeProof::DisjointBlocks);
        store.commit(t2).expect("t2 commit");

        let snap2 = store.current_snapshot();
        let got = store
            .read_visible(block, snap2)
            .expect("visible")
            .into_owned();
        let mut want = vec![0u8; 16];
        want[0..4].copy_from_slice(&100u32.to_le_bytes());
        want[4..8].copy_from_slice(&101u32.to_le_bytes());
        want[8..12].copy_from_slice(&2113u32.to_le_bytes());
        want[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(
            got, want,
            "all slots incl slot 2 (2113) must survive readback"
        );
    }

    /// bd-bw90c at scale: the real e2compr path RMWs the same indirect block
    /// ~32 times within one txn (4 pointer writes per cluster across 8
    /// clusters). Replicate with 40 sequential read-your-writes full-block
    /// overwrites of one block, each setting a distinct u32 slot, all staged
    /// with MergeProof::DisjointBlocks, after a prior commit. Every slot must
    /// survive readback.
    #[test]
    fn disjoint_proof_many_same_block_rmws_after_prior_commit_roundtrips() {
        let mut store = MvccStore::new();
        let block = BlockNumber(2101);
        let nslots = 40usize;
        let mut buf = vec![0u8; nslots * 4];

        // Prior commit (chunk 1): set slot 0.
        buf[0..4].copy_from_slice(&100u32.to_le_bytes());
        let mut t1 = store.begin();
        t1.stage_write_with_proof(block, buf.clone(), MergeProof::DisjointBlocks);
        store.commit(t1).expect("t1");

        // Later txn (chunk 2): RMW the same block once per slot 1..40.
        let snap1 = store.current_snapshot();
        let mut cur = store.read_visible(block, snap1).expect("base").into_owned();
        let mut t2 = store.begin();
        for slot in 1..nslots {
            let val = 2000u32 + u32::try_from(slot).expect("slot fits u32");
            cur[slot * 4..slot * 4 + 4].copy_from_slice(&val.to_le_bytes());
            t2.stage_write_with_proof(block, cur.clone(), MergeProof::DisjointBlocks);
            cur = t2.staged_write(block).expect("staged").to_vec();
        }
        store.commit(t2).expect("t2");

        let got = store
            .read_visible(block, store.current_snapshot())
            .expect("visible")
            .into_owned();
        assert_eq!(
            u32::from_le_bytes([got[0], got[1], got[2], got[3]]),
            100,
            "prior-commit slot 0 survives"
        );
        for slot in 1..nslots {
            let v = u32::from_le_bytes([
                got[slot * 4],
                got[slot * 4 + 1],
                got[slot * 4 + 2],
                got[slot * 4 + 3],
            ]);
            assert_eq!(
                v,
                2000u32 + u32::try_from(slot).expect("slot fits u32"),
                "slot {slot} must survive readback"
            );
        }
    }

    /// bd-bw90c exact-pattern: a 4096-byte indirect block, prior-committed with
    /// slots 0..20 set, then a later txn RMWs slots 20..52 in the e2compr
    /// cluster pattern (slot%4==0 -> data ptr (non-zero), %4 in {1,2} -> hole
    /// (0), %4==3 -> sentinel), each a full-block overwrite staged with
    /// DisjointBlocks. Every non-zero slot must survive readback.
    #[test]
    fn disjoint_proof_cluster_pattern_rmw_after_prior_commit_roundtrips() {
        let mut store = MvccStore::new();
        let block = BlockNumber(2101);
        let put = |buf: &mut [u8], slot: usize, val: u32| {
            buf[slot * 4..slot * 4 + 4].copy_from_slice(&val.to_le_bytes());
        };
        let get = |buf: &[u8], slot: usize| -> u32 {
            u32::from_le_bytes([
                buf[slot * 4],
                buf[slot * 4 + 1],
                buf[slot * 4 + 2],
                buf[slot * 4 + 3],
            ])
        };

        // Prior commit: slots 0..20 = data pointers.
        let mut base = vec![0u8; 4096];
        for slot in 0..20 {
            put(&mut base, slot, 3000 + u32::try_from(slot).expect("fits"));
        }
        let mut t1 = store.begin();
        t1.stage_write_with_proof(block, base, MergeProof::DisjointBlocks);
        store.commit(t1).expect("t1");

        // Later txn: RMW slots 20..52 in the cluster (data/hole/sentinel) shape.
        let mut cur = store
            .read_visible(block, store.current_snapshot())
            .expect("base")
            .into_owned();
        let mut t2 = store.begin();
        for slot in 20..52 {
            let val = match slot % 4 {
                0 => 2000 + u32::try_from(slot).expect("fits"), // data ptr (non-zero)
                3 => 0xFFFF_FFFF,                               // sentinel
                _ => 0,                                         // hole
            };
            put(&mut cur, slot, val);
            t2.stage_write_with_proof(block, cur.clone(), MergeProof::DisjointBlocks);
            cur = t2.staged_write(block).expect("staged").to_vec();
        }
        store.commit(t2).expect("t2");

        // Force version-chain consolidation (the real path prunes once snapshots
        // are released between request scopes and the watermark advances).
        let wm = store.current_snapshot().high;
        store.prune_versions_older_than(wm);

        let got = store
            .read_visible(block, store.current_snapshot())
            .expect("visible")
            .into_owned();
        for slot in 0..20 {
            assert_eq!(
                get(&got, slot),
                3000 + u32::try_from(slot).expect("fits"),
                "prior slot {slot}"
            );
        }
        for slot in (20..52).filter(|s| s % 4 == 0) {
            assert_eq!(
                get(&got, slot),
                2000 + u32::try_from(slot).expect("fits"),
                "data slot {slot} (a hole-flanked non-zero write) must survive"
            );
        }
    }

    /// Commits v1..v5 to the same block, captures a snapshot after each.
    /// Each snapshot sees exactly the version committed at or before it.
    #[test]
    fn snapshot_visibility_chain() {
        let mut store = MvccStore::new();
        let mut snapshots = Vec::new();
        let block = BlockNumber(42);

        for version in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![version; 4]);
            store.commit(txn).expect("commit");
            snapshots.push(store.current_snapshot());
        }

        // Each snapshot i should see version i+1 (1-indexed).
        for (i, snap) in snapshots.iter().enumerate() {
            let expected_version = u8::try_from(i + 1).expect("fits u8");
            let data = store.read_visible(block, *snap).expect("should be visible");
            assert_eq!(
                data.as_ref(),
                &[expected_version; 4],
                "snapshot {i} should see version {expected_version}"
            );
        }
    }

    /// Invariant: snapshot isolation prevents seeing future commits.
    ///
    /// Take a snapshot before any commits. Later commits must not be
    /// visible at that snapshot.
    #[test]
    fn snapshot_isolation_future_invisible() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        let early_snap = store.current_snapshot();

        // Commit 3 versions after the snapshot.
        for v in 1_u8..=3 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        // Early snapshot should see nothing.
        assert!(
            store.read_visible(block, early_snap).is_none(),
            "snapshot taken before any commits should see nothing"
        );
    }

    /// Invariant: FCW — interleaved writers to same block.
    ///
    /// Scenario: 3 transactions all begin at the same snapshot, all write
    /// the same block. Only the first to commit succeeds; the other two
    /// get Conflict errors.
    #[test]
    fn fcw_three_concurrent_writers() {
        let mut store = MvccStore::new();
        let block = BlockNumber(10);

        let mut t1 = store.begin();
        let mut t2 = store.begin();
        let mut t3 = store.begin();

        t1.stage_write(block, vec![1]);
        t2.stage_write(block, vec![2]);
        t3.stage_write(block, vec![3]);

        // T1 commits first — succeeds.
        let c1 = store.commit(t1).expect("t1 should succeed");
        assert_eq!(c1, CommitSeq(1));

        // T2 and T3 conflict because block was updated after their snapshot.
        let err2 = store.commit(t2).expect_err("t2 should conflict");
        assert!(matches!(err2, CommitError::Conflict { .. }));

        let err3 = store.commit(t3).expect_err("t3 should conflict");
        assert!(matches!(err3, CommitError::Conflict { .. }));
    }

    /// Invariant: FCW is per-block — disjoint writers don't conflict.
    ///
    /// Two concurrent transactions writing to different blocks both succeed.
    #[test]
    fn fcw_disjoint_blocks_no_conflict() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(1), vec![0xAA]);
        t2.stage_write(BlockNumber(2), vec![0xBB]);

        store.commit(t1).expect("t1 should succeed");
        store
            .commit(t2)
            .expect("t2 should succeed (disjoint block)");

        let snap = store.current_snapshot();
        assert_eq!(
            store.read_visible(BlockNumber(1), snap).unwrap().as_ref(),
            &[0xAA]
        );
        assert_eq!(
            store.read_visible(BlockNumber(2), snap).unwrap().as_ref(),
            &[0xBB]
        );
    }

    /// Invariant: no lost updates — every committed write is observable.
    ///
    /// Serial commits to different blocks; all are visible at the final snapshot.
    #[test]
    fn no_lost_updates_serial() {
        let mut store = MvccStore::new();

        for i in 0_u64..20 {
            let block = BlockNumber(i);
            let mut txn = store.begin();
            let val = u8::try_from(i % 256).expect("fits u8");
            txn.stage_write(block, vec![val; 8]);
            store.commit(txn).expect("commit");
        }

        let snap = store.current_snapshot();
        for i in 0_u64..20 {
            let block = BlockNumber(i);
            let expected_val = u8::try_from(i % 256).expect("fits u8");
            let data = store.read_visible(block, snap).expect("must be visible");
            assert_eq!(data.as_ref(), &[expected_val; 8], "block {i} data mismatch");
        }
    }

    /// Invariant: no lost updates under interleaved begin/commit ordering.
    ///
    /// Interleave: begin(t1), begin(t2), commit(t1), commit(t2)
    /// where t1 and t2 write disjoint blocks. Both must persist.
    #[test]
    fn no_lost_updates_interleaved_disjoint() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(100), vec![1; 16]);
        t2.stage_write(BlockNumber(200), vec![2; 16]);

        store.commit(t1).expect("commit t1");
        store.commit(t2).expect("commit t2");

        let snap = store.current_snapshot();
        assert_eq!(
            store.read_visible(BlockNumber(100), snap).unwrap().as_ref(),
            &[1; 16]
        );
        assert_eq!(
            store.read_visible(BlockNumber(200), snap).unwrap().as_ref(),
            &[2; 16]
        );
    }

    /// Invariant: prune does not break snapshot visibility.
    ///
    /// After pruning old versions, a snapshot that sees the latest
    /// version still returns the correct data.
    #[test]
    fn prune_preserves_latest_visibility() {
        let mut store = MvccStore::new();
        let block = BlockNumber(5);

        // Write 5 versions.
        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        let snap = store.current_snapshot();

        // Prune everything up to commit 4.
        store.prune_versions_older_than(CommitSeq(4));

        // Latest snapshot should still see version 5.
        let data = store.read_visible(block, snap).expect("still visible");
        assert_eq!(data.as_ref(), &[5]);
    }

    /// Multi-threaded stress: concurrent MvccBlockDevice writers on disjoint blocks.
    ///
    /// Multiple threads each write to their own block via the MvccBlockDevice.
    /// After all threads complete, all writes must be visible.
    #[test]
    fn concurrent_mvcc_device_disjoint_writers() {
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let num_threads: usize = 8;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                let block_num = u64::try_from(i).expect("thread index fits u64");
                std::thread::spawn(move || {
                    let cx = Cx::for_testing();
                    let snap = store.read().current_snapshot();
                    let base = MemBlockDevice::new(64, 256);
                    let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);

                    // Synchronize all threads to start at the same time.
                    barrier.wait();

                    let val = u8::try_from(i % 256).expect("fits u8");
                    dev.write_block(&cx, BlockNumber(block_num), &[val; 64])
                        .expect("write should succeed (disjoint blocks)");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Verify all writes are visible at the latest snapshot.
        let guard = store.read();
        let snap = guard.current_snapshot();
        for i in 0..num_threads {
            let block_num = u64::try_from(i).expect("thread index fits u64");
            let expected_val = u8::try_from(i % 256).expect("fits u8");
            let data = guard
                .read_visible(BlockNumber(block_num), snap)
                .expect("block must be visible");
            assert_eq!(data.as_ref(), &[expected_val; 64], "thread {i} write lost");
        }
        drop(guard);
    }

    /// Multi-threaded stress: concurrent readers see stable snapshots.
    ///
    /// A writer thread commits versions while reader threads assert that
    /// their snapshot view never changes mid-read.
    #[test]
    fn concurrent_readers_stable_snapshot() {
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let block = BlockNumber(0);

        // Seed an initial version so readers have something to see.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(block, vec![0; 64]);
            guard.commit(txn).expect("seed commit");
        }

        let snap = store.read().current_snapshot();
        let num_readers: usize = 4;
        let reads_per_thread: usize = 200;
        let barrier = Arc::new(std::sync::Barrier::new(num_readers + 1));

        // Reader threads: each reads the same block many times at `snap`.
        let reader_handles: Vec<_> = (0..num_readers)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let cx = Cx::for_testing();
                    let base = MemBlockDevice::new(64, 256);
                    let dev = MvccBlockDevice::new(base, Arc::clone(&store), snap);

                    barrier.wait();

                    for _ in 0..reads_per_thread {
                        let buf = dev.read_block(&cx, block).expect("read");
                        // Snapshot should always see version 0.
                        assert_eq!(buf.as_slice(), &[0; 64], "snapshot view changed");
                    }
                })
            })
            .collect();

        // Writer thread: commits new versions concurrently.
        let writer_store = Arc::clone(&store);
        let writer_barrier = Arc::clone(&barrier);
        let writer_handle = std::thread::spawn(move || {
            writer_barrier.wait();

            for v in 1_u8..=50 {
                let mut guard = writer_store.write();
                let mut txn = guard.begin();
                txn.stage_write(block, vec![v; 64]);
                guard.commit(txn).expect("writer commit");
            }
        });

        for h in reader_handles {
            h.join().expect("reader panicked");
        }
        writer_handle.join().expect("writer panicked");
    }

    // ── Lab runtime deterministic concurrency tests ─────────────────────
    //
    // These tests use the asupersync lab runtime for deterministic, seed-
    // driven scheduling.  Instead of OS thread interleaving (non-deterministic),
    // each test spawns async tasks that yield at specific points.  The lab
    // scheduler picks the next task deterministically based on the seed.
    //
    // Same seed → same interleaving → same result.  Different seeds explore
    // different interleavings.  This makes concurrency bugs reproducible.
    //
    // Invariants verified:
    //   1. Snapshot visibility — readers see only committed versions ≤ snap.
    //   2. FCW (first-committer-wins) — exactly one writer succeeds per block.
    //   3. No lost updates — every committed write is observable.
    //   4. Write skew — documents a known FCW limitation (SSI prerequisite).

    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::types::Budget;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    /// A future that yields once before completing, creating a scheduling
    /// opportunity for the lab runtime.
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

    async fn yield_now() {
        YieldOnce { yielded: false }.await;
    }

    /// Run N tasks that all write to the same block under lab scheduling.
    ///
    /// All transactions are pre-begun at the same snapshot so that the
    /// interesting interleaving is the commit order (which the lab
    /// scheduler determines based on the seed).
    ///
    /// Returns: (Vec<commit outcomes as Ok(seq)/Err>, steps executed).
    fn run_fcw_scenario(seed: u64, num_writers: usize) -> (Vec<Result<u64, usize>>, u64) {
        let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
        let region = runtime.state.create_root_region(Budget::INFINITE);

        let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
        let results = Arc::new(std::sync::Mutex::new(vec![None; num_writers]));
        let block = BlockNumber(42);

        // Pre-begin all transactions at the same snapshot.  This ensures
        // FCW is actually exercised regardless of scheduling order.
        let txns: Vec<Transaction> = {
            let mut s = store.lock().unwrap();
            (0..num_writers).map(|_| s.begin()).collect()
        };

        for (i, txn) in txns.into_iter().enumerate() {
            let store = Arc::clone(&store);
            let results = Arc::clone(&results);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async move {
                    // Stage write.
                    let mut txn = txn;
                    let writer_val = u8::try_from(i % 256).expect("fits u8");
                    txn.stage_write(block, vec![writer_val; 8]);
                    yield_now().await; // Scheduling point — other writers may stage.

                    // Commit (order determined by lab scheduler).
                    let outcome = {
                        let mut s = store.lock().unwrap();
                        s.commit(txn)
                    };
                    results.lock().unwrap()[i] = Some(outcome.map(|seq| seq.0).map_err(|_| i));
                })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
        }

        let steps = runtime.run_until_quiescent();

        let results: Vec<Result<u64, usize>> = Arc::try_unwrap(results)
            .unwrap()
            .into_inner()
            .unwrap()
            .into_iter()
            .map(|r| r.expect("task should have completed"))
            .collect();

        (results, steps)
    }

    /// Lab determinism: same seed → identical FCW conflict pattern.
    ///
    /// Runs the same scenario 3 times with the same seed and asserts the
    /// commit outcomes are identical.
    #[test]
    fn lab_deterministic_fcw_same_seed() {
        let seed = 42;
        let (r1, _) = run_fcw_scenario(seed, 4);
        let (r2, _) = run_fcw_scenario(seed, 4);
        let (r3, _) = run_fcw_scenario(seed, 4);

        assert_eq!(
            r1, r2,
            "same seed must produce identical outcomes (run 1 vs 2)"
        );
        assert_eq!(
            r2, r3,
            "same seed must produce identical outcomes (run 2 vs 3)"
        );
    }

    /// Lab invariant: FCW — across many seeds, exactly one writer succeeds.
    ///
    /// For each seed, N tasks write to the same block.  The invariant is
    /// that exactly one commit succeeds (Ok) and the rest fail (Err).
    #[test]
    fn lab_fcw_invariant_across_seeds() {
        let num_writers = 4;
        for seed in 0_u64..50 {
            let (results, _) = run_fcw_scenario(seed, num_writers);
            let successes = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(
                successes, 1,
                "seed {seed}: expected exactly 1 success, got {successes} in {results:?}"
            );
        }
    }

    /// Lab invariant: no lost updates — disjoint block writers under varied scheduling.
    ///
    /// N tasks each write to their own block.  Across many seeds, all N
    /// writes must be visible at the final snapshot.
    #[test]
    fn lab_no_lost_updates_disjoint_blocks() {
        let num_writers: usize = 8;

        for seed in 0_u64..30 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            let committed = Arc::new(std::sync::Mutex::new(Vec::new()));

            for i in 0..num_writers {
                let store = Arc::clone(&store);
                let committed = Arc::clone(&committed);
                let block = BlockNumber(u64::try_from(i).unwrap());
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        let txn = {
                            let mut s = store.lock().unwrap();
                            s.begin()
                        };
                        yield_now().await;

                        let mut txn = txn;
                        let val = u8::try_from(i % 256).unwrap();
                        txn.stage_write(block, vec![val; 4]);
                        yield_now().await;

                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit(txn)
                        };
                        if result.is_ok() {
                            committed.lock().unwrap().push(i);
                        }
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let committed = Arc::try_unwrap(committed).unwrap().into_inner().unwrap();
            assert_eq!(
                committed.len(),
                num_writers,
                "seed {seed}: all {num_writers} disjoint writers must succeed, got {committed:?}"
            );

            // Verify all data is visible.
            let store = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
            let snap = store.current_snapshot();
            for i in 0..num_writers {
                let block = BlockNumber(u64::try_from(i).unwrap());
                let val = u8::try_from(i % 256).unwrap();
                let data = store
                    .read_visible(block, snap)
                    .expect("committed writer block must be visible");
                assert_eq!(
                    data.as_ref(),
                    &[val; 4],
                    "seed {seed}: block {i} data mismatch"
                );
            }
        }
    }

    /// Lab invariant: snapshot visibility under interleaved writers.
    ///
    /// A snapshot is captured before writers begin.  Under all interleavings,
    /// reads at that snapshot return the initial version, never a writer's.
    #[test]
    fn lab_snapshot_visibility_under_interleaving() {
        for seed in 0_u64..30 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            let block = BlockNumber(1);

            // Seed an initial version.
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block, vec![0xAA; 4]);
                s.commit(txn).expect("seed commit");
            }

            // Pre-capture snapshot before any writer task runs.
            let reader_snap = store.lock().unwrap().current_snapshot();

            let reader_result = Arc::new(std::sync::Mutex::new(None));

            // Reader task: reads at the pre-captured snapshot.
            {
                let store = Arc::clone(&store);
                let reader_result = Arc::clone(&reader_result);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await; // Writers may commit here.
                        yield_now().await; // Extra yield for more interleaving.

                        let data = {
                            let s = store.lock().unwrap();
                            s.read_visible(block, reader_snap)
                                .map(std::borrow::Cow::into_owned)
                        };
                        *reader_result.lock().unwrap() = Some(data);
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // Writer tasks: commit new versions.
            for v in 1_u8..=3 {
                let store = Arc::clone(&store);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;
                        let mut s = store.lock().unwrap();
                        let mut txn = s.begin();
                        txn.stage_write(block, vec![v; 4]);
                        s.commit(txn).expect("writer commit");
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let result = Arc::try_unwrap(reader_result)
                .unwrap()
                .into_inner()
                .unwrap()
                .expect("reader task should have completed");

            // The reader's snapshot was captured before writers,
            // so it must see 0xAA regardless of interleaving.
            let data = result.expect("block must be visible at initial snapshot");
            assert_eq!(
                data,
                vec![0xAA; 4],
                "seed {seed}: reader must see initial version (0xAA), not a later writer's data"
            );
        }
    }

    /// Lab: write skew scenario — documents the FCW limitation.
    ///
    /// Classic write skew: T1 reads block A, T2 reads block B.
    /// T1 writes block B based on A's value, T2 writes block A based on B's value.
    /// Under FCW, both succeed because they write disjoint blocks.
    /// This is a known anomaly that SSI (bd-1wx) will prevent.
    ///
    /// The test verifies:
    /// - FCW allows both commits (expected, not a bug under FCW).
    /// - The resulting state violates a cross-block constraint.
    ///
    /// When SSI is implemented, this test should be updated to assert that
    /// at least one transaction is aborted.
    #[test]
    fn lab_write_skew_under_fcw() {
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        for seed in 0_u64..20 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));

            // Seed: both blocks start with value 1.
            // Constraint: block_a + block_b should remain ≤ 2.
            // Each transaction reads one block (sees 1), and sets the
            // other block to 2 (believing the total is 1+2=3 is ok for
            // its local view, but the combined effect is 2+2=4 — violated).
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block_a, vec![1]);
                txn.stage_write(block_b, vec![1]);
                s.commit(txn).expect("seed commit");
            }

            let outcomes = Arc::new(std::sync::Mutex::new((None, None)));

            // Pre-begin both transactions at the same snapshot so they
            // each see A=1, B=1 and write disjoint blocks.
            let (txn1, txn2) = {
                let mut s = store.lock().unwrap();
                (s.begin(), s.begin())
            };

            // T1: writes B to 2 (based on having seen A=1 at snapshot).
            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;

                        let mut txn1 = txn1;
                        txn1.stage_write(block_b, vec![2]);
                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit(txn1)
                        };
                        outcomes.lock().unwrap().0 = Some(result.is_ok());
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // T2: writes A to 2 (based on having seen B=1 at snapshot).
            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;

                        let mut txn2 = txn2;
                        txn2.stage_write(block_a, vec![2]);
                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit(txn2)
                        };
                        outcomes.lock().unwrap().1 = Some(result.is_ok());
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let outcomes = Arc::try_unwrap(outcomes).unwrap().into_inner().unwrap();
            let t1_ok = outcomes.0.expect("T1 should complete");
            let t2_ok = outcomes.1.expect("T2 should complete");

            // Under FCW, both succeed because they write disjoint blocks.
            // This IS the write skew anomaly — FCW does not detect it.
            assert!(
                t1_ok && t2_ok,
                "seed {seed}: under FCW, both disjoint-block writers should succeed \
                 (write skew is expected). Got t1={t1_ok}, t2={t2_ok}"
            );

            // Verify the constraint IS violated (both blocks are now 2).
            let s = store.lock().unwrap();
            let snap = s.current_snapshot();
            let a = s.read_visible(block_a, snap).unwrap()[0];
            let b = s.read_visible(block_b, snap).unwrap()[0];
            drop(s);
            assert!(
                a + b > 2,
                "seed {seed}: write skew should produce a+b > 2, got a={a} b={b}"
            );
        }
    }

    /// Lab: interleaved commit ordering with same-block conflict.
    ///
    /// Verifies that the commit-order winner is deterministic per seed.
    /// All transactions pre-begin at the same snapshot, all write the
    /// same block, and exactly one succeeds per seed.
    #[test]
    fn lab_commit_order_determines_winner() {
        let block = BlockNumber(7);
        let num_tasks: usize = 5;

        for seed in 0_u64..30 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            let winner = Arc::new(std::sync::Mutex::new(None));

            // Pre-begin all at the same snapshot.
            let txns: Vec<Transaction> = {
                let mut s = store.lock().unwrap();
                (0..num_tasks).map(|_| s.begin()).collect()
            };

            for (i, txn) in txns.into_iter().enumerate() {
                let store = Arc::clone(&store);
                let winner = Arc::clone(&winner);
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        let mut txn = txn;
                        let val = u8::try_from(i % 256).unwrap();
                        txn.stage_write(block, vec![val; 4]);
                        yield_now().await;

                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit(txn)
                        };
                        if result.is_ok() {
                            let mut w = winner.lock().unwrap();
                            assert!(w.is_none(), "seed {seed}: two tasks both claimed to win!");
                            *w = Some(i);
                        }
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let w = Arc::try_unwrap(winner).unwrap().into_inner().unwrap();
            assert!(
                w.is_some(),
                "seed {seed}: no task won the FCW race (all failed?)"
            );

            // Verify the winner's data is visible.
            let data = {
                let s = store.lock().unwrap();
                let snap = s.current_snapshot();
                s.read_visible(block, snap)
                    .expect("winner data must be visible")
                    .to_vec()
            };
            let expected_val = u8::try_from(w.unwrap() % 256).unwrap();
            assert_eq!(
                data,
                vec![expected_val; 4],
                "seed {seed}: visible data should match winner's write"
            );
        }
    }

    // ── Watermark / GC tests ───────────────────────────────────────────

    #[test]
    fn watermark_empty_when_no_snapshots_registered() {
        let store = MvccStore::new();
        assert!(store.watermark().is_none());
        assert_eq!(store.active_snapshot_count(), 0);
    }

    #[test]
    fn register_and_release_snapshot() {
        let mut store = MvccStore::new();
        let snap = Snapshot { high: CommitSeq(5) };

        store.register_snapshot(snap);
        assert_eq!(store.watermark(), Some(CommitSeq(5)));
        assert_eq!(store.active_snapshot_count(), 1);

        assert!(store.release_snapshot(snap));
        assert!(store.watermark().is_none());
        assert_eq!(store.active_snapshot_count(), 0);
    }

    #[test]
    fn watermark_tracks_oldest_active_snapshot() {
        let mut store = MvccStore::new();
        let old = Snapshot { high: CommitSeq(3) };
        let mid = Snapshot { high: CommitSeq(7) };
        let new = Snapshot {
            high: CommitSeq(12),
        };

        store.register_snapshot(mid);
        store.register_snapshot(new);
        store.register_snapshot(old);

        assert_eq!(store.watermark(), Some(CommitSeq(3)));
        assert_eq!(store.active_snapshot_count(), 3);

        // Release the oldest — watermark advances.
        store.release_snapshot(old);
        assert_eq!(store.watermark(), Some(CommitSeq(7)));

        // Release mid — watermark advances again.
        store.release_snapshot(mid);
        assert_eq!(store.watermark(), Some(CommitSeq(12)));

        // Release last — no watermark.
        store.release_snapshot(new);
        assert!(store.watermark().is_none());
    }

    #[test]
    fn snapshot_ref_counting() {
        let mut store = MvccStore::new();
        let snap = Snapshot { high: CommitSeq(5) };

        // Register same snapshot twice.
        store.register_snapshot(snap);
        store.register_snapshot(snap);
        assert_eq!(store.active_snapshot_count(), 2);
        assert_eq!(store.watermark(), Some(CommitSeq(5)));

        // First release — still active.
        store.release_snapshot(snap);
        assert_eq!(store.active_snapshot_count(), 1);
        assert_eq!(store.watermark(), Some(CommitSeq(5)));

        // Second release — gone.
        store.release_snapshot(snap);
        assert_eq!(store.active_snapshot_count(), 0);
        assert!(store.watermark().is_none());
    }

    #[test]
    fn snapshot_ref_count_saturates_at_numeric_limit() {
        let mut store = MvccStore::new();
        let snap = Snapshot { high: CommitSeq(5) };
        store.active_snapshots.insert(snap.high, u64::MAX - 1);

        store.register_snapshot(snap);
        assert_eq!(store.active_snapshots.get(&snap.high), Some(&u64::MAX));

        store.register_snapshot(snap);
        assert_eq!(store.active_snapshots.get(&snap.high), Some(&u64::MAX));
        assert_eq!(store.active_snapshot_count(), usize::MAX);

        assert!(store.release_snapshot(snap));
        assert_eq!(
            store.active_snapshots.get(&snap.high),
            Some(&(u64::MAX - 1))
        );
    }

    #[test]
    fn release_unregistered_snapshot_returns_false() {
        let mut store = MvccStore::new();
        let snap = Snapshot {
            high: CommitSeq(99),
        };
        assert!(!store.release_snapshot(snap));
    }

    #[test]
    fn prune_safe_respects_active_snapshots() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Write 5 versions (commit seqs 1..=5).
        let mut snaps = Vec::new();
        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snaps.push(store.current_snapshot());
        }

        // Register snapshot at commit 3.
        store.register_snapshot(snaps[2]);

        // Safe prune should keep versions readable at commit 3.
        let wm = store.prune_safe();
        assert_eq!(wm, CommitSeq(3));

        // Snapshot at commit 3 still works.
        assert_eq!(
            store.read_visible(block, snaps[2]).unwrap().as_ref(),
            &[3],
            "version at commit 3 should survive pruning"
        );

        // Latest snapshot still works.
        assert_eq!(
            store.read_visible(block, snaps[4]).unwrap().as_ref(),
            &[5],
            "latest version should always survive"
        );

        // Versions 1 and 2 should have been pruned.
        let snap_1 = Snapshot { high: CommitSeq(1) };
        let old_read = store.read_visible(block, snap_1);
        assert!(
            old_read.is_none() || old_read.unwrap().as_ref() == [3],
            "version 1 should be pruned or replaced by version 3"
        );
    }

    #[test]
    fn prune_safe_with_no_snapshots_keeps_only_latest() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Write 10 versions.
        for v in 1_u8..=10 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        assert_eq!(store.version_count(), 10);

        // No active snapshots — prune should reduce to 1 per block.
        store.prune_safe();

        // At most 1 version per block should remain.
        assert!(
            store.version_count() <= 1,
            "expected <= 1 version, got {}",
            store.version_count()
        );

        // Latest version still readable.
        let snap = store.current_snapshot();
        assert_eq!(store.read_visible(block, snap).unwrap().as_ref(), &[10]);
    }

    #[test]
    fn version_count_and_block_count_versioned() {
        let mut store = MvccStore::new();

        assert_eq!(store.version_count(), 0);
        assert_eq!(store.block_count_versioned(), 0);

        // 3 versions of block 1, 2 versions of block 2.
        for v in 1_u8..=3 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(1), vec![v]);
            store.commit(txn).expect("commit");
        }
        for v in 1_u8..=2 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(2), vec![v]);
            store.commit(txn).expect("commit");
        }

        assert_eq!(store.version_count(), 5);
        assert_eq!(store.block_count_versioned(), 2);
    }

    /// Memory bounding simulation: many commits with periodic pruning.
    ///
    /// Writes 200 versions to the same block.  With periodic `prune_safe`
    /// and a single active snapshot sliding forward, version count stays
    /// bounded.
    #[test]
    fn memory_bounded_under_periodic_gc() {
        let mut store = MvccStore::new();
        let block = BlockNumber(0);
        let mut max_versions = 0_usize;
        let mut current_snap: Option<Snapshot> = None;

        for round in 0_u64..200 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![u8::try_from(round % 256).unwrap()]);
            store.commit(txn).expect("commit");

            // Slide the active snapshot window every 10 commits.
            if round % 10 == 0 {
                if let Some(old) = current_snap {
                    store.release_snapshot(old);
                }
                let snap = store.current_snapshot();
                store.register_snapshot(snap);
                current_snap = Some(snap);

                store.prune_safe();
            }

            let vc = store.version_count();
            if vc > max_versions {
                max_versions = vc;
            }
        }

        // With pruning every 10 commits and a sliding window of ~10 commits,
        // the max version count should be bounded well below 200.
        assert!(
            max_versions < 25,
            "expected bounded version growth, but max_versions was {max_versions}"
        );

        // Final state: current snapshot still readable.
        let snap = store.current_snapshot();
        let data = store.read_visible(block, snap).expect("readable");
        assert_eq!(data.as_ref(), &[199_u8]);
    }

    /// Long-running simulation with multiple blocks.
    ///
    /// 500 commits across 10 blocks with periodic GC.  Verifies that
    /// version count stays bounded and all latest values are correct.
    #[test]
    fn memory_bounded_multi_block_simulation() {
        let mut store = MvccStore::new();
        let num_blocks = 10_u64;
        let num_rounds = 500_u64;
        let mut current_snap: Option<Snapshot> = None;

        for round in 0..num_rounds {
            let block = BlockNumber(round % num_blocks);
            let val = u8::try_from(round % 256).unwrap();

            let mut txn = store.begin();
            txn.stage_write(block, vec![val]);
            store.commit(txn).expect("commit");

            // Slide the active snapshot window every 20 commits.
            if round % 20 == 0 {
                if let Some(old) = current_snap {
                    store.release_snapshot(old);
                }
                let snap = store.current_snapshot();
                store.register_snapshot(snap);
                current_snap = Some(snap);

                store.prune_safe();
            }
        }

        // Final cleanup.
        if let Some(old) = current_snap {
            store.release_snapshot(old);
        }
        store.prune_safe();

        // After full cleanup, should have at most 1 version per block.
        let expected_max = usize::try_from(num_blocks).unwrap();
        assert!(
            store.version_count() <= expected_max,
            "expected <= {num_blocks} versions after full GC, got {}",
            store.version_count()
        );

        // Verify latest values are correct.
        let snap = store.current_snapshot();
        for b in 0..num_blocks {
            let block = BlockNumber(b);
            // The last round that wrote to this block:
            let last_round = num_rounds - num_blocks + b;
            let expected = u8::try_from(last_round % 256).unwrap();
            assert_eq!(
                store.read_visible(block, snap).unwrap().as_ref(),
                &[expected],
                "block {b} should have latest value"
            );
        }
    }

    // ── Version-chain compression tests ───────────────────────────────

    #[test]
    fn compression_reconstructs_chain_across_identical_markers() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy::dedup_only());
        let block = BlockNumber(9);
        let payloads = [
            vec![0xAA; 8],
            vec![0xAA; 8],
            vec![0xBB; 8],
            vec![0xBB; 8],
            vec![0xBB; 8],
            vec![0xCC; 8],
        ];

        let mut snaps = Vec::with_capacity(payloads.len());
        for payload in &payloads {
            let mut txn = store.begin();
            txn.stage_write(block, payload.clone());
            store.commit(txn).expect("commit");
            snaps.push(store.current_snapshot());
        }

        for (snap, expected) in snaps.iter().zip(payloads.iter()) {
            assert_eq!(
                store.read_visible(block, *snap).expect("visible"),
                expected.as_slice()
            );
        }

        let chain = store.versions.get(&block).expect("chain");
        assert!(matches!(chain[0].data, VersionData::Full(_)));
        assert!(matches!(chain[1].data, VersionData::Identical));
        assert!(matches!(chain[2].data, VersionData::Full(_)));
        assert!(matches!(chain[3].data, VersionData::Identical));
        assert!(matches!(chain[4].data, VersionData::Identical));
        assert!(matches!(chain[5].data, VersionData::Full(_)));
    }

    #[test]
    fn compression_chain_cap_respects_active_snapshot() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(3),
            algo: CompressionAlgo::None,
        });
        let block = BlockNumber(77);
        let mut snaps = Vec::new();

        for v in 1_u8..=4 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snaps.push(store.current_snapshot());
        }

        let held = snaps[3];
        store.register_snapshot(held);

        for v in 5_u8..=6 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        assert_eq!(
            store
                .read_visible(block, held)
                .expect("held snapshot remains visible")
                .as_ref(),
            &[4]
        );

        let chain = store.versions.get(&block).expect("chain");
        assert!(chain.len() >= 3);
        assert!(
            chain
                .first()
                .is_some_and(|v| matches!(v.data, VersionData::Full(_)))
        );

        assert!(store.release_snapshot(held));

        let mut txn = store.begin();
        txn.stage_write(block, vec![7]);
        store.commit(txn).expect("commit");

        let chain = store.versions.get(&block).expect("chain");
        assert!(chain.len() <= 3, "chain should be capped after release");
        assert!(
            chain
                .first()
                .is_some_and(|v| matches!(v.data, VersionData::Full(_)))
        );
    }

    #[test]
    fn chain_length_bounded_after_many_writes() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(8),
            algo: CompressionAlgo::None,
        });
        let block = BlockNumber(88);

        for v in 1_u8..=100 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        let chain_len = store.versions.get(&block).expect("chain").len();
        assert!(
            chain_len <= 8,
            "chain should remain bounded by cap, got {chain_len}"
        );

        let stats = store.block_version_stats();
        assert_eq!(stats.chain_cap, Some(8));
        assert_eq!(stats.tracked_blocks, 1);
        assert!(stats.max_chain_length <= 8);
    }

    #[test]
    fn chain_backpressure_triggers_and_force_advances_oldest_snapshot() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(2),
            algo: CompressionAlgo::None,
        });
        let block = BlockNumber(89);

        let mut snapshots = Vec::new();
        for v in 1_u8..=2 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("seed");
            snapshots.push(store.current_snapshot());
        }

        let oldest = snapshots[0];
        // Hold two refs to oldest snapshot so one forced advance still leaves
        // a pin, ensuring backpressure is observable.
        store.register_snapshot(oldest);
        store.register_snapshot(oldest);
        assert_eq!(store.active_snapshot_count(), 2);

        let mut saw_backpressure = false;
        for v in 3_u8..=64 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            match store.commit(txn) {
                Ok(_) => {}
                Err(CommitError::ChainBackpressure {
                    cap,
                    critical_len,
                    chain_len,
                    ..
                }) => {
                    assert_eq!(cap, 2);
                    assert!(chain_len >= critical_len);
                    saw_backpressure = true;
                    break;
                }
                Err(other) => assert!(
                    matches!(other, CommitError::ChainBackpressure { .. }),
                    "unexpected commit error: {other:?}"
                ),
            }
        }
        assert!(
            saw_backpressure,
            "expected backpressure at critical chain length"
        );
        assert_eq!(
            store.active_snapshot_count(),
            1,
            "one oldest snapshot ref should be force-advanced"
        );

        assert!(store.release_snapshot(oldest));
        store.prune_safe();
        store.ebr_collect();

        let mut retry = store.begin();
        retry.stage_write(block, vec![0xAA]);
        store
            .commit(retry)
            .expect("commit should recover after release");
        let chain_len = store.versions.get(&block).expect("chain").len();
        assert!(chain_len <= 2, "chain should recover back under cap");

        let stats = store.block_version_stats();
        assert_eq!(stats.chain_cap, Some(2));
        assert_eq!(stats.chains_over_critical, 0);
    }

    #[test]
    fn compression_hot_block_memory_reduction_is_measurable() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy::dedup_only());
        let block = BlockNumber(101);
        let payload = vec![0x42; 4096];
        let writes = 100_usize;

        for _ in 0..writes {
            let mut txn = store.begin();
            txn.stage_write(block, payload.clone());
            store.commit(txn).expect("commit");
        }

        let stats = store.compression_stats();
        let uncompressed = writes * payload.len();
        assert_eq!(stats.full_versions, 1);
        assert_eq!(stats.identical_versions, writes - 1);
        assert_eq!(stats.bytes_stored, payload.len());
        assert_eq!(stats.bytes_saved, uncompressed - payload.len());
        assert!(stats.compression_ratio() < 0.02);

        let latest = store.current_snapshot();
        assert_eq!(
            store.read_visible(block, latest).expect("latest").as_ref(),
            payload.as_slice()
        );
    }

    #[test]
    fn ebr_reclaims_retired_versions_after_collect() {
        let mut store = MvccStore::new();
        let block = BlockNumber(333);

        for v in 1_u8..=12 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v; 32]);
            store.commit(txn).expect("commit");
        }

        let before = store.ebr_stats();
        store.prune_versions_older_than(CommitSeq(10));
        let after_prune = store.ebr_stats();
        assert!(
            after_prune.retired_versions > before.retired_versions,
            "prune should retire at least one version"
        );

        store.ebr_collect();
        let after_collect = store.ebr_stats();
        assert_eq!(
            after_collect.retired_versions, after_collect.reclaimed_versions,
            "all retired versions should be reclaimed after collection in quiescent state"
        );
        assert_eq!(after_collect.pending_versions(), 0);
    }

    #[test]
    fn ebr_retirement_waits_for_snapshot_safe_pruning() {
        let mut store = MvccStore::new();
        let block = BlockNumber(334);
        let mut snapshots = Vec::new();

        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snapshots.push(store.current_snapshot());
        }

        let held = snapshots[0];
        store.register_snapshot(held);

        let before = store.ebr_stats();
        let _ = store.prune_safe();
        let after_blocked = store.ebr_stats();
        assert_eq!(
            after_blocked.retired_versions, before.retired_versions,
            "oldest held snapshot should block retirement"
        );

        assert!(store.release_snapshot(held));
        let _ = store.prune_safe();
        store.ebr_collect();
        let after_release = store.ebr_stats();
        assert!(
            after_release.retired_versions > after_blocked.retired_versions,
            "retirement should progress after snapshot release"
        );
        assert_eq!(
            after_release.retired_versions, after_release.reclaimed_versions,
            "retired versions should be reclaimable after release"
        );
    }

    #[test]
    fn ebr_collect_is_noop_without_retirements() {
        let store = MvccStore::new();
        let before = store.ebr_stats();
        store.ebr_collect();
        let after = store.ebr_stats();
        assert_eq!(before, after);
        assert_eq!(after.pending_versions(), 0);
    }

    #[test]
    fn ebr_reclaimer_counters_saturate_at_numeric_limits() {
        let reclaimer = EbrVersionReclaimer::default();
        reclaimer
            .retired_versions
            .store(u64::MAX, Ordering::Relaxed);
        reclaimer
            .reclaimed_versions
            .store(u64::MAX, Ordering::Relaxed);

        reclaimer.retire_versions(vec![BlockVersion {
            block: BlockNumber(1),
            commit_seq: CommitSeq(1),
            writer: TxnId(1),
            data: VersionData::full(vec![0xA5; 8]),
        }]);
        reclaimer.collect();

        let stats = reclaimer.stats();
        assert_eq!(stats.retired_versions, u64::MAX);
        assert_eq!(stats.reclaimed_versions, u64::MAX);
        assert_eq!(stats.pending_versions(), 0);
    }

    #[test]
    fn gc_batch_skips_when_budget_below_threshold() {
        let mut store = MvccStore::new();
        let block = BlockNumber(777);
        for v in 1_u8..=16 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v; 32]);
            store.commit(txn).expect("commit");
        }

        let _ = store.prune_safe();
        let pending_before = store.ebr_stats().pending_versions();
        assert!(pending_before > 0, "expected pending retired versions");

        let low_budget_cx =
            Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(8));
        let result = store.run_gc_batch(
            &low_budget_cx,
            GcBackpressureConfig {
                min_poll_quota: 16,
                throttle_sleep: Duration::ZERO,
            },
        );

        assert!(result.is_none(), "expected GC batch to be skipped");
        assert_eq!(
            store.ebr_stats().pending_versions(),
            pending_before,
            "pending retired versions should be unchanged when throttled"
        );
    }

    #[test]
    fn gc_batch_honors_expired_cx_without_throttle_sleep() {
        let mut store = MvccStore::new();
        let block = BlockNumber(779);
        for v in 1_u8..=16 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v; 32]);
            store.commit(txn).expect("commit");
        }

        let _ = store.prune_safe();
        let pending_before = store.ebr_stats().pending_versions();
        assert!(pending_before > 0, "expected pending retired versions");

        let expired = asupersync::Budget::new().with_deadline(asupersync::types::Time::ZERO);
        let expired_cx = Cx::for_testing_with_budget(expired);
        let throttle_sleep = Duration::from_millis(250);
        let started = Instant::now();
        let _ = store.run_gc_batch(
            &expired_cx,
            GcBackpressureConfig {
                min_poll_quota: 0,
                throttle_sleep,
            },
        );
        let elapsed = started.elapsed();

        assert!(
            elapsed < throttle_sleep / 2,
            "expired Cx should skip throttle sleep promptly, elapsed={elapsed:?}"
        );
        assert_eq!(
            store.ebr_stats().pending_versions(),
            pending_before,
            "expired Cx should not reclaim retired versions"
        );
    }

    #[test]
    fn gc_batch_throttle_observes_mid_sleep_cancellation() {
        let mut store = MvccStore::new();
        let block = BlockNumber(780);
        for v in 1_u8..=16 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v; 32]);
            store.commit(txn).expect("commit");
        }

        let _ = store.prune_safe();
        let pending_before = store.ebr_stats().pending_versions();
        assert!(pending_before > 0, "expected pending retired versions");

        let low_budget_cx =
            Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(8));
        let cancel_cx = low_budget_cx.clone();
        let throttle_sleep = Duration::from_millis(250);

        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(15));
            cancel_cx.set_cancel_requested(true);
        });

        let started = Instant::now();
        let result = store.run_gc_batch(
            &low_budget_cx,
            GcBackpressureConfig {
                min_poll_quota: 16,
                throttle_sleep,
            },
        );
        let elapsed = started.elapsed();
        canceller.join().expect("canceller thread should finish");

        assert!(result.is_none(), "expected GC batch to be skipped");
        assert!(
            elapsed < throttle_sleep / 2,
            "cancelled Cx should interrupt GC throttle sleep promptly, elapsed={elapsed:?}"
        );
        assert_eq!(
            store.ebr_stats().pending_versions(),
            pending_before,
            "cancelled Cx should not reclaim retired versions"
        );
    }

    #[test]
    fn gc_batch_throttling_reduces_reclamation_throughput() {
        let build_store = || {
            let mut store = MvccStore::new();
            let block = BlockNumber(778);
            for v in 1_u8..=32 {
                let mut txn = store.begin();
                txn.stage_write(block, vec![v; 32]);
                store.commit(txn).expect("commit");
            }
            let _ = store.prune_safe();
            assert!(store.ebr_stats().pending_versions() > 0);
            store
        };

        let mut throttled_store = build_store();
        let throttled_cx =
            Cx::for_testing_with_budget(asupersync::Budget::new().with_poll_quota(8));
        for _ in 0..4 {
            let _ = throttled_store.run_gc_batch(
                &throttled_cx,
                GcBackpressureConfig {
                    min_poll_quota: 16,
                    throttle_sleep: Duration::ZERO,
                },
            );
        }
        let throttled_reclaimed = throttled_store.ebr_stats().reclaimed_versions;

        let mut unthrottled_store = build_store();
        let unthrottled_cx = Cx::for_testing();
        for _ in 0..4 {
            let _ = unthrottled_store.run_gc_batch(
                &unthrottled_cx,
                GcBackpressureConfig {
                    min_poll_quota: 16,
                    throttle_sleep: Duration::ZERO,
                },
            );
        }
        let unthrottled_reclaimed = unthrottled_store.ebr_stats().reclaimed_versions;

        assert!(
            unthrottled_reclaimed > throttled_reclaimed,
            "expected more reclamation throughput without budget pressure"
        );
    }

    #[test]
    fn ebr_retirement_waits_for_all_snapshots_to_release() {
        let mut store = MvccStore::new();
        let block = BlockNumber(335);
        let mut snapshots = Vec::new();

        for v in 1_u8..=6 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snapshots.push(store.current_snapshot());
        }

        let oldest = snapshots[0];
        let middle = snapshots[2];
        store.register_snapshot(oldest);
        store.register_snapshot(middle);

        let before = store.ebr_stats();
        let _ = store.prune_safe();
        let after_two_pins = store.ebr_stats();
        assert_eq!(
            after_two_pins.retired_versions, before.retired_versions,
            "retirement must not start while oldest snapshot is pinned"
        );

        assert!(store.release_snapshot(middle));
        let _ = store.prune_safe();
        let after_one_pin = store.ebr_stats();
        assert_eq!(
            after_one_pin.retired_versions, before.retired_versions,
            "oldest snapshot pin should still block retirement"
        );

        assert!(store.release_snapshot(oldest));
        let _ = store.prune_safe();
        store.ebr_collect();
        let after_release = store.ebr_stats();
        assert!(
            after_release.retired_versions > before.retired_versions,
            "retirement should progress once all snapshots are released"
        );
        assert_eq!(after_release.pending_versions(), 0);
    }

    #[test]
    fn ebr_prune_reduces_chain_and_keeps_latest_visible() {
        let mut store = MvccStore::new();
        let block = BlockNumber(336);

        for v in 1_u8..=20 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v; 8]);
            store.commit(txn).expect("commit");
        }

        let latest_snapshot = store.current_snapshot();
        let latest_payload = store
            .read_visible(block, latest_snapshot)
            .expect("latest visible")
            .to_vec();
        let before_len = store.versions.get(&block).expect("chain before").len();
        let before_stats = store.ebr_stats();

        store.prune_versions_older_than(CommitSeq(19));
        let after_len = store.versions.get(&block).expect("chain after").len();
        let after_prune_stats = store.ebr_stats();
        store.ebr_collect();
        let after_collect_stats = store.ebr_stats();

        assert!(after_len < before_len, "prune should shrink version chain");
        assert!(
            after_len >= 1,
            "version chain must keep at least one committed version"
        );
        assert_eq!(
            store
                .read_visible(block, store.current_snapshot())
                .expect("latest remains visible"),
            latest_payload.as_slice()
        );

        let retired_delta = after_prune_stats.retired_versions - before_stats.retired_versions;
        let expected_delta = u64::try_from(before_len - after_len).expect("fits in u64");
        assert_eq!(
            retired_delta, expected_delta,
            "retired version accounting should match actual chain trimming"
        );
        assert_eq!(after_collect_stats.pending_versions(), 0);
    }

    #[test]
    fn ebr_batch_retirement_counts_across_multiple_blocks() {
        let mut store = MvccStore::new();
        let blocks = [BlockNumber(340), BlockNumber(341), BlockNumber(342)];

        for &block in &blocks {
            for v in 1_u8..=10 {
                let mut txn = store.begin();
                txn.stage_write(block, vec![v; 4]);
                store.commit(txn).expect("commit");
            }
        }

        let before_stats = store.ebr_stats();
        let before_total_len: usize = blocks
            .iter()
            .map(|block| store.versions.get(block).expect("chain before").len())
            .sum();

        store.prune_versions_older_than(CommitSeq(8));
        let after_stats = store.ebr_stats();
        let after_total_len: usize = blocks
            .iter()
            .map(|block| store.versions.get(block).expect("chain after").len())
            .sum();

        let expected_retired =
            u64::try_from(before_total_len - after_total_len).expect("fits in u64");
        assert_eq!(
            after_stats.retired_versions - before_stats.retired_versions,
            expected_retired,
            "retirement counter should match total trimmed versions across blocks"
        );

        store.ebr_collect();
        let collected = store.ebr_stats();
        assert_eq!(collected.pending_versions(), 0);
    }

    // ── SSI conflict detection tests ───────────────────────────────────

    /// Classic write-skew scenario that FCW allows but SSI rejects.
    ///
    /// T1 reads A, writes B.  T2 reads B, writes A.
    /// Both succeed under FCW (disjoint write sets).
    /// Under SSI, the second committer detects the rw-antidependency.
    #[test]
    fn ssi_detects_write_skew() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        // Seed: both blocks start at 1.
        let mut seed_txn = store.begin();
        seed_txn.stage_write(block_a, vec![1]);
        seed_txn.stage_write(block_b, vec![1]);
        store.commit_ssi(seed_txn).expect("seed");

        // T1: reads A (sees 1), writes B to 2.
        let mut t1 = store.begin();
        let a_version = store.latest_commit_seq(block_a);
        t1.record_read(block_a, a_version);
        t1.stage_write(block_b, vec![2]);

        // T2: reads B (sees 1), writes A to 2.
        let mut t2 = store.begin();
        let b_version = store.latest_commit_seq(block_b);
        t2.record_read(block_b, b_version);
        t2.stage_write(block_a, vec![2]);

        // T1 commits first — succeeds.
        store.commit_ssi(t1).expect("T1 should succeed");

        // T2 commits second — SSI detects that T2 read B, which T1 just wrote.
        let result = store.commit_ssi(t2);
        assert!(
            matches!(result, Err(CommitError::SsiConflict { .. })),
            "SSI should reject T2 due to rw-antidependency on block B, got {result:?}"
        );
    }

    #[test]
    fn transaction_outcome_stats_track_aborts_and_ssi_conflicts() {
        let mut store = MvccStore::new();
        assert_eq!(
            store.transaction_outcome_stats(),
            TransactionOutcomeStats::default()
        );

        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        let mut seed_txn = store.begin();
        seed_txn.stage_write(block_a, vec![1]);
        seed_txn.stage_write(block_b, vec![1]);
        store.commit_ssi(seed_txn).expect("seed");

        let mut t1 = store.begin();
        let a_version = store.latest_commit_seq(block_a);
        t1.record_read(block_a, a_version);
        t1.stage_write(block_b, vec![2]);

        let mut t2 = store.begin();
        let b_version = store.latest_commit_seq(block_b);
        t2.record_read(block_b, b_version);
        t2.stage_write(block_a, vec![2]);

        store.commit_ssi(t1).expect("T1 should succeed");
        let ssi_conflict = store.commit_ssi(t2);
        assert!(
            matches!(ssi_conflict, Err(CommitError::SsiConflict { .. })),
            "expected SSI conflict, got {ssi_conflict:?}"
        );

        let after_ssi = store.transaction_outcome_stats();
        assert_eq!(after_ssi.aborted_transactions, 1);
        assert_eq!(after_ssi.ssi_conflicts, 1);

        let user_abort = store.begin();
        store.abort(user_abort, TxnAbortReason::UserAbort, None);

        let after_user_abort = store.transaction_outcome_stats();
        assert_eq!(after_user_abort.aborted_transactions, 2);
        assert_eq!(after_user_abort.ssi_conflicts, 1);
    }

    /// SSI does not reject read-only transactions.
    #[test]
    fn ssi_allows_read_only_transactions() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Seed.
        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: read-only, reads block 1.
        let mut t1 = store.begin();
        let v = store.latest_commit_seq(block);
        t1.record_read(block, v);

        // T2: writes block 1 to 2.
        let mut t2 = store.begin();
        t2.stage_write(block, vec![2]);
        store.commit_ssi(t2).expect("T2 should succeed");

        // T1: read-only commit — should succeed even though its read was
        // invalidated, because read-only txns have no writes.
        store.commit_ssi(t1).expect("read-only T1 should succeed");
    }

    /// SSI allows disjoint readers/writers (no overlap).
    #[test]
    fn ssi_allows_disjoint_read_write_sets() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(1);
        let block_b = BlockNumber(2);

        // Seed both blocks.
        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads A, writes A (same block — no cross-block dependency).
        let mut t1 = store.begin();
        let v_a = store.latest_commit_seq(block_a);
        t1.record_read(block_a, v_a);
        t1.stage_write(block_a, vec![2]);

        // T2: reads B, writes B.
        let mut t2 = store.begin();
        let v_b = store.latest_commit_seq(block_b);
        t2.record_read(block_b, v_b);
        t2.stage_write(block_b, vec![2]);

        // Both should succeed — no cross-block rw-antidependencies.
        store.commit_ssi(t1).expect("T1 should succeed");
        store.commit_ssi(t2).expect("T2 should succeed");
    }

    /// SSI still catches write-write conflicts (FCW layer).
    #[test]
    fn ssi_fcw_layer_still_active() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit_ssi(seed).expect("seed");

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(block, vec![2]);
        t2.stage_write(block, vec![3]);

        store.commit_ssi(t1).expect("T1 should succeed");

        let result = store.commit_ssi(t2);
        assert!(
            matches!(result, Err(CommitError::Conflict { .. })),
            "FCW should reject T2, got {result:?}"
        );
    }

    /// Edge case: an empty transaction commits successfully and does not
    /// mutate any version chains.
    #[test]
    fn edge_empty_transaction_commit_preserves_version_state() {
        let mut store = MvccStore::new();
        let before = store.current_snapshot().high;
        eprintln!(
            "scenario=edge_empty_transaction_commit before_commit_seq={} version_count={}",
            before.0,
            store.version_count()
        );

        let empty = store.begin();
        assert_eq!(empty.pending_writes(), 0, "transaction should be empty");
        let committed = store
            .commit(empty)
            .expect("empty transaction should commit");

        assert_eq!(committed, CommitSeq(before.0 + 1));
        assert_eq!(store.current_snapshot().high, committed);
        assert_eq!(
            store.version_count(),
            0,
            "empty transaction must not create block versions"
        );
    }

    /// Edge case: reading and then writing the same block in a single
    /// transaction is not a self-conflict under SSI.
    #[test]
    fn ssi_self_read_write_same_block_no_self_conflict() {
        let mut store = MvccStore::new();
        let block = BlockNumber(44);

        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit_ssi(seed).expect("seed");

        let mut txn = store.begin();
        let seen_version = store.latest_commit_seq(block);
        txn.record_read(block, seen_version);
        txn.stage_write(block, vec![2]);
        eprintln!(
            "scenario=ssi_self_conflict txn_id={} block={} seen_version={}",
            txn.id().0,
            block.0,
            seen_version.0
        );

        let committed = store
            .commit_ssi(txn)
            .expect("self read-write should not trigger SSI conflict");
        assert_eq!(committed, CommitSeq(2));
        let latest = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(block, latest)
                .expect("latest block visible")
                .as_ref(),
            &[2]
        );
    }

    /// Single-edge stale-source readers are serializable before the upstream
    /// update. SSI should avoid cascading aborts unless a second rw edge
    /// makes the committing transaction a dangerous-structure pivot.
    #[test]
    fn ssi_avoids_cascading_abort_for_single_edge_stale_readers() {
        let mut store = MvccStore::new();
        let source = BlockNumber(500);
        let derived_a = BlockNumber(501);
        let derived_b = BlockNumber(502);

        // Seed source + derived outputs.
        let mut seed = store.begin();
        seed.stage_write(source, vec![1]);
        seed.stage_write(derived_a, vec![10]);
        seed.stage_write(derived_b, vec![10]);
        store.commit_ssi(seed).expect("seed");

        // Two dependents read the same source snapshot and compute outputs.
        let mut dependent_a = store.begin();
        let read_version = store.latest_commit_seq(source);
        dependent_a.record_read(source, read_version);
        dependent_a.stage_write(derived_a, vec![11]);

        let mut dependent_b = store.begin();
        dependent_b.record_read(source, read_version);
        dependent_b.stage_write(derived_b, vec![12]);

        // Upstream update invalidates both stale readers.
        let mut upstream = store.begin();
        upstream.stage_write(source, vec![2]);
        store.commit_ssi(upstream).expect("upstream update");

        eprintln!(
            "scenario=ssi_cascading_abort source={} read_version={} current_snapshot={}",
            source.0,
            read_version.0,
            store.current_snapshot().high.0
        );

        store
            .commit_ssi(dependent_a)
            .expect("single-edge stale reader A remains serializable");
        store
            .commit_ssi(dependent_b)
            .expect("single-edge stale reader B remains serializable");

        let snap_after_commits = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(derived_a, snap_after_commits)
                .expect("derived_a visible")
                .as_ref(),
            &[11]
        );
        assert_eq!(
            store
                .read_visible(derived_b, snap_after_commits)
                .expect("derived_b visible")
                .as_ref(),
            &[12]
        );

        // Fresh retry after the upstream update should also succeed with the
        // new source version.
        let mut retry = store.begin();
        let fresh_version = store.latest_commit_seq(source);
        retry.record_read(source, fresh_version);
        retry.stage_write(derived_a, vec![11]);
        store.commit_ssi(retry).expect("retry after abort");
        let latest = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(derived_a, latest)
                .expect("retry value visible")
                .as_ref(),
            &[11]
        );
    }

    /// SSI log pruning does not affect correctness for active transactions.
    #[test]
    fn ssi_log_pruning() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Create several committed transactions.
        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit_ssi(txn).expect("commit");
        }

        // SSI log should have 5 entries.
        assert_eq!(store.ssi_log.len(), 5);

        // Prune entries with commit_seq <= 3.
        store.prune_ssi_log(CommitSeq(3));

        // Should have 2 entries remaining (commit_seq 4 and 5).
        assert_eq!(store.ssi_log.len(), 2);
    }

    // ── Read-set tracking tests ─────────────────────────────────────────

    /// `record_read` tracks the block and version; first read wins.
    #[test]
    fn read_set_tracks_first_read() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit(seed).expect("seed");

        let mut txn = store.begin();
        txn.record_read(block, CommitSeq(1));
        // Second record_read for same block is ignored (first wins).
        txn.record_read(block, CommitSeq(99));

        assert_eq!(txn.read_set().len(), 1);
        assert_eq!(txn.read_set().get(&block), Some(&CommitSeq(1)));
    }

    /// Multiple distinct blocks are tracked independently.
    #[test]
    fn read_set_tracks_multiple_blocks() {
        let mut store = MvccStore::new();
        let blocks: Vec<BlockNumber> = (1..=5).map(BlockNumber).collect();

        let mut seed = store.begin();
        for &b in &blocks {
            seed.stage_write(b, vec![0xAA]);
        }
        store.commit(seed).expect("seed");

        let mut txn = store.begin();
        for &b in &blocks {
            txn.record_read(b, CommitSeq(1));
        }

        assert_eq!(txn.read_set().len(), 5);
        for &b in &blocks {
            assert!(txn.read_set().contains_key(&b));
        }
    }

    /// A transaction with an empty read-set does not trigger SSI aborts.
    #[test]
    fn empty_read_set_no_ssi_conflict() {
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1 writes block without recording any reads.
        let mut t1 = store.begin();
        t1.stage_write(block, vec![2]);
        store.commit_ssi(t1).expect("T1 no read-set");

        // T2 also writes block without reads — FCW should still
        // trigger, but not SSI phantom.
        let mut t2 = store.begin();
        t2.stage_write(block, vec![3]);
        store
            .commit_ssi(t2)
            .expect("T2 no overlap with T1 writes (new snapshot)");
    }

    /// A single rw-antidependency is serializable by ordering this transaction
    /// before the concurrent writer. SSI must not abort until the transaction
    /// is both the source and target of rw-antidependency edges.
    #[test]
    fn ssi_single_rw_antidependency_does_not_abort() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(10);
        let block_b = BlockNumber(20);

        // Seed both blocks.
        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads block_a, writes block_b.
        let mut t1 = store.begin();
        let v_a = store.latest_commit_seq(block_a);
        t1.record_read(block_a, v_a);
        t1.stage_write(block_b, vec![2]);

        // T2: writes block_a (the block T1 read).
        let mut t2 = store.begin();
        t2.stage_write(block_a, vec![99]);
        store.commit_ssi(t2).expect("T2 commits first");

        store
            .commit_ssi(t1)
            .expect("single rw-antidependency is serializable");
    }

    /// No false positive: reading a block nobody else writes is clean.
    #[test]
    fn no_false_positive_when_read_block_unmodified() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(1);
        let block_b = BlockNumber(2);

        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads block_a, writes block_b.
        let mut t1 = store.begin();
        let v_a = store.latest_commit_seq(block_a);
        t1.record_read(block_a, v_a);
        t1.stage_write(block_b, vec![2]);

        // T2: writes block_b (same write target as T1, but T1 didn't
        // read block_b).  This is a pure FCW conflict, not phantom.
        let mut t2 = store.begin();
        t2.stage_write(block_b, vec![3]);
        store.commit_ssi(t2).expect("T2 commits first");

        // T1 should fail with FCW Conflict, NOT SSI phantom.
        let result = store.commit_ssi(t1);
        assert!(
            matches!(result, Err(CommitError::Conflict { .. })),
            "expected FCW conflict, got {result:?}"
        );
    }

    /// SSI commit record preserves read-set in the ssi_log.
    #[test]
    fn ssi_log_contains_read_set() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(1);
        let block_b = BlockNumber(2);

        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        let mut txn = store.begin();
        txn.record_read(block_a, CommitSeq(1));
        txn.record_read(block_b, CommitSeq(1));
        txn.stage_write(block_a, vec![2]);
        store.commit_ssi(txn).expect("commit");

        // The SSI log should contain both the read-set and write-set.
        assert_eq!(store.ssi_log.len(), 2); // seed + our txn
        let record = &store.ssi_log[1];
        assert_eq!(record.read_set.len(), 2);
        assert!(record.read_set.contains_key(&block_a));
        assert!(record.read_set.contains_key(&block_b));
        assert_eq!(record.write_set.len(), 1);
        assert!(record.write_set.contains(&block_a));
    }

    // ── SSI write-skew and false-positive tests ─────────────────────────

    /// Quantitative false-positive test: N non-conflicting concurrent
    /// transactions committed via SSI, each touching a unique pair of
    /// blocks.  Zero should be spuriously aborted.
    #[test]
    fn ssi_zero_false_positives_for_non_conflicting_workload() {
        let mut store = MvccStore::new();
        let n = 200_u64;

        // Seed: create blocks 0..2*N.
        let mut seed = store.begin();
        for i in 0..(2 * n) {
            seed.stage_write(BlockNumber(i), vec![0]);
        }
        store.commit_ssi(seed).expect("seed");

        // Each transaction reads block 2*i, writes block 2*i+1.
        // All pairs are disjoint so zero conflicts should arise.
        let mut aborts = 0_u64;
        for i in 0..n {
            let read_block = BlockNumber(2 * i);
            let write_block = BlockNumber(2 * i + 1);

            let mut txn = store.begin();
            let v = store.latest_commit_seq(read_block);
            txn.record_read(read_block, v);
            txn.stage_write(write_block, vec![1]);

            if store.commit_ssi(txn).is_err() {
                aborts += 1;
            }
        }

        assert_eq!(
            aborts, 0,
            "SSI should not spuriously abort non-conflicting transactions, \
             got {aborts}/{n} aborts"
        );
    }

    /// Three-way write-skew cycle: T1 reads A writes B, T2 reads B
    /// writes C, T3 reads C writes A.  SSI must abort at least one.
    #[test]
    fn ssi_three_way_write_skew_cycle() {
        let mut store = MvccStore::new();
        let a = BlockNumber(1);
        let b = BlockNumber(2);
        let c = BlockNumber(3);

        // Seed all three blocks.
        let mut seed = store.begin();
        seed.stage_write(a, vec![1]);
        seed.stage_write(b, vec![1]);
        seed.stage_write(c, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // All three begin concurrently at the same snapshot.
        let mut t1 = store.begin();
        let mut t2 = store.begin();
        let mut t3 = store.begin();

        let v_a = store.latest_commit_seq(a);
        let v_b = store.latest_commit_seq(b);
        let v_c = store.latest_commit_seq(c);

        // T1: reads A, writes B.
        t1.record_read(a, v_a);
        t1.stage_write(b, vec![2]);

        // T2: reads B, writes C.
        t2.record_read(b, v_b);
        t2.stage_write(c, vec![2]);

        // T3: reads C, writes A.
        t3.record_read(c, v_c);
        t3.stage_write(a, vec![2]);

        // Commit T1 first — should succeed (nothing written to A yet).
        store.commit_ssi(t1).expect("T1 should succeed");

        // T2 has only one rw edge here: it read B, which T1 just wrote.
        // That is serializable by ordering T2 before T1, so it must not abort
        // until another edge closes the dangerous structure.
        let r2 = store.commit_ssi(t2);
        assert!(
            r2.is_ok(),
            "T2 should not be rejected for a single rw edge, got {r2:?}"
        );

        // T3 reads C, which T2 wrote, and writes A, which T1 read. T3 is now
        // the pivot in a two-edge dangerous structure: T1 -rw-> T3 -rw-> T2.
        let r3 = store.commit_ssi(t3);
        assert!(
            matches!(r3, Err(CommitError::SsiConflict { .. })),
            "T3 should be rejected after closing the two-edge structure, got {r3:?}"
        );
    }

    /// SSI with the write-skew scenario across 20 seeds using the lab runtime.
    ///
    /// Under SSI (unlike FCW), exactly one of the two transactions must
    /// be rejected when they form a write-skew pattern.
    #[test]
    fn lab_ssi_rejects_write_skew() {
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        for seed in 0_u64..20 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));

            // Seed: both blocks start with value 1.
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block_a, vec![1]);
                txn.stage_write(block_b, vec![1]);
                s.commit_ssi(txn).expect("seed commit");
            }

            let outcomes = Arc::new(std::sync::Mutex::new((None, None)));

            // Pre-begin both at the same snapshot.
            let mut s = store.lock().unwrap();
            let t1 = s.begin();
            let a_ver = s.latest_commit_seq(block_a);
            let b_ver = s.latest_commit_seq(block_b);
            let t2 = s.begin();
            drop(s);
            let t1_base = (t1, a_ver);
            let t2_base = (t2, b_ver);

            // T1: reads A, writes B.
            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (mut txn1, a_ver) = t1_base;
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;

                        txn1.record_read(block_a, a_ver);
                        txn1.stage_write(block_b, vec![2]);
                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit_ssi(txn1)
                        };
                        outcomes.lock().unwrap().0 = Some(result.is_ok());
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            // T2: reads B, writes A.
            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (mut txn2, b_ver) = t2_base;
                let (task_id, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;

                        txn2.record_read(block_b, b_ver);
                        txn2.stage_write(block_a, vec![2]);
                        let result = {
                            let mut s = store.lock().unwrap();
                            s.commit_ssi(txn2)
                        };
                        outcomes.lock().unwrap().1 = Some(result.is_ok());
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let outcomes = Arc::try_unwrap(outcomes).unwrap().into_inner().unwrap();
            let t1_ok = outcomes.0.expect("T1 should complete");
            let t2_ok = outcomes.1.expect("T2 should complete");

            // Under SSI, exactly one should succeed and one should fail.
            assert!(
                t1_ok ^ t2_ok,
                "seed {seed}: SSI should reject exactly one of the write-skew \
                 transactions. Got t1={t1_ok}, t2={t2_ok}"
            );

            // Under SSI, only one writer succeeds.  The winning writer sets
            // one block to 2 while the other remains 1, so a+b=3 (not 4 as
            // under FCW's write-skew).  The key SSI property is that the
            // "double write" (a=2, b=2, sum=4) is prevented.
            let s = store.lock().unwrap();
            let snap = s.current_snapshot();
            let a = s.read_visible(block_a, snap).unwrap()[0];
            let b = s.read_visible(block_b, snap).unwrap()[0];
            drop(s);
            assert_eq!(
                a + b,
                3,
                "seed {seed}: SSI should prevent both writers from succeeding, got a={a} b={b}"
            );
        }
    }

    // ── E2E: Concurrent SSI Scenarios ─────────────────────────────────

    /// E2E Scenario 1: Write-skew detection across many iterations.
    ///
    /// T1 reads A, writes B; T2 reads B, writes A.  Over 100 seeds,
    /// SSI must abort exactly one transaction every time.
    #[test]
    fn e2e_write_skew_detection_100_seeds() {
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        for seed in 0_u64..100 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block_a, vec![1]);
                txn.stage_write(block_b, vec![1]);
                s.commit_ssi(txn).expect("seed");
            }

            let outcomes = Arc::new(std::sync::Mutex::new((None, None)));

            let mut s = store.lock().unwrap();
            let t1 = s.begin();
            let a_ver = s.latest_commit_seq(block_a);
            let b_ver = s.latest_commit_seq(block_b);
            let t2 = s.begin();
            drop(s);

            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (mut txn1, a_v) = (t1, a_ver);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;
                        txn1.record_read(block_a, a_v);
                        txn1.stage_write(block_b, vec![2]);
                        let r = store.lock().unwrap().commit_ssi(txn1);
                        outcomes.lock().unwrap().0 = Some(r.is_ok());
                    })
                    .expect("create");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (mut txn2, b_v) = (t2, b_ver);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;
                        txn2.record_read(block_b, b_v);
                        txn2.stage_write(block_a, vec![2]);
                        let r = store.lock().unwrap().commit_ssi(txn2);
                        outcomes.lock().unwrap().1 = Some(r.is_ok());
                    })
                    .expect("create");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let (t1_ok, t2_ok) = {
                let o = outcomes.lock().unwrap();
                (o.0.expect("T1 ran"), o.1.expect("T2 ran"))
            };

            assert!(
                t1_ok ^ t2_ok,
                "seed {seed}: SSI must reject exactly one, got t1={t1_ok}, t2={t2_ok}"
            );
        }
    }

    /// E2E Scenario 2: Lost update prevention.
    ///
    /// Two writers both read X, compute X+1, and write X.
    /// FCW must detect the conflict — final value is initial+1.
    #[test]
    fn e2e_lost_update_prevention() {
        let block_x = BlockNumber(42);

        for seed in 0_u64..100 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block_x, vec![10]); // initial value = 10
                s.commit(txn).expect("seed");
            }

            let outcomes = Arc::new(std::sync::Mutex::new((None, None)));

            let t1 = store.lock().unwrap().begin();
            let t2 = store.lock().unwrap().begin();

            for (i, txn) in [t1, t2].into_iter().enumerate() {
                let store = Arc::clone(&store);
                let outcomes = Arc::clone(&outcomes);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        yield_now().await;
                        let mut txn = txn;
                        // Both "read" value 10 and write 11.
                        txn.stage_write(block_x, vec![11]);
                        let r = store.lock().unwrap().commit(txn);
                        if i == 0 {
                            outcomes.lock().unwrap().0 = Some(r.is_ok());
                        } else {
                            outcomes.lock().unwrap().1 = Some(r.is_ok());
                        }
                    })
                    .expect("create");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let (t1_ok, t2_ok) = {
                let o = outcomes.lock().unwrap();
                (o.0.expect("T1 ran"), o.1.expect("T2 ran"))
            };

            // FCW: exactly one must succeed.
            assert!(
                t1_ok ^ t2_ok,
                "seed {seed}: FCW must reject one, got t1={t1_ok}, t2={t2_ok}"
            );

            // Final value must be 11 (not 12 from a lost update).
            let s = store.lock().unwrap();
            let snap = s.current_snapshot();
            let val = s.read_visible(block_x, snap).unwrap()[0];
            drop(s);
            assert_eq!(val, 11, "seed {seed}: lost update detected, val={val}");
        }
    }

    /// E2E Scenario 3: range-summary write skew prevention via SSI.
    ///
    /// T1 reads blocks 0..10 and writes a summary block. T2 reads the summary
    /// block and writes to block 5. T1 is the pivot when it commits second:
    /// T2 read T1's write target, and T1 read T2's write target.
    #[test]
    fn e2e_ssi_two_edge_range_summary_write_skew_prevention() {
        let mut store = MvccStore::new();

        // Seed blocks 0..10 plus the summary block.
        let mut seed_txn = store.begin();
        for i in 0_u64..10 {
            seed_txn.stage_write(BlockNumber(i), vec![1]);
        }
        seed_txn.stage_write(BlockNumber(100), vec![0]);
        store.commit_ssi(seed_txn).expect("seed");

        // T1: reads blocks 0..10 (the "scan").
        let mut t1 = store.begin();
        for i in 0_u64..10 {
            let v = store.latest_commit_seq(BlockNumber(i));
            t1.record_read(BlockNumber(i), v);
        }
        // T1 also writes something (required for SSI check to fire).
        t1.stage_write(BlockNumber(100), vec![99]);

        // T2: reads the summary block, then writes block 5 (a "phantom"
        // insert into T1's read range).
        let mut t2 = store.begin();
        t2.record_read(BlockNumber(100), store.latest_commit_seq(BlockNumber(100)));
        t2.stage_write(BlockNumber(5), vec![2]);
        store.commit_ssi(t2).expect("T2 commits first");

        // T1 should be aborted: T2 read the summary block that T1 writes,
        // and T1 read block 5 that T2 writes.
        let result = store.commit_ssi(t1);
        assert!(
            matches!(
                result,
                Err(CommitError::SsiConflict {
                    pivot_block: BlockNumber(5),
                    ..
                })
            ),
            "expected SSI conflict on block 5, got {result:?}"
        );
    }

    /// E2E Scenario 4: Multi-writer stress test (deterministic).
    ///
    /// 4 concurrent Lab tasks, each running 50 transactions.
    /// Each writes a unique block per iteration.  No conflicts should
    /// occur (disjoint write sets), and all commits should succeed.
    #[test]
    fn e2e_multi_writer_stress_disjoint() {
        for seed in 0_u64..10 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(500_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            let total_commits = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let total_aborts = Arc::new(std::sync::atomic::AtomicU64::new(0));

            let num_writers = 4_u64;
            let txns_per_writer = 50_u64;

            for writer_id in 0..num_writers {
                let store = Arc::clone(&store);
                let commits = Arc::clone(&total_commits);
                let aborts = Arc::clone(&total_aborts);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        for j in 0..txns_per_writer {
                            yield_now().await;
                            let block = BlockNumber(writer_id * txns_per_writer + j);
                            let mut txn = store.lock().unwrap().begin();
                            #[allow(clippy::cast_possible_truncation)]
                            let tag = writer_id as u8;
                            txn.stage_write(block, vec![tag; 64]);
                            let r = store.lock().unwrap().commit_ssi(txn);
                            if r.is_ok() {
                                commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            } else {
                                aborts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    })
                    .expect("create");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let commits = total_commits.load(std::sync::atomic::Ordering::Relaxed);
            let aborts = total_aborts.load(std::sync::atomic::Ordering::Relaxed);

            assert_eq!(
                commits,
                num_writers * txns_per_writer,
                "seed {seed}: all disjoint writes should commit, got {commits} commits, {aborts} aborts"
            );
            assert_eq!(aborts, 0, "seed {seed}: no aborts expected");
        }
    }

    /// E2E Scenario 5: High-contention hot key with retries.
    ///
    /// 4 Lab tasks each increment a shared counter block 20 times.
    /// On abort, they retry.  Final value must equal 4*20 = 80.
    #[test]
    fn e2e_hot_key_counter_with_retries() {
        let block = BlockNumber(0);

        for seed in 0_u64..10 {
            let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(1_000_000));
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let store = Arc::new(std::sync::Mutex::new(MvccStore::new()));
            // Seed: counter = 0.
            {
                let mut s = store.lock().unwrap();
                let mut txn = s.begin();
                txn.stage_write(block, vec![0; 8]); // u64 LE counter = 0
                s.commit(txn).expect("seed");
            }

            let total_aborts = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let num_workers = 4_u64;
            let increments_per = 20_u64;

            for _worker_id in 0..num_workers {
                let store = Arc::clone(&store);
                let aborts = Arc::clone(&total_aborts);
                let (task_id, _h) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async move {
                        for _ in 0..increments_per {
                            loop {
                                yield_now().await;
                                let mut s = store.lock().unwrap();
                                let snap = s.current_snapshot();
                                let current_val = s.read_visible(block, snap).map_or(0, |b| {
                                    let mut buf = [0_u8; 8];
                                    let len = b.len().min(8);
                                    buf[..len].copy_from_slice(&b[..len]);
                                    u64::from_le_bytes(buf)
                                });
                                let new_val = current_val + 1;
                                let mut txn = s.begin();
                                txn.stage_write(block, new_val.to_le_bytes().to_vec());
                                match s.commit(txn) {
                                    Ok(_) => break,
                                    Err(_) => {
                                        aborts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    })
                    .expect("create");
                runtime.scheduler.lock().schedule(task_id, 0);
            }

            runtime.run_until_quiescent();

            let s = store.lock().unwrap();
            let snap = s.current_snapshot();
            let final_bytes = s.read_visible(block, snap).expect("read counter");
            let mut buf = [0_u8; 8];
            let len = final_bytes.len().min(8);
            buf[..len].copy_from_slice(&final_bytes[..len]);
            let final_val = u64::from_le_bytes(buf);
            drop(s);

            let expected = num_workers * increments_per;
            assert_eq!(
                final_val, expected,
                "seed {seed}: counter should be {expected}, got {final_val}"
            );
        }
    }

    #[test]
    fn e2e_ebr_basic_reclamation_correctness() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: Some(64),
            algo: CompressionAlgo::None,
        });
        let block = BlockNumber(910);
        let mut snapshots = Vec::new();

        for v in 1_u8..=8 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            snapshots.push(store.current_snapshot());
        }

        let held_snapshot = snapshots[4]; // commit 5
        store.register_snapshot(held_snapshot);
        assert_eq!(
            store
                .read_visible(block, held_snapshot)
                .expect("held read")
                .as_ref(),
            &[5]
        );

        let before = store.ebr_stats();
        let _ = store.prune_safe();
        store.ebr_collect();
        let during_pin = store.ebr_stats();
        assert!(
            during_pin.retired_versions >= before.retired_versions,
            "prune during pin should only retire versions safe under held snapshot"
        );
        assert_eq!(
            store
                .read_visible(block, held_snapshot)
                .expect("still pinned")
                .as_ref(),
            &[5],
            "held snapshot must keep version 5 visible"
        );

        assert!(store.release_snapshot(held_snapshot));
        let _ = store.prune_safe();
        store.ebr_collect();
        let after_release = store.ebr_stats();
        assert!(
            after_release.reclaimed_versions >= during_pin.reclaimed_versions,
            "reclamation should progress after release"
        );
        assert_eq!(after_release.pending_versions(), 0);

        let old_snapshot_value = store
            .read_visible(block, held_snapshot)
            .map(std::borrow::Cow::into_owned);
        assert_ne!(
            old_snapshot_value,
            Some(vec![5]),
            "old pinned version should no longer be retained after release+prune"
        );
    }

    #[test]
    fn e2e_ebr_multi_reader_multi_writer_release_order() {
        let blocks = [
            BlockNumber(0),
            BlockNumber(1),
            BlockNumber(2),
            BlockNumber(3),
        ];

        let mut base = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: None,
            algo: CompressionAlgo::None,
        });
        let mut snapshots = Vec::new();

        for seq in 1_u64..=40 {
            let mut txn = base.begin();
            let idx = usize::try_from((seq - 1) % 4).expect("fits");
            let block = blocks[idx];
            let payload = vec![u8::try_from(seq).expect("seq fits in u8")];
            txn.stage_write(block, payload);
            base.commit(txn).expect("seed");
            if matches!(seq, 10 | 20 | 30 | 40) {
                snapshots.push(base.current_snapshot());
            }
        }
        for snap in &snapshots {
            base.register_snapshot(*snap);
        }

        let expected: Vec<(Snapshot, Vec<Vec<u8>>)> = snapshots
            .iter()
            .map(|snap| {
                let values = blocks
                    .iter()
                    .map(|block| {
                        base.read_visible(*block, *snap)
                            .expect("snapshot value")
                            .to_vec()
                    })
                    .collect();
                (*snap, values)
            })
            .collect();

        let shared = Arc::new(std::sync::Mutex::new(base));
        let mut handles = Vec::new();
        for writer_id in 0_u64..4 {
            let store = Arc::clone(&shared);
            handles.push(std::thread::spawn(move || {
                let mut rng = 0x9E37_79B9_u64.wrapping_add(writer_id);
                for i in 0_u64..1_000 {
                    rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    let idx = usize::try_from(rng % 4).expect("fits");
                    let block = blocks[idx];
                    let byte = u8::try_from((rng >> 16) & 0xFF).expect("fits");
                    let mut s = store.lock().expect("lock");
                    let mut txn = s.begin();
                    txn.stage_write(block, vec![byte; 8]);
                    let _ = s.commit(txn);
                    if i % 32 == 0 {
                        let _ = s.prune_safe();
                        s.ebr_collect();
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("writer join");
        }

        let mut store = Arc::try_unwrap(shared)
            .expect("single owner")
            .into_inner()
            .expect("mutex");

        for (snap, values) in &expected {
            for (idx, block) in blocks.iter().enumerate() {
                assert_eq!(
                    store.read_visible(*block, *snap).expect("snapshot read"),
                    values[idx].as_slice(),
                    "snapshot {:?} on block {} must remain stable",
                    snap.high.0,
                    block.0
                );
            }
        }

        let mut reclaimed_prev = store.ebr_stats().reclaimed_versions;
        for snap in snapshots.iter().rev().copied() {
            assert!(store.release_snapshot(snap));
            let _ = store.prune_safe();
            store.ebr_collect();
            let now = store.ebr_stats().reclaimed_versions;
            assert!(now >= reclaimed_prev, "reclaimed counter must be monotonic");
            reclaimed_prev = now;
        }
        let _ = store.prune_safe();
        store.ebr_collect();
        let final_stats = store.ebr_stats();
        assert_eq!(final_stats.pending_versions(), 0);
        assert!(
            store.version_count() <= blocks.len(),
            "after all readers release, only latest versions should remain"
        );
    }

    #[test]
    fn e2e_ebr_reader_pin_blocks_reclamation_until_release() {
        let mut store = MvccStore::with_compression_policy(CompressionPolicy {
            dedup_identical: false,
            max_chain_length: None,
            algo: CompressionAlgo::None,
        });
        let block = BlockNumber(920);

        let mut seed = store.begin();
        seed.stage_write(block, vec![1]);
        store.commit(seed).expect("seed");
        let held_snapshot = store.current_snapshot();
        store.register_snapshot(held_snapshot);

        for v in 2_u8..=128 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
            let _ = store.prune_safe();
            store.ebr_collect();
            assert_eq!(
                store
                    .read_visible(block, held_snapshot)
                    .expect("held read")
                    .as_ref(),
                &[1],
                "held reader must keep original version visible"
            );
        }

        let version_count_during_pin = store.version_count();
        assert!(
            version_count_during_pin >= 100,
            "without cap and with held snapshot, chain should grow materially"
        );

        assert!(store.release_snapshot(held_snapshot));
        let _ = store.prune_safe();
        store.ebr_collect();

        let version_count_after_release = store.version_count();
        assert!(
            version_count_after_release < version_count_during_pin,
            "release should allow aggressive reclamation"
        );
        let old_visible = store
            .read_visible(block, held_snapshot)
            .map(std::borrow::Cow::into_owned);
        assert_ne!(
            old_visible,
            Some(vec![1]),
            "old value should no longer be retained post-release"
        );
        assert_eq!(store.ebr_stats().pending_versions(), 0);
    }

    #[test]
    fn e2e_ebr_chain_length_enforced_under_concurrent_writers() {
        let block = BlockNumber(930);
        let store = Arc::new(std::sync::Mutex::new(MvccStore::with_compression_policy(
            CompressionPolicy {
                dedup_identical: false,
                max_chain_length: Some(16),
                algo: CompressionAlgo::None,
            },
        )));

        let mut handles = Vec::new();
        for writer_id in 0_u64..4 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                for i in 0_u64..2_000 {
                    let mut s = store.lock().expect("lock");
                    let mut txn = s.begin();
                    let byte = u8::try_from((writer_id + i) % 255).expect("fits");
                    txn.stage_write(block, vec![byte; 16]);
                    let _ = s.commit(txn);
                    if i % 64 == 0 {
                        let _ = s.prune_safe();
                        s.ebr_collect();
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("writer join");
        }

        let mut s = Arc::try_unwrap(store)
            .expect("single owner")
            .into_inner()
            .expect("mutex");
        let _ = s.prune_safe();
        s.ebr_collect();

        let chain_len = s.versions.get(&block).map_or(0, Vec::len);
        assert!(
            chain_len <= 16,
            "chain length should remain bounded by cap, got {chain_len}"
        );
        let chain_stats = s.block_version_stats();
        assert_eq!(chain_stats.chain_cap, Some(16));
        assert!(chain_stats.max_chain_length <= 16);

        let latest = s.current_snapshot();
        assert!(
            s.read_visible(block, latest).is_some(),
            "latest block value must remain readable"
        );
    }

    #[test]
    fn e2e_ebr_restart_preserves_latest_visible_value() {
        let cx = Cx::for_testing();
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();
        std::fs::remove_file(&path).ok();
        let block = BlockNumber(940);

        {
            let store = crate::persist::PersistentMvccStore::open_with_options(
                &cx,
                &path,
                &crate::persist::PersistOptions {
                    sync_on_commit: false,
                    ..crate::persist::PersistOptions::default()
                },
            )
            .expect("open persistent store");

            for v in 1_u8..=64 {
                let mut txn = store.begin();
                txn.stage_write(block, vec![v]);
                store.commit(txn).expect("commit");
            }
        }

        let reopened = crate::persist::PersistentMvccStore::open_with_options(
            &cx,
            &path,
            &crate::persist::PersistOptions {
                sync_on_commit: false,
                ..crate::persist::PersistOptions::default()
            },
        )
        .expect("reopen");
        let snap = reopened.current_snapshot();
        let recovered = reopened.read_visible(block, snap).expect("recovered value");
        assert_eq!(
            recovered,
            vec![64],
            "latest committed value should survive restart"
        );
        assert!(
            reopened.recovery_report().commits_replayed >= 1,
            "recovery report should show replay activity"
        );
    }

    // ── SnapshotRegistry + SnapshotHandle tests ─────────────────────────

    #[test]
    fn snapshot_handle_increments_ref_count_on_create() {
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = Snapshot { high: CommitSeq(5) };

        assert_eq!(registry.active_count(), 0);
        let handle = SnapshotRegistry::acquire(&registry, snap);
        assert_eq!(registry.active_count(), 1);
        assert_eq!(handle.snapshot(), snap);
    }

    #[test]
    fn snapshot_handle_decrements_ref_count_on_drop() {
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = Snapshot { high: CommitSeq(5) };

        let handle = SnapshotRegistry::acquire(&registry, snap);
        assert_eq!(registry.active_count(), 1);

        drop(handle);
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn read_visible_block_buf_shares_full_block_correctly_under_concurrency() {
        // bd-xmh5g.394 made VersionData::Full(Arc<AlignedVec>) and
        // read_visible_block_buf SHARE that buffer (BlockBuf::from_shared_aligned,
        // Arc::clone) instead of copying it. This is the conformance guard the new
        // shared-Arc read path lacked: concurrent readers of one uncompressed Full
        // block must each get a BlockBuf with the EXACT stored bytes — the shared
        // Arc must never corrupt or tear the data. (MvccStore::new defaults to
        // algo: None => Full; the assertion holds even if a version is compressed,
        // since the contract is "a read returns the written bytes".)
        let mut store = MvccStore::new();
        let block = BlockNumber(7);
        let data: Vec<u8> = (0..4096_u32).map(|i| (i & 0xff) as u8).collect();

        let mut txn = store.begin();
        txn.stage_write(block, data.clone());
        store.commit(txn).expect("commit");
        let snap = store.current_snapshot();

        // Single-threaded: the shared BlockBuf matches the stored bytes and the
        // materialized read_visible Vec.
        let shared = store
            .read_visible_block_buf(block, snap)
            .expect("visible block buf");
        assert_eq!(shared.as_slice(), data.as_slice());
        assert_eq!(
            store.read_visible(block, snap).unwrap().as_ref(),
            data.as_slice()
        );

        // Concurrency: 8 threads share the same Full Arc; every read returns the bytes.
        std::thread::scope(|s| {
            for _ in 0..8 {
                let store = &store;
                let data = &data;
                s.spawn(move || {
                    for _ in 0..20_000 {
                        let buf = store.read_visible_block_buf(block, snap).expect("visible");
                        assert_eq!(buf.as_slice(), data.as_slice());
                    }
                });
            }
        });
    }

    #[test]
    fn registry_gc_respects_oldest_active_snapshot() {
        let registry = Arc::new(SnapshotRegistry::new());
        let mut store = MvccStore::new();
        let block = BlockNumber(1);

        // Write 5 versions.
        for v in 1_u8..=5 {
            let mut txn = store.begin();
            txn.stage_write(block, vec![v]);
            store.commit(txn).expect("commit");
        }

        // Acquire a handle at commit 3.
        let snap3 = Snapshot { high: CommitSeq(3) };
        let _handle = SnapshotRegistry::acquire(&registry, snap3);

        // Use registry watermark for pruning.
        let wm = registry.watermark().unwrap();
        assert_eq!(wm, CommitSeq(3));
        store.prune_versions_older_than(wm);

        // Version at commit 3 should still be readable.
        assert_eq!(store.read_visible(block, snap3).unwrap().as_ref(), &[3]);

        // Latest version should also be readable.
        let snap_latest = store.current_snapshot();
        assert_eq!(
            store.read_visible(block, snap_latest).unwrap().as_ref(),
            &[5]
        );
    }

    #[test]
    fn registry_watermark_advances_when_oldest_released() {
        let registry = Arc::new(SnapshotRegistry::new());

        let old = Snapshot { high: CommitSeq(3) };
        let mid = Snapshot { high: CommitSeq(7) };
        let new = Snapshot {
            high: CommitSeq(12),
        };

        let h_old = SnapshotRegistry::acquire(&registry, old);
        let h_mid = SnapshotRegistry::acquire(&registry, mid);
        let _h_new = SnapshotRegistry::acquire(&registry, new);

        assert_eq!(registry.watermark(), Some(CommitSeq(3)));

        // Release oldest — watermark advances.
        drop(h_old);
        assert_eq!(registry.watermark(), Some(CommitSeq(7)));

        // Release mid — watermark advances again.
        drop(h_mid);
        assert_eq!(registry.watermark(), Some(CommitSeq(12)));
    }

    #[test]
    fn registry_multiple_handles_same_snapshot() {
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = Snapshot { high: CommitSeq(5) };

        let h1 = SnapshotRegistry::acquire(&registry, snap);
        let h2 = SnapshotRegistry::acquire(&registry, snap);
        assert_eq!(registry.active_count(), 2);

        drop(h1);
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.watermark(), Some(CommitSeq(5)));

        drop(h2);
        assert_eq!(registry.active_count(), 0);
        assert!(registry.watermark().is_none());
    }

    #[test]
    fn registry_no_memory_leak_100k_acquire_release() {
        let registry = Arc::new(SnapshotRegistry::new());

        for i in 0_u64..100_000 {
            let snap = Snapshot {
                high: CommitSeq(i % 100),
            };
            let handle = SnapshotRegistry::acquire(&registry, snap);
            drop(handle);
        }

        assert_eq!(registry.active_count(), 0);
        assert!(registry.watermark().is_none());
        assert_eq!(registry.acquired_total(), 100_000);
        assert_eq!(registry.released_total(), 100_000);
    }

    #[test]
    fn registry_concurrent_16_threads() {
        let registry = Arc::new(SnapshotRegistry::new());
        let num_threads: usize = 16;
        let ops_per_thread: usize = 1000;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for j in 0..ops_per_thread {
                        let seq = u64::try_from(i * ops_per_thread + j).unwrap();
                        let snap = Snapshot {
                            high: CommitSeq(seq % 50),
                        };
                        let handle = SnapshotRegistry::acquire(&registry, snap);
                        // Hold briefly.
                        std::hint::black_box(&handle);
                        drop(handle);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(registry.active_count(), 0);
        let total = u64::try_from(num_threads * ops_per_thread).unwrap();
        assert_eq!(registry.acquired_total(), total);
        assert_eq!(registry.released_total(), total);
    }

    #[test]
    fn snapshot_handle_released_on_panic() {
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = Snapshot { high: CommitSeq(7) };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _handle = SnapshotRegistry::acquire(&registry, snap);
            std::panic::panic_any("simulated FUSE handler panic");
        }));

        assert!(result.is_err(), "panic should have been caught");
        // The handle's Drop should have released the snapshot.
        assert_eq!(
            registry.active_count(),
            0,
            "snapshot should be released even after panic"
        );
    }

    #[test]
    fn registry_stall_detection() {
        // A zero threshold should report any active snapshot as stalled immediately.
        let registry = Arc::new(SnapshotRegistry::with_stall_threshold(0));
        let snap = Snapshot { high: CommitSeq(1) };

        let _handle = SnapshotRegistry::acquire(&registry, snap);
        let stall = registry.check_stalls();
        assert_eq!(stall, Some(0), "should detect stall with threshold=0");
    }

    #[test]
    fn registry_metrics_counters() {
        let registry = Arc::new(SnapshotRegistry::new());
        assert_eq!(registry.acquired_total(), 0);
        assert_eq!(registry.released_total(), 0);

        let snap = Snapshot { high: CommitSeq(1) };
        let h1 = SnapshotRegistry::acquire(&registry, snap);
        let h2 = SnapshotRegistry::acquire(&registry, snap);
        assert_eq!(registry.acquired_total(), 2);
        assert_eq!(registry.released_total(), 0);

        drop(h1);
        assert_eq!(registry.released_total(), 1);

        drop(h2);
        assert_eq!(registry.acquired_total(), 2);
        assert_eq!(registry.released_total(), 2);
    }

    #[test]
    fn registry_metrics_and_refcounts_saturate_at_numeric_limits() {
        let registry = SnapshotRegistry::new();
        let snap = Snapshot { high: CommitSeq(9) };
        registry
            .acquired_total
            .store(u64::MAX - 1, Ordering::Relaxed);
        registry
            .released_total
            .store(u64::MAX - 1, Ordering::Relaxed);
        registry.active.write().insert(snap.high, u64::MAX - 1);

        registry.register(snap);
        assert_eq!(registry.acquired_total(), u64::MAX);
        assert_eq!(registry.active.read().get(&snap.high), Some(&u64::MAX));

        registry.register(snap);
        assert_eq!(registry.acquired_total(), u64::MAX);
        assert_eq!(registry.active.read().get(&snap.high), Some(&u64::MAX));

        assert!(registry.release(snap));
        assert_eq!(registry.released_total(), u64::MAX);
        assert_eq!(
            registry.active.read().get(&snap.high),
            Some(&(u64::MAX - 1))
        );
    }

    #[test]
    fn store_backed_flush_lifecycle_counters_saturate_at_numeric_limits() {
        let lifecycle = StoreBackedMvccFlushLifecycle::new(Arc::new(RwLock::new(MvccStore::new())));
        lifecycle
            .active_flush_pins
            .store(u64::MAX, Ordering::SeqCst);
        lifecycle
            .acquired_flush_pins
            .store(u64::MAX - 1, Ordering::Relaxed);
        lifecycle
            .released_flush_pins
            .store(u64::MAX - 1, Ordering::Relaxed);

        let flush_pin = lifecycle
            .pin_for_flush(BlockNumber(1), CommitSeq(1))
            .expect("pin at nonzero commit");
        assert_eq!(lifecycle.active_flush_pins(), u64::MAX);
        assert_eq!(lifecycle.acquired_flush_pins(), u64::MAX);

        drop(flush_pin);
        assert_eq!(lifecycle.released_flush_pins(), u64::MAX);
        assert_eq!(lifecycle.active_flush_pins(), u64::MAX - 1);
    }

    #[test]
    fn mvcc_device_with_registry_lifecycle() {
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let registry = Arc::new(SnapshotRegistry::new());
        let snap = store.read().current_snapshot();

        assert_eq!(registry.active_count(), 0);

        {
            let base = MemBlockDevice::new(512, 4);
            let dev = MvccBlockDevice::with_registry(base, Arc::clone(&store), snap, &registry);
            assert_eq!(dev.snapshot(), snap);
            assert_eq!(registry.active_count(), 1);
            // MvccStore's inline tracking should NOT be affected.
            assert_eq!(store.read().active_snapshot_count(), 0);
        }

        // After drop, registry count returns to 0.
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn mvcc_device_with_registry_reads_correctly() {
        let cx = test_cx();
        let store = Arc::new(RwLock::new(MvccStore::new()));
        let registry = Arc::new(SnapshotRegistry::new());

        // Commit a version.
        {
            let mut guard = store.write();
            let mut txn = guard.begin();
            txn.stage_write(BlockNumber(1), vec![0xAB; 512]);
            guard.commit(txn).expect("commit");
        }

        let snap = store.read().current_snapshot();
        let base = MemBlockDevice::new(512, 16);
        let dev = MvccBlockDevice::with_registry(base, Arc::clone(&store), snap, &registry);

        let buf = dev.read_block(&cx, BlockNumber(1)).expect("read");
        assert_eq!(buf.as_slice(), &[0xAB; 512]);
    }

    #[test]
    fn abort_with_cow_allocator_frees_blocks() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let alloc = TestCowAllocator::new(1000);

        // Begin a transaction and do two COW writes.
        let mut txn = store.begin();
        store
            .write_cow(BlockNumber(0), &[0xAA; 64], &mut txn, &alloc, &cx)
            .expect("cow write 1");
        store
            .write_cow(BlockNumber(1), &[0xBB; 64], &mut txn, &alloc, &cx)
            .expect("cow write 2");

        // Should have allocated 2 blocks.
        assert_eq!(alloc.allocated_blocks().len(), 2);

        // Abort should defer-free those blocks and GC them.
        store.abort_with_cow_allocator(txn, TxnAbortReason::UserAbort, None, &alloc, &cx);

        // Blocks should have been freed (deferred at CommitSeq(0), GC'd with
        // watermark >= 0).
        assert_eq!(alloc.freed_blocks().len(), 2);
    }

    #[test]
    fn abort_with_cow_allocator_frees_orphans() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let alloc = TestCowAllocator::new(1000);

        // Begin a transaction and write the SAME block twice to produce an orphan.
        let mut txn = store.begin();
        store
            .write_cow(BlockNumber(0), &[0xAA; 64], &mut txn, &alloc, &cx)
            .expect("cow write 1");
        let first_physical = alloc.allocated_blocks()[0];
        store
            .write_cow(BlockNumber(0), &[0xBB; 64], &mut txn, &alloc, &cx)
            .expect("cow write 2 (re-write)");

        // Should have allocated 2 blocks (first becomes orphan).
        assert_eq!(alloc.allocated_blocks().len(), 2);

        // Abort should free both the active block and the orphan.
        store.abort_with_cow_allocator(txn, TxnAbortReason::UserAbort, None, &alloc, &cx);

        let freed = alloc.freed_blocks();
        assert!(
            freed.contains(&first_physical),
            "first (orphaned) physical block should be freed"
        );
        assert_eq!(freed.len(), 2);
    }

    #[test]
    fn preflight_commit_fcw_detects_conflict() {
        let mut store = MvccStore::new();
        let block = BlockNumber(0);

        // Begin two transactions at the same snapshot.
        let mut txn_a = store.begin();
        let mut txn_b = store.begin();

        txn_a.stage_write(block, vec![0xAA; 64]);
        txn_b.stage_write(block, vec![0xBB; 64]);

        // Commit txn_a.
        store.commit(txn_a).expect("txn_a commits");

        // Preflight check for txn_b should detect conflict.
        let result = store.preflight_commit_fcw(&txn_b);
        assert!(result.is_err(), "preflight should detect conflict");
    }

    #[test]
    fn preflight_then_prechecked_commit_succeeds() {
        let mut store = MvccStore::new();
        let block = BlockNumber(0);

        let mut txn = store.begin();
        txn.stage_write(block, vec![0xCC; 64]);

        // Preflight passes with no conflict.
        store
            .preflight_commit_fcw(&txn)
            .expect("preflight should pass");

        // Prechecked commit should succeed.
        let commit_seq = store
            .commit_fcw_prechecked(txn)
            .expect("prechecked commit should succeed");
        assert!(commit_seq.0 > 0);

        // Data should be visible.
        let snap = store.current_snapshot();
        let data = store.read_visible(block, snap).expect("must be visible");
        assert_eq!(data[0], 0xCC);
    }

    #[test]
    fn prechecked_commit_revalidates_conflict_and_preserves_latest_bytes() {
        let mut store = MvccStore::new();
        store.set_conflict_policy(ConflictPolicy::SafeMerge);
        let block = BlockNumber(0);
        seed_block(&mut store, block, &[0x00; 4]);

        let mut stale = store.begin();
        stale.stage_write(block, vec![0xAA; 4]);

        store
            .preflight_commit_fcw(&stale)
            .expect("preflight passes before a competing writer appears");

        let mut winner = store.begin();
        winner.stage_write(block, vec![0xBB; 4]);
        store.commit(winner).expect("winner commits first");

        let err = store
            .commit_fcw_prechecked(stale)
            .expect_err("prechecked commit must revalidate stale conflicts");
        assert!(
            matches!(err, CommitError::Conflict { block: b, .. } if b == block),
            "expected FCW conflict, got {err:?}"
        );

        let snap = store.current_snapshot();
        let data = store
            .read_visible(block, snap)
            .expect("winner remains visible");
        assert_eq!(data.as_ref(), &[0xBB; 4]);
        assert_eq!(
            store.latest_commit_seq(block),
            CommitSeq(2),
            "failed prechecked commit must not allocate a commit sequence"
        );
    }

    #[test]
    fn commit_sequence_exhaustion_returns_error() {
        let mut store = MvccStore::new();
        store.next_commit = u64::MAX;

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(0), vec![0xAA; 8]);

        let err = store
            .commit(txn)
            .expect_err("commit should fail at max sequence");
        match err {
            CommitError::DurabilityFailure { detail } => {
                assert!(detail.contains("commit sequence exhausted"));
            }
            other => assert!(
                matches!(other, CommitError::DurabilityFailure { .. }),
                "unexpected error: {other:?}"
            ),
        }
        assert_eq!(store.next_commit, u64::MAX);
    }

    #[test]
    fn reserved_transaction_ids_are_rejected_by_all_commit_paths() {
        fn assert_invalid_transaction_id(error: CommitError) {
            match error {
                CommitError::DurabilityFailure { detail } => {
                    assert!(detail.contains("invalid transaction id"));
                }
                other => assert!(
                    matches!(other, CommitError::DurabilityFailure { .. }),
                    "unexpected error: {other:?}"
                ),
            }
        }

        let mut store = MvccStore::new();
        store.next_txn = u64::MAX;

        let mut sentinel = store.begin();
        assert_eq!(sentinel.id(), TxnId(u64::MAX));
        sentinel.stage_write(BlockNumber(0), vec![0xAA; 8]);
        let err = store
            .commit(sentinel)
            .expect_err("FCW commit must reject sentinel transaction id");
        assert_invalid_transaction_id(err);
        assert_eq!(store.current_snapshot().high, CommitSeq(0));

        let mut ssi_sentinel = store.begin();
        assert_eq!(ssi_sentinel.id(), TxnId(u64::MAX));
        ssi_sentinel.stage_write(BlockNumber(1), vec![0xBB; 8]);
        let err = store
            .commit_ssi(ssi_sentinel)
            .expect_err("SSI commit must reject sentinel transaction id");
        assert_invalid_transaction_id(err);
        assert_eq!(store.current_snapshot().high, CommitSeq(0));

        let mut prechecked_sentinel = Transaction::new(TxnId(u64::MAX), store.current_snapshot());
        prechecked_sentinel.stage_write(BlockNumber(2), vec![0xCC; 8]);
        let err = store
            .commit_fcw_prechecked(prechecked_sentinel)
            .expect_err("prechecked commit must reject sentinel transaction id");
        assert_invalid_transaction_id(err);
        assert_eq!(store.current_snapshot().high, CommitSeq(0));
    }

    #[test]
    fn write_cow_double_write_produces_orphan_on_commit() {
        let cx = test_cx();
        let mut store = MvccStore::new();
        let alloc = TestCowAllocator::new(1000);

        // Commit an initial version so there's something to COW.
        {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![0x01; 64]);
            store.commit(txn).expect("initial commit");
        }

        // In a single transaction, write the same block twice via COW.
        let mut txn = store.begin();
        store
            .write_cow(BlockNumber(0), &[0xAA; 64], &mut txn, &alloc, &cx)
            .expect("cow write 1");
        let first_alloc = alloc.allocated_blocks()[0];
        store
            .write_cow(BlockNumber(0), &[0xBB; 64], &mut txn, &alloc, &cx)
            .expect("cow write 2");
        let second_alloc = alloc.allocated_blocks()[1];

        // The first allocation should become an orphan.
        assert_ne!(first_alloc, second_alloc, "should be different blocks");

        // Commit with cow allocator — the orphan and old physical should be deferred.
        store
            .commit_with_cow_allocator(txn, &alloc, &cx)
            .expect("commit with cow");

        // Data should be the second write value.
        let snap = store.current_snapshot();
        let data = store
            .read_visible(BlockNumber(0), snap)
            .expect("must be visible");
        assert_eq!(data[0], 0xBB);
    }

    #[test]
    fn registry_watermark_lockfree_tracks_register_release() {
        let registry = Arc::new(SnapshotRegistry::new());

        // No snapshots: lockfree watermark should be None.
        assert_eq!(registry.watermark_lockfree(), None);

        let snap1 = Snapshot {
            high: CommitSeq(10),
        };
        let snap2 = Snapshot {
            high: CommitSeq(20),
        };

        let h1 = SnapshotRegistry::acquire(&registry, snap1);
        assert_eq!(registry.watermark_lockfree(), Some(CommitSeq(10)));

        let h2 = SnapshotRegistry::acquire(&registry, snap2);
        assert_eq!(
            registry.watermark_lockfree(),
            Some(CommitSeq(10)),
            "watermark should be min(10, 20) = 10"
        );

        drop(h1);
        assert_eq!(
            registry.watermark_lockfree(),
            Some(CommitSeq(20)),
            "after releasing snap1, watermark should be 20"
        );

        drop(h2);
        assert_eq!(
            registry.watermark_lockfree(),
            None,
            "after releasing all, watermark should be None"
        );
    }

    #[test]
    fn advance_counters_sets_minimum() {
        let mut store = MvccStore::new();

        // With fresh store, next_commit and next_txn should be small.
        store.advance_counters(100, 200);

        // Now transactions should use IDs >= 201 and commits >= 101.
        let txn = store.begin();
        assert!(
            txn.id().0 >= 201,
            "txn id should be >= 201, got {}",
            txn.id().0
        );
    }

    #[test]
    fn insert_versions_makes_block_visible() {
        let mut store = MvccStore::new();

        // Advance counters so current_snapshot().high >= our version's commit_seq.
        store.advance_counters(10, 10);

        // Manually commit something so the store's snapshot moves forward.
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(999), vec![0xFF; 8]);
        store.commit(txn).expect("advance commit");

        // Insert a pre-built version chain for block 42.
        store.insert_versions(
            BlockNumber(42),
            vec![BlockVersion {
                block: BlockNumber(42),
                commit_seq: CommitSeq(5),
                writer: TxnId(1),
                data: VersionData::full(vec![0xDE; 64]),
            }],
        );

        // Should be visible at the current snapshot (which is > CommitSeq(5)).
        let snap = store.current_snapshot();
        let data = store
            .read_visible(BlockNumber(42), snap)
            .expect("must be visible");
        assert_eq!(data[0], 0xDE);
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn transaction_new_has_empty_sets() {
        let store = MvccStore::new();
        let txn = Transaction::new(TxnId(1), store.current_snapshot());
        assert_eq!(txn.id(), TxnId(1));
        assert_eq!(txn.pending_writes(), 0);
        assert!(txn.read_set().is_empty());
        assert!(txn.write_set().is_empty());
        assert!(txn.staged_write(BlockNumber(0)).is_none());
        assert!(txn.staged_physical(BlockNumber(0)).is_none());
    }

    #[test]
    fn transaction_record_read_only_tracks_first() {
        let store = MvccStore::new();
        let mut txn = Transaction::new(TxnId(1), store.current_snapshot());
        txn.record_read(BlockNumber(5), CommitSeq(10));
        txn.record_read(BlockNumber(5), CommitSeq(20)); // should be ignored
        assert_eq!(txn.read_set().len(), 1);
        assert_eq!(txn.read_set()[&BlockNumber(5)], CommitSeq(10));
    }

    #[test]
    fn transaction_stage_write_overwrites_previous() {
        let store = MvccStore::new();
        let mut txn = Transaction::new(TxnId(1), store.current_snapshot());
        txn.stage_write(BlockNumber(0), vec![1, 2, 3]);
        txn.stage_write(BlockNumber(0), vec![4, 5, 6]);
        assert_eq!(txn.pending_writes(), 1);
        assert_eq!(txn.staged_write(BlockNumber(0)), Some(&[4, 5, 6][..]));
    }

    #[test]
    fn block_version_bytes_inline_returns_none_for_identical() {
        let v = BlockVersion {
            block: BlockNumber(0),
            commit_seq: CommitSeq(1),
            writer: TxnId(1),
            data: VersionData::Identical,
        };
        assert!(v.bytes_inline().is_none());
    }

    #[test]
    fn block_version_bytes_inline_returns_some_for_full() {
        let v = BlockVersion {
            block: BlockNumber(0),
            commit_seq: CommitSeq(1),
            writer: TxnId(1),
            data: VersionData::full(vec![0xAA; 64]),
        };
        assert_eq!(v.bytes_inline().unwrap(), &[0xAA; 64]);
    }

    #[test]
    fn ebr_version_stats_pending_versions() {
        let s = EbrVersionStats {
            retired_versions: 10,
            reclaimed_versions: 3,
        };
        assert_eq!(s.pending_versions(), 7);

        // Saturating: reclaimed > retired should give 0, not underflow.
        let s2 = EbrVersionStats {
            retired_versions: 0,
            reclaimed_versions: 5,
        };
        assert_eq!(s2.pending_versions(), 0);
    }

    #[test]
    fn commit_error_display_formats() {
        let e = CommitError::Conflict {
            block: BlockNumber(42),
            snapshot: CommitSeq(1),
            observed: CommitSeq(3),
        };
        let msg = format!("{e}");
        assert!(msg.contains("42"), "should mention block number");

        let e2 = CommitError::SsiConflict {
            pivot_block: BlockNumber(7),
            read_version: CommitSeq(1),
            write_version: CommitSeq(2),
            concurrent_txn: TxnId(5),
        };
        let msg2 = format!("{e2}");
        assert!(msg2.contains("SSI"), "should mention SSI");

        let e3 = CommitError::DurabilityFailure {
            detail: "disk error".to_owned(),
        };
        let msg3 = format!("{e3}");
        assert!(msg3.contains("disk error"));
    }

    #[test]
    fn mvcc_store_new_is_consistent() {
        let store = MvccStore::new();
        assert_eq!(store.version_count(), 0);
        assert_eq!(store.block_count_versioned(), 0);
        assert!(store.watermark().is_none());
        assert_eq!(store.active_snapshot_count(), 0);
        let snap = store.current_snapshot();
        assert_eq!(snap.high, CommitSeq(0));
    }

    #[test]
    fn mvcc_store_commit_empty_transaction_advances_sequence() {
        let mut store = MvccStore::new();
        let txn = store.begin();
        assert_eq!(txn.pending_writes(), 0);
        let seq = store.commit(txn).expect("commit empty");
        assert_eq!(seq, CommitSeq(1));
        // Another empty commit advances again.
        let txn2 = store.begin();
        let seq2 = store.commit(txn2).expect("commit empty 2");
        assert_eq!(seq2, CommitSeq(2));
    }

    #[test]
    fn read_visible_returns_none_for_unwritten_block() {
        let store = MvccStore::new();
        let snap = store.current_snapshot();
        assert!(store.read_visible(BlockNumber(999), snap).is_none());
    }

    #[test]
    fn snapshot_double_register_and_release() {
        let mut store = MvccStore::new();
        let snap = Snapshot { high: CommitSeq(1) };
        store.register_snapshot(snap);
        store.register_snapshot(snap);
        assert_eq!(store.active_snapshot_count(), 2);

        assert!(store.release_snapshot(snap));
        assert_eq!(store.active_snapshot_count(), 1);
        assert!(store.release_snapshot(snap));
        assert_eq!(store.active_snapshot_count(), 0);

        // Release when already gone returns false.
        assert!(!store.release_snapshot(snap));
    }

    #[test]
    fn prune_safe_keeps_latest_version_per_block() {
        let mut store = MvccStore::new();
        // Write 3 versions to the same block.
        for i in 0..3_u8 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![i; 8]);
            store.commit(txn).expect("commit");
        }
        assert_eq!(store.version_count(), 3);

        // No active snapshots, so prune_safe keeps only the latest.
        store.prune_safe();
        assert_eq!(store.version_count(), 1);

        // The surviving version should be the last committed value.
        let snap = store.current_snapshot();
        let data = store
            .read_visible(BlockNumber(0), snap)
            .expect("visible after prune");
        assert_eq!(&*data, &[2_u8; 8]);
    }

    #[test]
    fn block_version_stats_reflect_chain_state() {
        let mut store = MvccStore::new();
        // Write 5 versions to block 0.
        for i in 0..5_u8 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![i; 8]);
            store.commit(txn).expect("commit");
        }
        let stats = store.block_version_stats();
        assert_eq!(stats.tracked_blocks, 1);
        assert_eq!(stats.max_chain_length, 5);
    }

    #[test]
    fn gc_backpressure_config_default_is_sensible() {
        let cfg = GcBackpressureConfig::default();
        assert!(cfg.min_poll_quota > 0);
        assert!(!cfg.throttle_sleep.is_zero());
    }

    // ── Additional edge-case hardening tests ────────────────────────────

    #[test]
    fn commit_error_clone_and_eq() {
        let e = CommitError::Conflict {
            block: BlockNumber(1),
            snapshot: CommitSeq(0),
            observed: CommitSeq(2),
        };
        let e2 = e.clone();
        assert_eq!(e, e2);
    }

    #[test]
    fn commit_error_chain_backpressure_display() {
        let e = CommitError::ChainBackpressure {
            block: BlockNumber(10),
            chain_len: 100,
            cap: 50,
            critical_len: 80,
            watermark: CommitSeq(5),
        };
        let msg = format!("{e}");
        assert!(msg.contains("backpressure"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn block_version_serde_round_trip() {
        let v = BlockVersion {
            block: BlockNumber(42),
            commit_seq: CommitSeq(7),
            writer: TxnId(3),
            data: VersionData::full(vec![0xBE; 16]),
        };
        let json = serde_json::to_string(&v).expect("serialize");
        let parsed: BlockVersion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.block, v.block);
        assert_eq!(parsed.commit_seq, v.commit_seq);
        assert_eq!(parsed.writer, v.writer);
        assert_eq!(parsed.bytes_inline().unwrap(), &[0xBE; 16]);
    }

    #[test]
    fn block_version_clone_and_eq() {
        let v = BlockVersion {
            block: BlockNumber(0),
            commit_seq: CommitSeq(1),
            writer: TxnId(1),
            data: VersionData::full(vec![1, 2, 3]),
        };
        let v2 = v.clone();
        assert_eq!(v, v2);
    }

    #[test]
    fn physical_block_version_serde_round_trip() {
        let pv = PhysicalBlockVersion {
            logical: BlockNumber(10),
            physical: BlockNumber(200),
            commit_seq: CommitSeq(5),
            writer: TxnId(2),
        };
        let json = serde_json::to_string(&pv).expect("serialize");
        let parsed: PhysicalBlockVersion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, pv);
    }

    #[test]
    fn physical_block_version_clone_and_copy() {
        let pv = PhysicalBlockVersion {
            logical: BlockNumber(0),
            physical: BlockNumber(100),
            commit_seq: CommitSeq(1),
            writer: TxnId(1),
        };
        let pv2 = pv; // Copy
        assert_eq!(pv, pv2);
    }

    #[test]
    fn ebr_version_stats_serde_round_trip() {
        let s = EbrVersionStats {
            retired_versions: 42,
            reclaimed_versions: 10,
        };
        let json = serde_json::to_string(&s).expect("serialize");
        let parsed: EbrVersionStats = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, s);
    }

    #[test]
    fn ebr_version_stats_default_is_zero() {
        let s = EbrVersionStats::default();
        assert_eq!(s.retired_versions, 0);
        assert_eq!(s.reclaimed_versions, 0);
        assert_eq!(s.pending_versions(), 0);
    }

    #[test]
    fn block_version_stats_serde_round_trip() {
        let s = BlockVersionStats {
            tracked_blocks: 10,
            max_chain_length: 5,
            chains_over_cap: 1,
            chains_over_critical: 0,
            chain_cap: Some(100),
            critical_chain_length: Some(80),
        };
        let json = serde_json::to_string(&s).expect("serialize");
        let parsed: BlockVersionStats = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, s);
    }

    #[test]
    fn block_version_stats_default_is_zero() {
        let s = BlockVersionStats::default();
        assert_eq!(s.tracked_blocks, 0);
        assert_eq!(s.max_chain_length, 0);
        assert_eq!(s.chains_over_cap, 0);
        assert_eq!(s.chain_cap, None);
    }

    #[test]
    fn gc_backpressure_config_clone_and_eq() {
        let cfg = GcBackpressureConfig::default();
        let cfg2 = cfg;
        assert_eq!(cfg, cfg2);
        let _ = format!("{cfg:?}");
    }

    #[test]
    fn transaction_multiple_reads_different_blocks() {
        let store = MvccStore::new();
        let mut txn = Transaction::new(TxnId(1), store.current_snapshot());
        txn.record_read(BlockNumber(0), CommitSeq(1));
        txn.record_read(BlockNumber(1), CommitSeq(2));
        txn.record_read(BlockNumber(2), CommitSeq(3));
        assert_eq!(txn.read_set().len(), 3);
    }

    #[test]
    fn transaction_serde_round_trip() {
        let store = MvccStore::new();
        let mut txn = Transaction::new(TxnId(42), store.current_snapshot());
        txn.stage_write(BlockNumber(5), vec![0xAA; 8]);
        let json = serde_json::to_string(&txn).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json value");
        assert!(value.get("writes").is_some());
        assert!(value.get("merge_proofs").is_some());
        assert!(value.get("staged_writes").is_none());
        let parsed: Transaction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id(), TxnId(42));
        assert_eq!(parsed.pending_writes(), 1);
        assert_eq!(parsed.staged_write(BlockNumber(5)), Some(&[0xAA; 8][..]));
        assert_eq!(
            parsed.merge_proof(BlockNumber(5)),
            Some(&MergeProof::Unsafe)
        );
    }

    #[test]
    fn mvcc_store_read_latest_version_after_overwrites() {
        let mut store = MvccStore::new();
        for i in 0..5_u8 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![i; 4]);
            store.commit(txn).expect("commit");
        }
        let snap = store.current_snapshot();
        let data = store.read_visible(BlockNumber(0), snap).expect("visible");
        assert_eq!(&*data, &[4_u8; 4]);
    }

    #[test]
    fn mvcc_store_read_at_old_snapshot() {
        let mut store = MvccStore::new();
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(0), vec![1; 4]);
        store.commit(txn).expect("commit");

        let old_snap = store.current_snapshot();

        let mut txn2 = store.begin();
        txn2.stage_write(BlockNumber(0), vec![2; 4]);
        store.commit(txn2).expect("commit");

        // Old snapshot should see the first version.
        let data = store
            .read_visible(BlockNumber(0), old_snap)
            .expect("visible");
        assert_eq!(&*data, &[1_u8; 4]);
    }

    #[test]
    fn mvcc_store_multiple_blocks_isolated() {
        let mut store = MvccStore::new();
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(0), vec![0xAA; 4]);
        txn.stage_write(BlockNumber(1), vec![0xBB; 4]);
        store.commit(txn).expect("commit");

        let snap = store.current_snapshot();
        assert_eq!(
            &*store.read_visible(BlockNumber(0), snap).unwrap(),
            &[0xAA; 4]
        );
        assert_eq!(
            &*store.read_visible(BlockNumber(1), snap).unwrap(),
            &[0xBB; 4]
        );
        assert!(store.read_visible(BlockNumber(2), snap).is_none());
    }

    #[test]
    fn mvcc_store_fcw_conflict_detected() {
        let mut store = MvccStore::new();
        let mut txn1 = store.begin();
        txn1.stage_write(BlockNumber(0), vec![1; 4]);
        store.commit(txn1).expect("commit txn1");

        // txn2 started before txn1 committed, writing to same block.
        let snap_before = Snapshot { high: CommitSeq(0) };
        let mut txn2 = Transaction::new(TxnId(2), snap_before);
        txn2.stage_write(BlockNumber(0), vec![2; 4]);
        let result = store.commit(txn2);
        assert!(result.is_err(), "should detect FCW conflict on block 0");
    }

    // ── Property-based tests (proptest) ────────────────────────────────────

    use proptest::prelude::*;

    /// Strategy: generate a sequence of (block_number, data_byte) write operations.
    fn write_ops_strategy() -> impl Strategy<Value = Vec<(u16, u8)>> {
        prop::collection::vec((0_u16..64, any::<u8>()), 1..32)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Invariant: committed writes are visible to subsequent snapshots.
        ///
        /// For any sequence of writes committed in a single transaction,
        /// a new snapshot taken after commit must see all of them.
        /// When duplicate block numbers appear, the last write wins.
        #[test]
        fn proptest_committed_writes_visible_to_new_snapshots(
            ops in write_ops_strategy(),
        ) {
            let mut store = MvccStore::new();

            // Build expected: last write per block wins (BTreeMap overwrites).
            let mut expected = std::collections::BTreeMap::<u16, u8>::new();
            let mut txn = store.begin();
            for &(block, byte) in &ops {
                txn.stage_write(BlockNumber(u64::from(block)), vec![byte; 64]);
                expected.insert(block, byte);
            }
            store.commit(txn).expect("commit should succeed");

            // Read from a new snapshot — all committed blocks must be visible
            // with the last-written value.
            let snap = store.current_snapshot();
            for (&block, &byte) in &expected {
                let data = store
                    .read_visible(BlockNumber(u64::from(block)), snap)
                    .expect("committed block must be visible");
                prop_assert_eq!(data[0], byte, "block {} data mismatch", block);
            }
        }

        /// Algebra of the [`MergeProof::BitmapOr`] merge: for any two set-only
        /// writers with disjoint newly-set bits, the merge equals `latest |
        /// staged`, loses no allocation from any input, and invents no bit
        /// outside the two writers.
        #[test]
        fn proptest_bitmap_or_merges_disjoint_set_only_writers(
            base in prop::collection::vec(any::<u8>(), 8),
            a_mask in prop::collection::vec(any::<u8>(), 8),
            b_mask in prop::collection::vec(any::<u8>(), 8),
        ) {
            // latest = base ∪ A; staged = base ∪ (B \ A) so the new bits are
            // disjoint — always a valid OR-merge construction.
            let latest: Vec<u8> =
                base.iter().zip(&a_mask).map(|(&x, &a)| x | a).collect();
            let staged: Vec<u8> = base
                .iter()
                .zip(&b_mask)
                .zip(&a_mask)
                .map(|((&x, &b), &a)| x | (b & !a))
                .collect();

            let proof = MergeProof::BitmapOr;
            prop_assert!(proof.merge_valid(&base, &latest, &staged));
            let merged = proof
                .merge_bytes(&base, &latest, &staged)
                .expect("disjoint set-only writers must OR-merge");
            prop_assert_eq!(
                proof.merge_valid(&base, &latest, &staged),
                merged.len() == base.len()
            );
            for i in 0..base.len() {
                // Output is exactly the byte-wise OR of the two writers.
                prop_assert_eq!(merged[i], latest[i] | staged[i]);
                // No allocation lost: superset of every input.
                prop_assert_eq!(merged[i] & base[i], base[i]);
                prop_assert_eq!(merged[i] & latest[i], latest[i]);
                prop_assert_eq!(merged[i] & staged[i], staged[i]);
                // No bit invented beyond the two writers.
                prop_assert_eq!(merged[i] | (latest[i] | staged[i]), latest[i] | staged[i]);
            }
        }

        /// A bit-clear (free) or a same-new-bit double-allocation must reject
        /// the OR merge (`merge_valid` and `merge_bytes` agree on the rejection).
        #[test]
        fn proptest_bitmap_or_rejects_clear_and_double_set(
            base in prop::collection::vec(1u8..=255, 8),
            pick in 0usize..8,
        ) {
            let proof = MergeProof::BitmapOr;
            let idx = pick % base.len();

            // A writer that clears a set base bit (a free) is not set-only.
            let lsb = base[idx] & base[idx].wrapping_neg();
            let mut latest = base.clone();
            latest[idx] &= !lsb;
            prop_assert!(proof.merge_bytes(&base, &latest, &base).is_none());
            prop_assert_eq!(
                proof.merge_valid(&base, &latest, &base),
                proof.merge_bytes(&base, &latest, &base).is_some()
            );

            // Two writers setting the SAME new bit is a double-allocation.
            let zbase = vec![0u8; 8];
            let mut dbl = zbase.clone();
            dbl[idx] = 0b0000_0010;
            prop_assert!(proof.merge_bytes(&zbase, &dbl, &dbl).is_none());
        }

        /// Invariant: snapshot isolation — a snapshot sees only versions committed
        /// before its creation, not versions committed after.
        #[test]
        fn proptest_snapshot_isolation_excludes_later_commits(
            pre_ops in write_ops_strategy(),
            post_ops in write_ops_strategy(),
        ) {
            let mut store = MvccStore::new();

            // Build expected: last write per block within the transaction wins.
            let mut pre_expected = std::collections::BTreeMap::<u16, u8>::new();
            let mut txn1 = store.begin();
            for &(block, byte) in &pre_ops {
                txn1.stage_write(BlockNumber(u64::from(block)), vec![byte; 64]);
                pre_expected.insert(block, byte);
            }
            store.commit(txn1).expect("commit pre");

            // Take snapshot.
            let snap = store.current_snapshot();

            // Commit post-snapshot writes with different data.
            let mut txn2 = store.begin();
            for &(block, byte) in &post_ops {
                txn2.stage_write(BlockNumber(u64::from(block)), vec![byte.wrapping_add(1); 64]);
            }
            store.commit(txn2).expect("commit post");

            // The snapshot must still see the pre-commit values, not the post-commit ones.
            for (&block, &byte) in &pre_expected {
                if let Some(data) = store.read_visible(BlockNumber(u64::from(block)), snap) {
                    prop_assert_eq!(
                        data[0], byte,
                        "snapshot isolation violated for block {}",
                        block
                    );
                }
            }
        }

        /// Invariant: version chain monotonicity — commit sequences in a block's
        /// version chain are strictly increasing.
        #[test]
        fn proptest_version_chain_monotonic(
            num_commits in 2_usize..16,
            block_id in 0_u16..32,
        ) {
            let mut store = MvccStore::new();
            let block = BlockNumber(u64::from(block_id));

            let mut committed_seqs = Vec::new();
            for i in 0..num_commits {
                let mut txn = store.begin();
                #[allow(clippy::cast_possible_truncation)]
                txn.stage_write(block, vec![i as u8; 64]);
                let seq = store.commit(txn).expect("commit");
                committed_seqs.push(seq);
            }

            // All commit sequences must be strictly increasing.
            for window in committed_seqs.windows(2) {
                prop_assert!(
                    window[0] < window[1],
                    "commit seq not monotonic: {:?} >= {:?}",
                    window[0],
                    window[1]
                );
            }
        }

        /// Invariant: FCW conflict detection — when two transactions write to
        /// the same block, only the first committer succeeds.
        #[test]
        fn proptest_fcw_detects_write_write_conflict(
            block_id in 0_u16..64,
            byte_a in any::<u8>(),
            byte_b in any::<u8>(),
        ) {
            let mut store = MvccStore::new();
            let block = BlockNumber(u64::from(block_id));

            // Begin two concurrent transactions at the same snapshot.
            let mut txn_a = store.begin();
            let mut txn_b = store.begin();

            txn_a.stage_write(block, vec![byte_a; 64]);
            txn_b.stage_write(block, vec![byte_b; 64]);

            // First committer wins.
            store.commit(txn_a).expect("txn_a should commit first");

            // Second committer must fail with a conflict.
            let result = store.commit(txn_b);
            prop_assert!(
                result.is_err(),
                "FCW should reject txn_b for block {}",
                block_id,
            );
            match result.unwrap_err() {
                CommitError::Conflict { block: b, .. } => {
                    prop_assert_eq!(b, block, "conflict block mismatch");
                }
                other => {
                    prop_assert!(false, "expected Conflict, got {:?}", other);
                }
            }
        }

        /// Invariant: non-overlapping writes from concurrent transactions
        /// both commit successfully.
        #[test]
        fn proptest_non_overlapping_concurrent_writes_succeed(
            block_a in 0_u16..32,
            block_b in 32_u16..64,
            byte_a in any::<u8>(),
            byte_b in any::<u8>(),
        ) {
            let mut store = MvccStore::new();

            let mut txn_a = store.begin();
            let mut txn_b = store.begin();

            txn_a.stage_write(BlockNumber(u64::from(block_a)), vec![byte_a; 64]);
            txn_b.stage_write(BlockNumber(u64::from(block_b)), vec![byte_b; 64]);

            store.commit(txn_a).expect("disjoint txn_a should commit");
            store.commit(txn_b).expect("disjoint txn_b should commit");

            // Both writes must be visible.
            let snap = store.current_snapshot();
            let va = store
                .read_visible(BlockNumber(u64::from(block_a)), snap)
                .expect("block_a visible");
            let vb = store
                .read_visible(BlockNumber(u64::from(block_b)), snap)
                .expect("block_b visible");
            prop_assert_eq!(va[0], byte_a);
            prop_assert_eq!(vb[0], byte_b);
        }

        /// Invariant: last-writer-wins semantics across sequential transactions.
        ///
        /// When multiple transactions write to the same block and commit
        /// sequentially (not concurrently), the latest committed value is
        /// the one visible to a new snapshot.
        #[test]
        fn proptest_sequential_writes_last_value_wins(
            writes in prop::collection::vec(any::<u8>(), 2..8),
            block_id in 0_u16..32,
        ) {
            let mut store = MvccStore::new();
            let block = BlockNumber(u64::from(block_id));

            for &byte in &writes {
                let mut txn = store.begin();
                txn.stage_write(block, vec![byte; 64]);
                store.commit(txn).expect("sequential commit");
            }

            let snap = store.current_snapshot();
            let version = store.read_visible(block, snap).expect("must be visible");
            let expected = *writes.last().unwrap();
            let actual = version[0];
            prop_assert_eq!(actual, expected, "last writer should win");
        }

        /// Invariant: reading an unwritten block returns None.
        #[test]
        fn proptest_unwritten_block_returns_none(
            block_id in 0_u64..1024,
        ) {
            let store = MvccStore::new();
            let snap = store.current_snapshot();
            let result = store.read_visible(BlockNumber(block_id), snap);
            prop_assert!(result.is_none(), "unwritten block {} should be None", block_id);
        }

        /// Invariant: abort discards writes — a transaction's writes become
        /// invisible after abort.
        #[test]
        fn proptest_abort_discards_writes(
            ops in write_ops_strategy(),
        ) {
            let mut store = MvccStore::new();

            let mut txn = store.begin();
            for &(block, byte) in &ops {
                txn.stage_write(BlockNumber(u64::from(block)), vec![byte; 64]);
            }
            store.abort(txn, TxnAbortReason::UserAbort, None);

            // All blocks should be unwritten.
            let snap = store.current_snapshot();
            for &(block, _) in &ops {
                let result = store.read_visible(BlockNumber(u64::from(block)), snap);
                prop_assert!(result.is_none(), "aborted write to block {} should not be visible", block);
            }
        }

        /// critical_chain_len is always strictly greater than max_len.
        #[test]
        fn proptest_critical_chain_len_greater_than_input(
            max_len in 0_usize..10_000,
        ) {
            let critical = MvccStore::critical_chain_len(max_len);
            prop_assert!(
                critical > max_len,
                "critical_chain_len({}) = {} should be > {}",
                max_len, critical, max_len,
            );
        }

        /// critical_chain_len is monotonically non-decreasing.
        #[test]
        fn proptest_critical_chain_len_monotonic(
            a in 0_usize..5000,
            b in 0_usize..5000,
        ) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            let c_lo = MvccStore::critical_chain_len(lo);
            let c_hi = MvccStore::critical_chain_len(hi);
            prop_assert!(
                c_lo <= c_hi,
                "critical_chain_len({}) = {} > critical_chain_len({}) = {}",
                lo, c_lo, hi, c_hi,
            );
        }

        /// Snapshot register/release ref-counting: watermark tracks the minimum.
        #[test]
        fn proptest_snapshot_register_release_refcount(
            commits in 2_usize..8,
            register_at in 0_usize..2,
        ) {
            let mut store = MvccStore::new();

            // Generate multiple commits.
            let mut all_seqs = Vec::new();
            for i in 0..commits {
                let mut txn = store.begin();
                #[allow(clippy::cast_possible_truncation)]
                txn.stage_write(BlockNumber(0), vec![i as u8; 64]);
                let seq = store.commit(txn).expect("commit");
                all_seqs.push(seq);
            }

            let snap_idx = register_at.min(all_seqs.len() - 1);
            let snap = Snapshot { high: all_seqs[snap_idx] };
            store.register_snapshot(snap);
            prop_assert_eq!(store.active_snapshot_count(), 1);
            prop_assert_eq!(store.watermark(), Some(snap.high));

            store.release_snapshot(snap);
            prop_assert_eq!(store.active_snapshot_count(), 0);
            prop_assert_eq!(store.watermark(), None);
        }

        /// Snapshot watermark is always the minimum of registered snapshots.
        #[test]
        fn proptest_watermark_is_minimum_snapshot(
            seq_a in 1_u64..1000,
            seq_b in 1_u64..1000,
        ) {
            let mut store = MvccStore::new();
            // Advance store commit counter past our snapshot values.
            let max_seq = seq_a.max(seq_b) + 1;
            for i in 0..max_seq {
                let mut txn = store.begin();
                #[allow(clippy::cast_possible_truncation)]
                txn.stage_write(BlockNumber(i), vec![1; 8]);
                store.commit(txn).expect("commit");
            }

            let snap_a = Snapshot { high: CommitSeq(seq_a) };
            let snap_b = Snapshot { high: CommitSeq(seq_b) };
            store.register_snapshot(snap_a);
            store.register_snapshot(snap_b);
            let expected_min = CommitSeq(seq_a.min(seq_b));
            prop_assert_eq!(store.watermark(), Some(expected_min));

            store.release_snapshot(snap_a);
            store.release_snapshot(snap_b);
        }

        /// Compression dedup: writing identical data produces Identical markers.
        #[test]
        fn proptest_compression_dedup_identical_writes(
            data_byte in any::<u8>(),
            repeat_count in 2_usize..8,
        ) {
            let mut store = MvccStore::new();
            for _ in 0..repeat_count {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(0), vec![data_byte; 64]);
                store.commit(txn).expect("commit");
            }
            let stats = store.compression_stats();
            // First write is Full, subsequent writes are Identical (dedup enabled by default).
            prop_assert_eq!(stats.full_versions, 1, "should be exactly 1 Full version");
            prop_assert_eq!(
                stats.identical_versions,
                repeat_count - 1,
                "should have {} Identical versions",
                repeat_count - 1,
            );
        }

        /// SSI log prune removes records at or before the given commit.
        #[test]
        fn proptest_prune_ssi_log_removes_old_records(
            num_commits in 2_usize..16,
            prune_at in 0_usize..8,
        ) {
            let mut store = MvccStore::new();
            for i in 0..num_commits {
                let mut txn = store.begin();
                #[allow(clippy::cast_possible_truncation)]
                txn.stage_write(BlockNumber(u64::try_from(i).unwrap()), vec![1; 8]);
                store.commit(txn).expect("commit");
            }
            let prune_seq = CommitSeq(u64::try_from(prune_at.min(num_commits)).unwrap());
            store.prune_ssi_log(prune_seq);
            // All remaining SSI entries must have commit_seq > prune_seq.
            for record in &store.ssi_log {
                prop_assert!(
                    record.commit_seq > prune_seq,
                    "SSI record at {:?} should have been pruned at {:?}",
                    record.commit_seq, prune_seq,
                );
            }
        }

        /// Invariant: SSI detects write-skew (rw-antidependency cycles).
        ///
        /// Two concurrent transactions each read a block written by the other.
        /// Under SSI, the second committer must be rejected because the read-write
        /// dependency forms a dangerous cycle.
        #[test]
        fn proptest_ssi_detects_write_skew(
            block_a in 0_u16..32,
            block_b in 32_u16..64,
            seed_a in any::<u8>(),
            seed_b in any::<u8>(),
        ) {
            let mut store = MvccStore::new();
            let ba = BlockNumber(u64::from(block_a));
            let bb = BlockNumber(u64::from(block_b));

            // Seed initial values so reads return something.
            let mut seed = store.begin();
            seed.stage_write(ba, vec![seed_a; 64]);
            seed.stage_write(bb, vec![seed_b; 64]);
            store.commit_ssi(seed).expect("seed commit");

            // T1: reads block_b, writes block_a.
            let mut t1 = store.begin();
            t1.record_read(bb, CommitSeq(1));
            t1.stage_write(ba, vec![seed_a.wrapping_add(1); 64]);

            // T2: reads block_a, writes block_b.
            let mut t2 = store.begin();
            t2.record_read(ba, CommitSeq(1));
            t2.stage_write(bb, vec![seed_b.wrapping_add(1); 64]);

            // First committer succeeds (SSI).
            store.commit_ssi(t1).expect("t1 SSI commit");

            // Second committer must be rejected: rw-antidependency cycle.
            let result = store.commit_ssi(t2);
            prop_assert!(
                result.is_err(),
                "SSI should reject t2 due to write-skew on blocks {}, {}",
                block_a, block_b,
            );
        }

        /// Invariant: N concurrent writers to the same block — exactly one wins.
        ///
        /// For any number of concurrent transactions (2..8) all writing the same
        /// block, exactly one commits successfully under FCW.
        #[test]
        fn proptest_n_concurrent_writers_exactly_one_wins(
            n in 2_usize..8,
            block_id in 0_u16..64,
            bytes in prop::collection::vec(any::<u8>(), 2..8),
        ) {
            let mut store = MvccStore::new();
            let block = BlockNumber(u64::from(block_id));
            let writer_count = n.min(bytes.len());

            // Begin all transactions at the same snapshot.
            let mut txns: Vec<Transaction> = (0..writer_count)
                .map(|_| store.begin())
                .collect();

            // Each stages a write to the same block with different data.
            for (i, txn) in txns.iter_mut().enumerate() {
                txn.stage_write(block, vec![bytes[i]; 64]);
            }

            // Commit all — count successes and failures.
            let mut successes = 0_usize;
            let mut failures = 0_usize;
            for txn in txns {
                match store.commit(txn) {
                    Ok(_) => successes += 1,
                    Err(CommitError::Conflict { .. }) => failures += 1,
                    Err(other) => prop_assert!(false, "unexpected error: {:?}", other),
                }
            }

            prop_assert_eq!(successes, 1, "exactly one writer should succeed");
            prop_assert_eq!(failures, writer_count - 1, "rest should conflict");
        }

        /// Invariant: prune_safe preserves active snapshot visibility.
        ///
        /// After registering a snapshot and pruning, all blocks visible to that
        /// snapshot before pruning must still be visible after pruning.
        #[test]
        fn proptest_prune_safe_preserves_active_snapshot(
            ops in write_ops_strategy(),
            extra_commits in 1_usize..6,
        ) {
            let mut store = MvccStore::new();

            // Commit initial data.
            let mut txn = store.begin();
            for &(block, byte) in &ops {
                txn.stage_write(BlockNumber(u64::from(block)), vec![byte; 64]);
            }
            store.commit(txn).expect("initial commit");

            // Register a snapshot at current state.
            let snap = store.current_snapshot();
            store.register_snapshot(snap);

            // Record what's visible before additional commits and pruning.
            let mut expected = std::collections::BTreeMap::<u16, u8>::new();
            for &(block, byte) in &ops {
                expected.insert(block, byte);
            }

            // Commit more data (potentially overwriting same blocks).
            for i in 0..extra_commits {
                let mut txn = store.begin();
                for &(block, _) in &ops {
                    #[allow(clippy::cast_possible_truncation)]
                    txn.stage_write(
                        BlockNumber(u64::from(block)),
                        vec![(i as u8).wrapping_add(100); 64],
                    );
                }
                store.commit(txn).expect("extra commit");
            }

            // Prune — should respect the registered snapshot.
            store.prune_safe();

            // The registered snapshot must still see the original values.
            for (&block, &byte) in &expected {
                let data = store
                    .read_visible(BlockNumber(u64::from(block)), snap)
                    .expect("snapshot visibility must survive pruning");
                prop_assert_eq!(
                    data[0], byte,
                    "prune_safe violated snapshot visibility for block {}",
                    block,
                );
            }

            store.release_snapshot(snap);
        }

        /// Invariant: version chain integrity after pruning — the latest version
        /// for each block is always preserved by GC.
        #[test]
        fn proptest_latest_version_survives_pruning(
            num_writes in 2_usize..12,
            block_id in 0_u16..32,
        ) {
            let mut store = MvccStore::new();
            let block = BlockNumber(u64::from(block_id));

            let mut last_byte: u8 = 0;
            for i in 0..num_writes {
                let mut txn = store.begin();
                #[allow(clippy::cast_possible_truncation)]
                let byte = i as u8;
                txn.stage_write(block, vec![byte; 64]);
                store.commit(txn).expect("commit");
                last_byte = byte;
            }

            // Prune everything possible (no active snapshots).
            store.prune_safe();

            // The latest version must still be readable.
            let snap = store.current_snapshot();
            let data = store
                .read_visible(block, snap)
                .expect("latest version must survive pruning");
            prop_assert_eq!(
                data[0], last_byte,
                "latest version lost after pruning for block {}",
                block_id,
            );
        }

        /// Invariant: multi-block transaction atomicity — all writes in a
        /// committed transaction are visible together; no partial state.
        #[test]
        fn proptest_multi_block_transaction_all_or_nothing(
            blocks in prop::collection::vec(0_u16..128, 2..16),
            data_byte in any::<u8>(),
        ) {
            let mut store = MvccStore::new();

            let unique_blocks: BTreeSet<u16> = blocks.iter().copied().collect();

            let mut txn = store.begin();
            for &block in &unique_blocks {
                txn.stage_write(BlockNumber(u64::from(block)), vec![data_byte; 64]);
            }
            store.commit(txn).expect("multi-block commit");

            // All blocks must be visible as a group — no partial state.
            let snap = store.current_snapshot();
            for &block in &unique_blocks {
                let data = store
                    .read_visible(BlockNumber(u64::from(block)), snap)
                    .expect("all committed blocks must be visible");
                prop_assert_eq!(
                    data[0], data_byte,
                    "partial visibility for block {}",
                    block,
                );
            }
        }

        /// Invariant: interleaved serial transactions preserve all committed data.
        ///
        /// A sequence of transactions writing to random blocks, committed one after
        /// another, must result in every block having the value from its last writer.
        #[test]
        fn proptest_interleaved_serial_no_lost_updates(
            txn_ops in prop::collection::vec(
                prop::collection::vec((0_u16..32, any::<u8>()), 1..8),
                2..10,
            ),
        ) {
            let mut store = MvccStore::new();

            // Track expected final state: last write per block across all txns.
            let mut expected = std::collections::BTreeMap::<u16, u8>::new();

            for ops in &txn_ops {
                let mut txn = store.begin();
                for &(block, byte) in ops {
                    txn.stage_write(BlockNumber(u64::from(block)), vec![byte; 64]);
                    expected.insert(block, byte);
                }
                store.commit(txn).expect("serial commit");
            }

            // Verify final state matches expected.
            let snap = store.current_snapshot();
            for (&block, &byte) in &expected {
                let data = store
                    .read_visible(BlockNumber(u64::from(block)), snap)
                    .expect("committed block must be visible");
                prop_assert_eq!(
                    data[0], byte,
                    "lost update for block {} (expected {}, got {})",
                    block, byte, data[0],
                );
            }
        }
    }

    // ── Conflict detection edge-case tests ─────────────────────────────

    /// FCW: a write committed at exactly snapshot.high is NOT a conflict.
    /// Only writes with commit_seq > snapshot.high cause rejection.
    #[test]
    fn fcw_write_at_snapshot_boundary_is_not_conflict() {
        let mut store = MvccStore::new();

        // T1: write block 0, commits at seq 1.
        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(0), vec![1; 64]);
        let seq1 = store.commit(t1).expect("t1 commit");

        // T2: begins AFTER t1 committed → snapshot.high == seq1.
        let mut t2 = store.begin();
        assert_eq!(t2.snapshot.high, seq1);
        t2.stage_write(BlockNumber(0), vec![2; 64]);

        // latest_commit_seq(block 0) == seq1 == snapshot.high → NOT > → OK.
        assert!(store.commit(t2).is_ok());
    }

    /// FCW: a write committed AFTER snapshot.high IS a conflict.
    #[test]
    fn fcw_write_after_snapshot_boundary_is_conflict() {
        let mut store = MvccStore::new();

        // T1 begins.
        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(0), vec![1; 64]);

        // T2 begins concurrently (same snapshot as T1).
        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(0), vec![2; 64]);

        // T1 commits first → advances latest for block 0.
        store.commit(t1).expect("t1 commit");

        // T2 commits → latest_commit_seq(block 0) > t2.snapshot.high → Conflict.
        let err = store.commit(t2).unwrap_err();
        assert!(
            matches!(err, CommitError::Conflict { block, .. } if block == BlockNumber(0)),
            "expected Conflict on block 0, got {err:?}"
        );
    }

    /// FCW conflict reports correct block, snapshot, and observed commit seq.
    #[test]
    fn fcw_conflict_error_contains_correct_fields() {
        let mut store = MvccStore::new();

        let mut t2 = store.begin(); // snapshot.high == 0
        t2.stage_write(BlockNumber(7), vec![2; 32]);

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(7), vec![1; 32]);
        let seq1 = store.commit(t1).expect("t1");

        let err = store.commit(t2).unwrap_err();
        match err {
            CommitError::Conflict {
                block,
                snapshot,
                observed,
            } => {
                assert_eq!(block, BlockNumber(7));
                assert_eq!(snapshot, CommitSeq(0));
                assert_eq!(observed, seq1);
            }
            other => assert!(
                matches!(other, CommitError::Conflict { .. }),
                "expected Conflict, got {other:?}"
            ),
        }
    }

    /// FCW: three concurrent writers to same block — first wins, others conflict.
    #[test]
    fn fcw_three_concurrent_all_but_first_conflict() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();
        let mut t3 = store.begin();

        t1.stage_write(BlockNumber(0), vec![1; 16]);
        t2.stage_write(BlockNumber(0), vec![2; 16]);
        t3.stage_write(BlockNumber(0), vec![3; 16]);

        assert!(store.commit(t1).is_ok());
        assert!(matches!(
            store.commit(t2),
            Err(CommitError::Conflict { .. })
        ));
        assert!(matches!(
            store.commit(t3),
            Err(CommitError::Conflict { .. })
        ));
    }

    /// FCW: concurrent writers to DIFFERENT blocks all succeed.
    #[test]
    fn fcw_concurrent_disjoint_blocks_all_succeed() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();
        let mut t3 = store.begin();

        t1.stage_write(BlockNumber(10), vec![1; 16]);
        t2.stage_write(BlockNumber(20), vec![2; 16]);
        t3.stage_write(BlockNumber(30), vec![3; 16]);

        assert!(store.commit(t1).is_ok());
        assert!(store.commit(t2).is_ok());
        assert!(store.commit(t3).is_ok());
    }

    /// SSI: read-only transaction (no writes) always commits regardless of
    /// concurrent activity.
    #[test]
    fn ssi_read_only_txn_always_commits() {
        let mut store = MvccStore::new();

        let mut seed = store.begin();
        seed.stage_write(BlockNumber(0), vec![1; 64]);
        store.commit_ssi(seed).expect("seed");

        // T1 reads block 0 but writes nothing.
        let mut t1 = store.begin();
        t1.record_read(BlockNumber(0), CommitSeq(1));

        // Concurrent T2 writes block 0.
        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(0), vec![2; 64]);
        store.commit_ssi(t2).expect("t2");

        // T1 (read-only) commits — validate_ssi_read_set Ok(0) when writes empty.
        assert!(store.commit_ssi(t1).is_ok());
    }

    /// SSI: transaction writes block A and reads block B. A concurrent write
    /// to B alone is a single rw edge, not a dangerous structure.
    #[test]
    fn ssi_single_outgoing_rw_edge_is_allowed() {
        let mut store = MvccStore::new();

        let mut seed = store.begin();
        seed.stage_write(BlockNumber(0), vec![0; 64]);
        seed.stage_write(BlockNumber(1), vec![0; 64]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads block 1, writes block 0.
        let mut t1 = store.begin();
        t1.record_read(BlockNumber(1), store.latest_commit_seq(BlockNumber(1)));
        t1.stage_write(BlockNumber(0), vec![1; 64]);

        // T2: writes block 1 and commits first.
        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(1), vec![2; 64]);
        store.commit_ssi(t2).expect("t2");

        store
            .commit_ssi(t1)
            .expect("single outgoing rw edge remains serializable");
    }

    /// SSI: a concurrent transaction read a block this transaction writes.
    /// That inbound edge alone is serializable and should not abort.
    #[test]
    fn ssi_single_incoming_rw_edge_is_allowed() {
        let mut store = MvccStore::new();
        let block_a = BlockNumber(0);
        let block_b = BlockNumber(1);

        let mut seed = store.begin();
        seed.stage_write(block_a, vec![0; 64]);
        seed.stage_write(block_b, vec![0; 64]);
        store.commit_ssi(seed).expect("seed");

        let mut writer = store.begin();
        writer.stage_write(block_a, vec![1; 64]);

        let mut prior_reader = store.begin();
        prior_reader.record_read(block_a, store.latest_commit_seq(block_a));
        prior_reader.stage_write(block_b, vec![2; 64]);
        store
            .commit_ssi(prior_reader)
            .expect("prior reader commits");

        store
            .commit_ssi(writer)
            .expect("single incoming rw edge remains serializable");
    }

    /// SSI: write-write conflict is caught by FCW layer before SSI check.
    #[test]
    fn ssi_fcw_conflict_takes_precedence_over_ssi() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(5), vec![1; 64]);
        t2.stage_write(BlockNumber(5), vec![2; 64]);

        store.commit_ssi(t1).expect("t1");

        let err = store.commit_ssi(t2).unwrap_err();
        assert!(
            matches!(err, CommitError::Conflict { block, .. } if block == BlockNumber(5)),
            "expected FCW Conflict, got {err:?}"
        );
    }

    /// SSI: transaction reads and writes the same block — no self-conflict.
    #[test]
    fn ssi_self_read_write_no_conflict() {
        let mut store = MvccStore::new();

        let mut seed = store.begin();
        seed.stage_write(BlockNumber(0), vec![0; 64]);
        store.commit_ssi(seed).expect("seed");

        let mut t1 = store.begin();
        t1.record_read(BlockNumber(0), store.latest_commit_seq(BlockNumber(0)));
        t1.stage_write(BlockNumber(0), vec![1; 64]);
        assert!(store.commit_ssi(t1).is_ok());
    }

    /// SSI: T2 wrote block 0 (in T1's read set) and read block 2 (in T1's
    /// write set), so T1 has both inbound and outbound rw edges.
    #[test]
    fn ssi_overlapping_read_write_sets_detected() {
        let mut store = MvccStore::new();

        let mut seed = store.begin();
        seed.stage_write(BlockNumber(0), vec![0; 64]);
        seed.stage_write(BlockNumber(1), vec![0; 64]);
        seed.stage_write(BlockNumber(2), vec![0; 64]);
        seed.stage_write(BlockNumber(3), vec![0; 64]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads {0, 1}, writes {2}.
        let mut t1 = store.begin();
        t1.record_read(BlockNumber(0), store.latest_commit_seq(BlockNumber(0)));
        t1.record_read(BlockNumber(1), store.latest_commit_seq(BlockNumber(1)));
        t1.stage_write(BlockNumber(2), vec![1; 64]);

        // T2: reads {2, 3}, writes {0}. Commits first.
        let mut t2 = store.begin();
        t2.record_read(BlockNumber(2), store.latest_commit_seq(BlockNumber(2)));
        t2.record_read(BlockNumber(3), store.latest_commit_seq(BlockNumber(3)));
        t2.stage_write(BlockNumber(0), vec![2; 64]);
        store.commit_ssi(t2).expect("t2");

        // T1 fails: T2 wrote block 0, which is in T1's read set.
        let err = store.commit_ssi(t1).unwrap_err();
        assert!(
            matches!(err, CommitError::SsiConflict { pivot_block, .. } if pivot_block == BlockNumber(0)),
            "expected SsiConflict on block 0, got {err:?}"
        );
    }

    #[test]
    fn ssi_disjoint_key_spans_do_not_create_edges() {
        let mut pivot = Transaction::new(TxnId(10), Snapshot { high: CommitSeq(0) });
        for block in 0..192_u64 {
            pivot.record_read(BlockNumber(block), CommitSeq(1));
        }
        pivot.stage_write(BlockNumber(1_000_000), vec![1; 64]);

        let record = CommittedTxnRecord {
            txn_id: TxnId(11),
            commit_seq: CommitSeq(1),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(2_000_000)]),
            read_set: (10_000..10_192)
                .map(|block| (BlockNumber(block), CommitSeq(1)))
                .collect(),
        };

        assert!(ssi_incoming_edge(&pivot, &record).is_none());
        assert!(ssi_outgoing_edge(&pivot, &record).is_none());
        let (checks_performed, dangerous_structure) =
            detect_ssi_dangerous_structure(&pivot, [&record]);
        assert_eq!(checks_performed, 1);
        assert!(dangerous_structure.is_none());
    }

    fn one_read_set(block: u64) -> BTreeMap<BlockNumber, CommitSeq> {
        std::iter::once((BlockNumber(block), CommitSeq(1))).collect()
    }

    #[test]
    fn ssi_incoming_edge_attributes_reader_and_writer_correctly() {
        // The pivot WROTE block 5; the committed record READ block 5. The record's
        // read is anti the pivot's write -> an incoming rw-edge to the pivot, with
        // reader = the record and writer = the pivot.
        let mut pivot = Transaction::new(TxnId(70), Snapshot { high: CommitSeq(0) });
        pivot.stage_write(BlockNumber(5), vec![1; 64]);

        let record = CommittedTxnRecord {
            txn_id: TxnId(71),
            commit_seq: CommitSeq(3),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::new(),
            read_set: one_read_set(5),
        };
        let edge = ssi_incoming_edge(&pivot, &record).expect("incoming edge on block 5");
        assert_eq!(edge.block, BlockNumber(5));
        assert_eq!(edge.reader_txn, TxnId(71), "the record is the reader");
        assert_eq!(edge.writer_txn, TxnId(70), "the pivot is the writer");
    }

    #[test]
    fn ssi_outgoing_edge_attributes_reader_and_writer_correctly() {
        // The pivot READ block 5; the committed record WROTE block 5. The pivot's
        // read is anti the record's write -> an outgoing rw-edge from the pivot,
        // with reader = the pivot and writer = the record (mirror of incoming).
        let mut pivot = Transaction::new(TxnId(80), Snapshot { high: CommitSeq(0) });
        pivot.record_read(BlockNumber(5), CommitSeq(1));

        let record = CommittedTxnRecord {
            txn_id: TxnId(81),
            commit_seq: CommitSeq(3),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(5)]),
            read_set: one_read_set(99),
        };
        let edge = ssi_outgoing_edge(&pivot, &record).expect("outgoing edge on block 5");
        assert_eq!(edge.block, BlockNumber(5));
        assert_eq!(edge.reader_txn, TxnId(80), "the pivot is the reader");
        assert_eq!(edge.writer_txn, TxnId(81), "the record is the writer");
    }

    #[test]
    fn ssi_single_rw_edge_is_not_a_dangerous_structure() {
        let mut pivot = Transaction::new(TxnId(30), Snapshot { high: CommitSeq(0) });
        pivot.record_read(BlockNumber(0), CommitSeq(11));
        pivot.record_read(BlockNumber(1), CommitSeq(12));
        pivot.stage_write(BlockNumber(2), vec![1; 64]);
        pivot.stage_write(BlockNumber(3), vec![1; 64]);

        // Only an OUTGOING edge (pivot.read ∩ record.write = {0}): the pivot read
        // block 0 and this record wrote it; the record reads nothing the pivot
        // wrote. One edge is not a pivot.
        let outgoing_only = CommittedTxnRecord {
            txn_id: TxnId(31),
            commit_seq: CommitSeq(5),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(0)]),
            read_set: one_read_set(99),
        };
        assert!(ssi_incoming_edge(&pivot, &outgoing_only).is_none());
        assert!(ssi_outgoing_edge(&pivot, &outgoing_only).is_some());
        assert!(
            detect_ssi_dangerous_structure(&pivot, [&outgoing_only])
                .1
                .is_none()
        );

        // Only an INCOMING edge (record.read ∩ pivot.write = {2}): this record read
        // block 2 and the pivot wrote it; the record writes nothing the pivot read.
        let incoming_only = CommittedTxnRecord {
            txn_id: TxnId(32),
            commit_seq: CommitSeq(5),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(99)]),
            read_set: one_read_set(2),
        };
        assert!(ssi_incoming_edge(&pivot, &incoming_only).is_some());
        assert!(ssi_outgoing_edge(&pivot, &incoming_only).is_none());
        assert!(
            detect_ssi_dangerous_structure(&pivot, [&incoming_only])
                .1
                .is_none()
        );
    }

    #[test]
    fn ssi_skips_records_visible_in_snapshot() {
        // Pivot's snapshot already includes everything up to CommitSeq(5).
        let mut pivot = Transaction::new(TxnId(40), Snapshot { high: CommitSeq(5) });
        pivot.record_read(BlockNumber(0), CommitSeq(1));
        pivot.record_read(BlockNumber(1), CommitSeq(1));
        pivot.stage_write(BlockNumber(2), vec![1; 64]);
        pivot.stage_write(BlockNumber(3), vec![1; 64]);

        // A record committed at/before the snapshot high is already visible, so
        // it forms no rw-edge even though its key spans would otherwise create
        // both an incoming and an outgoing edge.
        let visible = CommittedTxnRecord {
            txn_id: TxnId(41),
            commit_seq: CommitSeq(5),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(0), BlockNumber(1)]),
            read_set: [
                (BlockNumber(2), CommitSeq(1)),
                (BlockNumber(3), CommitSeq(1)),
            ]
            .into_iter()
            .collect(),
        };
        let (checks_performed, dangerous) = detect_ssi_dangerous_structure(&pivot, [&visible]);
        assert_eq!(checks_performed, 0, "a snapshot-visible record is skipped");
        assert!(
            dangerous.is_none(),
            "no dangerous structure from a record the txn already observed"
        );
    }

    #[test]
    fn ssi_empty_write_set_is_never_a_dangerous_structure() {
        // A read-only transaction (no writes) can never be the pivot of a
        // write-skew; detect returns immediately without examining any records.
        let mut reader = Transaction::new(TxnId(50), Snapshot { high: CommitSeq(0) });
        reader.record_read(BlockNumber(0), CommitSeq(1));
        reader.record_read(BlockNumber(1), CommitSeq(1));

        // This record writes blocks the reader read (would form an incoming edge),
        // but with no write set the reader is never the pivot.
        let record = CommittedTxnRecord {
            txn_id: TxnId(51),
            commit_seq: CommitSeq(5),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(0), BlockNumber(1)]),
            read_set: one_read_set(2),
        };
        let (checks_performed, dangerous) = detect_ssi_dangerous_structure(&reader, [&record]);
        assert_eq!(
            checks_performed, 0,
            "no records examined for a read-only txn"
        );
        assert!(dangerous.is_none());
    }

    #[test]
    fn ssi_detect_stops_at_first_completed_dangerous_structure() {
        // The pivot reads block 0 and writes block 2.
        let mut pivot = Transaction::new(TxnId(90), Snapshot { high: CommitSeq(0) });
        pivot.record_read(BlockNumber(0), CommitSeq(1));
        pivot.stage_write(BlockNumber(2), vec![1; 64]);

        // rec1 alone completes BOTH edges: it writes block 0 (pivot read it ->
        // outgoing) AND reads block 2 (pivot wrote it -> incoming).
        let rec1 = CommittedTxnRecord {
            txn_id: TxnId(91),
            commit_seq: CommitSeq(5),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(0)]),
            read_set: one_read_set(2),
        };
        // rec2 would also form both edges, but detect must stop before examining it.
        let rec2 = CommittedTxnRecord {
            txn_id: TxnId(92),
            commit_seq: CommitSeq(6),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(0)]),
            read_set: one_read_set(2),
        };

        let (checks, dangerous) = detect_ssi_dangerous_structure(&pivot, [&rec1, &rec2]);
        assert!(
            dangerous.is_some(),
            "rec1 alone forms the dangerous structure"
        );
        assert_eq!(checks, 1, "detect returns at rec1 without examining rec2");
    }

    #[test]
    fn ssi_dangerous_structure_accumulates_edges_across_records() {
        let mut pivot = Transaction::new(TxnId(60), Snapshot { high: CommitSeq(0) });
        pivot.record_read(BlockNumber(0), CommitSeq(1));
        pivot.stage_write(BlockNumber(2), vec![1; 64]);

        // Record 1 writes a block the pivot read -> only an incoming edge.
        let rec1 = CommittedTxnRecord {
            txn_id: TxnId(61),
            commit_seq: CommitSeq(5),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(0)]),
            read_set: one_read_set(99),
        };
        // Record 2 reads a block the pivot wrote -> only an outgoing edge.
        let rec2 = CommittedTxnRecord {
            txn_id: TxnId(62),
            commit_seq: CommitSeq(6),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(99)]),
            read_set: one_read_set(2),
        };

        // Neither record alone is a dangerous structure.
        assert!(detect_ssi_dangerous_structure(&pivot, [&rec1]).1.is_none());
        assert!(detect_ssi_dangerous_structure(&pivot, [&rec2]).1.is_none());
        // Together they form the pivot: incoming from rec1, outgoing from rec2.
        let (checks, dangerous) = detect_ssi_dangerous_structure(&pivot, [&rec1, &rec2]);
        assert_eq!(checks, 2, "both records are examined");
        assert!(
            dangerous.is_some(),
            "edges from two distinct records form a dangerous structure"
        );
    }

    #[test]
    fn ssi_span_guard_preserves_min_intersection_tiebreaks() {
        use sha2::{Digest, Sha256};

        let mut pivot = Transaction::new(TxnId(20), Snapshot { high: CommitSeq(0) });
        pivot.record_read(BlockNumber(0), CommitSeq(11));
        pivot.record_read(BlockNumber(1), CommitSeq(12));
        pivot.stage_write(BlockNumber(2), vec![1; 64]);
        pivot.stage_write(BlockNumber(3), vec![1; 64]);

        let record = CommittedTxnRecord {
            txn_id: TxnId(21),
            commit_seq: CommitSeq(5),
            snapshot: Snapshot { high: CommitSeq(0) },
            write_set: BTreeSet::from([BlockNumber(0), BlockNumber(1)]),
            read_set: [
                (BlockNumber(2), CommitSeq(13)),
                (BlockNumber(3), CommitSeq(14)),
            ]
            .into_iter()
            .collect(),
        };

        let (checks_performed, dangerous_structure) =
            detect_ssi_dangerous_structure(&pivot, [&record]);
        let dangerous_structure = dangerous_structure.expect("both rw edges");
        assert_eq!(checks_performed, 1);
        assert_eq!(dangerous_structure.incoming.block, BlockNumber(2));
        assert_eq!(dangerous_structure.incoming.read_version, CommitSeq(13));
        assert_eq!(dangerous_structure.outgoing.block, BlockNumber(0));
        assert_eq!(dangerous_structure.outgoing.read_version, CommitSeq(11));
        assert_eq!(dangerous_structure.outgoing.write_version, CommitSeq(5));

        let mut hasher = Sha256::new();
        hasher.update(checks_performed.to_le_bytes());
        hasher.update(dangerous_structure.incoming.block.0.to_le_bytes());
        hasher.update(dangerous_structure.incoming.read_version.0.to_le_bytes());
        hasher.update(dangerous_structure.incoming.write_version.0.to_le_bytes());
        hasher.update(dangerous_structure.outgoing.block.0.to_le_bytes());
        hasher.update(dangerous_structure.outgoing.read_version.0.to_le_bytes());
        hasher.update(dangerous_structure.outgoing.write_version.0.to_le_bytes());
        let golden = hex_lower(&hasher.finalize());
        assert_eq!(
            golden, "1800c846028c2f980ca158d0ea6c41114d05e293588da3cbd25ad3b8f001eb37",
            "SSI span-guard golden digest changed"
        );
    }

    /// Chain backpressure: version chain at critical length with snapshot
    /// pin → rejection. Register the snapshot twice so force_advance only
    /// decrements the refcount without fully removing the pin.
    #[test]
    fn chain_backpressure_rejects_at_critical_with_snapshot_pin() {
        // cap=2 → critical = max(2*4, 2+1) = 8.
        let policy = CompressionPolicy {
            max_chain_length: Some(2),
            dedup_identical: false,
            algo: CompressionAlgo::None,
        };
        let mut store = MvccStore::with_compression_policy(policy);

        let pin_snap = store.current_snapshot();
        // Double-register so force_advance_oldest_snapshot only decrements
        // the refcount but does NOT remove the pin entirely.
        store.register_snapshot(pin_snap);
        store.register_snapshot(pin_snap);

        for i in 0..8_u8 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![i; 64]);
            store.commit(txn).expect("build chain");
        }

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(0), vec![99; 64]);
        let err = store.commit(txn).unwrap_err();
        assert!(
            matches!(err, CommitError::ChainBackpressure { block, .. } if block == BlockNumber(0)),
            "expected ChainBackpressure on block 0, got {err:?}"
        );

        store.release_snapshot(pin_snap);
        store.release_snapshot(pin_snap);
    }

    /// Chain backpressure: without snapshot pin, chain is trimmed and commit
    /// succeeds.
    #[test]
    fn chain_pressure_without_snapshot_pin_allows_commit() {
        let policy = CompressionPolicy {
            max_chain_length: Some(2),
            dedup_identical: false,
            algo: CompressionAlgo::None,
        };
        let mut store = MvccStore::with_compression_policy(policy);

        for i in 0..8_u8 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![i; 64]);
            store.commit(txn).expect("build chain");
        }

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(0), vec![99; 64]);
        assert!(store.commit(txn).is_ok());
    }

    /// Chain backpressure: force-advance oldest snapshot exercises the
    /// recovery path.
    #[test]
    fn chain_pressure_force_advance_exercises_recovery() {
        let policy = CompressionPolicy {
            max_chain_length: Some(2),
            dedup_identical: false,
            algo: CompressionAlgo::None,
        };
        let mut store = MvccStore::with_compression_policy(policy);

        let oldest_snap = store.current_snapshot();
        store.register_snapshot(oldest_snap);

        for i in 0..4_u8 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![i; 64]);
            store.commit(txn).expect("build chain");
        }

        let newer_snap = store.current_snapshot();
        store.register_snapshot(newer_snap);

        for i in 4..8_u8 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![i; 64]);
            store.commit(txn).expect("continue chain");
        }

        // Force-advance mechanism is exercised. Result depends on whether
        // newer_snap still blocks trimming.
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(0), vec![99; 64]);
        let _ = store.commit(txn);

        store.release_snapshot(oldest_snap);
        store.release_snapshot(newer_snap);
    }

    /// SSI log boundary: commit_seq exactly at snapshot.high is NOT scanned
    /// as a conflict.
    #[test]
    fn ssi_log_entry_at_snapshot_high_not_conflict() {
        let mut store = MvccStore::new();

        let mut seed = store.begin();
        seed.stage_write(BlockNumber(0), vec![0; 64]);
        seed.stage_write(BlockNumber(1), vec![0; 64]);
        let seq_seed = store.commit_ssi(seed).expect("seed");

        // T1 begins — snapshot.high == seq_seed.
        let mut t1 = store.begin();
        assert_eq!(t1.snapshot.high, seq_seed);
        t1.record_read(BlockNumber(0), seq_seed);
        t1.stage_write(BlockNumber(1), vec![1; 64]);

        // SSI log entry from seed has commit_seq == seq_seed == t1.snapshot.high.
        // Scan breaks at `record.commit_seq <= txn.snapshot.high`.
        assert!(store.commit_ssi(t1).is_ok());
    }

    /// Empty transaction commits without conflict under both FCW and SSI.
    #[test]
    fn empty_txn_commits_under_fcw_and_ssi() {
        let mut store = MvccStore::new();

        let mut seed = store.begin();
        seed.stage_write(BlockNumber(0), vec![1; 64]);
        store.commit(seed).expect("seed");

        let t1 = store.begin();
        assert!(store.commit(t1).is_ok());

        let t2 = store.begin();
        assert!(store.commit_ssi(t2).is_ok());
    }

    /// FCW: multi-block transaction fails on first conflicting block.
    #[test]
    fn fcw_multi_block_fails_on_conflicting_block() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(5), vec![1; 16]);

        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(3), vec![2; 16]);
        t2.stage_write(BlockNumber(5), vec![2; 16]);
        t2.stage_write(BlockNumber(7), vec![2; 16]);

        store.commit(t1).expect("t1");

        let err = store.commit(t2).unwrap_err();
        assert!(
            matches!(err, CommitError::Conflict { block, .. } if block == BlockNumber(5)),
            "expected Conflict on block 5, got {err:?}"
        );
    }

    /// SSI: prune_ssi_log with exact boundary — records at prune_seq removed.
    #[test]
    fn ssi_prune_log_exact_boundary() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(0), vec![1; 32]);
        store.commit_ssi(t1).expect("t1");

        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(1), vec![2; 32]);
        let seq2 = store.commit_ssi(t2).expect("t2");

        let mut t3 = store.begin();
        t3.stage_write(BlockNumber(2), vec![3; 32]);
        let seq3 = store.commit_ssi(t3).expect("t3");

        store.prune_ssi_log(seq2);

        assert_eq!(store.ssi_log.len(), 1);
        assert_eq!(store.ssi_log[0].commit_seq, seq3);
    }

    /// Versions eligible at watermark: empty store → 0 eligible.
    #[test]
    fn versions_eligible_empty_store() {
        let store = MvccStore::new();
        assert_eq!(store.versions_eligible_at_watermark(CommitSeq(100)), 0);
    }

    /// Versions eligible: single version per block → 0 (never trim last).
    #[test]
    fn versions_eligible_single_version_is_zero() {
        let mut store = MvccStore::new();
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(0), vec![1; 64]);
        store.commit(txn).expect("commit");

        assert_eq!(store.versions_eligible_at_watermark(CommitSeq(100)), 0);
    }

    /// Versions eligible: multi-version chain — all but latest below watermark.
    #[test]
    fn versions_eligible_multi_version_chain() {
        let mut store = MvccStore::new();

        for i in 0..5_u8 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![i; 64]);
            store.commit(txn).expect("commit");
        }

        // 5 versions at seqs 1..=5. Watermark 100 → 4 eligible.
        assert_eq!(store.versions_eligible_at_watermark(CommitSeq(100)), 4);
        // Watermark 0 → 0 eligible.
        assert_eq!(store.versions_eligible_at_watermark(CommitSeq(0)), 0);
    }

    /// latest_commit_seq returns CommitSeq(0) for an unwritten block.
    #[test]
    fn latest_commit_seq_unwritten_returns_zero() {
        let store = MvccStore::new();
        assert_eq!(store.latest_commit_seq(BlockNumber(999)), CommitSeq(0));
    }

    /// latest_commit_seq tracks the most recent commit.
    #[test]
    fn latest_commit_seq_tracks_most_recent_write() {
        let mut store = MvccStore::new();

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(0), vec![1; 64]);
        let seq1 = store.commit(t1).expect("t1");
        assert_eq!(store.latest_commit_seq(BlockNumber(0)), seq1);

        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(0), vec![2; 64]);
        let seq2 = store.commit(t2).expect("t2");
        assert_eq!(store.latest_commit_seq(BlockNumber(0)), seq2);
        assert!(seq2 > seq1);
    }

    /// critical_chain_len is always strictly greater than max_len.
    #[test]
    fn critical_chain_len_exceeds_cap_values() {
        assert_eq!(MvccStore::critical_chain_len(1), 4);
        assert_eq!(MvccStore::critical_chain_len(2), 8);
        assert_eq!(MvccStore::critical_chain_len(0), 4);
        assert_eq!(MvccStore::critical_chain_len(64), 256);
    }

    /// SSI: concurrent read-only transactions never conflict.
    #[test]
    fn ssi_concurrent_read_only_no_conflict() {
        let mut store = MvccStore::new();

        let mut seed = store.begin();
        seed.stage_write(BlockNumber(0), vec![1; 64]);
        seed.stage_write(BlockNumber(1), vec![2; 64]);
        store.commit_ssi(seed).expect("seed");

        let mut readers = Vec::new();
        for _ in 0..5 {
            let mut t = store.begin();
            t.record_read(BlockNumber(0), store.latest_commit_seq(BlockNumber(0)));
            t.record_read(BlockNumber(1), store.latest_commit_seq(BlockNumber(1)));
            readers.push(t);
        }

        for t in readers {
            assert!(store.commit_ssi(t).is_ok());
        }
    }

    // ── Adaptive conflict policy tests ─────────────────────────────────

    #[test]
    fn contention_metrics_ema_tracks_conflicts() {
        let mut m = ContentionMetrics::default();
        let alpha = 0.5;

        // No conflicts initially.
        assert!((m.conflict_rate - 0.0).abs() < f64::EPSILON);

        // Record a commit with a conflict that was merged.
        m.record_commit(alpha, true, true, false);
        assert!((m.conflict_rate - 0.5).abs() < f64::EPSILON);
        assert!((m.merge_success_rate - 1.0).abs() < f64::EPSILON);
        assert!((m.abort_rate - 0.0).abs() < f64::EPSILON);
        assert_eq!(m.total_commits, 1);
        assert_eq!(m.total_conflicts, 1);
        assert_eq!(m.total_merges, 1);

        // Record a commit with no conflict.
        m.record_commit(alpha, false, false, false);
        assert!((m.conflict_rate - 0.25).abs() < f64::EPSILON);
        assert_eq!(m.total_commits, 2);

        // Record an abort.
        m.record_commit(alpha, true, false, true);
        assert_eq!(m.total_aborts, 1);
        assert!(m.abort_rate > 0.0);
    }

    #[test]
    fn contention_metrics_totals_saturate_at_numeric_limits() {
        let mut m = ContentionMetrics {
            total_commits: u64::MAX,
            total_conflicts: u64::MAX,
            total_merges: u64::MAX,
            total_aborts: u64::MAX,
            ..ContentionMetrics::default()
        };

        m.record_commit(0.5, true, true, true);

        assert_eq!(m.total_commits, u64::MAX);
        assert_eq!(m.total_conflicts, u64::MAX);
        assert_eq!(m.total_merges, u64::MAX);
        assert_eq!(m.total_aborts, u64::MAX);
        assert!((m.conflict_rate - 0.5).abs() < f64::EPSILON);
        assert!((m.merge_success_rate - 1.0).abs() < f64::EPSILON);
        assert!((m.abort_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn expected_loss_strict_scales_with_conflict_rate() {
        let config = AdaptivePolicyConfig::default();
        let mut m = ContentionMetrics::default();

        // Zero conflicts => zero loss for strict.
        assert!((m.expected_loss_strict(&config) - 0.0).abs() < f64::EPSILON);

        // High conflict rate => proportional loss.
        // expected = 0.5 * 1.0 = 0.5
        m.conflict_rate = 0.5;
        let loss = m.expected_loss_strict(&config);
        assert!((loss - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn expected_loss_safe_merge_accounts_for_corruption_risk() {
        let config = AdaptivePolicyConfig::default();
        // Default ContentionMetrics has conflict_rate=0.0 and merge_success_rate=1.0.
        let m = ContentionMetrics::default();

        // Even with zero conflicts, safe-merge has a small baseline corruption cost.
        let loss = m.expected_loss_safe_merge(&config);
        let expected = config.base_corruption_probability * config.corruption_severity;
        assert!((loss - expected).abs() < 1e-12);
    }

    #[test]
    fn adaptive_selects_safe_merge_under_high_contention() {
        let config = AdaptivePolicyConfig {
            warmup_commits: 0,
            ..AdaptivePolicyConfig::default()
        };
        let m = ContentionMetrics {
            conflict_rate: 0.8,
            merge_success_rate: 0.95,
            abort_rate: 0.04,
            total_commits: 100,
            total_conflicts: 80,
            total_merges: 76,
            total_aborts: 4,
            last_selected: None,
        };

        // Under high contention with good merge success, SafeMerge should win
        // because strict would abort 80% of commits.
        assert_eq!(m.select_policy(&config), ConflictPolicy::SafeMerge);
    }

    #[test]
    fn adaptive_selects_strict_when_merges_fail() {
        let config = AdaptivePolicyConfig {
            warmup_commits: 0,
            corruption_severity: 1000.0,
            abort_cost: 1.0,
            base_corruption_probability: 0.01, // Elevated corruption risk.
            ..AdaptivePolicyConfig::default()
        };
        let m = ContentionMetrics {
            conflict_rate: 0.1,
            merge_success_rate: 0.0, // Merges never succeed.
            abort_rate: 0.1,
            total_commits: 100,
            total_conflicts: 10,
            total_merges: 0,
            total_aborts: 10,
            last_selected: None,
        };

        // When corruption risk is high and merges don't help, strict is safer.
        // Strict loss = 0.1 * 1.0 = 0.1
        // SafeMerge loss = 0.01 * 1000 + 0.1 * 1.0 = 10.1
        assert_eq!(m.select_policy(&config), ConflictPolicy::Strict);
    }

    #[test]
    fn adaptive_defaults_to_safe_merge_during_warmup() {
        let config = AdaptivePolicyConfig {
            warmup_commits: 20,
            ..AdaptivePolicyConfig::default()
        };
        let m = ContentionMetrics {
            total_commits: 5, // Below warmup threshold.
            ..ContentionMetrics::default()
        };
        assert_eq!(m.select_policy(&config), ConflictPolicy::SafeMerge);
    }

    #[test]
    fn adaptive_hysteresis_prevents_oscillation() {
        let config = AdaptivePolicyConfig {
            warmup_commits: 0,
            hysteresis_ratio: 1.5,
            ..AdaptivePolicyConfig::default()
        };

        // Step 1: First selection (no incumbent) — SafeMerge clearly wins.
        let mut m = ContentionMetrics {
            conflict_rate: 0.8,
            merge_success_rate: 0.95,
            abort_rate: 0.04,
            total_commits: 100,
            total_conflicts: 80,
            total_merges: 76,
            total_aborts: 4,
            last_selected: None,
        };
        assert_eq!(m.select_policy(&config), ConflictPolicy::SafeMerge);
        m.last_selected = Some(ConflictPolicy::SafeMerge);

        // Step 2: Strict is convincingly better (2x) — hysteresis allows switch.
        // Strict loss  = 0.001 * 1.0 = 0.001
        // SafeMerge loss = 1e-6 * 1000 + 0.001 * 1.0 = 0.002
        // challenger(Strict=0.001) * 1.5 = 0.0015 < incumbent(SafeMerge=0.002) ✓
        m.conflict_rate = 0.001;
        m.merge_success_rate = 0.0;
        assert_eq!(m.select_policy(&config), ConflictPolicy::Strict);
        m.last_selected = Some(ConflictPolicy::Strict);

        // Step 3: SafeMerge is raw winner but NOT convincingly better — hysteresis blocks.
        // Strict loss  = 0.0012
        // SafeMerge loss = 0.001 + 0.0012 * 0.05 = 0.00106
        // SafeMerge wins raw (0.00106 < 0.0012).
        // But: challenger(0.00106) * 1.5 = 0.00159 > incumbent(0.0012) — not convincing.
        m.conflict_rate = 0.0012;
        m.merge_success_rate = 0.95;
        assert_eq!(m.select_policy(&config), ConflictPolicy::Strict);
    }

    #[test]
    fn adaptive_hysteresis_disabled_at_ratio_one() {
        let config = AdaptivePolicyConfig {
            warmup_commits: 0,
            hysteresis_ratio: 1.0, // Disabled.
            ..AdaptivePolicyConfig::default()
        };
        let m = ContentionMetrics {
            conflict_rate: 0.0012,
            merge_success_rate: 0.95,
            abort_rate: 0.001,
            total_commits: 100,
            total_conflicts: 1,
            total_merges: 1,
            total_aborts: 0,
            // Incumbent is Strict; SafeMerge is raw winner by a tiny margin.
            last_selected: Some(ConflictPolicy::Strict),
        };
        // With ratio=1.0 (no hysteresis), any improvement triggers switch.
        // Strict loss = 0.0012, SafeMerge loss = 0.001 + tiny = 0.00106
        assert_eq!(m.select_policy(&config), ConflictPolicy::SafeMerge);
    }

    const REPRESENTATIVE_MVCC_RUNTIME_METRICS_JSON_GOLDEN: &str = r#"{
  "active_snapshots": 2,
  "commit_rate": 12.5,
  "conflict_rate": 0.125,
  "abort_rate": 0.25,
  "version_chain_max_length": 7,
  "prune_throughput": 3.5,
  "commit_attempts_total": 16,
  "commit_successes_total": 14,
  "conflicts_total": 2,
  "aborts_total": 4,
  "pruned_versions_total": 28,
  "commit_latency_us": {
    "buckets": [
      {
        "le": 5,
        "count": 1
      },
      {
        "le": 50,
        "count": 3
      },
      {
        "le": 500,
        "count": 10
      }
    ],
    "inf_count": 2,
    "sum": 912,
    "count": 14
  },
  "conflict_resolution_latency_us": {
    "buckets": [
      {
        "le": 10,
        "count": 1
      },
      {
        "le": 100,
        "count": 1
      }
    ],
    "inf_count": 0,
    "sum": 67,
    "count": 2
  }
}"#;

    fn representative_mvcc_runtime_metrics_snapshot() -> MvccRuntimeMetricsSnapshot {
        MvccRuntimeMetricsSnapshot {
            active_snapshots: 2,
            commit_rate: 12.5,
            conflict_rate: 0.125,
            abort_rate: 0.25,
            version_chain_max_length: 7,
            prune_throughput: 3.5,
            commit_attempts_total: 16,
            commit_successes_total: 14,
            conflicts_total: 2,
            aborts_total: 4,
            pruned_versions_total: 28,
            commit_latency_us: RuntimeHistogramSnapshot {
                buckets: vec![
                    RuntimeHistogramBucket { le: 5, count: 1 },
                    RuntimeHistogramBucket { le: 50, count: 3 },
                    RuntimeHistogramBucket { le: 500, count: 10 },
                ],
                inf_count: 2,
                sum: 912,
                count: 14,
            },
            conflict_resolution_latency_us: RuntimeHistogramSnapshot {
                buckets: vec![
                    RuntimeHistogramBucket { le: 10, count: 1 },
                    RuntimeHistogramBucket { le: 100, count: 1 },
                ],
                inf_count: 0,
                sum: 67,
                count: 2,
            },
        }
    }

    #[test]
    fn representative_mvcc_runtime_metrics_json_exact_golden_contract() {
        let metrics = representative_mvcc_runtime_metrics_snapshot();
        let json = serde_json::to_string_pretty(&metrics).expect("serialize representative JSON");

        assert_eq!(json, REPRESENTATIVE_MVCC_RUNTIME_METRICS_JSON_GOLDEN);

        let parsed: MvccRuntimeMetricsSnapshot =
            serde_json::from_str(&json).expect("deserialize representative JSON");
        assert_eq!(parsed, metrics);
    }

    #[test]
    fn mvcc_runtime_metrics_export_serializes_expected_fields() {
        let mut store = MvccStore::new();

        let mut txn = store.begin();
        txn.stage_write(BlockNumber(7), vec![0xAB; 64]);
        store.commit(txn).expect("commit");

        let metrics = store.runtime_metrics();
        let json = serde_json::to_value(&metrics).expect("serialize runtime metrics");

        assert_eq!(json["active_snapshots"], 0);
        assert_eq!(json["commit_attempts_total"], 1);
        assert_eq!(json["commit_successes_total"], 1);
        assert_eq!(json["conflicts_total"], 0);
        assert_eq!(json["aborts_total"], 0);
        assert_eq!(json["pruned_versions_total"], 0);
        assert!(
            json["commit_rate"].as_f64().expect("commit_rate f64") > 0.0,
            "commit_rate should be positive after a successful commit"
        );
        assert_eq!(json["commit_latency_us"]["count"], 1);
        assert_eq!(json["conflict_resolution_latency_us"]["count"], 0);
    }

    #[test]
    fn mvcc_runtime_metrics_track_conflicts_and_aborts() {
        let mut store = MvccStore::new();
        store.set_conflict_policy(ConflictPolicy::Strict);

        let mut first = store.begin();
        let mut second = store.begin();
        first.stage_write(BlockNumber(3), vec![1; 32]);
        second.stage_write(BlockNumber(3), vec![2; 32]);

        store.commit(first).expect("first commit");
        let err = store.commit(second).expect_err("second should conflict");
        assert!(matches!(err, CommitError::Conflict { .. }));

        let metrics = store.runtime_metrics();
        assert_eq!(metrics.commit_attempts_total, 2);
        assert_eq!(metrics.commit_successes_total, 1);
        assert_eq!(metrics.conflicts_total, 1);
        assert_eq!(metrics.aborts_total, 1);
        assert!(metrics.conflict_rate > 0.0);
        assert!(metrics.abort_rate > 0.0);
        assert_eq!(metrics.conflict_resolution_latency_us.count, 1);
    }

    #[test]
    fn mvcc_runtime_metrics_track_active_snapshots_and_pruning() {
        let mut store = MvccStore::new();

        let mut txn1 = store.begin();
        txn1.stage_write(BlockNumber(11), vec![1; 32]);
        let snap = store.current_snapshot();
        store.commit(txn1).expect("commit 1");

        let mut txn2 = store.begin();
        txn2.stage_write(BlockNumber(11), vec![2; 32]);
        store.commit(txn2).expect("commit 2");

        store.register_snapshot(snap);
        assert_eq!(store.runtime_metrics().active_snapshots, 1);

        assert!(store.release_snapshot(snap));
        store.prune_safe();

        let metrics = store.runtime_metrics();
        assert_eq!(metrics.active_snapshots, 0);
        assert!(
            metrics.pruned_versions_total >= 1,
            "pruning should retire at least one older version"
        );
        assert!(
            metrics.prune_throughput > 0.0,
            "prune throughput should be positive once versions are pruned"
        );
    }

    #[test]
    fn mvcc_store_strict_policy_aborts_on_conflict() {
        let mut store = MvccStore::new();
        store.set_conflict_policy(ConflictPolicy::Strict);

        // Writer A writes block 0.
        let mut txn_a = store.begin();
        txn_a.stage_write(BlockNumber(0), vec![1, 2, 3]);
        store.commit(txn_a).unwrap();

        // Writer B starts before A committed, then tries to write block 0
        // with an AppendOnly merge proof — should still abort under Strict.
        let snapshot = store.current_snapshot();
        let mut txn_b = Transaction::new(TxnId(store.next_txn), snapshot);
        store.next_txn += 1;
        txn_b.stage_write_with_proof(
            BlockNumber(0),
            vec![1, 2, 3, 4],
            MergeProof::AppendOnly { base_len: 0 },
        );

        // But first, let another writer commit to block 0.
        let mut txn_c = store.begin();
        txn_c.stage_write(BlockNumber(0), vec![10, 20, 30]);
        store.commit(txn_c).unwrap();

        // Now B tries to commit — should fail because Strict ignores merge proofs.
        let result = store.commit(txn_b);
        assert!(result.is_err());
        match result.unwrap_err() {
            CommitError::Conflict { block, .. } => assert_eq!(block, BlockNumber(0)),
            other => assert!(
                matches!(other, CommitError::Conflict { .. }),
                "expected Conflict, got {other:?}"
            ),
        }
    }

    #[test]
    fn mvcc_store_safe_merge_policy_allows_mergeable_conflicts() {
        let mut store = MvccStore::new();
        store.set_conflict_policy(ConflictPolicy::SafeMerge);

        let mut txn_a = store.begin();
        txn_a.stage_write(BlockNumber(0), vec![0; 64]);
        store.commit(txn_a).unwrap();

        // B reads at snapshot before C writes.
        let snap = store.current_snapshot();
        let base_len = 64;

        // C appends to block 0.
        let mut txn_c = store.begin();
        let mut c_data = vec![0; 64];
        c_data.extend_from_slice(&[0xCC; 16]);
        txn_c.stage_write_with_proof(BlockNumber(0), c_data, MergeProof::AppendOnly { base_len });
        store.commit(txn_c).unwrap();

        // B appends to block 0 with AppendOnly proof.
        let mut txn_b = Transaction::new(TxnId(store.next_txn), snap);
        store.next_txn += 1;
        let mut b_data = vec![0; 64];
        b_data.extend_from_slice(&[0xBB; 8]);
        txn_b.stage_write_with_proof(BlockNumber(0), b_data, MergeProof::AppendOnly { base_len });

        // Should succeed via merge proof.
        let result = store.commit(txn_b);
        assert!(result.is_ok());
    }

    #[test]
    fn mvcc_store_adaptive_policy_tracks_contention() {
        let mut store = MvccStore::new();
        store.set_conflict_policy(ConflictPolicy::Adaptive);
        store.set_adaptive_config(AdaptivePolicyConfig {
            warmup_commits: 0,
            ..AdaptivePolicyConfig::default()
        });

        // Warm up with non-conflicting commits.
        for i in 0..10_u8 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(u64::from(i)), vec![i]);
            store.commit(txn).unwrap();
        }

        let metrics = store.contention_metrics();
        assert_eq!(metrics.total_commits, 10);
        assert_eq!(metrics.total_conflicts, 0);
        assert!((metrics.conflict_rate - 0.0).abs() < 0.01);
    }

    #[test]
    fn effective_policy_resolves_adaptive() {
        let mut store = MvccStore::new();

        // SafeMerge by default.
        assert_eq!(store.effective_policy(), ConflictPolicy::SafeMerge);

        store.set_conflict_policy(ConflictPolicy::Strict);
        assert_eq!(store.effective_policy(), ConflictPolicy::Strict);

        store.set_conflict_policy(ConflictPolicy::Adaptive);
        // During warmup, adaptive defaults to SafeMerge.
        assert_eq!(store.effective_policy(), ConflictPolicy::SafeMerge);
    }

    /// bd-7esyh — concurrent regression test for the SnapshotRegistry
    /// lock-ordering invariant (active → oldest_registered_at). If a
    /// future regression nested either lock under the other in the
    /// inverse order, this test would deadlock against register()
    /// running concurrently and trip the watchdog.
    #[test]
    fn snapshot_registry_concurrent_register_release_check_stalls_no_hang() {
        const ITERATIONS: usize = 256;
        const REGISTERERS: usize = 4;
        const RELEASERS: usize = 2;
        const CHECKERS: usize = 2;
        const WATCHDOG_SECS: u64 = 5;

        let registry = Arc::new(SnapshotRegistry::new());

        let stop = Arc::new(AtomicBool::new(false));
        let workers_complete = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        for tid in 0..REGISTERERS {
            let registry = Arc::clone(&registry);
            let stop = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                for i in 0..ITERATIONS {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    // Use distinct CommitSeq per thread interleaved with
                    // shared values so register/release contend on both
                    // the BTreeMap insert path and the same-key
                    // refcount-bump path.
                    let seq = CommitSeq(((tid * 11 + i) % 17) as u64);
                    let snap = Snapshot { high: seq };
                    registry.register(snap);
                }
            }));
        }

        for tid in 0..RELEASERS {
            let registry = Arc::clone(&registry);
            let stop = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                for i in 0..ITERATIONS {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let seq = CommitSeq(((tid * 13 + i) % 17) as u64);
                    let snap = Snapshot { high: seq };
                    let _ = registry.release(snap);
                }
            }));
        }

        for _ in 0..CHECKERS {
            let registry = Arc::clone(&registry);
            let stop = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                for _ in 0..ITERATIONS {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let _ = registry.check_stalls();
                    let _ = registry.watermark();
                    let _ = registry.distinct_count();
                }
            }));
        }

        let watchdog_handle = spawn_snapshot_registry_watchdog(
            Arc::clone(&stop),
            Arc::clone(&workers_complete),
            Duration::from_secs(WATCHDOG_SECS),
        );

        let start = Instant::now();
        for handle in handles {
            handle.join().expect("worker thread joins cleanly");
        }
        let elapsed = start.elapsed();
        workers_complete.store(true, Ordering::Release);
        let watchdog_join_started_at = Instant::now();
        let watchdog_timed_out = watchdog_handle
            .join()
            .expect("watchdog thread joins cleanly");
        let watchdog_join_elapsed = watchdog_join_started_at.elapsed();
        let watchdog_join_limit = SNAPSHOT_REGISTRY_WATCHDOG_POLL_INTERVAL.saturating_mul(25);

        assert!(
            elapsed < Duration::from_secs(WATCHDOG_SECS),
            "concurrent register + release + check_stalls must not deadlock; elapsed={elapsed:?}"
        );
        assert!(
            !watchdog_timed_out,
            "watchdog timed out even though all workers joined; elapsed={elapsed:?}"
        );
        assert!(
            watchdog_join_elapsed < watchdog_join_limit,
            "watchdog should return within {watchdog_join_limit:?} after worker completion; join elapsed={watchdog_join_elapsed:?}"
        );
    }
}
