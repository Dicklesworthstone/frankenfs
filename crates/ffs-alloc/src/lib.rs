#![forbid(unsafe_code)]
//! Block and inode allocation.
//!
//! See [`succinct::SuccinctBitmap`] for O(1) rank / O(log n) select over bitmaps.
//!
//! mballoc-style multi-block allocator (buddy system, best-fit,
//! per-inode and per-locality-group preallocation) and Orlov
//! inode allocator for directory spreading.
//!
//! ## Design
//!
//! The allocator is layered:
//!
//! 1. **Bitmap** — raw bit manipulation on block/inode bitmaps.
//! 2. **GroupStats** — cached per-group free counts.
//! 3. **BlockAllocator** — goal-directed block allocation across groups.
//! 4. **InodeAllocator** — Orlov-style inode placement.

pub mod succinct;

use asupersync::Cx;
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::{Ext4GroupDesc, Ext4Superblock};
use ffs_types::{BlockNumber, GroupNumber, InodeNumber};

// ── Bitmap operations ───────────────────────────────────────────────────────

/// Group flags from `bg_flags` field.
const GD_FLAG_INODE_UNINIT: u16 = 0x0001;
const GD_FLAG_BLOCK_UNINIT: u16 = 0x0002;

#[derive(Clone, Copy)]
struct ByteZeroRun {
    prefix: u8,
    suffix: u8,
    best: u8,
}

const BYTE_ZERO_RUNS: [ByteZeroRun; 256] = build_byte_zero_runs();

const fn build_byte_zero_runs() -> [ByteZeroRun; 256] {
    let mut runs = [ByteZeroRun {
        prefix: 0,
        suffix: 0,
        best: 0,
    }; 256];
    let mut byte = 0_u8;
    loop {
        runs[byte as usize] = byte_zero_run(byte);
        if byte == u8::MAX {
            break;
        }
        byte += 1;
    }
    runs
}

const fn byte_zero_run(byte: u8) -> ByteZeroRun {
    let mut prefix = 0;
    while prefix < 8 && ((byte >> prefix) & 1) == 0 {
        prefix += 1;
    }

    let mut suffix = 0;
    while suffix < 8 && ((byte >> (7 - suffix)) & 1) == 0 {
        suffix += 1;
    }

    let mut best = 0;
    let mut run = 0;
    let mut bit = 0;
    while bit < 8 {
        if ((byte >> bit) & 1) == 0 {
            run += 1;
            if run > best {
                best = run;
            }
        } else {
            run = 0;
        }
        bit += 1;
    }

    ByteZeroRun {
        prefix,
        suffix,
        best,
    }
}

/// Get bit `idx` from a bitmap byte slice.
#[must_use]
pub fn bitmap_get(bitmap: &[u8], idx: u32) -> bool {
    let byte_idx = (idx / 8) as usize;
    let bit_idx = idx % 8;
    if byte_idx >= bitmap.len() {
        return true;
    }
    (bitmap[byte_idx] >> bit_idx) & 1 == 1
}

/// Set bit `idx` in a bitmap byte slice.
pub fn bitmap_set(bitmap: &mut [u8], idx: u32) {
    let byte_idx = (idx / 8) as usize;
    let bit_idx = idx % 8;
    if byte_idx < bitmap.len() {
        bitmap[byte_idx] |= 1 << bit_idx;
    }
}

/// Highest set bit index strictly below `count`, or `None` if no bit is set.
/// Matches [`bitmap_set`]'s LSB-first-within-byte convention.
fn highest_set_bit_index(bitmap: &[u8], count: u32) -> Option<u32> {
    let count = count as usize;
    let nbytes = count.div_ceil(8).min(bitmap.len());
    for byte_idx in (0..nbytes).rev() {
        let byte = bitmap[byte_idx];
        if byte == 0 {
            continue;
        }
        for bit in (0..8u32).rev() {
            if byte & (1 << bit) != 0 {
                let idx = byte_idx * 8 + bit as usize;
                if idx < count {
                    #[expect(clippy::cast_possible_truncation)]
                    return Some(idx as u32);
                }
            }
        }
    }
    None
}

/// Clear bit `idx` in a bitmap byte slice.
pub fn bitmap_clear(bitmap: &mut [u8], idx: u32) {
    let byte_idx = (idx / 8) as usize;
    let bit_idx = idx % 8;
    if byte_idx < bitmap.len() {
        bitmap[byte_idx] &= !(1 << bit_idx);
    }
}

/// Count free (zero) bits in the first `count` bits of `bitmap`.
#[must_use]
pub fn bitmap_count_free(bitmap: &[u8], count: u32) -> u32 {
    let requested_full_bytes = (count / 8) as usize;
    let full_bytes = requested_full_bytes.min(bitmap.len());
    let remainder = count % 8;
    let mut free = 0u32;

    let mut chunks = bitmap[..full_bytes].chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        free += (!word).count_ones();
    }
    for &byte in chunks.remainder() {
        free += byte.count_zeros();
    }

    if remainder > 0 && requested_full_bytes < bitmap.len() {
        let byte = bitmap[requested_full_bytes];
        let mask = u8::MAX >> (8 - remainder);
        free += ((!byte) & mask).count_ones();
    }

    free
}

/// Find the first free (zero) bit in the first `count` bits of `bitmap`,
/// starting from `start`.
#[must_use]
pub fn bitmap_find_free(bitmap: &[u8], count: u32, start: u32) -> Option<u32> {
    let start = start.min(count);
    if let Some(idx) = bitmap_find_free_range(bitmap, start, count) {
        return Some(idx);
    }
    // Wrap around: search from 0 to start.
    bitmap_find_free_range(bitmap, 0, start)
}

fn bitmap_find_free_range(bitmap: &[u8], mut idx: u32, end: u32) -> Option<u32> {
    while idx < end && idx % 8 != 0 {
        let byte_idx = (idx / 8) as usize;
        let &byte = bitmap.get(byte_idx)?;
        if (byte >> (idx % 8)) & 1 == 0 {
            return Some(idx);
        }
        idx += 1;
    }

    // Word-at-a-time fast path: scan 64 bits per iteration. `idx` is byte-
    // aligned here (the leading loop advanced to a byte boundary), so the 8
    // bytes at `idx / 8` cover bits [idx, idx + 64). `(!word).trailing_zeros()`
    // is the first free (zero) bit relative to `idx` — bit-identical to the
    // byte loop below, just 8× fewer iterations on a full bitmap scan.
    while end.saturating_sub(idx) >= 64 {
        let byte_idx = (idx / 8) as usize;
        let chunk = bitmap.get(byte_idx..byte_idx + 8)?;
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        if word != u64::MAX {
            return Some(idx + (!word).trailing_zeros());
        }
        idx += 64;
    }

    while end.saturating_sub(idx) >= 8 {
        let byte_idx = (idx / 8) as usize;
        let &byte = bitmap.get(byte_idx)?;
        if byte != 0xFF {
            return Some(idx + (!byte).trailing_zeros());
        }
        idx += 8;
    }

    while idx < end {
        let byte_idx = (idx / 8) as usize;
        let &byte = bitmap.get(byte_idx)?;
        if (byte >> (idx % 8)) & 1 == 0 {
            return Some(idx);
        }
        idx += 1;
    }

    None
}

fn bitmap_take_free_bits_cyclic<F>(
    bitmap: &mut [u8],
    count: u32,
    max_count: u32,
    start: u32,
    mut record: F,
) -> u32
where
    F: FnMut(u32),
{
    if count == 0 || max_count == 0 {
        return 0;
    }

    let start = start.min(count);
    let mut taken = bitmap_take_free_bits_range(bitmap, start, count, max_count, &mut record);
    if taken < max_count && start > 0 {
        taken += bitmap_take_free_bits_range(bitmap, 0, start, max_count - taken, &mut record);
    }
    taken
}

fn bitmap_take_free_bits_range<F>(
    bitmap: &mut [u8],
    mut idx: u32,
    end: u32,
    max_count: u32,
    record: &mut F,
) -> u32
where
    F: FnMut(u32),
{
    let mut taken = 0;

    while idx < end && idx % 8 != 0 {
        let byte_idx = (idx / 8) as usize;
        let Some(byte) = bitmap.get_mut(byte_idx) else {
            return taken;
        };
        let bit = idx % 8;
        if (*byte >> bit) & 1 == 0 {
            *byte |= 1 << bit;
            record(idx);
            taken += 1;
            if taken == max_count {
                return taken;
            }
        }
        idx += 1;
    }

    while end.saturating_sub(idx) >= 64 {
        let byte_idx = (idx / 8) as usize;
        let Some(chunk) = bitmap.get_mut(byte_idx..byte_idx + 8) else {
            return taken;
        };
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        let mut free = !word;
        while free != 0 {
            let bit = free.trailing_zeros();
            let byte_offset = (bit / 8) as usize;
            let bit_offset = bit % 8;
            chunk[byte_offset] |= 1 << bit_offset;
            record(idx + bit);
            taken += 1;
            if taken == max_count {
                return taken;
            }
            free &= free - 1;
        }
        idx += 64;
    }

    while end.saturating_sub(idx) >= 8 {
        let byte_idx = (idx / 8) as usize;
        let Some(byte) = bitmap.get_mut(byte_idx) else {
            return taken;
        };
        let mut free = !*byte;
        while free != 0 {
            let bit = free.trailing_zeros();
            *byte |= 1 << bit;
            record(idx + bit);
            taken += 1;
            if taken == max_count {
                return taken;
            }
            free &= free - 1;
        }
        idx += 8;
    }

    while idx < end {
        let byte_idx = (idx / 8) as usize;
        let Some(byte) = bitmap.get_mut(byte_idx) else {
            return taken;
        };
        let bit = idx % 8;
        if (*byte >> bit) & 1 == 0 {
            *byte |= 1 << bit;
            record(idx);
            taken += 1;
            if taken == max_count {
                return taken;
            }
        }
        idx += 1;
    }

    taken
}

/// Find `n` contiguous free bits in the first `count` bits of `bitmap`,
/// starting from `start`.
#[must_use]
pub fn bitmap_find_contiguous(bitmap: &[u8], count: u32, n: u32, start: u32) -> Option<u32> {
    if n == 0 {
        return Some(0);
    }
    if n > count {
        return None;
    }

    // Pass 1: from `start` to `count`
    if let Some(pos) = bitmap_find_contiguous_linear(bitmap, count, n, start) {
        return Some(pos);
    }

    // Pass 2: wrap around from 0 to `start + n - 1`
    let pass2_end = start.saturating_add(n).saturating_sub(1).min(count);
    bitmap_find_contiguous_linear(bitmap, pass2_end, n, 0)
}

/// Return the length of the longest run of consecutive free (zero) bits in
/// the first `count` bits of `bitmap`.
///
/// Used by `OpenFs::largest_contiguous_free_run` to surface fragmentation-
/// aware available-space numbers for `statvfs(3)` callers and the
/// fallocate/free-space-FIEMAP fast paths.
///
/// Full 64-bit words are summarized with bit-parallel zero-run operations;
/// remaining bytes use the byte summary table. Partial-byte boundaries (the
/// trailing remainder when `count % 8 != 0`) are masked to preserve the exact
/// LSB-first bitmap semantics.
#[must_use]
pub fn bitmap_largest_free_run(bitmap: &[u8], count: u32) -> u32 {
    if count == 0 {
        return 0;
    }
    let full_bytes = (count / 8) as usize;
    let remainder = count % 8;

    let mut best = 0_u32;
    let mut run = 0_u32;

    let available_full_bytes = full_bytes.min(bitmap.len());
    let word_bytes = available_full_bytes - (available_full_bytes % 8);

    for chunk in bitmap[..word_bytes].chunks_exact(8) {
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        apply_word_zero_run(word, &mut run, &mut best);
    }

    for &byte in &bitmap[word_bytes..available_full_bytes] {
        apply_byte_zero_run(BYTE_ZERO_RUNS[byte as usize], &mut run, &mut best);
    }

    // Mirror `bitmap_count_free`: bytes past the end of the slice contribute
    // zero to the free count and break any in-flight run.
    if full_bytes > available_full_bytes {
        run = 0;
    }

    if remainder > 0 {
        if let Some(&byte) = bitmap.get(full_bytes) {
            let mask = u8::MAX >> (8 - remainder);
            let bounded_byte = byte | !mask;
            apply_byte_zero_run(BYTE_ZERO_RUNS[bounded_byte as usize], &mut run, &mut best);
        }
        // No bitmap byte for the remainder → cannot extend; leave `best` unchanged.
    }

    best
}

fn apply_word_zero_run(word: u64, run: &mut u32, best: &mut u32) {
    if word == 0 {
        *run = run.saturating_add(64);
        *best = (*best).max(*run);
        return;
    }
    if word == u64::MAX {
        *run = 0;
        return;
    }

    let prefix = word.trailing_zeros();
    if prefix > 0 {
        *best = (*best).max(run.saturating_add(prefix));
    }
    *best = (*best).max(longest_zero_run_in_mixed_word(word));
    *run = word.leading_zeros();
}

fn longest_zero_run_in_mixed_word(word: u64) -> u32 {
    let mut free = !word;
    let mut len = 0;
    while free != 0 {
        len += 1;
        free &= free << 1;
    }
    len
}

fn apply_byte_zero_run(stats: ByteZeroRun, run: &mut u32, best: &mut u32) {
    if stats.prefix == 8 {
        *run = run.saturating_add(8);
        *best = (*best).max(*run);
        return;
    }

    if stats.prefix > 0 {
        *best = (*best).max(run.saturating_add(u32::from(stats.prefix)));
    }
    *best = (*best).max(u32::from(stats.best));
    *run = u32::from(stats.suffix);
}

/// Linear scan for `n` contiguous free bits in `[start, count)`.
fn bitmap_find_contiguous_linear(bitmap: &[u8], count: u32, n: u32, start: u32) -> Option<u32> {
    let mut run_start = start;
    let mut run_len = 0u32;
    let mut idx = start;

    while idx < count && idx % 8 != 0 {
        if bitmap_get(bitmap, idx) {
            idx += 1;
            run_start = idx;
            run_len = 0;
        } else {
            run_len += 1;
            if run_len >= n {
                return Some(run_start);
            }
            idx += 1;
        }
    }

    while count.saturating_sub(idx) >= 64 {
        let byte_idx = (idx / 8) as usize;
        let Some(chunk) = bitmap.get(byte_idx..byte_idx + 8) else {
            break;
        };
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);

        if word == u64::MAX {
            run_start = idx + 64;
            run_len = 0;
        } else if let Some(found) =
            apply_contiguous_word_zero_run(word, idx, n, &mut run_start, &mut run_len)
        {
            return Some(found);
        }
        idx += 64;
    }

    while idx < count {
        if idx % 8 == 0 && (idx + 8) <= count {
            let byte_idx = (idx / 8) as usize;
            match bitmap.get(byte_idx).copied() {
                None | Some(0xFF) => {
                    idx += 8;
                    run_start = idx;
                    run_len = 0;
                    continue;
                }
                Some(0x00) => {
                    if run_len == 0 {
                        run_start = idx;
                    }
                    run_len = run_len.saturating_add(8);
                    if run_len >= n {
                        return Some(run_start);
                    }
                    idx += 8;
                    continue;
                }
                Some(byte) => {
                    let base = idx;
                    for bit in 0..8 {
                        let pos = base + bit;
                        if (byte >> bit) & 1 == 1 {
                            run_start = pos + 1;
                            run_len = 0;
                        } else {
                            run_len += 1;
                            if run_len >= n {
                                return Some(run_start);
                            }
                        }
                    }
                    idx += 8;
                    continue;
                }
            }
        }

        if bitmap_get(bitmap, idx) {
            idx += 1;
            run_start = idx;
            run_len = 0;
        } else {
            run_len += 1;
            if run_len >= n {
                return Some(run_start);
            }
            idx += 1;
        }
    }
    None
}

fn apply_contiguous_word_zero_run(
    word: u64,
    base: u32,
    n: u32,
    run_start: &mut u32,
    run_len: &mut u32,
) -> Option<u32> {
    if word == 0 {
        if *run_len == 0 {
            *run_start = base;
        }
        *run_len = run_len.saturating_add(64);
        return (*run_len >= n).then_some(*run_start);
    }

    for bit in 0..64 {
        let pos = base + bit;
        if (word >> bit) & 1 == 1 {
            *run_start = pos + 1;
            *run_len = 0;
        } else {
            *run_len += 1;
            if *run_len >= n {
                return Some(*run_start);
            }
        }
    }
    None
}

// ── Group stats ─────────────────────────────────────────────────────────────

/// Cached per-group statistics loaded from group descriptors.
#[derive(Debug, Clone)]
pub struct GroupStats {
    pub group: GroupNumber,
    pub free_blocks: u32,
    pub free_inodes: u32,
    pub used_dirs: u32,
    pub block_bitmap_block: BlockNumber,
    pub inode_bitmap_block: BlockNumber,
    pub inode_table_block: BlockNumber,
    pub flags: u16,
    /// CRC32C of the block bitmap (updated on allocation/free when metadata_csum enabled).
    pub block_bitmap_csum: u32,
    /// CRC32C of the inode bitmap (updated on inode allocation/free when metadata_csum enabled).
    pub inode_bitmap_csum: u32,
}

impl GroupStats {
    /// Create from a parsed group descriptor.
    #[must_use]
    pub fn from_group_desc(group: GroupNumber, gd: &Ext4GroupDesc) -> Self {
        Self {
            group,
            free_blocks: gd.free_blocks_count,
            free_inodes: gd.free_inodes_count,
            used_dirs: gd.used_dirs_count,
            block_bitmap_csum: gd.block_bitmap_csum,
            inode_bitmap_csum: gd.inode_bitmap_csum,
            block_bitmap_block: BlockNumber(gd.block_bitmap),
            inode_bitmap_block: BlockNumber(gd.inode_bitmap),
            inode_table_block: BlockNumber(gd.inode_table),
            flags: gd.flags,
        }
    }

    /// Whether the block bitmap is uninitialized (all free).
    #[must_use]
    pub fn block_bitmap_uninit(&self) -> bool {
        self.flags & GD_FLAG_BLOCK_UNINIT != 0
    }

    /// Whether the inode bitmap is uninitialized (all free).
    #[must_use]
    pub fn inode_bitmap_uninit(&self) -> bool {
        self.flags & GD_FLAG_INODE_UNINIT != 0
    }
}

// ── Allocation hint ─────────────────────────────────────────────────────────

/// Hint for the block allocator to guide placement decisions.
#[derive(Debug, Clone, Default)]
pub struct AllocHint {
    /// Preferred block group (e.g., same as parent inode).
    pub goal_group: Option<GroupNumber>,
    /// Preferred block number (e.g., adjacent to last allocated extent).
    pub goal_block: Option<BlockNumber>,
    /// Optional NUMA placement preference prepared by higher layers.
    pub numa: Option<NumaAllocationPreference>,
}

// ── NUMA allocation topology contract ──────────────────────────────────────

/// Maximum advisory topology age accepted by the NUMA allocation contract.
pub const NUMA_TOPOLOGY_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Highest NUMA node id the allocator contract accepts from host probes.
pub const MAX_NUMA_NODE_ID: u32 = 4095;

/// Downstream consumers that must be named by any NUMA topology contract input.
pub const REQUIRED_NUMA_TOPOLOGY_CONSUMERS: [&str; 5] = [
    "ffs-alloc",
    "ffs-core",
    "topology_adaptive_runtime_reports",
    "proof_bundle_release_gate",
    "docs",
];

/// NUMA node identifier reported by host topology probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaNodeId(pub u32);

/// Contiguous block-group range owned by one NUMA node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaNodeGroupRange {
    pub node_id: NumaNodeId,
    pub first_group: GroupNumber,
    pub group_count: u32,
}

/// Host topology evidence source for NUMA-aware allocation placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumaTopologySource {
    /// No trusted node map is available; allocator placement must use legacy hints.
    Unknown { reason: String },
    /// Host is known to expose a single NUMA node.
    SingleNode,
    /// Fresh observed topology ranges, covering every block group exactly once.
    Observed {
        observed_at_unix_secs: u64,
        max_age_secs: u64,
        node_groups: Vec<NumaNodeGroupRange>,
    },
}

/// Evidence claim level attached to NUMA topology inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumaEvidenceClaim {
    /// Input may influence advisory placement only.
    AdvisoryOnly,
    /// Invalid for allocator topology input; release readiness is proven elsewhere.
    ProductReadiness,
}

/// Executable NUMA allocation topology contract input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaAllocationTopology {
    pub source: NumaTopologySource,
    pub evidence_claim: NumaEvidenceClaim,
    pub downstream_consumers: Vec<String>,
}

/// Validated NUMA allocation plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaAllocationPlan {
    pub group_nodes: Vec<Option<NumaNodeId>>,
    pub disposition: NumaTopologyDisposition,
}

/// Optional NUMA preference attached to an allocation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaAllocationPreference {
    pub plan: NumaAllocationPlan,
    pub preferred_node: NumaNodeId,
}

/// How the allocator may interpret the validated topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumaTopologyDisposition {
    /// Multi-node topology is fresh enough for advisory placement.
    AdvisoryMap,
    /// Topology is unknown; preserve legacy placement semantics.
    UnknownFallback,
    /// Single-node host; every group maps to node zero.
    SingleNodeFallback,
}

/// Contract validation failures for NUMA allocation topology input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumaTopologyError {
    ProductReadinessClaim,
    MissingConsumer {
        consumer: &'static str,
    },
    EmptyUnknownReason,
    EmptyGeometry,
    GeometryTooLarge,
    MissingNodeMap,
    InvalidNodeId {
        node_id: NumaNodeId,
    },
    EmptyGroupRange {
        node_id: NumaNodeId,
        first_group: GroupNumber,
    },
    GroupRangeOutOfBounds {
        first_group: GroupNumber,
        group_count: u32,
        total_groups: u32,
    },
    DuplicateGroup {
        group: GroupNumber,
    },
    UncoveredGroup {
        group: GroupNumber,
    },
    FutureEvidence {
        observed_at_unix_secs: u64,
        now_unix_secs: u64,
    },
    StaleEvidence {
        age_secs: u64,
        max_age_secs: u64,
    },
    ExcessiveEvidenceWindow {
        max_age_secs: u64,
    },
}

/// Validate the executable NUMA allocation topology contract.
pub fn validate_numa_allocation_topology(
    geo: &FsGeometry,
    topology: &NumaAllocationTopology,
    now_unix_secs: u64,
) -> std::result::Result<NumaAllocationPlan, NumaTopologyError> {
    validate_numa_contract_metadata(topology)?;

    let group_len = numa_group_len(geo)?;
    match &topology.source {
        NumaTopologySource::Unknown { reason } => {
            if reason.trim().is_empty() {
                return Err(NumaTopologyError::EmptyUnknownReason);
            }
            Ok(NumaAllocationPlan {
                group_nodes: vec![None; group_len],
                disposition: NumaTopologyDisposition::UnknownFallback,
            })
        }
        NumaTopologySource::SingleNode => Ok(NumaAllocationPlan {
            group_nodes: vec![Some(NumaNodeId(0)); group_len],
            disposition: NumaTopologyDisposition::SingleNodeFallback,
        }),
        NumaTopologySource::Observed {
            observed_at_unix_secs,
            max_age_secs,
            node_groups,
        } => validate_observed_numa_topology(
            geo,
            group_len,
            *observed_at_unix_secs,
            *max_age_secs,
            node_groups,
            now_unix_secs,
        ),
    }
}

/// Resolve allocation goal precedence with optional NUMA placement.
///
/// Explicit `goal_group` and `goal_block` keep their existing precedence over
/// advisory NUMA placement. The preferred NUMA node can only select a starting
/// group when no explicit allocation hint is present.
#[must_use]
pub fn resolve_numa_allocation_goal(
    geo: &FsGeometry,
    hint: &AllocHint,
    plan: &NumaAllocationPlan,
    preferred_node: Option<NumaNodeId>,
) -> GroupNumber {
    if let Some(goal_group) = hint.goal_group {
        return goal_group;
    }
    if let Some(goal_block) = hint.goal_block {
        return geo.absolute_to_group_block(goal_block).0;
    }
    if let Some(preferred_node) = preferred_node {
        if let Some(group_index) = plan
            .group_nodes
            .iter()
            .position(|node| *node == Some(preferred_node))
        {
            return GroupNumber(u32::try_from(group_index).unwrap_or(u32::MAX));
        }
    }
    GroupNumber(0)
}

fn allocation_group_order(geo: &FsGeometry, hint: &AllocHint) -> Result<Vec<GroupNumber>> {
    let group_len = usize::try_from(geo.group_count)
        .map_err(|_| FfsError::InvalidGeometry("group_count does not fit usize".into()))?;
    let mut order = Vec::with_capacity(group_len);

    if let Some(numa) = &hint.numa {
        validate_allocator_numa_preference(geo, numa)?;
        if hint.goal_group.is_none() && hint.goal_block.is_none() {
            push_numa_preferred_groups(geo, numa, &mut order);
        }
    }

    let fallback_goal = legacy_allocation_goal_group(geo, hint);
    push_legacy_group_order(geo, fallback_goal, &mut order);
    Ok(order)
}

fn validate_allocator_numa_preference(
    geo: &FsGeometry,
    numa: &NumaAllocationPreference,
) -> Result<()> {
    let group_len = usize::try_from(geo.group_count)
        .map_err(|_| FfsError::InvalidGeometry("group_count does not fit usize".into()))?;
    if numa.plan.group_nodes.len() != group_len {
        return Err(FfsError::InvalidGeometry(format!(
            "NUMA allocation plan covers {} groups but geometry has {} groups",
            numa.plan.group_nodes.len(),
            geo.group_count
        )));
    }
    Ok(())
}

fn legacy_allocation_goal_group(geo: &FsGeometry, hint: &AllocHint) -> GroupNumber {
    hint.goal_group
        .or_else(|| hint.goal_block.map(|b| geo.absolute_to_group_block(b).0))
        .unwrap_or(GroupNumber(0))
}

fn push_numa_preferred_groups(
    geo: &FsGeometry,
    numa: &NumaAllocationPreference,
    order: &mut Vec<GroupNumber>,
) {
    for (index, node) in numa.plan.group_nodes.iter().enumerate() {
        if *node != Some(numa.preferred_node) {
            continue;
        }
        let Ok(group) = u32::try_from(index) else {
            continue;
        };
        push_unique_group(geo, order, GroupNumber(group));
    }
}

fn push_legacy_group_order(
    geo: &FsGeometry,
    goal_group: GroupNumber,
    order: &mut Vec<GroupNumber>,
) {
    push_unique_group(geo, order, goal_group);

    for delta in 1..=8_u32 {
        let next = goal_group.0.wrapping_add(delta);
        if next < geo.group_count {
            push_unique_group(geo, order, GroupNumber(next));
        }
        let prev = goal_group.0.wrapping_sub(delta);
        if prev < geo.group_count {
            push_unique_group(geo, order, GroupNumber(prev));
        }
    }

    for group in 0..geo.group_count {
        push_unique_group(geo, order, GroupNumber(group));
    }
}

fn push_unique_group(geo: &FsGeometry, order: &mut Vec<GroupNumber>, group: GroupNumber) {
    if group.0 < geo.group_count && !order.contains(&group) {
        order.push(group);
    }
}

fn validate_numa_contract_metadata(
    topology: &NumaAllocationTopology,
) -> std::result::Result<(), NumaTopologyError> {
    if topology.evidence_claim == NumaEvidenceClaim::ProductReadiness {
        return Err(NumaTopologyError::ProductReadinessClaim);
    }
    if let Some(consumer) = REQUIRED_NUMA_TOPOLOGY_CONSUMERS
        .iter()
        .copied()
        .find(|required| {
            !topology
                .downstream_consumers
                .iter()
                .any(|consumer| consumer == required)
        })
    {
        return Err(NumaTopologyError::MissingConsumer { consumer });
    }
    Ok(())
}

fn numa_group_len(geo: &FsGeometry) -> std::result::Result<usize, NumaTopologyError> {
    if geo.group_count == 0 {
        return Err(NumaTopologyError::EmptyGeometry);
    }
    usize::try_from(geo.group_count).map_err(|_| NumaTopologyError::GeometryTooLarge)
}

fn validate_observed_numa_topology(
    geo: &FsGeometry,
    group_len: usize,
    observed_at_unix_secs: u64,
    max_age_secs: u64,
    node_groups: &[NumaNodeGroupRange],
    now_unix_secs: u64,
) -> std::result::Result<NumaAllocationPlan, NumaTopologyError> {
    if node_groups.is_empty() {
        return Err(NumaTopologyError::MissingNodeMap);
    }
    if max_age_secs > NUMA_TOPOLOGY_MAX_AGE_SECS {
        return Err(NumaTopologyError::ExcessiveEvidenceWindow { max_age_secs });
    }
    let age_secs = now_unix_secs.checked_sub(observed_at_unix_secs).ok_or(
        NumaTopologyError::FutureEvidence {
            observed_at_unix_secs,
            now_unix_secs,
        },
    )?;
    if age_secs > max_age_secs {
        return Err(NumaTopologyError::StaleEvidence {
            age_secs,
            max_age_secs,
        });
    }

    let mut group_nodes = vec![None; group_len];
    for range in node_groups {
        validate_numa_group_range(geo, range)?;
        let end = range.first_group.0.checked_add(range.group_count).ok_or(
            NumaTopologyError::GroupRangeOutOfBounds {
                first_group: range.first_group,
                group_count: range.group_count,
                total_groups: geo.group_count,
            },
        )?;

        for group in range.first_group.0..end {
            let group_index =
                usize::try_from(group).map_err(|_| NumaTopologyError::GeometryTooLarge)?;
            let slot = group_nodes.get_mut(group_index).ok_or(
                NumaTopologyError::GroupRangeOutOfBounds {
                    first_group: range.first_group,
                    group_count: range.group_count,
                    total_groups: geo.group_count,
                },
            )?;
            if slot.is_some() {
                return Err(NumaTopologyError::DuplicateGroup {
                    group: GroupNumber(group),
                });
            }
            *slot = Some(range.node_id);
        }
    }

    if let Some(group_index) = group_nodes.iter().position(Option::is_none) {
        let group = u32::try_from(group_index).map_err(|_| NumaTopologyError::GeometryTooLarge)?;
        return Err(NumaTopologyError::UncoveredGroup {
            group: GroupNumber(group),
        });
    }

    Ok(NumaAllocationPlan {
        group_nodes,
        disposition: NumaTopologyDisposition::AdvisoryMap,
    })
}

fn validate_numa_group_range(
    geo: &FsGeometry,
    range: &NumaNodeGroupRange,
) -> std::result::Result<(), NumaTopologyError> {
    if range.node_id.0 > MAX_NUMA_NODE_ID {
        return Err(NumaTopologyError::InvalidNodeId {
            node_id: range.node_id,
        });
    }
    if range.group_count == 0 {
        return Err(NumaTopologyError::EmptyGroupRange {
            node_id: range.node_id,
            first_group: range.first_group,
        });
    }
    let Some(end) = range.first_group.0.checked_add(range.group_count) else {
        return Err(NumaTopologyError::GroupRangeOutOfBounds {
            first_group: range.first_group,
            group_count: range.group_count,
            total_groups: geo.group_count,
        });
    };
    if range.first_group.0 >= geo.group_count || end > geo.group_count {
        return Err(NumaTopologyError::GroupRangeOutOfBounds {
            first_group: range.first_group,
            group_count: range.group_count,
            total_groups: geo.group_count,
        });
    }
    Ok(())
}

// ── Allocation result ───────────────────────────────────────────────────────

/// Result of a block allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockAlloc {
    /// First allocated block.
    pub start: BlockNumber,
    /// Number of contiguous blocks allocated.
    pub count: u32,
}

/// Result of an inode allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeAlloc {
    /// Allocated inode number.
    pub ino: InodeNumber,
    /// Group the inode was allocated in.
    pub group: GroupNumber,
}

// ── Filesystem geometry ─────────────────────────────────────────────────────

/// Cached filesystem geometry needed by the allocator.
#[derive(Debug, Clone)]
pub struct FsGeometry {
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub block_size: u32,
    pub total_blocks: u64,
    pub total_inodes: u32,
    pub first_data_block: u32,
    pub group_count: u32,
    pub inode_size: u16,
    pub desc_size: u16,
    pub reserved_gdt_blocks: u16,
    pub first_meta_bg: u32,
    pub feature_compat: ffs_ondisk::Ext4CompatFeatures,
    pub feature_incompat: ffs_ondisk::Ext4IncompatFeatures,
    pub feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures,
    pub log_groups_per_flex: u8,
    pub backup_bgs: [u32; 2],
    /// First non-reserved inode number (s_first_ino).
    pub first_inode: u32,
    /// Cluster-to-block ratio for bigalloc filesystems.
    ///
    /// For non-bigalloc: 1 (extent lengths are in blocks).
    /// For bigalloc: `cluster_size / block_size` (extent lengths are in clusters).
    pub cluster_ratio: u32,
}

impl FsGeometry {
    /// Derive geometry from a parsed superblock.
    #[must_use]
    pub fn from_superblock(sb: &Ext4Superblock) -> Self {
        let group_count =
            if sb.blocks_per_group > 0 && sb.blocks_count >= u64::from(sb.first_data_block) {
                let data_blocks = sb.blocks_count - u64::from(sb.first_data_block);
                let full = data_blocks / u64::from(sb.blocks_per_group);
                let remainder = data_blocks % u64::from(sb.blocks_per_group);
                let count = full + u64::from(remainder > 0);
                // Saturate at u32::MAX; geometry validation catches oversized values.
                u32::try_from(count).unwrap_or(u32::MAX)
            } else {
                0
            };
        Self {
            blocks_per_group: sb.blocks_per_group,
            inodes_per_group: sb.inodes_per_group,
            block_size: sb.block_size,
            total_blocks: sb.blocks_count,
            total_inodes: sb.inodes_count,
            first_data_block: sb.first_data_block,
            group_count,
            inode_size: sb.inode_size,
            desc_size: sb.group_desc_size(),
            reserved_gdt_blocks: sb.reserved_gdt_blocks,
            first_meta_bg: sb.first_meta_bg,
            feature_compat: sb.feature_compat,
            feature_incompat: sb.feature_incompat,
            feature_ro_compat: sb.feature_ro_compat,
            log_groups_per_flex: sb.log_groups_per_flex,
            backup_bgs: sb.backup_bgs,
            first_inode: sb.first_ino,
            cluster_ratio: if sb
                .feature_ro_compat
                .contains(ffs_ondisk::Ext4RoCompatFeatures::BIGALLOC)
                && sb.cluster_size > 0
                && sb.block_size > 0
            {
                (sb.cluster_size / sb.block_size).max(1)
            } else {
                1
            },
        }
    }

    #[must_use]
    pub fn groups_per_flex(&self) -> u32 {
        if self.feature_incompat.0 & ffs_ondisk::Ext4IncompatFeatures::FLEX_BG.0 == 0
            || self.log_groups_per_flex >= 32
        {
            return 1;
        }
        1_u32 << self.log_groups_per_flex
    }

    #[must_use]
    pub fn has_backup_superblock(&self, group: GroupNumber) -> bool {
        let group = group.0;
        if group == 0 {
            return true;
        }
        if self.feature_compat.0 & ffs_ondisk::Ext4CompatFeatures::SPARSE_SUPER2.0 != 0 {
            return group == self.backup_bgs[0] || group == self.backup_bgs[1];
        }
        if group <= 1
            || self.feature_ro_compat.0 & ffs_ondisk::Ext4RoCompatFeatures::SPARSE_SUPER.0 == 0
        {
            return true;
        }
        if group & 1 == 0 {
            return false;
        }
        is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7)
    }

    #[must_use]
    pub fn gdt_blocks_count(&self) -> u32 {
        let desc_size = u32::from(self.desc_size);
        if desc_size == 0 {
            return 0;
        }
        let desc_per_block = self.block_size / desc_size;
        if desc_per_block == 0 {
            return 0;
        }
        self.group_count.div_ceil(desc_per_block)
    }

    #[must_use]
    pub fn reserved_gdt_blocks_in_group(&self, group: GroupNumber) -> u32 {
        if self.feature_compat.0 & ffs_ondisk::Ext4CompatFeatures::RESIZE_INODE.0 == 0
            || !self.has_backup_superblock(group)
        {
            return 0;
        }
        if self.feature_incompat.0 & ffs_ondisk::Ext4IncompatFeatures::META_BG.0 != 0
            && group.0 >= self.first_meta_bg
        {
            return 0;
        }
        u32::from(self.reserved_gdt_blocks)
    }

    #[must_use]
    pub fn base_meta_blocks_in_group(&self, group: GroupNumber) -> u32 {
        if !self.has_backup_superblock(group) {
            return 0;
        }
        let mut blocks = 1_u32; // superblock copy
        if self.feature_incompat.0 & ffs_ondisk::Ext4IncompatFeatures::META_BG.0 == 0
            || group.0 < self.first_meta_bg
        {
            blocks = blocks
                .saturating_add(self.gdt_blocks_count())
                .saturating_add(self.reserved_gdt_blocks_in_group(group));
        }
        blocks
    }

    /// Number of blocks in a specific group (last group may be shorter).
    #[must_use]
    #[expect(clippy::cast_possible_truncation)]
    pub fn blocks_in_group(&self, group: GroupNumber) -> u32 {
        let group_start = u64::from(self.first_data_block)
            + u64::from(group.0) * u64::from(self.blocks_per_group);
        let remaining = self.total_blocks.saturating_sub(group_start);
        if remaining >= u64::from(self.blocks_per_group) {
            self.blocks_per_group
        } else {
            remaining as u32
        }
    }

    /// Number of inodes in a specific group (last group may be shorter).
    #[must_use]
    #[expect(clippy::cast_possible_truncation)]
    pub fn inodes_in_group(&self, group: GroupNumber) -> u32 {
        let inode_start = u64::from(group.0) * u64::from(self.inodes_per_group);
        let remaining = u64::from(self.total_inodes).saturating_sub(inode_start);
        if remaining >= u64::from(self.inodes_per_group) {
            self.inodes_per_group
        } else {
            remaining as u32
        }
    }

    /// Absolute block number for a relative block within a group.
    #[must_use]
    pub fn group_block_to_absolute(&self, group: GroupNumber, rel_block: u32) -> BlockNumber {
        let abs = u64::from(self.first_data_block)
            + u64::from(group.0) * u64::from(self.blocks_per_group)
            + u64::from(rel_block);
        BlockNumber(abs)
    }

    /// Convert absolute block to (group, relative_block).
    #[must_use]
    pub fn absolute_to_group_block(&self, block: BlockNumber) -> (GroupNumber, u32) {
        let rel = block.0.saturating_sub(u64::from(self.first_data_block));
        let bpg = u64::from(self.blocks_per_group);
        if bpg == 0 {
            // Malformed geometry; return group 0 with capped offset to avoid panic.
            let offset = u32::try_from(rel).unwrap_or(u32::MAX);
            return (GroupNumber(0), offset);
        }
        // Group number: ext4 uses u32 group addressing; cap on overflow.
        let group = u32::try_from(rel / bpg).unwrap_or(u32::MAX);
        // Offset is always < blocks_per_group (u32), so the cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        let offset = (rel % bpg) as u32;
        (GroupNumber(group), offset)
    }
}

// ── On-disk persistence context ─────────────────────────────────────────────

/// Context needed to persist allocator accounting changes to disk.
///
/// When provided to allocation/free operations, group descriptor counters are
/// written back to the device after bitmap updates, keeping on-disk metadata
/// self-consistent.
#[derive(Debug, Clone)]
pub struct PersistCtx {
    /// Block number of the first group descriptor table block.
    /// Group descriptors are packed contiguously starting here.
    pub gdt_block: BlockNumber,
    /// On-disk group descriptor size (32 or 64).
    pub desc_size: u16,
    /// Whether metadata_csum is enabled (triggers checksum stamping).
    pub has_metadata_csum: bool,
    /// CRC32C seed for metadata_csum (from superblock).
    pub csum_seed: u32,
    /// Filesystem UUID used by legacy `gdt_csum`.
    pub uuid: [u8; 16],
    /// Group-descriptor checksum mode derived from the superblock feature bits.
    pub group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind,
    /// Blocks (clusters) per group — needed for bitmap checksum length.
    pub blocks_per_group: u32,
    /// Inodes per group — needed for inode bitmap checksum length.
    pub inodes_per_group: u32,
}

fn is_power_of(mut value: u32, factor: u32) -> bool {
    if factor <= 1 {
        return value == 1;
    }
    while value >= factor {
        let rem = value % factor;
        if rem != 0 {
            return false;
        }
        value /= factor;
    }
    value == 1
}

/// Determine which relative block offsets within a group are reserved metadata
/// and must never be allocated as data blocks.
///
/// Returns a sorted `Vec` of relative block offsets within the group that are
/// occupied by: the superblock copy, the group descriptor table, the block
/// bitmap, the inode bitmap, and the inode table.
#[must_use]
pub fn reserved_blocks_in_group(
    geo: &FsGeometry,
    groups: &[GroupStats],
    group: GroupNumber,
) -> Vec<u32> {
    let gidx = group.0 as usize;
    if gidx >= groups.len() {
        return Vec::new();
    }

    let gs = &groups[gidx];
    let group_start =
        u64::from(geo.first_data_block) + u64::from(group.0) * u64::from(geo.blocks_per_group);
    let blocks_in_group = geo.blocks_in_group(group);
    let mut reserved = Vec::new();

    // Helper: convert absolute block to relative offset in this group,
    // and add to reserved if it falls within the group.
    let add_abs = |reserved: &mut Vec<u32>, abs: u64| {
        if abs >= group_start {
            let rel = abs - group_start;
            if rel < u64::from(blocks_in_group) {
                #[expect(clippy::cast_possible_truncation)]
                reserved.push(rel as u32);
            }
        }
    };

    let base_meta_blocks = geo.base_meta_blocks_in_group(group).min(blocks_in_group);
    for rel in 0..base_meta_blocks {
        reserved.push(rel);
    }

    // Block bitmap, inode bitmap.
    add_abs(&mut reserved, gs.block_bitmap_block.0);
    add_abs(&mut reserved, gs.inode_bitmap_block.0);

    // Inode table spans multiple blocks.
    let inode_table_blocks = if geo.inodes_per_group > 0 && geo.inode_size > 0 && geo.block_size > 0
    {
        (u64::from(geo.inodes_per_group) * u64::from(geo.inode_size))
            .div_ceil(u64::from(geo.block_size))
    } else {
        0
    };
    for i in 0..inode_table_blocks {
        add_abs(&mut reserved, gs.inode_table_block.0 + i);
    }

    // FLEX_BG support: other groups' metadata (bitmaps, inode tables) may
    // reside within THIS group.
    let gpf = geo.groups_per_flex();
    if gpf > 1 {
        // Only check groups in the same flex group. Metadata for group G
        // is always stored within the same flex group F where F = G / gpf.
        let flex_index = group.0 / gpf;
        let first_group = flex_index.saturating_mul(gpf);
        let last_group = first_group.saturating_add(gpf).min(geo.group_count);

        for g in first_group..last_group {
            if g == group.0 {
                continue; // Already handled above.
            }
            if let Some(other_gs) = groups.get(g as usize) {
                add_abs(&mut reserved, other_gs.block_bitmap_block.0);
                add_abs(&mut reserved, other_gs.inode_bitmap_block.0);
                for i in 0..inode_table_blocks {
                    add_abs(&mut reserved, other_gs.inode_table_block.0 + i);
                }
            }
        }
    }

    reserved.sort_unstable();
    reserved.dedup();
    reserved
}

/// Check if a relative block offset in a group is reserved.
#[must_use]
fn is_reserved(reserved: &[u32], rel_block: u32) -> bool {
    reserved.binary_search(&rel_block).is_ok()
}

/// Determine which relative inode offsets within a group are reserved
/// and must never be allocated.
///
/// In ext4, inodes 1 through `s_first_ino - 1` are reserved and always
/// reside in group 0.
#[must_use]
pub fn reserved_inodes_in_group(geo: &FsGeometry, group: GroupNumber) -> Vec<u32> {
    // Total number of reserved inodes across the entire filesystem
    // s_first_ino is 1-based. Reserved are [1, first_inode).
    let total_reserved = u64::from(geo.first_inode.saturating_sub(1));

    // The number of inodes before this group.
    let inodes_before = u64::from(group.0).saturating_mul(u64::from(geo.inodes_per_group));

    if inodes_before >= total_reserved {
        return Vec::new();
    }

    // The number of reserved inodes that fall into this group.
    let remaining_reserved = total_reserved - inodes_before;

    let limit = remaining_reserved.min(u64::from(geo.inodes_in_group(group)));
    let limit = u32::try_from(limit).unwrap_or(u32::MAX);
    let mut reserved = Vec::with_capacity(limit as usize);
    for i in 0..limit {
        reserved.push(i);
    }
    reserved
}

/// Persist a group descriptor's counter fields back to the on-disk GDT.
///
/// Reads the GDT block containing `group`, patches the free_blocks/inodes/dirs
/// fields, recomputes the checksum (if enabled), and writes the block back.
fn persist_group_desc_with_bitmap_overrides(
    cx: &Cx,
    dev: &dyn BlockDevice,
    pctx: &PersistCtx,
    group: GroupNumber,
    stats: &GroupStats,
    block_bitmap_override: Option<&[u8]>,
    inode_bitmap_override: Option<&[u8]>,
) -> Result<()> {
    let ds = usize::from(pctx.desc_size);
    if ds == 0 {
        return Err(FfsError::InvalidGeometry("desc_size is zero".into()));
    }
    let descs_per_block = dev.block_size() as usize / ds;
    if descs_per_block == 0 {
        return Err(FfsError::InvalidGeometry(
            "block_size smaller than desc_size".into(),
        ));
    }
    let gdt_block_idx = group.0 as usize / descs_per_block;
    let offset_in_block = (group.0 as usize % descs_per_block) * ds;

    let block_num = BlockNumber(
        pctx.gdt_block
            .0
            .checked_add(gdt_block_idx as u64)
            .ok_or_else(|| FfsError::InvalidGeometry("GDT block number overflow".into()))?,
    );
    let raw = dev.read_block(cx, block_num)?;
    let mut buf = raw.as_slice().to_vec();

    // Build a temporary Ext4GroupDesc with updated counters and serialize.
    // Read existing descriptor to preserve fields we don't track.
    let existing = Ext4GroupDesc::parse_from_bytes(&buf[offset_in_block..], pctx.desc_size)
        .map_err(|e| FfsError::Format(format!("GDT parse: {e}")))?;

    let mut updated = Ext4GroupDesc {
        free_blocks_count: stats.free_blocks,
        free_inodes_count: stats.free_inodes,
        used_dirs_count: stats.used_dirs,
        ..existing
    };

    if pctx.has_metadata_csum {
        let block_bitmap_buf;
        let block_bitmap = if let Some(bitmap) = block_bitmap_override {
            bitmap
        } else {
            block_bitmap_buf = dev.read_block(cx, stats.block_bitmap_block)?;
            block_bitmap_buf.as_slice()
        };
        let inode_bitmap_buf;
        let inode_bitmap = if let Some(bitmap) = inode_bitmap_override {
            bitmap
        } else {
            inode_bitmap_buf = dev.read_block(cx, stats.inode_bitmap_block)?;
            inode_bitmap_buf.as_slice()
        };
        ffs_ondisk::ext4::stamp_block_bitmap_checksum(
            block_bitmap,
            pctx.csum_seed,
            pctx.blocks_per_group,
            &mut updated,
            pctx.desc_size,
        );
        ffs_ondisk::ext4::stamp_inode_bitmap_checksum(
            inode_bitmap,
            pctx.csum_seed,
            pctx.inodes_per_group,
            &mut updated,
            pctx.desc_size,
        );
    }

    // bd-0ta4z: once a group's bitmap is written explicitly, the group is no
    // longer "uninitialized" — clear the matching UNINIT flag so e2fsck reads
    // the on-disk bitmap as authoritative instead of recomputing it as all-free.
    // For inode allocations also shrink `itable_unused` (the count of inodes at
    // the end of the table never yet used) so the freshly allocated inode leaves
    // the descriptor's "unused inodes" tail. It is monotonic — taken as a `min`
    // so it never grows back when inodes are freed (the inode table stays
    // initialized up to the high-water mark).
    if let Some(ibitmap) = inode_bitmap_override {
        updated.flags &= !GD_FLAG_INODE_UNINIT;
        if let Some(highest_used) = highest_set_bit_index(ibitmap, pctx.inodes_per_group) {
            let unused = pctx
                .inodes_per_group
                .saturating_sub(highest_used.saturating_add(1));
            updated.itable_unused = updated.itable_unused.min(unused);
        }
    }
    if block_bitmap_override.is_some() {
        updated.flags &= !GD_FLAG_BLOCK_UNINIT;
    }

    updated
        .write_to_bytes(&mut buf[offset_in_block..], pctx.desc_size)
        .map_err(|e| FfsError::Format(format!("GDT write: {e}")))?;

    if pctx.group_desc_checksum_kind != ffs_ondisk::ext4::Ext4GroupDescChecksumKind::None {
        ffs_ondisk::ext4::stamp_group_desc_checksum(
            &mut buf[offset_in_block..offset_in_block + ds],
            &pctx.uuid,
            pctx.csum_seed,
            group.0,
            pctx.desc_size,
            pctx.group_desc_checksum_kind,
        );
    }

    dev.write_block(cx, block_num, &buf)?;
    Ok(())
}

// ── Block allocator ─────────────────────────────────────────────────────────

/// Allocate `count` contiguous blocks, using `hint` for goal-directed placement.
///
/// Strategy:
/// 1. Try the goal group/block if specified.
/// 2. Try nearby groups.
/// 3. Scan all groups for best fit.
pub fn alloc_blocks(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    count: u32,
    hint: &AllocHint,
) -> Result<BlockAlloc> {
    cx_checkpoint(cx)?;

    if count == 0 {
        return Err(FfsError::Format("cannot allocate 0 blocks".into()));
    }

    for group in allocation_group_order(geo, hint)? {
        if let Some(alloc) = try_alloc_in_group(cx, dev, geo, groups, group, count, hint)? {
            return Ok(alloc);
        }
    }

    Err(FfsError::NoSpace)
}

/// Try to allocate `count` blocks in a specific group.
fn try_alloc_in_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    group: GroupNumber,
    count: u32,
    hint: &AllocHint,
) -> Result<Option<BlockAlloc>> {
    let gidx = group.0 as usize;
    if gidx >= groups.len() {
        return Ok(None);
    }

    let gs = &groups[gidx];
    if gs.free_blocks < count {
        return Ok(None);
    }

    let blocks_in_group = geo.blocks_in_group(group);

    // Read the block bitmap.
    let bitmap_buf = dev.read_block(cx, gs.block_bitmap_block)?;
    let mut bitmap = bitmap_buf.as_slice().to_vec();

    let reserved = reserved_blocks_in_group(geo, groups, group);
    for &r in &reserved {
        bitmap_set(&mut bitmap, r);
    }

    // Determine start position for search.
    let start = hint.goal_block.map_or(0, |goal| {
        let (g, off) = geo.absolute_to_group_block(goal);
        if g == group { off } else { 0 }
    });

    // Try to find contiguous free blocks.
    let found = if count == 1 {
        bitmap_find_free(&bitmap, blocks_in_group, start).map(|idx| (idx, 1))
    } else {
        bitmap_find_contiguous(&bitmap, blocks_in_group, count, start).map(|idx| (idx, count))
    };

    if let Some((rel_start, alloc_count)) = found {
        // Mark blocks as allocated.
        for i in rel_start..rel_start + alloc_count {
            bitmap_set(&mut bitmap, i);
        }

        // Write bitmap back.
        dev.write_block(cx, gs.block_bitmap_block, &bitmap)?;

        // Update group stats.
        groups[gidx].free_blocks = groups[gidx].free_blocks.saturating_sub(alloc_count);

        let abs_start = geo.group_block_to_absolute(group, rel_start);
        Ok(Some(BlockAlloc {
            start: abs_start,
            count: alloc_count,
        }))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy)]
struct FreeBlockSegment {
    group: GroupNumber,
    rel_start: u32,
    count: u32,
}

fn split_free_block_segments(
    geo: &FsGeometry,
    groups_len: usize,
    start: BlockNumber,
    count: u32,
    detail_prefix: &str,
) -> Result<Vec<FreeBlockSegment>> {
    let mut segments = Vec::new();
    if count == 0 {
        return Ok(segments);
    }

    let mut next_abs = start.0;
    let mut remaining = count;

    while remaining > 0 {
        let block = BlockNumber(next_abs);
        let (group, rel_start) = geo.absolute_to_group_block(block);
        let gidx = group.0 as usize;
        if gidx >= groups_len {
            return Err(FfsError::Corruption {
                block: block.0,
                detail: format!("{detail_prefix}: group out of range"),
            });
        }

        let blocks_in_group = geo.blocks_in_group(group);
        if rel_start >= blocks_in_group {
            return Err(FfsError::Corruption {
                block: block.0,
                detail: format!("{detail_prefix}: relative block out of range"),
            });
        }

        let segment_count = remaining.min(blocks_in_group - rel_start);
        segments.push(FreeBlockSegment {
            group,
            rel_start,
            count: segment_count,
        });

        next_abs = next_abs.saturating_add(u64::from(segment_count));
        remaining -= segment_count;
    }

    Ok(segments)
}

/// Free `count` contiguous blocks starting at `start`.
pub fn free_blocks(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    start: BlockNumber,
    count: u32,
) -> Result<()> {
    cx_checkpoint(cx)?;

    let segments = split_free_block_segments(geo, groups.len(), start, count, "free_blocks")?;

    for segment in segments {
        let gidx = segment.group.0 as usize;
        let gs = &groups[gidx];
        let bitmap_buf = dev.read_block(cx, gs.block_bitmap_block)?;
        let mut bitmap = bitmap_buf.as_slice().to_vec();

        for i in segment.rel_start..segment.rel_start + segment.count {
            bitmap_clear(&mut bitmap, i);
        }

        dev.write_block(cx, gs.block_bitmap_block, &bitmap)?;
        groups[gidx].free_blocks = groups[gidx].free_blocks.saturating_add(segment.count);
    }
    Ok(())
}

// ── Persistent block allocator ──────────────────────────────────────────────

/// Allocate `count` contiguous data blocks with full on-disk accounting.
///
/// Like [`alloc_blocks`], but additionally:
/// - Skips reserved metadata blocks (bitmaps, inode tables, GDT blocks).
/// - Writes updated group descriptor counters back to the device.
///
/// Returns the total number of free blocks delta for the caller to update
/// superblock counters at commit time.
pub fn alloc_blocks_persist(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    count: u32,
    hint: &AllocHint,
    pctx: &PersistCtx,
) -> Result<BlockAlloc> {
    cx_checkpoint(cx)?;

    if count == 0 {
        return Err(FfsError::Format("cannot allocate 0 blocks".into()));
    }

    for group in allocation_group_order(geo, hint)? {
        if let Some(alloc) = try_alloc_safe(cx, dev, geo, groups, group, count, hint, pctx)? {
            return Ok(alloc);
        }
    }

    Err(FfsError::NoSpace)
}

/// Try to allocate `count` blocks in a group, skipping reserved blocks and
/// persisting group descriptor updates.
#[expect(clippy::too_many_arguments)]
fn try_alloc_safe(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    group: GroupNumber,
    count: u32,
    hint: &AllocHint,
    pctx: &PersistCtx,
) -> Result<Option<BlockAlloc>> {
    let gidx = group.0 as usize;
    if gidx >= groups.len() {
        return Ok(None);
    }

    if groups[gidx].free_blocks < count {
        return Ok(None);
    }

    let blocks_in_group = geo.blocks_in_group(group);
    let reserved = reserved_blocks_in_group(geo, groups, group);

    let bitmap_buf = dev.read_block(cx, groups[gidx].block_bitmap_block)?;
    let mut bitmap = bitmap_buf.as_slice().to_vec();

    // Ensure all reserved blocks are marked as allocated in the bitmap.
    for &r in &reserved {
        bitmap_set(&mut bitmap, r);
    }

    let start = hint.goal_block.map_or(0, |goal| {
        let (g, off) = geo.absolute_to_group_block(goal);
        if g == group { off } else { 0 }
    });

    // Find free blocks, respecting reserved bits now set in the bitmap.
    let found = if count == 1 {
        bitmap_find_free(&bitmap, blocks_in_group, start).map(|idx| (idx, 1))
    } else {
        bitmap_find_contiguous(&bitmap, blocks_in_group, count, start).map(|idx| (idx, count))
    };

    if let Some((rel_start, alloc_count)) = found {
        // Verify no allocated block is reserved.
        for i in rel_start..rel_start + alloc_count {
            if is_reserved(&reserved, i) {
                return Err(FfsError::Corruption {
                    block: geo.group_block_to_absolute(group, i).0,
                    detail: "alloc would overlap reserved metadata block".into(),
                });
            }
        }

        // Mark blocks as allocated.
        for i in rel_start..rel_start + alloc_count {
            bitmap_set(&mut bitmap, i);
        }

        dev.write_block(cx, groups[gidx].block_bitmap_block, &bitmap)?;
        let previous_free_blocks = groups[gidx].free_blocks;
        groups[gidx].free_blocks = previous_free_blocks.saturating_sub(alloc_count);

        // Persist group descriptor (includes bitmap checksum stamping if metadata_csum).
        if let Err(error) = persist_group_desc_with_bitmap_overrides(
            cx,
            dev,
            pctx,
            group,
            &groups[gidx],
            Some(&bitmap),
            None,
        ) {
            groups[gidx].free_blocks = previous_free_blocks;
            restore_bitmap_after_group_desc_error(
                cx,
                dev,
                groups[gidx].block_bitmap_block,
                bitmap_buf.as_slice(),
                "block bitmap allocation",
                error,
            )?;
        }

        let abs_start = geo.group_block_to_absolute(group, rel_start);
        Ok(Some(BlockAlloc {
            start: abs_start,
            count: alloc_count,
        }))
    } else {
        Ok(None)
    }
}

fn restore_bitmap_after_group_desc_error(
    cx: &Cx,
    dev: &dyn BlockDevice,
    bitmap_block: BlockNumber,
    original_bitmap: &[u8],
    mutation: &str,
    error: FfsError,
) -> Result<()> {
    if let Err(rollback_error) = dev.write_block(cx, bitmap_block, original_bitmap) {
        return Err(FfsError::Corruption {
            block: bitmap_block.0,
            detail: format!(
                "group descriptor persistence failed after {mutation} ({error}); \
                 rollback of bitmap block failed ({rollback_error})"
            ),
        });
    }
    Err(error)
}

/// Free `count` contiguous blocks with full on-disk accounting.
///
/// Like [`free_blocks`], but additionally:
/// - Validates that freed blocks are not reserved metadata.
/// - Validates that freed blocks are currently allocated.
/// - Writes updated group descriptor counters back to the device.
pub fn free_blocks_persist(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    start: BlockNumber,
    count: u32,
    pctx: &PersistCtx,
) -> Result<()> {
    cx_checkpoint(cx)?;

    let segments =
        split_free_block_segments(geo, groups.len(), start, count, "free_blocks_persist")?;
    let mut prepared = Vec::with_capacity(segments.len());

    for segment in segments {
        let gidx = segment.group.0 as usize;
        let reserved = reserved_blocks_in_group(geo, groups, segment.group);

        // Validate none of the blocks being freed are reserved.
        for i in segment.rel_start..segment.rel_start + segment.count {
            if is_reserved(&reserved, i) {
                return Err(FfsError::Corruption {
                    block: geo.group_block_to_absolute(segment.group, i).0,
                    detail: "attempt to free reserved metadata block".into(),
                });
            }
        }

        let bitmap_buf = dev.read_block(cx, groups[gidx].block_bitmap_block)?;
        let original_bitmap = bitmap_buf.as_slice().to_vec();
        let mut bitmap = original_bitmap.clone();

        // Validate all blocks are currently allocated (double-free detection).
        for i in segment.rel_start..segment.rel_start + segment.count {
            if !bitmap_get(&bitmap, i) {
                return Err(FfsError::Corruption {
                    block: geo.group_block_to_absolute(segment.group, i).0,
                    detail: "double-free: block already free in bitmap".into(),
                });
            }
        }

        for i in segment.rel_start..segment.rel_start + segment.count {
            bitmap_clear(&mut bitmap, i);
        }

        prepared.push((segment, bitmap, original_bitmap, groups[gidx].free_blocks));
    }

    for (segment, bitmap, original_bitmap, previous_free_blocks) in prepared {
        let gidx = segment.group.0 as usize;
        dev.write_block(cx, groups[gidx].block_bitmap_block, &bitmap)?;
        groups[gidx].free_blocks = groups[gidx].free_blocks.saturating_add(segment.count);

        // Persist group descriptor.
        if let Err(error) = persist_group_desc_with_bitmap_overrides(
            cx,
            dev,
            pctx,
            segment.group,
            &groups[gidx],
            Some(&bitmap),
            None,
        ) {
            groups[gidx].free_blocks = previous_free_blocks;
            restore_bitmap_after_group_desc_error(
                cx,
                dev,
                groups[gidx].block_bitmap_block,
                &original_bitmap,
                "block bitmap free",
                error,
            )?;
        }
    }

    Ok(())
}

// ── Batch block allocator ───────────────────────────────────────────────────

/// Allocate `n` independent single blocks from the same goal group, amortizing
/// bitmap I/O and group descriptor persistence.
///
/// Returns exactly `n` allocations. Each block is independently placed (not
/// necessarily contiguous) but all drawn from the same group when possible.
/// Falls back to per-block `alloc_blocks_persist` if a single group lacks
/// space.
///
/// Compared to `n` individual `alloc_blocks_persist(count=1)` calls, this
/// function:
/// - Reads the bitmap **once** per group
/// - Writes the bitmap **once** per group
/// - Persists the group descriptor **once** per group
///
/// This is the recommended path for callers that need many single-block
/// allocations (B+tree node splits, directory block allocation, xattr COW).
pub fn alloc_blocks_batch_persist(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    n: u32,
    hint: &AllocHint,
    pctx: &PersistCtx,
) -> Result<Vec<BlockAlloc>> {
    if n == 0 {
        return Ok(Vec::new());
    }

    // For single allocation, delegate to the standard path.
    if n == 1 {
        return alloc_blocks_persist(cx, dev, geo, groups, 1, hint, pctx).map(|a| vec![a]);
    }

    cx_checkpoint(cx)?;

    let mut results = Vec::with_capacity(n as usize);
    let mut remaining = n;
    let group_order = allocation_group_order(geo, hint)?;

    for &group in &group_order {
        if remaining == 0 {
            break;
        }

        let gidx = group.0 as usize;
        if gidx >= groups.len() || groups[gidx].free_blocks == 0 {
            continue;
        }

        let allocated_in_group =
            try_alloc_batch_in_group(cx, dev, geo, groups, group, remaining, hint, pctx)?;

        let allocated_in_group_len =
            u32::try_from(allocated_in_group.len()).map_err(|_| FfsError::Corruption {
                block: 0,
                detail: "batch allocation count is bounded by requested u32 count".into(),
            })?;
        remaining -= allocated_in_group_len;
        results.extend(allocated_in_group);
    }

    if results.len() < n as usize {
        // Rollback any successfully persisted blocks to prevent a persistent block leak.
        // We do this individually since batch allocations may span multiple groups.
        for alloc in &results {
            let _ = free_blocks_persist(cx, dev, geo, groups, alloc.start, alloc.count, pctx);
        }
        return Err(FfsError::NoSpace);
    }

    Ok(results)
}

/// Allocate up to `max_count` single blocks from one group in a single
/// bitmap read/write cycle.
#[expect(clippy::too_many_arguments)]
fn try_alloc_batch_in_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    group: GroupNumber,
    max_count: u32,
    hint: &AllocHint,
    pctx: &PersistCtx,
) -> Result<Vec<BlockAlloc>> {
    let gidx = group.0 as usize;
    if gidx >= groups.len() || groups[gidx].free_blocks == 0 {
        return Ok(Vec::new());
    }

    let blocks_in_group = geo.blocks_in_group(group);
    let reserved = reserved_blocks_in_group(geo, groups, group);

    let bitmap_buf = dev.read_block(cx, groups[gidx].block_bitmap_block)?;
    let mut bitmap = bitmap_buf.as_slice().to_vec();

    // Mark reserved blocks.
    for &r in &reserved {
        bitmap_set(&mut bitmap, r);
    }

    let start = hint.goal_block.map_or(0, |goal| {
        let (g, off) = geo.absolute_to_group_block(goal);
        if g == group { off } else { 0 }
    });

    let to_alloc = max_count.min(groups[gidx].free_blocks);
    let mut allocated = Vec::with_capacity(to_alloc as usize);

    bitmap_take_free_bits_cyclic(&mut bitmap, blocks_in_group, to_alloc, start, |idx| {
        let abs = geo.group_block_to_absolute(group, idx);
        allocated.push(BlockAlloc {
            start: abs,
            count: 1,
        });
    });

    if allocated.is_empty() {
        return Ok(Vec::new());
    }

    // Single bitmap write for all allocations in this group.
    dev.write_block(cx, groups[gidx].block_bitmap_block, &bitmap)?;
    let count_allocated = u32::try_from(allocated.len()).map_err(|_| FfsError::Corruption {
        block: 0,
        detail: "group allocation count is bounded by u32 request".into(),
    })?;
    let previous_free_blocks = groups[gidx].free_blocks;
    groups[gidx].free_blocks = previous_free_blocks.saturating_sub(count_allocated);

    // Single GDT persist for all allocations in this group.
    if let Err(error) = persist_group_desc_with_bitmap_overrides(
        cx,
        dev,
        pctx,
        group,
        &groups[gidx],
        Some(&bitmap),
        None,
    ) {
        groups[gidx].free_blocks = previous_free_blocks;
        restore_bitmap_after_group_desc_error(
            cx,
            dev,
            groups[gidx].block_bitmap_block,
            bitmap_buf.as_slice(),
            "batch block bitmap allocation",
            error,
        )?;
    }

    Ok(allocated)
}

// ── Inode allocator (Orlov) ─────────────────────────────────────────────────

/// Allocate an inode using the Orlov strategy.
///
/// - Directories: spread across groups (prefer groups with above-average free
///   inodes AND free blocks, fewest directories).
/// - Files: co-locate with parent directory's group.
pub fn alloc_inode(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    parent_group: GroupNumber,
    is_directory: bool,
) -> Result<InodeAlloc> {
    cx_checkpoint(cx)?;

    let target_group = if is_directory {
        orlov_choose_group_for_dir(geo, groups)?
    } else {
        // Files: try parent group first, then nearby.
        parent_group
    };

    // Try target group.
    if let Some(alloc) = try_alloc_inode_in_group(cx, dev, geo, groups, target_group)? {
        return Ok(alloc);
    }

    // Try nearby groups (within 8 groups of target).
    for delta in 1..=8u32 {
        for dir in [1i64, -1i64] {
            let g = i64::from(target_group.0) + dir * i64::from(delta);
            #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            if g >= 0 && (g as u32) < geo.group_count {
                let group = GroupNumber(g as u32);
                if let Some(alloc) = try_alloc_inode_in_group(cx, dev, geo, groups, group)? {
                    return Ok(alloc);
                }
            }
        }
    }

    // Scan all groups.
    for g in 0..geo.group_count {
        let group = GroupNumber(g);
        if group == target_group {
            continue;
        }
        if let Some(alloc) = try_alloc_inode_in_group(cx, dev, geo, groups, group)? {
            return Ok(alloc);
        }
    }

    Err(FfsError::NoSpace)
}

/// Orlov: choose a group for a new directory.
fn orlov_choose_group_for_dir(_geo: &FsGeometry, groups: &[GroupStats]) -> Result<GroupNumber> {
    if groups.is_empty() {
        return Err(FfsError::NoSpace);
    }

    // Compute averages.
    let total_free_inodes: u64 = groups.iter().map(|g| u64::from(g.free_inodes)).sum();
    let total_free_blocks: u64 = groups.iter().map(|g| u64::from(g.free_blocks)).sum();
    let total_dirs: u64 = groups.iter().map(|g| u64::from(g.used_dirs)).sum();
    let n = groups.len() as u64;
    let avg_free_inodes = total_free_inodes / n;
    let avg_free_blocks = total_free_blocks / n;
    let avg_dirs = total_dirs / n;

    // Find best group: above-average free inodes AND blocks, fewest dirs.
    let mut best_group = GroupNumber(0);
    let mut best_score = u64::MAX;

    for gs in groups {
        if u64::from(gs.free_inodes) < avg_free_inodes {
            continue;
        }
        if u64::from(gs.free_blocks) < avg_free_blocks {
            continue;
        }
        let score = u64::from(gs.used_dirs);
        if score < best_score || (score == best_score && score <= avg_dirs) {
            best_score = score;
            best_group = gs.group;
        }
    }

    // Fallback: any group with free inodes.
    if best_score == u64::MAX {
        for gs in groups {
            if gs.free_inodes > 0 {
                return Ok(gs.group);
            }
        }
        return Err(FfsError::NoSpace);
    }

    Ok(best_group)
}

/// Try to allocate an inode in a specific group.
fn try_alloc_inode_in_group(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    group: GroupNumber,
) -> Result<Option<InodeAlloc>> {
    let gidx = group.0 as usize;
    if gidx >= groups.len() {
        return Ok(None);
    }

    let inodes_in_group = geo.inodes_in_group(group);
    if inodes_in_group == 0 {
        return Ok(None);
    }

    let gs = &groups[gidx];
    if gs.free_inodes == 0 {
        return Ok(None);
    }

    let bitmap_buf = dev.read_block(cx, gs.inode_bitmap_block)?;
    let mut bitmap = bitmap_buf.as_slice().to_vec();

    // Mark reserved inodes as allocated.
    let reserved = reserved_inodes_in_group(geo, group);
    for &r in &reserved {
        bitmap_set(&mut bitmap, r);
    }

    let found = bitmap_find_free(&bitmap, inodes_in_group, 0);
    if let Some(idx) = found {
        // Compute absolute inode number: group * inodes_per_group + idx + 1.
        let ino = u64::from(group.0) * u64::from(geo.inodes_per_group) + u64::from(idx) + 1;
        if ino > u64::from(geo.total_inodes) {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!("allocated inode {ino} exceeds total inode count"),
            });
        }

        bitmap_set(&mut bitmap, idx);
        dev.write_block(cx, gs.inode_bitmap_block, &bitmap)?;

        groups[gidx].free_inodes = groups[gidx].free_inodes.saturating_sub(1);

        Ok(Some(InodeAlloc {
            ino: InodeNumber(ino),
            group,
        }))
    } else {
        Ok(None)
    }
}

/// Allocate an inode using the Orlov strategy with full on-disk accounting.
pub fn alloc_inode_persist(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    parent_group: GroupNumber,
    is_directory: bool,
    pctx: &PersistCtx,
) -> Result<InodeAlloc> {
    cx_checkpoint(cx)?;

    let target_group = if is_directory {
        orlov_choose_group_for_dir(geo, groups)?
    } else {
        parent_group
    };

    if let Some(alloc) = try_alloc_inode_in_group_persist(cx, dev, geo, groups, target_group, pctx)?
    {
        return Ok(alloc);
    }

    // Try nearby groups (within 8 groups of target).
    for delta in 1..=8u32 {
        for dir in [1i64, -1i64] {
            let g = i64::from(target_group.0) + dir * i64::from(delta);
            #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            if g >= 0 && (g as u32) < geo.group_count {
                let group = GroupNumber(g as u32);
                if let Some(alloc) =
                    try_alloc_inode_in_group_persist(cx, dev, geo, groups, group, pctx)?
                {
                    return Ok(alloc);
                }
            }
        }
    }

    for g in 0..geo.group_count {
        let group = GroupNumber(g);
        if group == target_group {
            continue;
        }
        if let Some(alloc) = try_alloc_inode_in_group_persist(cx, dev, geo, groups, group, pctx)? {
            return Ok(alloc);
        }
    }

    Err(FfsError::NoSpace)
}

/// Try to allocate an inode in a specific group with full on-disk accounting.
fn try_alloc_inode_in_group_persist(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    group: GroupNumber,
    pctx: &PersistCtx,
) -> Result<Option<InodeAlloc>> {
    let gidx = group.0 as usize;
    if gidx >= groups.len() || geo.inodes_in_group(group) == 0 || groups[gidx].free_inodes == 0 {
        return Ok(None);
    }

    let bitmap_block = groups[gidx].inode_bitmap_block;
    let original_bitmap = dev.read_block(cx, bitmap_block)?.as_slice().to_vec();
    let mut bitmap = original_bitmap.clone();
    let previous_free_inodes = groups[gidx].free_inodes;

    let inodes_in_group = geo.inodes_in_group(group);
    let reserved = reserved_inodes_in_group(geo, group);
    for &r in &reserved {
        bitmap_set(&mut bitmap, r);
    }

    let Some(idx) = bitmap_find_free(&bitmap, inodes_in_group, 0) else {
        return Ok(None);
    };

    let ino = u64::from(group.0) * u64::from(geo.inodes_per_group) + u64::from(idx) + 1;
    if ino > u64::from(geo.total_inodes) {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("allocated inode {ino} exceeds total inode count"),
        });
    }

    bitmap_set(&mut bitmap, idx);
    dev.write_block(cx, bitmap_block, &bitmap)?;
    groups[gidx].free_inodes = groups[gidx].free_inodes.saturating_sub(1);

    if let Err(error) = persist_group_desc_with_bitmap_overrides(
        cx,
        dev,
        pctx,
        group,
        &groups[gidx],
        None,
        Some(&bitmap),
    ) {
        groups[gidx].free_inodes = previous_free_inodes;
        restore_bitmap_after_group_desc_error(
            cx,
            dev,
            bitmap_block,
            &original_bitmap,
            "inode bitmap allocation",
            error,
        )?;
    }

    Ok(Some(InodeAlloc {
        ino: InodeNumber(ino),
        group,
    }))
}

/// Free an inode.
pub fn free_inode(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    ino: InodeNumber,
) -> Result<()> {
    cx_checkpoint(cx)?;

    // Compute group and index.
    if geo.inodes_per_group == 0 {
        return Err(FfsError::Format(
            "free_inode: inodes_per_group is zero".into(),
        ));
    }
    let ino_zero = ino.0.checked_sub(1).ok_or_else(|| FfsError::Corruption {
        block: 0,
        detail: "inode number 0 is invalid".into(),
    })?;
    if ino.0 > u64::from(geo.total_inodes) {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("inode {} exceeds total inode count", ino.0),
        });
    }
    let group_idx_u64 = ino_zero / u64::from(geo.inodes_per_group);
    let group_idx = u32::try_from(group_idx_u64).map_err(|_| FfsError::Corruption {
        block: 0,
        detail: format!("free_inode: group index {group_idx_u64} exceeds u32"),
    })?;
    #[expect(clippy::cast_possible_truncation)]
    let bit_idx = (ino_zero % u64::from(geo.inodes_per_group)) as u32;
    let gidx = group_idx as usize;

    if gidx >= groups.len() {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("free_inode: group {group_idx} out of range"),
        });
    }
    let inodes_in_group = geo.inodes_in_group(GroupNumber(group_idx));
    if bit_idx >= inodes_in_group {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!(
                "inode {} is outside group {group_idx} inode capacity",
                ino.0
            ),
        });
    }

    let gs = &groups[gidx];
    let bitmap_buf = dev.read_block(cx, gs.inode_bitmap_block)?;
    let mut bitmap = bitmap_buf.as_slice().to_vec();

    if !bitmap_get(&bitmap, bit_idx) {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("double-free: inode {} already free in bitmap", ino.0),
        });
    }

    let reserved = reserved_inodes_in_group(geo, GroupNumber(group_idx));
    if is_reserved(&reserved, bit_idx) {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("attempt to free reserved inode {}", ino.0),
        });
    }

    bitmap_clear(&mut bitmap, bit_idx);
    dev.write_block(cx, gs.inode_bitmap_block, &bitmap)?;
    groups[gidx].free_inodes = groups[gidx].free_inodes.saturating_add(1);
    Ok(())
}

/// Free an inode with full on-disk accounting.
pub fn free_inode_persist(
    cx: &Cx,
    dev: &dyn BlockDevice,
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    ino: InodeNumber,
    pctx: &PersistCtx,
) -> Result<()> {
    if geo.inodes_per_group == 0 {
        return Err(FfsError::Format(
            "free_inode_persist: inodes_per_group is zero".into(),
        ));
    }
    let ino_zero = ino.0.checked_sub(1).ok_or_else(|| FfsError::Corruption {
        block: 0,
        detail: "inode number 0 is invalid".into(),
    })?;
    if ino.0 > u64::from(geo.total_inodes) {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("inode {} exceeds total inode count", ino.0),
        });
    }
    let group_idx_u64 = ino_zero / u64::from(geo.inodes_per_group);
    let group_idx = u32::try_from(group_idx_u64).map_err(|_| FfsError::Corruption {
        block: 0,
        detail: format!("free_inode_persist: group index {group_idx_u64} exceeds u32"),
    })?;
    let gidx = group_idx as usize;
    if gidx >= groups.len() {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("free_inode_persist: group {group_idx} out of range"),
        });
    }
    let bitmap_block = groups[gidx].inode_bitmap_block;
    let original_bitmap = dev.read_block(cx, bitmap_block)?.as_slice().to_vec();
    let mut bitmap = original_bitmap.clone();
    let previous_free_inodes = groups[gidx].free_inodes;
    let group = GroupNumber(group_idx);
    let bit_idx = u32::try_from(ino_zero % u64::from(geo.inodes_per_group)).map_err(|_| {
        FfsError::Corruption {
            block: 0,
            detail: format!("free_inode_persist: inode {} bit index exceeds u32", ino.0),
        }
    })?;
    let inodes_in_group = geo.inodes_in_group(group);
    if bit_idx >= inodes_in_group {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!(
                "inode {} is outside group {group_idx} inode capacity",
                ino.0
            ),
        });
    }
    if !bitmap_get(&bitmap, bit_idx) {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("double-free: inode {} already free in bitmap", ino.0),
        });
    }
    let reserved = reserved_inodes_in_group(geo, group);
    if is_reserved(&reserved, bit_idx) {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("attempt to free reserved inode {}", ino.0),
        });
    }

    bitmap_clear(&mut bitmap, bit_idx);
    dev.write_block(cx, bitmap_block, &bitmap)?;
    groups[gidx].free_inodes = groups[gidx].free_inodes.saturating_add(1);

    if let Err(error) = persist_group_desc_with_bitmap_overrides(
        cx,
        dev,
        pctx,
        group,
        &groups[gidx],
        None,
        Some(&bitmap),
    ) {
        groups[gidx].free_inodes = previous_free_inodes;
        restore_bitmap_after_group_desc_error(
            cx,
            dev,
            bitmap_block,
            &original_bitmap,
            "inode bitmap free",
            error,
        )?;
    }
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn cx_checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[expect(clippy::option_if_let_else)]
mod tests {
    use super::*;
    use ffs_block::BlockBuf;
    use std::collections::HashMap;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct MemBlockDevice {
        block_size: u32,
        blocks: Mutex<HashMap<u64, Vec<u8>>>,
    }

    impl MemBlockDevice {
        fn new(block_size: u32) -> Self {
            Self {
                block_size,
                blocks: Mutex::new(HashMap::new()),
            }
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            let blocks = self.blocks.lock().unwrap();
            if let Some(data) = blocks.get(&block.0) {
                Ok(BlockBuf::new(data.clone()))
            } else {
                Ok(BlockBuf::new(vec![0u8; self.block_size as usize]))
            }
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.blocks.lock().unwrap().insert(block.0, data.to_vec());
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            1_000_000
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    struct FailGdtWriteDevice<'a> {
        inner: &'a MemBlockDevice,
        gdt_block: BlockNumber,
        remaining_failures: AtomicUsize,
    }

    impl<'a> FailGdtWriteDevice<'a> {
        fn new(inner: &'a MemBlockDevice, gdt_block: BlockNumber) -> Self {
            Self {
                inner,
                gdt_block,
                remaining_failures: AtomicUsize::new(1),
            }
        }
    }

    impl BlockDevice for FailGdtWriteDevice<'_> {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.inner.read_block(cx, block)
        }

        fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            if block == self.gdt_block
                && self
                    .remaining_failures
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_ok()
            {
                return Err(FfsError::Io(std::io::Error::other(
                    "injected GDT write failure",
                )));
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

    fn test_cx() -> Cx {
        Cx::for_testing()
    }

    fn make_geometry() -> FsGeometry {
        FsGeometry {
            blocks_per_group: 8192,
            inodes_per_group: 2048,
            block_size: 4096,
            total_blocks: 32768,
            total_inodes: 8192,
            first_data_block: 0,
            group_count: 4,
            inode_size: 256,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        }
    }

    fn make_batch_equivalence_geometry() -> FsGeometry {
        FsGeometry {
            blocks_per_group: 64,
            inodes_per_group: 16,
            block_size: 1024,
            total_blocks: 256,
            total_inodes: 64,
            first_data_block: 0,
            group_count: 4,
            inode_size: 128,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        }
    }

    fn make_groups(geo: &FsGeometry) -> Vec<GroupStats> {
        let bpg = u64::from(geo.blocks_per_group);
        (0..geo.group_count)
            .map(|g| {
                // Place metadata within each group's own block range so that
                // FLEX_BG cross-group checks don't create spurious reservations.
                let group_start = u64::from(g) * bpg;
                GroupStats {
                    group: GroupNumber(g),
                    free_blocks: geo.blocks_per_group,
                    free_inodes: geo.inodes_per_group,
                    used_dirs: 0,
                    block_bitmap_block: BlockNumber(group_start + 1),
                    inode_bitmap_block: BlockNumber(group_start + 2),
                    inode_table_block: BlockNumber(group_start + 3),
                    flags: 0,
                    block_bitmap_csum: 0,
                    inode_bitmap_csum: 0,
                }
            })
            .collect()
    }

    fn make_batch_equivalence_groups(geo: &FsGeometry) -> Vec<GroupStats> {
        let bpg = u64::from(geo.blocks_per_group);
        (0..geo.group_count)
            .map(|g| {
                let group_start = u64::from(g) * bpg;
                GroupStats {
                    group: GroupNumber(g),
                    free_blocks: geo.blocks_per_group,
                    free_inodes: geo.inodes_per_group,
                    used_dirs: 0,
                    block_bitmap_block: BlockNumber(group_start + 1),
                    inode_bitmap_block: BlockNumber(group_start + 2),
                    inode_table_block: BlockNumber(group_start + 3),
                    flags: 0,
                    block_bitmap_csum: 0,
                    inode_bitmap_csum: 0,
                }
            })
            .collect()
    }

    fn first_non_reserved_block(
        geo: &FsGeometry,
        groups: &[GroupStats],
        group: GroupNumber,
    ) -> u32 {
        let reserved = reserved_blocks_in_group(geo, groups, group);
        (0..geo.blocks_in_group(group))
            .find(|rel| !is_reserved(&reserved, *rel))
            .expect("test geometry should expose at least one allocatable block")
    }

    // ── Bitmap tests ────────────────────────────────────────────────────

    #[test]
    fn bitmap_get_set_clear() {
        let mut bm = vec![0u8; 4];
        assert!(!bitmap_get(&bm, 0));
        bitmap_set(&mut bm, 0);
        assert!(bitmap_get(&bm, 0));
        bitmap_clear(&mut bm, 0);
        assert!(!bitmap_get(&bm, 0));

        bitmap_set(&mut bm, 7);
        assert!(bitmap_get(&bm, 7));
        assert_eq!(bm[0], 0x80);

        bitmap_set(&mut bm, 8);
        assert!(bitmap_get(&bm, 8));
        assert_eq!(bm[1], 0x01);
    }

    #[test]
    fn bitmap_count_free_all_free() {
        let bm = vec![0u8; 2]; // 16 bits, all free
        assert_eq!(bitmap_count_free(&bm, 16), 16);
    }

    #[test]
    fn bitmap_count_free_some_allocated() {
        let mut bm = vec![0u8; 2];
        bitmap_set(&mut bm, 0);
        bitmap_set(&mut bm, 5);
        bitmap_set(&mut bm, 15);
        assert_eq!(bitmap_count_free(&bm, 16), 13);
    }

    #[test]
    fn bitmap_count_free_word_path_handles_partial_tail() {
        let mut bm = vec![0u8; 9];
        bm[8] = 0b1111_0000;
        assert_eq!(bitmap_count_free(&bm, 68), 68);
    }

    #[test]
    fn bitmap_count_free_overscan_treats_missing_bytes_as_allocated() {
        assert_eq!(bitmap_count_free(&[0u8], 16), 8);
    }

    #[test]
    fn bitmap_find_free_basic() {
        let mut bm = vec![0u8; 2];
        bitmap_set(&mut bm, 0);
        bitmap_set(&mut bm, 1);
        assert_eq!(bitmap_find_free(&bm, 16, 0), Some(2));
    }

    #[test]
    fn bitmap_find_free_wraps() {
        let mut bm = vec![0xFFu8; 2];
        bitmap_clear(&mut bm, 3);
        assert_eq!(bitmap_find_free(&bm, 16, 5), Some(3));
    }

    #[test]
    fn bitmap_find_free_byte_scan_respects_partial_bounds() {
        let mut bm = vec![0xFFu8; 2];
        bitmap_clear(&mut bm, 9);
        assert_eq!(bitmap_find_free(&bm, 10, 1), Some(9));
        assert_eq!(bitmap_find_free(&bm, 9, 1), None);
    }

    #[test]
    fn bitmap_find_free_overscan_treats_missing_bytes_as_allocated() {
        let bm = vec![0xFFu8; 1];
        assert_eq!(bitmap_find_free(&bm, 32, 0), None);
    }

    #[test]
    fn bitmap_find_contiguous_basic() {
        let mut bm = vec![0u8; 4];
        bitmap_set(&mut bm, 0);
        bitmap_set(&mut bm, 1);
        // Free: 2,3,4,5,... contiguous from 2
        assert_eq!(bitmap_find_contiguous(&bm, 32, 4, 0), Some(2));
    }

    #[test]
    fn bitmap_find_contiguous_byte_scan_extends_partial_run() {
        let bm = vec![0b0000_0011, 0x00, 0xFF];
        assert_eq!(bitmap_find_contiguous(&bm, 24, 10, 2), Some(2));
    }

    #[test]
    fn bitmap_find_contiguous_overscan_treats_missing_bytes_as_allocated() {
        let bm = vec![0x00];
        assert_eq!(bitmap_find_contiguous(&bm, 16, 9, 0), None);
    }

    #[test]
    fn bitmap_find_contiguous_none() {
        let mut bm = vec![0u8; 2];
        // Set every other bit: 0,2,4,6,8,10,12,14
        for i in (0..16).step_by(2) {
            bitmap_set(&mut bm, i);
        }
        // No 2-contiguous free bits.
        assert_eq!(bitmap_find_contiguous(&bm, 16, 2, 0), None);
    }

    /// Naive first-fit reference: pure per-bit scan, no word/byte fast paths.
    /// `bitmap_get` reports out-of-range positions as allocated, matching the
    /// production scan's treatment of a truncated bitmap.
    fn find_contiguous_linear_naive(bitmap: &[u8], count: u32, n: u32, start: u32) -> Option<u32> {
        let mut run_start = start;
        let mut run_len = 0u32;
        for idx in start..count {
            if bitmap_get(bitmap, idx) {
                run_start = idx + 1;
                run_len = 0;
            } else {
                run_len += 1;
                if run_len >= n {
                    return Some(run_start);
                }
            }
        }
        None
    }

    #[test]
    fn bitmap_find_contiguous_golden_report() {
        use std::fmt::Write as _;
        // 320 bits crossing multiple 64-bit word boundaries: all-used words,
        // an all-free word, and mixed words.
        let mut bm = vec![0xFF_u8; 40];
        for pos in [70_u32, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80] {
            bm[(pos / 8) as usize] &= !(1 << (pos % 8));
        }
        for byte in bm.iter_mut().take(24).skip(16) {
            *byte = 0x00; // bits 128..192 all free (a full aligned word)
        }
        let count = 320;
        let mut report = String::new();
        for n in [1_u32, 8, 11, 12, 32, 64, 65, 128] {
            for start in [0_u32, 1, 64, 65, 128, 200, 256] {
                let actual = bitmap_find_contiguous_linear(&bm, count, n, start);
                let expected = find_contiguous_linear_naive(&bm, count, n, start);
                assert_eq!(actual, expected, "n={n} start={start}");
                writeln!(
                    report,
                    "FIND_CONTIG_GOLDEN\t{n}\t{start}\t{}",
                    actual.map_or_else(|| String::from("None"), |p| p.to_string())
                )
                .expect("write to String");
            }
        }
        print!("{report}");
    }

    fn take_free_bits_cyclic_naive(
        bitmap: &mut [u8],
        count: u32,
        max_count: u32,
        start: u32,
    ) -> Vec<u32> {
        let mut taken = Vec::new();
        let mut search_pos = start;
        for _ in 0..max_count {
            let Some(idx) = bitmap_find_free(bitmap, count, search_pos) else {
                break;
            };
            bitmap_set(bitmap, idx);
            taken.push(idx);
            search_pos = idx + 1;
        }
        taken
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(hex, "{byte:02x}").expect("write to String");
        }
        hex
    }

    #[test]
    fn bitmap_take_free_bits_cyclic_golden_report() {
        use std::fmt::Write as _;
        let cases = vec![
            ("truncated", Vec::new(), 16, 3, 0),
            ("start_aligned_dense", vec![0xF0, 0x00, 0xFF], 24, 6, 0),
            ("unaligned_start", vec![0xEF, 0x00, 0xFE], 24, 7, 5),
            ("wraparound", vec![0xFF, 0xF0, 0x0F], 24, 8, 20),
            ("partial_count_wrap", vec![0x00, 0x00, 0x00], 20, 12, 16),
            (
                "word_window",
                vec![
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                128,
                10,
                64,
            ),
        ];

        let mut report = String::new();
        for (name, bytes, count, max_count, start) in cases {
            let mut actual_bitmap = bytes.clone();
            let mut actual = Vec::new();
            let taken =
                bitmap_take_free_bits_cyclic(&mut actual_bitmap, count, max_count, start, |idx| {
                    actual.push(idx);
                });

            let mut expected_bitmap = bytes;
            let expected =
                take_free_bits_cyclic_naive(&mut expected_bitmap, count, max_count, start);
            assert_eq!(taken as usize, actual.len(), "{name}: taken count");
            assert_eq!(actual, expected, "{name}: allocation order");
            assert_eq!(actual_bitmap, expected_bitmap, "{name}: bitmap state");

            let allocations = actual
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            writeln!(
                report,
                "BATCH_TAKE_GOLDEN\t{name}\tcount={count}\tmax={max_count}\tstart={start}\talloc={allocations}\tbitmap={}",
                hex_bytes(&actual_bitmap)
            )
            .expect("write to String");
        }
        print!("{report}");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        #[test]
        fn proptest_find_contiguous_matches_naive(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..48),
            n in 1u32..80,
            start_frac in 0u32..200,
        ) {
            let count = u32::try_from(bytes.len()).expect("len fits u32") * 8;
            let start = (start_frac % (count + 1)).min(count);
            let got = bitmap_find_contiguous_linear(&bytes, count, n, start);
            let want = find_contiguous_linear_naive(&bytes, count, n, start);
            proptest::prop_assert_eq!(got, want, "n={} start={}", n, start);
        }
    }

    // ── Geometry tests ──────────────────────────────────────────────────

    #[test]
    fn geometry_group_block_conversion() {
        let geo = make_geometry();
        let abs = geo.group_block_to_absolute(GroupNumber(1), 42);
        assert_eq!(abs, BlockNumber(8192 + 42));
        let (g, off) = geo.absolute_to_group_block(abs);
        assert_eq!(g, GroupNumber(1));
        assert_eq!(off, 42);
    }

    #[test]
    fn geometry_blocks_in_group() {
        let mut geo = make_geometry();
        assert_eq!(geo.blocks_in_group(GroupNumber(0)), 8192);
        // Last group might be shorter: 32768 - 3*8192 = 8192 (exact fit).
        assert_eq!(geo.blocks_in_group(GroupNumber(3)), 8192);

        // Make total not evenly divisible.
        geo.total_blocks = 30000;
        // Groups 0,1,2 have 8192 each = 24576. Group 3 has 30000-24576 = 5424.
        assert_eq!(geo.blocks_in_group(GroupNumber(3)), 5424);
    }

    #[test]
    fn geometry_inodes_in_group() {
        let mut geo = make_geometry();
        // 4 groups * 2048 inodes_per_group = 8192 total_inodes (exact fit)
        assert_eq!(geo.inodes_in_group(GroupNumber(0)), 2048);
        assert_eq!(geo.inodes_in_group(GroupNumber(3)), 2048);

        // Make total not evenly divisible: 7000 total inodes
        // Groups 0,1,2 have 2048 each = 6144. Group 3 has 7000-6144 = 856.
        geo.total_inodes = 7000;
        assert_eq!(geo.inodes_in_group(GroupNumber(0)), 2048);
        assert_eq!(geo.inodes_in_group(GroupNumber(2)), 2048);
        assert_eq!(geo.inodes_in_group(GroupNumber(3)), 856);
    }

    #[test]
    fn reserved_inodes_large_group_index_does_not_overflow() {
        let mut geo = make_geometry();
        geo.inodes_per_group = 65_536;
        geo.total_inodes = u32::MAX;
        geo.group_count = u32::MAX;
        geo.first_inode = 32;

        let reserved = reserved_inodes_in_group(&geo, GroupNumber(65_536));
        assert!(reserved.is_empty());
    }

    // ── Block allocation tests ──────────────────────────────────────────

    #[test]
    fn alloc_single_block() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let result = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &AllocHint::default());
        assert!(result.is_ok());
        let alloc = result.unwrap();
        assert_eq!(alloc.count, 1);
        assert_eq!(groups[0].free_blocks, 8191);
    }

    #[test]
    fn alloc_contiguous_blocks() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let hint = AllocHint {
            goal_group: Some(GroupNumber(1)),
            ..Default::default()
        };
        let alloc = alloc_blocks(&cx, &dev, &geo, &mut groups, 4, &hint).unwrap();
        assert_eq!(alloc.count, 4);
        // Should be in group 1.
        let (g, _) = geo.absolute_to_group_block(alloc.start);
        assert_eq!(g, GroupNumber(1));
        assert_eq!(groups[1].free_blocks, 8188);
    }

    #[test]
    fn alloc_and_free_roundtrip() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let alloc = alloc_blocks(&cx, &dev, &geo, &mut groups, 3, &AllocHint::default()).unwrap();
        assert_eq!(groups[0].free_blocks, 8189);

        free_blocks(&cx, &dev, &geo, &mut groups, alloc.start, alloc.count).unwrap();
        assert_eq!(groups[0].free_blocks, 8192);
    }

    #[test]
    fn alloc_no_space_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        // Mark all groups as having 0 free blocks.
        for g in &mut groups {
            g.free_blocks = 0;
        }

        let result = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &AllocHint::default());
        assert!(matches!(result, Err(FfsError::NoSpace)));
    }

    // ── Inode allocation tests ──────────────────────────────────────────

    #[test]
    fn alloc_inode_basic() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let result = alloc_inode(&cx, &dev, &geo, &mut groups, GroupNumber(0), false).unwrap();
        assert_eq!(result.ino, InodeNumber(11));
        assert_eq!(result.group, GroupNumber(0));
        assert_eq!(groups[0].free_inodes, 2047);
    }

    #[test]
    fn alloc_inode_directory_orlov() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        // Make group 0 have many dirs, group 2 have fewest.
        groups[0].used_dirs = 100;
        groups[1].used_dirs = 50;
        groups[2].used_dirs = 10;
        groups[3].used_dirs = 30;

        let result = alloc_inode(&cx, &dev, &geo, &mut groups, GroupNumber(0), true).unwrap();
        // Orlov should prefer group 2 (fewest dirs, above-average free).
        assert_eq!(result.group, GroupNumber(2));
    }

    #[test]
    fn alloc_and_free_inode_roundtrip() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let result = alloc_inode(&cx, &dev, &geo, &mut groups, GroupNumber(1), false).unwrap();
        assert_eq!(groups[1].free_inodes, 2047);

        free_inode(&cx, &dev, &geo, &mut groups, result.ino).unwrap();
        assert_eq!(groups[1].free_inodes, 2048);
    }

    #[test]
    fn alloc_inode_no_space() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        for g in &mut groups {
            g.free_inodes = 0;
        }

        let result = alloc_inode(&cx, &dev, &geo, &mut groups, GroupNumber(0), false);
        assert!(matches!(result, Err(FfsError::NoSpace)));
    }

    #[test]
    fn alloc_inode_allows_last_real_inode_in_short_final_group() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut geo = make_geometry();
        geo.total_inodes = geo.inodes_per_group + 2;
        let mut groups = make_groups(&geo);
        for group in &mut groups {
            group.free_inodes = 0;
        }
        groups[1].free_inodes = 1;

        let mut bitmap = vec![0u8; 4096];
        bitmap_set(&mut bitmap, 0);
        dev.write_block(&cx, groups[1].inode_bitmap_block, &bitmap)
            .unwrap();

        let result = alloc_inode(&cx, &dev, &geo, &mut groups, GroupNumber(1), false).unwrap();
        assert_eq!(result.group, GroupNumber(1));
        assert_eq!(result.ino, InodeNumber(u64::from(geo.total_inodes)));
    }

    #[test]
    fn alloc_inode_rejects_bits_past_short_final_group() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut geo = make_geometry();
        geo.total_inodes = geo.inodes_per_group + 2;
        let mut groups = make_groups(&geo);
        for group in &mut groups {
            group.free_inodes = 0;
        }
        groups[1].free_inodes = 1;

        let mut bitmap = vec![0u8; 4096];
        bitmap_set(&mut bitmap, 0);
        bitmap_set(&mut bitmap, 1);
        dev.write_block(&cx, groups[1].inode_bitmap_block, &bitmap)
            .unwrap();

        let result = alloc_inode(&cx, &dev, &geo, &mut groups, GroupNumber(1), false);
        assert!(matches!(result, Err(FfsError::NoSpace)));
    }

    #[test]
    fn free_inode_rejects_inode_past_total_count() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut geo = make_geometry();
        geo.total_inodes = geo.inodes_per_group + 2;
        let mut groups = make_groups(&geo);

        let result = free_inode(
            &cx,
            &dev,
            &geo,
            &mut groups,
            InodeNumber(u64::from(geo.total_inodes) + 1),
        );
        assert!(
            matches!(result, Err(FfsError::Corruption { .. })),
            "freeing an inode past s_inodes_count must be rejected"
        );
    }

    #[test]
    fn alloc_multiple_blocks_same_group() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let a1 = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &AllocHint::default()).unwrap();
        let a2 = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &AllocHint::default()).unwrap();
        // Second allocation should get the next free block.
        assert_eq!(a2.start.0, a1.start.0 + 1);
    }

    // ── Reserved block tests ───────────────────────────────────────────

    #[test]
    fn reserved_blocks_includes_bitmaps_and_inode_table() {
        let geo = make_geometry();
        let groups = make_groups(&geo);

        // Group 0: base metadata at rel 0..1, block bitmap at 1, inode bitmap at 2,
        // inode table at 3.
        // Inode table: 2048 inodes * 256 bytes / 4096 bytes = 128 blocks.
        let reserved = reserved_blocks_in_group(&geo, &groups, GroupNumber(0));

        // Should contain base metadata block 0, bitmap block 1, inode bitmap 2,
        // and inode table blocks 3..130.
        assert!(
            reserved.contains(&0),
            "superblock/GDT block should be reserved"
        );
        assert!(reserved.contains(&1), "block bitmap should be reserved");
        assert!(reserved.contains(&2), "inode bitmap should be reserved");
        assert!(
            reserved.contains(&3),
            "inode table start should be reserved"
        );
        assert!(
            reserved.contains(&130),
            "inode table end (3+127) should be reserved"
        );
        assert!(
            !reserved.contains(&131),
            "block after inode table should NOT be reserved"
        );
        // Total: 2 (superblock+GDT) + 1 (inode bitmap beyond dedup) + 128 (inode table) = 131
        assert_eq!(reserved.len(), 131);
    }

    // ── Persistent allocator tests ─────────────────────────────────────

    fn make_persist_ctx() -> PersistCtx {
        PersistCtx {
            gdt_block: BlockNumber(50), // arbitrary GDT location
            desc_size: 32,
            has_metadata_csum: false,
            csum_seed: 0,
            uuid: [0; 16],
            group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::None,
            blocks_per_group: 32768,
            inodes_per_group: 2048,
        }
    }

    fn seed_gdt_block(dev: &MemBlockDevice, pctx: &PersistCtx, groups: &[GroupStats]) {
        // Write a GDT block with group descriptors packed at desc_size intervals.
        let block_size = dev.block_size() as usize;
        let ds = usize::from(pctx.desc_size);
        let mut buf = vec![0u8; block_size];
        for (i, gs) in groups.iter().enumerate() {
            let offset = i * ds;
            if offset + ds > block_size {
                break;
            }
            let gd = Ext4GroupDesc {
                block_bitmap: gs.block_bitmap_block.0,
                inode_bitmap: gs.inode_bitmap_block.0,
                inode_table: gs.inode_table_block.0,
                free_blocks_count: gs.free_blocks,
                free_inodes_count: gs.free_inodes,
                used_dirs_count: gs.used_dirs,
                itable_unused: 0,
                flags: gs.flags,
                checksum: 0,
                block_bitmap_csum: 0,
                inode_bitmap_csum: 0,
            };
            gd.write_to_bytes(&mut buf[offset..], pctx.desc_size)
                .unwrap();
        }
        let cx = test_cx();
        dev.write_block(&cx, pctx.gdt_block, &buf).unwrap();
    }

    fn make_batch_equivalence_persist_ctx(geo: &FsGeometry) -> PersistCtx {
        PersistCtx {
            gdt_block: BlockNumber(200),
            desc_size: geo.desc_size,
            has_metadata_csum: false,
            csum_seed: 0,
            uuid: [0; 16],
            group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::None,
            blocks_per_group: geo.blocks_per_group,
            inodes_per_group: geo.inodes_per_group,
        }
    }

    fn seed_batch_equivalence_bitmaps(
        cx: &Cx,
        dev: &MemBlockDevice,
        geo: &FsGeometry,
        groups: &mut [GroupStats],
        occupied_by_group: &[Vec<u32>],
    ) {
        for group_idx in 0..geo.group_count {
            let group = GroupNumber(group_idx);
            let gidx = group_idx as usize;
            let mut bitmap = vec![0_u8; geo.block_size as usize];
            let blocks_in_group = geo.blocks_in_group(group);
            for rel in reserved_blocks_in_group(geo, groups, group) {
                bitmap_set(&mut bitmap, rel);
            }
            if let Some(occupied) = occupied_by_group.get(gidx) {
                for &rel in occupied {
                    if rel < blocks_in_group {
                        bitmap_set(&mut bitmap, rel);
                    }
                }
            }
            groups[gidx].free_blocks = bitmap_count_free(&bitmap, blocks_in_group);
            dev.write_block(cx, groups[gidx].block_bitmap_block, &bitmap)
                .unwrap();
        }
    }

    fn make_batch_equivalence_world(
        occupied_by_group: &[Vec<u32>],
    ) -> (MemBlockDevice, FsGeometry, Vec<GroupStats>, PersistCtx) {
        let cx = test_cx();
        let geo = make_batch_equivalence_geometry();
        let dev = MemBlockDevice::new(geo.block_size);
        let mut groups = make_batch_equivalence_groups(&geo);
        seed_batch_equivalence_bitmaps(&cx, &dev, &geo, &mut groups, occupied_by_group);
        let pctx = make_batch_equivalence_persist_ctx(&geo);
        seed_gdt_block(&dev, &pctx, &groups);
        (dev, geo, groups, pctx)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct BatchAllocationSnapshot {
        free_blocks: Vec<u32>,
        block_bitmaps: Vec<Vec<u8>>,
        gdt_free_blocks: Vec<u32>,
    }

    fn batch_allocation_snapshot(
        cx: &Cx,
        dev: &MemBlockDevice,
        geo: &FsGeometry,
        groups: &[GroupStats],
        pctx: &PersistCtx,
    ) -> BatchAllocationSnapshot {
        let block_bitmaps = groups
            .iter()
            .map(|group| {
                dev.read_block(cx, group.block_bitmap_block)
                    .unwrap()
                    .as_slice()
                    .to_vec()
            })
            .collect();

        BatchAllocationSnapshot {
            free_blocks: groups.iter().map(|group| group.free_blocks).collect(),
            block_bitmaps,
            gdt_free_blocks: (0..geo.group_count)
                .map(|group| read_gdt_free_blocks(cx, dev, pctx, GroupNumber(group)))
                .collect(),
        }
    }

    fn read_gdt_free_blocks(
        cx: &Cx,
        dev: &MemBlockDevice,
        pctx: &PersistCtx,
        group: GroupNumber,
    ) -> u32 {
        read_gdt_group_desc(cx, dev, pctx, group).free_blocks_count
    }

    fn read_gdt_free_inodes(
        cx: &Cx,
        dev: &MemBlockDevice,
        pctx: &PersistCtx,
        group: GroupNumber,
    ) -> u32 {
        read_gdt_group_desc(cx, dev, pctx, group).free_inodes_count
    }

    fn read_gdt_group_desc(
        cx: &Cx,
        dev: &MemBlockDevice,
        pctx: &PersistCtx,
        group: GroupNumber,
    ) -> Ext4GroupDesc {
        let ds = usize::from(pctx.desc_size);
        let descs_per_block = dev.block_size() as usize / ds;
        let group_index = group.0 as usize;
        let gdt_block_idx = group_index / descs_per_block;
        let offset_in_block = (group_index % descs_per_block) * ds;
        let raw = dev
            .read_block(cx, BlockNumber(pctx.gdt_block.0 + gdt_block_idx as u64))
            .unwrap();
        Ext4GroupDesc::parse_from_bytes(&raw.as_slice()[offset_in_block..], pctx.desc_size).unwrap()
    }

    fn rollback_single_allocations(
        cx: &Cx,
        dev: &MemBlockDevice,
        geo: &FsGeometry,
        groups: &mut [GroupStats],
        pctx: &PersistCtx,
        allocations: &[BlockAlloc],
    ) {
        for alloc in allocations.iter().rev() {
            free_blocks_persist(cx, dev, geo, groups, alloc.start, alloc.count, pctx).unwrap();
        }
    }

    fn assert_batch_single_equivalence(
        occupied_by_group: &[Vec<u32>],
        request: u32,
        hint: &AllocHint,
    ) {
        let cx = test_cx();
        let (dev_batch, geo, mut groups_batch, pctx) =
            make_batch_equivalence_world(occupied_by_group);
        let (dev_single, _, mut groups_single, _) = make_batch_equivalence_world(occupied_by_group);
        let initial = batch_allocation_snapshot(&cx, &dev_batch, &geo, &groups_batch, &pctx);

        let batch_result = alloc_blocks_batch_persist(
            &cx,
            &dev_batch,
            &geo,
            &mut groups_batch,
            request,
            hint,
            &pctx,
        );

        let mut single_allocations = Vec::new();
        let mut single_error = None;
        for _ in 0..request {
            match alloc_blocks_persist(&cx, &dev_single, &geo, &mut groups_single, 1, hint, &pctx) {
                Ok(alloc) => single_allocations.push(alloc),
                Err(error) => {
                    single_error = Some(error);
                    break;
                }
            }
        }
        if single_error.is_some() {
            rollback_single_allocations(
                &cx,
                &dev_single,
                &geo,
                &mut groups_single,
                &pctx,
                &single_allocations,
            );
        }

        match (batch_result, single_error) {
            (Ok(batch_allocations), None) => {
                assert_eq!(batch_allocations, single_allocations);
                assert_eq!(
                    batch_allocation_snapshot(&cx, &dev_batch, &geo, &groups_batch, &pctx),
                    batch_allocation_snapshot(&cx, &dev_single, &geo, &groups_single, &pctx)
                );
            }
            (Err(FfsError::NoSpace), Some(FfsError::NoSpace)) => {
                assert_eq!(
                    batch_allocation_snapshot(&cx, &dev_batch, &geo, &groups_batch, &pctx),
                    initial
                );
                assert_eq!(
                    batch_allocation_snapshot(&cx, &dev_single, &geo, &groups_single, &pctx),
                    initial
                );
            }
            (batch, single) => panic!(
                "batch and single allocation outcomes diverged: batch={batch:?} single={single:?}"
            ),
        }
    }

    fn occupied_all_allocatable_except(
        geo: &FsGeometry,
        groups: &[GroupStats],
        group: GroupNumber,
        free_rels: &[u32],
    ) -> Vec<u32> {
        let reserved = reserved_blocks_in_group(geo, groups, group);
        (0..geo.blocks_in_group(group))
            .filter(|rel| !is_reserved(&reserved, *rel) && !free_rels.contains(rel))
            .collect()
    }

    fn assert_group_bitmap_checksums_valid(
        cx: &Cx,
        dev: &MemBlockDevice,
        groups: &[GroupStats],
        pctx: &PersistCtx,
        group: GroupNumber,
    ) {
        let ds = usize::from(pctx.desc_size);
        let descs_per_block = dev.block_size() as usize / ds;
        let gdt_block_idx = group.0 as usize / descs_per_block;
        let offset_in_block = (group.0 as usize % descs_per_block) * ds;
        let gdt_raw = dev
            .read_block(cx, BlockNumber(pctx.gdt_block.0 + gdt_block_idx as u64))
            .unwrap();
        let gd =
            Ext4GroupDesc::parse_from_bytes(&gdt_raw.as_slice()[offset_in_block..], pctx.desc_size)
                .unwrap();
        let stats = &groups[group.0 as usize];
        let block_bitmap = dev.read_block(cx, stats.block_bitmap_block).unwrap();
        let inode_bitmap = dev.read_block(cx, stats.inode_bitmap_block).unwrap();

        ffs_ondisk::ext4::verify_block_bitmap_checksum(
            block_bitmap.as_slice(),
            pctx.csum_seed,
            pctx.blocks_per_group,
            &gd,
            pctx.desc_size,
        )
        .unwrap();
        ffs_ondisk::ext4::verify_inode_bitmap_checksum(
            inode_bitmap.as_slice(),
            pctx.csum_seed,
            pctx.inodes_per_group,
            &gd,
            pctx.desc_size,
        )
        .unwrap();
    }

    #[test]
    fn alloc_persist_skips_reserved_and_updates_gdt() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        let alloc = alloc_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            1,
            &AllocHint::default(),
            &pctx,
        )
        .unwrap();

        let expected_rel = first_non_reserved_block(&geo, &groups, GroupNumber(0));
        assert_eq!(
            alloc.start,
            geo.group_block_to_absolute(GroupNumber(0), expected_rel)
        );

        // In-memory stats should be decremented.
        assert_eq!(groups[0].free_blocks, 8191);

        // On-disk GDT should also be updated.
        let gdt_raw = dev.read_block(&cx, pctx.gdt_block).unwrap();
        let gd = Ext4GroupDesc::parse_from_bytes(gdt_raw.as_slice(), pctx.desc_size).unwrap();
        assert_eq!(gd.free_blocks_count, 8191);
    }

    #[test]
    fn alloc_persist_gdt_write_failure_restores_bitmap_and_group_stats() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        let initial_free = groups[0].free_blocks;
        let bitmap_block = groups[0].block_bitmap_block;
        let initial_bitmap = dev
            .read_block(&cx, bitmap_block)
            .unwrap()
            .as_slice()
            .to_vec();
        let initial_gdt_free = read_gdt_free_blocks(&cx, &dev, &pctx, GroupNumber(0));
        let failing = FailGdtWriteDevice::new(&dev, pctx.gdt_block);

        let err = alloc_blocks_persist(
            &cx,
            &failing,
            &geo,
            &mut groups,
            1,
            &AllocHint::default(),
            &pctx,
        )
        .unwrap_err();

        assert!(matches!(err, FfsError::Io(_)));
        assert_eq!(groups[0].free_blocks, initial_free);
        assert_eq!(
            dev.read_block(&cx, bitmap_block).unwrap().as_slice(),
            initial_bitmap.as_slice()
        );
        assert_eq!(
            read_gdt_free_blocks(&cx, &dev, &pctx, GroupNumber(0)),
            initial_gdt_free
        );
    }

    #[test]
    fn free_persist_gdt_write_failure_restores_bitmap_and_group_stats() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        let alloc = alloc_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            1,
            &AllocHint::default(),
            &pctx,
        )
        .unwrap();
        let initial_free = groups[0].free_blocks;
        let bitmap_block = groups[0].block_bitmap_block;
        let initial_bitmap = dev
            .read_block(&cx, bitmap_block)
            .unwrap()
            .as_slice()
            .to_vec();
        let initial_gdt_free = read_gdt_free_blocks(&cx, &dev, &pctx, GroupNumber(0));
        let failing = FailGdtWriteDevice::new(&dev, pctx.gdt_block);

        let err = free_blocks_persist(&cx, &failing, &geo, &mut groups, alloc.start, 1, &pctx)
            .unwrap_err();

        assert!(matches!(err, FfsError::Io(_)));
        assert_eq!(groups[0].free_blocks, initial_free);
        assert_eq!(
            dev.read_block(&cx, bitmap_block).unwrap().as_slice(),
            initial_bitmap.as_slice()
        );
        assert_eq!(
            read_gdt_free_blocks(&cx, &dev, &pctx, GroupNumber(0)),
            initial_gdt_free
        );
    }

    #[test]
    fn alloc_inode_persist_gdt_write_failure_restores_bitmap_and_group_stats() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        let initial_free = groups[0].free_inodes;
        let bitmap_block = groups[0].inode_bitmap_block;
        let initial_bitmap = dev
            .read_block(&cx, bitmap_block)
            .unwrap()
            .as_slice()
            .to_vec();
        let initial_gdt_free = read_gdt_free_inodes(&cx, &dev, &pctx, GroupNumber(0));
        let failing = FailGdtWriteDevice::new(&dev, pctx.gdt_block);

        let err = alloc_inode_persist(
            &cx,
            &failing,
            &geo,
            &mut groups,
            GroupNumber(0),
            false,
            &pctx,
        )
        .unwrap_err();

        assert!(matches!(err, FfsError::Io(_)));
        assert_eq!(groups[0].free_inodes, initial_free);
        assert_eq!(
            dev.read_block(&cx, bitmap_block).unwrap().as_slice(),
            initial_bitmap.as_slice()
        );
        assert_eq!(
            read_gdt_free_inodes(&cx, &dev, &pctx, GroupNumber(0)),
            initial_gdt_free
        );
    }

    #[test]
    fn free_inode_persist_gdt_write_failure_restores_bitmap_and_group_stats() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        let alloc = alloc_inode_persist(&cx, &dev, &geo, &mut groups, GroupNumber(0), false, &pctx)
            .unwrap();
        let initial_free = groups[0].free_inodes;
        let bitmap_block = groups[0].inode_bitmap_block;
        let initial_bitmap = dev
            .read_block(&cx, bitmap_block)
            .unwrap()
            .as_slice()
            .to_vec();
        let initial_gdt_free = read_gdt_free_inodes(&cx, &dev, &pctx, GroupNumber(0));
        let failing = FailGdtWriteDevice::new(&dev, pctx.gdt_block);

        let err =
            free_inode_persist(&cx, &failing, &geo, &mut groups, alloc.ino, &pctx).unwrap_err();

        assert!(matches!(err, FfsError::Io(_)));
        assert_eq!(groups[0].free_inodes, initial_free);
        assert_eq!(
            dev.read_block(&cx, bitmap_block).unwrap().as_slice(),
            initial_bitmap.as_slice()
        );
        assert_eq!(
            read_gdt_free_inodes(&cx, &dev, &pctx, GroupNumber(0)),
            initial_gdt_free
        );
    }

    #[test]
    fn alloc_persist_never_allocates_reserved_metadata() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        // Pre-mark the first allocatable data block so the allocator must
        // move forward without ever returning reserved metadata.
        let first_allocatable = first_non_reserved_block(&geo, &groups, GroupNumber(0));
        let mut bitmap = vec![0u8; 4096];
        bitmap_set(&mut bitmap, first_allocatable);
        dev.write_block(&cx, groups[0].block_bitmap_block, &bitmap)
            .unwrap();

        let alloc = alloc_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            1,
            &AllocHint::default(),
            &pctx,
        )
        .unwrap();

        // Blocks 1..130 are reserved (bitmap, inode bitmap, inode table).
        // The allocator should skip them and return block 131.
        let reserved = reserved_blocks_in_group(&geo, &groups, GroupNumber(0));
        let (_, rel) = geo.absolute_to_group_block(alloc.start);
        assert!(
            !is_reserved(&reserved, rel),
            "allocated block {} (rel {}) is reserved",
            alloc.start.0,
            rel
        );
        let expected_rel = ((first_allocatable + 1)..geo.blocks_in_group(GroupNumber(0)))
            .find(|candidate| !is_reserved(&reserved, *candidate))
            .expect("test geometry should expose a second allocatable block");
        assert_eq!(
            rel, expected_rel,
            "should allocate next non-reserved free block"
        );
    }

    #[test]
    fn free_persist_detects_double_free() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        // Allocate a block.
        let alloc = alloc_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            1,
            &AllocHint::default(),
            &pctx,
        )
        .unwrap();

        // Free it.
        free_blocks_persist(&cx, &dev, &geo, &mut groups, alloc.start, 1, &pctx).unwrap();

        // Double-free should fail.
        let result = free_blocks_persist(&cx, &dev, &geo, &mut groups, alloc.start, 1, &pctx);
        assert!(result.is_err(), "double-free should return error");
    }

    #[test]
    fn free_persist_rejects_reserved_block() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        // Try to free the block bitmap block (reserved).
        let bitmap_block = groups[0].block_bitmap_block;
        let result = free_blocks_persist(&cx, &dev, &geo, &mut groups, bitmap_block, 1, &pctx);
        assert!(
            result.is_err(),
            "freeing a reserved metadata block should fail"
        );
    }

    #[test]
    fn alloc_and_free_persist_roundtrip() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        let original_free = groups[0].free_blocks;

        let alloc = alloc_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            3,
            &AllocHint::default(),
            &pctx,
        )
        .unwrap();
        assert_eq!(groups[0].free_blocks, original_free - 3);

        free_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            alloc.start,
            alloc.count,
            &pctx,
        )
        .unwrap();
        assert_eq!(groups[0].free_blocks, original_free);

        // Verify on-disk GDT matches.
        let gdt_raw = dev.read_block(&cx, pctx.gdt_block).unwrap();
        let gd = Ext4GroupDesc::parse_from_bytes(gdt_raw.as_slice(), pctx.desc_size).unwrap();
        assert_eq!(gd.free_blocks_count, original_free);
    }

    #[test]
    fn alloc_and_free_persist_keep_bitmap_checksums_in_sync() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut geo = make_geometry();
        geo.desc_size = 64;
        let mut groups = make_groups(&geo);
        let pctx = PersistCtx {
            gdt_block: BlockNumber(50),
            desc_size: 64,
            has_metadata_csum: true,
            csum_seed: 0x1357_2468,
            uuid: [0x5A; 16],
            group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::MetadataCsum,
            blocks_per_group: geo.blocks_per_group,
            inodes_per_group: geo.inodes_per_group,
        };
        seed_gdt_block(&dev, &pctx, &groups);

        let first = alloc_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            2,
            &AllocHint::default(),
            &pctx,
        )
        .unwrap();
        assert_group_bitmap_checksums_valid(&cx, &dev, &groups, &pctx, GroupNumber(0));

        free_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            first.start,
            first.count,
            &pctx,
        )
        .unwrap();
        assert_group_bitmap_checksums_valid(&cx, &dev, &groups, &pctx, GroupNumber(0));

        let second = alloc_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            3,
            &AllocHint::default(),
            &pctx,
        )
        .unwrap();
        assert_eq!(second.count, 3);
        assert_group_bitmap_checksums_valid(&cx, &dev, &groups, &pctx, GroupNumber(0));
    }

    // ── bd-1xe.5: ext4 read path allocator bitmap tests ─────────────────

    // Allocator Bitmap Test 6: Read block bitmap — free/used status correct
    #[test]
    fn readpath_block_bitmap_free_used_correct() {
        let mut bm = vec![0u8; 128]; // 1024 bits

        // Mark blocks 0-9 as used (typical for metadata reservation).
        for i in 0..10 {
            bitmap_set(&mut bm, i);
        }

        // Verify used blocks report correctly.
        for i in 0..10 {
            assert!(bitmap_get(&bm, i), "block {i} should be used (allocated)");
        }

        // Verify free blocks report correctly.
        for i in 10..64 {
            assert!(!bitmap_get(&bm, i), "block {i} should be free");
        }
    }

    // Allocator Bitmap Test 7: Read inode bitmap — free/used status correct
    #[test]
    fn readpath_inode_bitmap_free_used_correct() {
        let mut bm = vec![0u8; 32]; // 256 bits (inodes_per_group)

        // Mark inodes 0-10 as allocated (root inode + reserved + first user inodes).
        for i in 0..11 {
            bitmap_set(&mut bm, i);
        }

        // Verify allocated inodes.
        for i in 0..11 {
            assert!(bitmap_get(&bm, i), "inode {i} should be allocated");
        }

        // Verify free inodes.
        for i in 11..32 {
            assert!(!bitmap_get(&bm, i), "inode {i} should be free");
        }

        // Free count should match.
        assert_eq!(
            bitmap_count_free(&bm, 256),
            256 - 11,
            "free inode count should be total minus allocated"
        );
    }

    // Allocator Bitmap Test 8: Free block count matches bitmap popcount
    #[test]
    fn readpath_free_block_count_matches_popcount() {
        let blocks_per_group: u32 = 8192;
        let mut bm = vec![0u8; (blocks_per_group / 8) as usize];

        // Allocate specific blocks: 0, 1, 2 (superblock/GDT), 100, 200, 500
        let allocated = [0, 1, 2, 100, 200, 500];
        for &b in &allocated {
            bitmap_set(&mut bm, b);
        }

        let free = bitmap_count_free(&bm, blocks_per_group);
        let expected_free = blocks_per_group - u32::try_from(allocated.len()).unwrap();
        assert_eq!(
            free,
            expected_free,
            "free count ({free}) should equal blocks_per_group ({blocks_per_group}) minus allocated ({})",
            allocated.len()
        );

        // Double-check by counting set bits manually.
        let used: u32 = (0..blocks_per_group)
            .filter(|&i| bitmap_get(&bm, i))
            .count()
            .try_into()
            .unwrap();
        assert_eq!(used, u32::try_from(allocated.len()).unwrap());
        assert_eq!(free + used, blocks_per_group);
    }

    // Allocator Bitmap Test 9: Reserved blocks excluded from free count
    #[test]
    fn readpath_reserved_blocks_excluded_from_free() {
        let blocks_per_group: u32 = 64;
        let mut bm = vec![0u8; (blocks_per_group / 8) as usize]; // 8 bytes

        // Reserve first 5 blocks (superblock, GDT, bitmaps, inode table).
        let reserved_count = 5_u32;
        for i in 0..reserved_count {
            bitmap_set(&mut bm, i);
        }

        let free = bitmap_count_free(&bm, blocks_per_group);
        assert_eq!(
            free,
            blocks_per_group - reserved_count,
            "reserved blocks should not count as free"
        );

        // Find first free block — should skip reserved.
        let first_free = bitmap_find_free(&bm, blocks_per_group, 0);
        assert_eq!(
            first_free,
            Some(reserved_count),
            "first free block should be after reserved area"
        );
    }

    // ── Error-path and boundary hardening tests ────────────────────────

    #[test]
    fn reserved_blocks_out_of_range_group_returns_empty() {
        let geo = make_geometry();
        let groups = make_groups(&geo);
        // Group 99 is well beyond the 4 groups we created.
        let reserved = reserved_blocks_in_group(&geo, &groups, GroupNumber(99));
        assert!(
            reserved.is_empty(),
            "out-of-range group should return empty"
        );
    }

    #[test]
    fn reserved_blocks_includes_bitmap_and_inode_table() {
        let geo = make_geometry();
        let groups = make_groups(&geo);

        let reserved = reserved_blocks_in_group(&geo, &groups, GroupNumber(0));
        // Group 0 has base metadata at 0..1, block_bitmap at 1,
        // inode_bitmap at 2, inode_table at 3..130.
        // (2048 inodes * 256 bytes / 4096 block_size = 128 blocks for inode table)
        assert!(
            reserved.contains(&0),
            "superblock/GDT block should be reserved, got: {reserved:?}"
        );
        assert!(
            reserved.contains(&1),
            "block bitmap should be reserved, got: {reserved:?}"
        );
        assert!(
            reserved.contains(&2),
            "inode bitmap should be reserved, got: {reserved:?}"
        );
        assert!(
            reserved.contains(&3),
            "first inode table block should be reserved"
        );
        assert!(
            reserved.contains(&130),
            "last inode table block should be reserved"
        );
        assert!(
            !reserved.contains(&131),
            "block past inode table should not be reserved"
        );
        assert_eq!(
            reserved.len(),
            131,
            "group 0 should reserve 131 metadata blocks"
        );
    }

    #[test]
    fn free_blocks_group_out_of_range_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        // Block far beyond total_blocks → group out of range.
        let result = free_blocks(&cx, &dev, &geo, &mut groups, BlockNumber(1_000_000), 1);
        assert!(result.is_err());
    }

    #[test]
    fn free_blocks_cross_boundary_updates_each_group_segment() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut geo = make_geometry();
        let mut groups = make_groups(&geo);
        geo.feature_ro_compat.0 |= ffs_ondisk::Ext4RoCompatFeatures::SPARSE_SUPER.0;
        geo.feature_ro_compat.0 |= ffs_ondisk::Ext4RoCompatFeatures::BIGALLOC.0;
        geo.cluster_ratio = 4;

        let group2_start = u64::from(geo.blocks_per_group) * 2;
        groups[2].block_bitmap_block = BlockNumber(group2_start + 64);
        groups[2].inode_bitmap_block = BlockNumber(group2_start + 65);
        groups[2].inode_table_block = BlockNumber(group2_start + 96);

        let tail_start = geo.blocks_in_group(GroupNumber(1)) - 2;
        let mut group1_bitmap = dev
            .read_block(&cx, groups[1].block_bitmap_block)
            .unwrap()
            .as_slice()
            .to_vec();
        for idx in tail_start..tail_start + 2 {
            bitmap_set(&mut group1_bitmap, idx);
        }
        dev.write_block(&cx, groups[1].block_bitmap_block, &group1_bitmap)
            .unwrap();
        groups[1].free_blocks -= 2;

        let mut group2_bitmap = dev
            .read_block(&cx, groups[2].block_bitmap_block)
            .unwrap()
            .as_slice()
            .to_vec();
        for idx in 0..3 {
            bitmap_set(&mut group2_bitmap, idx);
        }
        dev.write_block(&cx, groups[2].block_bitmap_block, &group2_bitmap)
            .unwrap();
        groups[2].free_blocks -= 3;

        let start = geo.group_block_to_absolute(GroupNumber(1), tail_start);
        free_blocks(&cx, &dev, &geo, &mut groups, start, 5).unwrap();

        assert_eq!(groups[1].free_blocks, geo.blocks_in_group(GroupNumber(1)));
        assert_eq!(groups[2].free_blocks, geo.blocks_in_group(GroupNumber(2)));
    }

    #[test]
    fn free_blocks_persist_cross_boundary_splits_bigalloc_segments() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut geo = make_geometry();
        let mut groups = make_groups(&geo);
        geo.feature_ro_compat.0 |= ffs_ondisk::Ext4RoCompatFeatures::SPARSE_SUPER.0;
        geo.feature_ro_compat.0 |= ffs_ondisk::Ext4RoCompatFeatures::BIGALLOC.0;
        geo.cluster_ratio = 4;

        let group2_start = u64::from(geo.blocks_per_group) * 2;
        groups[2].block_bitmap_block = BlockNumber(group2_start + 64);
        groups[2].inode_bitmap_block = BlockNumber(group2_start + 65);
        groups[2].inode_table_block = BlockNumber(group2_start + 96);

        let pctx = make_persist_ctx();
        let tail_start = geo.blocks_in_group(GroupNumber(1)) - 2;

        let mut group1_bitmap = dev
            .read_block(&cx, groups[1].block_bitmap_block)
            .unwrap()
            .as_slice()
            .to_vec();
        for idx in tail_start..tail_start + 2 {
            bitmap_set(&mut group1_bitmap, idx);
        }
        dev.write_block(&cx, groups[1].block_bitmap_block, &group1_bitmap)
            .unwrap();
        groups[1].free_blocks -= 2;

        let mut group2_bitmap = dev
            .read_block(&cx, groups[2].block_bitmap_block)
            .unwrap()
            .as_slice()
            .to_vec();
        for idx in 0..3 {
            bitmap_set(&mut group2_bitmap, idx);
        }
        dev.write_block(&cx, groups[2].block_bitmap_block, &group2_bitmap)
            .unwrap();
        groups[2].free_blocks -= 3;

        seed_gdt_block(&dev, &pctx, &groups);

        let start = geo.group_block_to_absolute(GroupNumber(1), tail_start);
        free_blocks_persist(&cx, &dev, &geo, &mut groups, start, 5, &pctx).unwrap();

        assert_eq!(groups[1].free_blocks, geo.blocks_in_group(GroupNumber(1)));
        assert_eq!(groups[2].free_blocks, geo.blocks_in_group(GroupNumber(2)));

        let gdt_raw = dev.read_block(&cx, pctx.gdt_block).unwrap();
        let gdt_raw = gdt_raw.as_slice();
        let ds = usize::from(pctx.desc_size);
        let gd1 = Ext4GroupDesc::parse_from_bytes(&gdt_raw[ds..ds * 2], pctx.desc_size).unwrap();
        let gd2 =
            Ext4GroupDesc::parse_from_bytes(&gdt_raw[ds * 2..ds * 3], pctx.desc_size).unwrap();
        assert_eq!(gd1.free_blocks_count, geo.blocks_in_group(GroupNumber(1)));
        assert_eq!(gd2.free_blocks_count, geo.blocks_in_group(GroupNumber(2)));
    }

    #[test]
    fn free_blocks_persist_cross_boundary_rejects_reserved_segment() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();

        // Crossing from group 0 into group 1 reaches group-1 backup metadata immediately.
        let start =
            geo.group_block_to_absolute(GroupNumber(0), geo.blocks_in_group(GroupNumber(0)) - 2);
        let result = free_blocks_persist(&cx, &dev, &geo, &mut groups, start, 5, &pctx);
        assert!(
            result.is_err(),
            "reserved cross-group segment should still fail"
        );
    }

    #[test]
    fn alloc_blocks_zero_count_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let result = alloc_blocks(&cx, &dev, &geo, &mut groups, 0, &AllocHint::default());
        assert!(result.is_err(), "allocating 0 blocks should fail");
    }

    #[test]
    fn alloc_blocks_persist_zero_count_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();

        let result = alloc_blocks_persist(
            &cx,
            &dev,
            &geo,
            &mut groups,
            0,
            &AllocHint::default(),
            &pctx,
        );
        assert!(result.is_err(), "allocating 0 blocks (persist) should fail");
    }

    #[test]
    fn alloc_blocks_goal_block_in_different_group_falls_back() {
        // When goal_block maps to a different group than goal_group,
        // the search start should fall back to 0 within the goal group.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let hint = AllocHint {
            goal_group: Some(GroupNumber(0)),
            goal_block: Some(BlockNumber(10000)), // This is in group 1
            numa: None,
        };

        let alloc = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &hint).unwrap();
        // Should still allocate in group 0 (goal_group), starting from 0.
        let (group, _) = geo.absolute_to_group_block(alloc.start);
        assert_eq!(
            group,
            GroupNumber(0),
            "should allocate in goal group even when goal_block is in a different group"
        );
    }

    #[test]
    fn alloc_blocks_no_hint_uses_group_0() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let alloc = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &AllocHint::default()).unwrap();

        let (group, _) = geo.absolute_to_group_block(alloc.start);
        assert_eq!(group, GroupNumber(0), "no hint should default to group 0");
    }

    #[test]
    fn free_inode_zero_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let result = free_inode(&cx, &dev, &geo, &mut groups, InodeNumber(0));
        assert!(result.is_err(), "freeing inode 0 should fail");
    }

    #[test]
    fn free_inode_out_of_range_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        let result = free_inode(&cx, &dev, &geo, &mut groups, InodeNumber(100_000));
        assert!(result.is_err(), "freeing out-of-range inode should fail");
    }

    #[test]
    fn free_inode_double_free_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        // Allocate then free twice.
        let alloc = alloc_inode(&cx, &dev, &geo, &mut groups, GroupNumber(0), false).unwrap();
        free_inode(&cx, &dev, &geo, &mut groups, alloc.ino).unwrap();
        let result = free_inode(&cx, &dev, &geo, &mut groups, alloc.ino);
        assert!(
            result.is_err(),
            "double-freeing an inode should return error"
        );
    }

    #[test]
    fn bitmap_find_free_start_at_count_wraps_to_zero() {
        // When start == count, the forward search is empty.
        // The backward search 0..start should find a free bit.
        let mut bm = vec![0u8; 4];
        let count = 32;
        // Fill bits 0..15, leave 16..31 free.
        for i in 0..16 {
            bitmap_set(&mut bm, i);
        }
        // start=count=32 → forward loop is empty, wrap-around finds bit 16.
        let result = bitmap_find_free(&bm, count, count);
        assert_eq!(result, Some(16), "should wrap around and find bit 16");
    }

    #[test]
    fn bitmap_find_free_start_beyond_count_returns_wrap_result() {
        let bm = vec![0u8; 4]; // all free
        // start > count → forward loop is empty, wraps to find 0.
        let result = bitmap_find_free(&bm, 32, 100);
        assert_eq!(result, Some(0), "start > count should wrap to bit 0");
    }

    #[test]
    fn bitmap_find_contiguous_n_zero_returns_zero() {
        let bm = vec![0xFF; 4]; // all set
        let result = bitmap_find_contiguous(&bm, 32, 0, 0);
        assert_eq!(result, Some(0), "finding 0 contiguous bits always succeeds");
    }

    #[test]
    fn bitmap_count_free_zero_count_returns_zero() {
        let bm = vec![0u8; 4]; // all free
        assert_eq!(bitmap_count_free(&bm, 0), 0, "count=0 should return 0");
    }

    #[test]
    fn geometry_blocks_in_last_group_shorter() {
        // When total_blocks is not evenly divisible by blocks_per_group,
        // the last group should be shorter.
        let geo = FsGeometry {
            blocks_per_group: 8192,
            inodes_per_group: 2048,
            block_size: 4096,
            total_blocks: 30000, // not evenly divisible: 3 full groups + partial
            total_inodes: 8192,
            first_data_block: 0,
            group_count: 4,
            inode_size: 256,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        };

        assert_eq!(geo.blocks_in_group(GroupNumber(0)), 8192);
        assert_eq!(geo.blocks_in_group(GroupNumber(1)), 8192);
        assert_eq!(geo.blocks_in_group(GroupNumber(2)), 8192);
        // Last group: 30000 - 3*8192 = 5424.
        assert_eq!(geo.blocks_in_group(GroupNumber(3)), 5424);
    }

    #[test]
    fn geometry_absolute_to_group_with_first_data_block() {
        let geo = FsGeometry {
            blocks_per_group: 8192,
            inodes_per_group: 2048,
            block_size: 4096,
            total_blocks: 32768,
            total_inodes: 8192,
            first_data_block: 1, // ext4 with 1K blocks has first_data_block=1
            group_count: 4,
            inode_size: 256,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        };

        // Block 1 should be in group 0, relative 0.
        let (g, off) = geo.absolute_to_group_block(BlockNumber(1));
        assert_eq!(g, GroupNumber(0));
        assert_eq!(off, 0);

        // Block 8193 should be in group 1, relative 0.
        let (g, off) = geo.absolute_to_group_block(BlockNumber(8193));
        assert_eq!(g, GroupNumber(1));
        assert_eq!(off, 0);
    }

    #[test]
    fn absolute_to_group_block_caps_at_u32_max_on_overflow() {
        let geo = FsGeometry {
            block_size: 4096,
            blocks_per_group: 8192,
            inodes_per_group: 2048,
            inode_size: 256,
            first_data_block: 1,
            total_blocks: u64::MAX,
            total_inodes: 0,
            group_count: u32::MAX,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        };
        // Block number large enough that group index exceeds u32.
        let huge_block = BlockNumber(u64::from(u32::MAX) * 8192 + 8193);
        let (g, _off) = geo.absolute_to_group_block(huge_block);
        // Group should be capped at u32::MAX instead of silently truncating.
        assert_eq!(g, GroupNumber(u32::MAX));
    }

    #[test]
    fn absolute_to_group_block_zero_bpg_returns_group_zero_without_panic() {
        let geo = FsGeometry {
            block_size: 4096,
            blocks_per_group: 0, // Malformed geometry
            inodes_per_group: 2048,
            inode_size: 256,
            first_data_block: 1,
            total_blocks: 1000,
            total_inodes: 0,
            group_count: 0,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        };
        // Must not panic on zero blocks_per_group.
        let (g, off) = geo.absolute_to_group_block(BlockNumber(100));
        assert_eq!(g, GroupNumber(0));
        assert_eq!(off, 99); // 100 - first_data_block(1) = 99
    }

    #[test]
    fn gdt_blocks_count_zero_desc_size_returns_zero_without_panic() {
        let mut geo = make_geometry();
        geo.desc_size = 0;

        assert_eq!(geo.gdt_blocks_count(), 0);
        assert_eq!(geo.base_meta_blocks_in_group(GroupNumber(0)), 1);
    }

    #[test]
    fn orlov_all_groups_exhausted_returns_nospace() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);

        // Exhaust all inodes.
        for g in &mut groups {
            g.free_inodes = 0;
        }

        let result = alloc_inode(&cx, &dev, &geo, &mut groups, GroupNumber(0), true);
        assert!(
            result.is_err(),
            "all groups exhausted should return NoSpace"
        );
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    #[test]
    fn group_stats_uninit_flags() {
        let mut gs = GroupStats {
            group: GroupNumber(0),
            free_blocks: 100,
            free_inodes: 50,
            used_dirs: 0,
            block_bitmap_block: BlockNumber(1),
            inode_bitmap_block: BlockNumber(2),
            inode_table_block: BlockNumber(3),
            flags: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };
        assert!(!gs.block_bitmap_uninit());
        assert!(!gs.inode_bitmap_uninit());

        gs.flags = 0x0001; // GD_FLAG_INODE_UNINIT
        assert!(!gs.block_bitmap_uninit());
        assert!(gs.inode_bitmap_uninit());

        gs.flags = 0x0002; // GD_FLAG_BLOCK_UNINIT
        assert!(gs.block_bitmap_uninit());
        assert!(!gs.inode_bitmap_uninit());

        gs.flags = 0x0003; // both
        assert!(gs.block_bitmap_uninit());
        assert!(gs.inode_bitmap_uninit());
    }

    #[test]
    fn geometry_coordinate_roundtrip_with_first_data_block() {
        let geo = FsGeometry {
            blocks_per_group: 32768,
            inodes_per_group: 8192,
            block_size: 4096,
            total_blocks: 131_072,
            total_inodes: 32768,
            first_data_block: 1,
            group_count: 4,
            inode_size: 256,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        };
        // Group 0, rel 0 -> absolute = first_data_block + 0 = 1
        let abs = geo.group_block_to_absolute(GroupNumber(0), 0);
        assert_eq!(abs, BlockNumber(1));

        let (g, r) = geo.absolute_to_group_block(BlockNumber(1));
        assert_eq!(g, GroupNumber(0));
        assert_eq!(r, 0);

        // Group 1, rel 5 -> absolute = 1 + 32768 + 5 = 32774
        let abs2 = geo.group_block_to_absolute(GroupNumber(1), 5);
        assert_eq!(abs2, BlockNumber(32774));
        let (g2, r2) = geo.absolute_to_group_block(abs2);
        assert_eq!(g2, GroupNumber(1));
        assert_eq!(r2, 5);
    }

    #[test]
    fn geometry_inodes_in_last_group_may_be_smaller() {
        let geo = FsGeometry {
            blocks_per_group: 8192,
            inodes_per_group: 2048,
            block_size: 4096,
            total_blocks: 20000,
            total_inodes: 5000, // 2 full groups + partial
            first_data_block: 0,
            group_count: 3,
            inode_size: 256,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        };
        assert_eq!(geo.inodes_in_group(GroupNumber(0)), 2048);
        assert_eq!(geo.inodes_in_group(GroupNumber(1)), 2048);
        assert_eq!(geo.inodes_in_group(GroupNumber(2)), 904); // 5000 - 4096
    }

    #[test]
    fn alloc_hint_default_has_no_preferences() {
        let hint = AllocHint::default();
        assert!(hint.goal_group.is_none());
        assert!(hint.goal_block.is_none());
    }

    #[test]
    fn block_alloc_and_inode_alloc_equality() {
        let a = BlockAlloc {
            start: BlockNumber(10),
            count: 3,
        };
        let b = BlockAlloc {
            start: BlockNumber(10),
            count: 3,
        };
        assert_eq!(a, b);

        let ia = InodeAlloc {
            ino: InodeNumber(100),
            group: GroupNumber(2),
        };
        let ib = InodeAlloc {
            ino: InodeNumber(100),
            group: GroupNumber(2),
        };
        assert_eq!(ia, ib);
    }

    #[test]
    fn bitmap_full_count_free_is_zero() {
        let bitmap = [0xFF_u8; 4];
        assert_eq!(bitmap_count_free(&bitmap, 32), 0);
    }

    #[test]
    fn bitmap_empty_count_free_is_count() {
        let bitmap = [0x00_u8; 4];
        assert_eq!(bitmap_count_free(&bitmap, 32), 32);
        assert_eq!(bitmap_count_free(&bitmap, 16), 16);
    }

    #[test]
    fn bitmap_find_free_on_full_returns_none() {
        let bitmap = [0xFF_u8; 4];
        assert!(bitmap_find_free(&bitmap, 32, 0).is_none());
    }

    #[test]
    fn bitmap_find_contiguous_larger_than_available_returns_none() {
        let bitmap = [0x00_u8; 2]; // 16 bits free
        assert!(bitmap_find_contiguous(&bitmap, 16, 17, 0).is_none());
    }

    // ── Hardening edge-case tests ────────────────────────────────────

    #[test]
    fn gd_flag_constants_match_ext4_spec() {
        assert_eq!(GD_FLAG_INODE_UNINIT, 0x0001);
        assert_eq!(GD_FLAG_BLOCK_UNINIT, 0x0002);
    }

    #[test]
    fn persist_ctx_debug_clone() {
        let pctx = PersistCtx {
            gdt_block: BlockNumber(1),
            desc_size: 32,
            has_metadata_csum: false,
            csum_seed: 0,
            uuid: [0; 16],
            group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::None,
            blocks_per_group: 32768,
            inodes_per_group: 2048,
        };
        let cloned = pctx.clone();
        assert_eq!(cloned.gdt_block, pctx.gdt_block);
        assert_eq!(cloned.desc_size, pctx.desc_size);
        let _ = format!("{pctx:?}");
    }

    #[test]
    fn fs_geometry_zero_blocks_per_group_zero_group_count() {
        let geo = FsGeometry {
            blocks_per_group: 0,
            inodes_per_group: 2048,
            block_size: 4096,
            total_blocks: 32768,
            total_inodes: 8192,
            first_data_block: 0,
            group_count: 0,
            inode_size: 256,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        };
        assert_eq!(geo.group_count, 0);
    }

    #[test]
    fn fs_geometry_clone_and_debug() {
        let geo = make_geometry();
        let cloned = geo.clone();
        assert_eq!(cloned.total_blocks, geo.total_blocks);
        let _ = format!("{geo:?}");
    }

    #[test]
    fn group_stats_clone_and_debug() {
        let geo = make_geometry();
        let groups = make_groups(&geo);
        let cloned = groups[0].clone();
        assert_eq!(cloned.group, groups[0].group);
        let _ = format!("{:?}", groups[0]);
    }

    #[test]
    fn block_alloc_debug_clone_copy_eq() {
        let a = BlockAlloc {
            start: BlockNumber(100),
            count: 5,
        };
        let b = a; // Copy
        assert_eq!(a, b);
        let _ = format!("{a:?}");

        let d = BlockAlloc {
            start: BlockNumber(200),
            count: 5,
        };
        assert_ne!(a, d);
    }

    #[test]
    fn inode_alloc_debug_clone_copy_eq() {
        let a = InodeAlloc {
            ino: InodeNumber(11),
            group: GroupNumber(0),
        };
        let b = a; // Copy
        assert_eq!(a, b);
        let _ = format!("{a:?}");

        let c = InodeAlloc {
            ino: InodeNumber(12),
            group: GroupNumber(0),
        };
        assert_ne!(a, c);
    }

    #[test]
    fn is_reserved_binary_search() {
        let reserved = vec![0, 1, 2, 3, 10, 20];
        assert!(is_reserved(&reserved, 0));
        assert!(is_reserved(&reserved, 10));
        assert!(is_reserved(&reserved, 20));
        assert!(!is_reserved(&reserved, 5));
        assert!(!is_reserved(&reserved, 100));
    }

    #[test]
    fn reserved_blocks_include_backup_super_and_gdt_for_sparse_super2() {
        let mut geo = make_geometry();
        geo.feature_compat = ffs_ondisk::Ext4CompatFeatures(
            ffs_ondisk::Ext4CompatFeatures::SPARSE_SUPER2.0
                | ffs_ondisk::Ext4CompatFeatures::RESIZE_INODE.0,
        );
        geo.backup_bgs = [2, 0];
        geo.reserved_gdt_blocks = 2;
        let groups = make_groups(&geo);
        let reserved = reserved_blocks_in_group(&geo, &groups, GroupNumber(2));
        assert!(
            reserved.contains(&0),
            "backup superblock should reserve rel block 0"
        );
        assert!(
            reserved.contains(&1),
            "backup GDT should reserve rel block 1"
        );
        assert!(
            reserved.contains(&2),
            "reserved GDT block should reserve rel block 2"
        );
    }

    #[test]
    fn reserved_blocks_skip_reserved_gdt_after_first_meta_bg() {
        let mut geo = make_geometry();
        geo.feature_compat =
            ffs_ondisk::Ext4CompatFeatures(ffs_ondisk::Ext4CompatFeatures::RESIZE_INODE.0);
        geo.feature_incompat =
            ffs_ondisk::Ext4IncompatFeatures(ffs_ondisk::Ext4IncompatFeatures::META_BG.0);
        geo.first_meta_bg = 2;
        geo.reserved_gdt_blocks = 2;
        geo.group_count = 4;
        geo.total_blocks = u64::from(geo.blocks_per_group) * u64::from(geo.group_count);
        let mut groups = make_groups(&geo);
        for group in [GroupNumber(1), GroupNumber(3)] {
            let gidx = group.0 as usize;
            groups[gidx].block_bitmap_block = geo.group_block_to_absolute(group, 100);
            groups[gidx].inode_bitmap_block = geo.group_block_to_absolute(group, 101);
            groups[gidx].inode_table_block = geo.group_block_to_absolute(group, 102);
        }

        let early_reserved = reserved_blocks_in_group(&geo, &groups, GroupNumber(1));
        assert!(
            early_reserved.contains(&0),
            "backup superblock copy should remain reserved"
        );
        assert!(
            early_reserved.contains(&1),
            "early META_BG groups still carry backup GDT blocks"
        );
        assert!(
            early_reserved.contains(&2),
            "early META_BG groups still reserve resize GDT slots"
        );
        assert!(
            early_reserved.contains(&3),
            "early META_BG groups still reserve all backup-GDT prefix blocks"
        );

        let late_reserved = reserved_blocks_in_group(&geo, &groups, GroupNumber(3));
        assert!(
            late_reserved.contains(&0),
            "backup superblock copy should remain reserved"
        );
        assert!(
            !late_reserved.contains(&1),
            "groups at or after first_meta_bg must not reserve contiguous backup GDT blocks",
        );
        assert!(
            !late_reserved.contains(&2),
            "groups at or after first_meta_bg must not reserve resize GDT slots",
        );
        assert!(
            !late_reserved.contains(&3),
            "groups at or after first_meta_bg must not reserve backup-GDT prefix blocks",
        );
    }

    #[test]
    fn reserved_blocks_only_mark_flex_metadata_when_it_lives_in_group() {
        let mut geo = make_geometry();
        geo.feature_incompat =
            ffs_ondisk::Ext4IncompatFeatures(ffs_ondisk::Ext4IncompatFeatures::FLEX_BG.0);
        geo.log_groups_per_flex = 2;
        let mut groups = make_groups(&geo);
        groups[1].block_bitmap_block = geo.group_block_to_absolute(GroupNumber(0), 200);
        groups[1].inode_bitmap_block = geo.group_block_to_absolute(GroupNumber(1), 60);
        let reserved = reserved_blocks_in_group(&geo, &groups, GroupNumber(1));
        assert!(
            !reserved.contains(&200),
            "metadata in another flex group member must not reserve this group's block 200"
        );
        assert!(
            reserved.contains(&60),
            "metadata stored inside the current group must still be reserved"
        );
    }

    #[test]
    fn bitmap_get_out_of_bounds_returns_true() {
        let bitmap = [0xFF_u8; 1]; // 8 bits all set
        assert!(bitmap_get(&bitmap, 0));
        assert!(bitmap_get(&bitmap, 7));
        assert!(bitmap_get(&bitmap, 8)); // out of bounds
        assert!(bitmap_get(&bitmap, 100));
    }

    #[test]
    fn bitmap_set_clear_out_of_bounds_is_noop() {
        let mut bitmap = [0x00_u8; 1];
        bitmap_set(&mut bitmap, 100); // should not panic
        assert_eq!(bitmap[0], 0x00);
        bitmap_clear(&mut bitmap, 100); // should not panic
        assert_eq!(bitmap[0], 0x00);
    }

    #[test]
    fn bitmap_count_free_partial_byte() {
        // 2 bytes = 16 bits, but only count 10. First byte = 0xFF (all set), second = 0x00.
        let bitmap = [0xFF_u8, 0x00];
        // First 8 bits: all set (0 free). Bits 8-9: both free (2 free).
        assert_eq!(bitmap_count_free(&bitmap, 10), 2);
    }

    #[test]
    fn bitmap_find_contiguous_wraps_around() {
        // 8 bits: 0b1111_0001 = 0xF1 → bits 1-3 are free, bits 4-7 set, bit 0 set.
        let bitmap = [0xF1_u8];
        // Find 3 contiguous starting from bit 0. Run at bits 1-3 should be found.
        let found = bitmap_find_contiguous(&bitmap, 8, 3, 0).unwrap();
        assert_eq!(found, 1);
    }

    #[test]
    fn geometry_group_block_to_absolute_with_first_data_block() {
        let geo = FsGeometry {
            blocks_per_group: 8192,
            inodes_per_group: 2048,
            block_size: 4096,
            total_blocks: 32768,
            total_inodes: 8192,
            first_data_block: 1, // non-zero
            group_count: 4,
            inode_size: 256,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_inode: 11,
            cluster_ratio: 1,
        };
        // Group 0, rel 0 → absolute 1 (first_data_block).
        assert_eq!(
            geo.group_block_to_absolute(GroupNumber(0), 0),
            BlockNumber(1)
        );
        // Group 1, rel 0 → absolute 1 + 8192 = 8193.
        assert_eq!(
            geo.group_block_to_absolute(GroupNumber(1), 0),
            BlockNumber(8193)
        );
    }

    #[test]
    fn alloc_hint_with_goal_group() {
        let hint = AllocHint {
            goal_group: Some(GroupNumber(2)),
            goal_block: None,
            numa: None,
        };
        assert_eq!(hint.goal_group, Some(GroupNumber(2)));
        assert!(hint.goal_block.is_none());
    }

    fn required_numa_consumers() -> Vec<String> {
        REQUIRED_NUMA_TOPOLOGY_CONSUMERS
            .iter()
            .map(|consumer| (*consumer).to_owned())
            .collect()
    }

    fn observed_numa_topology(node_groups: Vec<NumaNodeGroupRange>) -> NumaAllocationTopology {
        NumaAllocationTopology {
            source: NumaTopologySource::Observed {
                observed_at_unix_secs: 1_000,
                max_age_secs: 60,
                node_groups,
            },
            evidence_claim: NumaEvidenceClaim::AdvisoryOnly,
            downstream_consumers: required_numa_consumers(),
        }
    }

    fn balanced_numa_preference(
        geo: &FsGeometry,
        preferred_node: NumaNodeId,
    ) -> NumaAllocationPreference {
        let topology = observed_numa_topology(vec![
            NumaNodeGroupRange {
                node_id: NumaNodeId(0),
                first_group: GroupNumber(0),
                group_count: 2,
            },
            NumaNodeGroupRange {
                node_id: NumaNodeId(1),
                first_group: GroupNumber(2),
                group_count: 2,
            },
        ]);
        let plan = validate_numa_allocation_topology(geo, &topology, 1_010).unwrap();
        NumaAllocationPreference {
            plan,
            preferred_node,
        }
    }

    #[test]
    fn numa_topology_unknown_falls_back_without_product_claim() {
        let geo = make_geometry();
        let topology = NumaAllocationTopology {
            source: NumaTopologySource::Unknown {
                reason: "host probe unavailable".to_owned(),
            },
            evidence_claim: NumaEvidenceClaim::AdvisoryOnly,
            downstream_consumers: required_numa_consumers(),
        };

        let plan = validate_numa_allocation_topology(&geo, &topology, 1_000).unwrap();

        assert_eq!(plan.disposition, NumaTopologyDisposition::UnknownFallback);
        assert_eq!(plan.group_nodes, vec![None; 4]);
        assert_eq!(
            resolve_numa_allocation_goal(&geo, &AllocHint::default(), &plan, Some(NumaNodeId(1))),
            GroupNumber(0)
        );
    }

    #[test]
    fn numa_topology_single_node_maps_all_groups_to_node_zero() {
        let geo = make_geometry();
        let topology = NumaAllocationTopology {
            source: NumaTopologySource::SingleNode,
            evidence_claim: NumaEvidenceClaim::AdvisoryOnly,
            downstream_consumers: required_numa_consumers(),
        };

        let plan = validate_numa_allocation_topology(&geo, &topology, 1_000).unwrap();

        assert_eq!(
            plan.disposition,
            NumaTopologyDisposition::SingleNodeFallback
        );
        assert_eq!(plan.group_nodes, vec![Some(NumaNodeId(0)); 4]);
        assert_eq!(
            resolve_numa_allocation_goal(&geo, &AllocHint::default(), &plan, Some(NumaNodeId(0))),
            GroupNumber(0)
        );
    }

    #[test]
    fn numa_topology_balanced_mapping_validates() {
        let geo = make_geometry();
        let topology = observed_numa_topology(vec![
            NumaNodeGroupRange {
                node_id: NumaNodeId(0),
                first_group: GroupNumber(0),
                group_count: 2,
            },
            NumaNodeGroupRange {
                node_id: NumaNodeId(1),
                first_group: GroupNumber(2),
                group_count: 2,
            },
        ]);

        let plan = validate_numa_allocation_topology(&geo, &topology, 1_010).unwrap();

        assert_eq!(plan.disposition, NumaTopologyDisposition::AdvisoryMap);
        assert_eq!(
            plan.group_nodes,
            vec![
                Some(NumaNodeId(0)),
                Some(NumaNodeId(0)),
                Some(NumaNodeId(1)),
                Some(NumaNodeId(1)),
            ]
        );
        assert_eq!(
            resolve_numa_allocation_goal(&geo, &AllocHint::default(), &plan, Some(NumaNodeId(1))),
            GroupNumber(2)
        );
    }

    #[test]
    fn numa_topology_imbalanced_groups_validate() {
        let geo = make_geometry();
        let topology = observed_numa_topology(vec![
            NumaNodeGroupRange {
                node_id: NumaNodeId(0),
                first_group: GroupNumber(0),
                group_count: 1,
            },
            NumaNodeGroupRange {
                node_id: NumaNodeId(1),
                first_group: GroupNumber(1),
                group_count: 3,
            },
        ]);

        let plan = validate_numa_allocation_topology(&geo, &topology, 1_010).unwrap();

        assert_eq!(
            plan.group_nodes,
            vec![
                Some(NumaNodeId(0)),
                Some(NumaNodeId(1)),
                Some(NumaNodeId(1)),
                Some(NumaNodeId(1)),
            ]
        );
        assert_eq!(
            resolve_numa_allocation_goal(&geo, &AllocHint::default(), &plan, Some(NumaNodeId(1))),
            GroupNumber(1)
        );
    }

    #[test]
    fn numa_topology_goal_group_precedence_over_numa_and_goal_block() {
        let geo = make_geometry();
        let topology = observed_numa_topology(vec![
            NumaNodeGroupRange {
                node_id: NumaNodeId(0),
                first_group: GroupNumber(0),
                group_count: 2,
            },
            NumaNodeGroupRange {
                node_id: NumaNodeId(1),
                first_group: GroupNumber(2),
                group_count: 2,
            },
        ]);
        let plan = validate_numa_allocation_topology(&geo, &topology, 1_010).unwrap();
        let goal_block = geo.group_block_to_absolute(GroupNumber(1), 7);
        let explicit_group = AllocHint {
            goal_group: Some(GroupNumber(3)),
            goal_block: Some(goal_block),
            numa: None,
        };
        let explicit_block = AllocHint {
            goal_group: None,
            goal_block: Some(goal_block),
            numa: None,
        };

        assert_eq!(
            resolve_numa_allocation_goal(&geo, &explicit_group, &plan, Some(NumaNodeId(0))),
            GroupNumber(3)
        );
        assert_eq!(
            resolve_numa_allocation_goal(&geo, &explicit_block, &plan, Some(NumaNodeId(0))),
            GroupNumber(1)
        );
    }

    #[test]
    fn numa_topology_rejects_invalid_contracts() {
        let geo = make_geometry();

        let missing_map = observed_numa_topology(Vec::new());
        assert_eq!(
            validate_numa_allocation_topology(&geo, &missing_map, 1_000).unwrap_err(),
            NumaTopologyError::MissingNodeMap
        );

        let duplicate_group = observed_numa_topology(vec![
            NumaNodeGroupRange {
                node_id: NumaNodeId(0),
                first_group: GroupNumber(0),
                group_count: 2,
            },
            NumaNodeGroupRange {
                node_id: NumaNodeId(1),
                first_group: GroupNumber(1),
                group_count: 3,
            },
        ]);
        assert_eq!(
            validate_numa_allocation_topology(&geo, &duplicate_group, 1_000).unwrap_err(),
            NumaTopologyError::DuplicateGroup {
                group: GroupNumber(1)
            }
        );

        let uncovered_group = observed_numa_topology(vec![NumaNodeGroupRange {
            node_id: NumaNodeId(0),
            first_group: GroupNumber(0),
            group_count: 3,
        }]);
        assert_eq!(
            validate_numa_allocation_topology(&geo, &uncovered_group, 1_000).unwrap_err(),
            NumaTopologyError::UncoveredGroup {
                group: GroupNumber(3)
            }
        );

        let invalid_node = observed_numa_topology(vec![NumaNodeGroupRange {
            node_id: NumaNodeId(MAX_NUMA_NODE_ID + 1),
            first_group: GroupNumber(0),
            group_count: 4,
        }]);
        assert_eq!(
            validate_numa_allocation_topology(&geo, &invalid_node, 1_000).unwrap_err(),
            NumaTopologyError::InvalidNodeId {
                node_id: NumaNodeId(MAX_NUMA_NODE_ID + 1)
            }
        );

        let stale = observed_numa_topology(vec![NumaNodeGroupRange {
            node_id: NumaNodeId(0),
            first_group: GroupNumber(0),
            group_count: 4,
        }]);
        assert_eq!(
            validate_numa_allocation_topology(&geo, &stale, 1_061).unwrap_err(),
            NumaTopologyError::StaleEvidence {
                age_secs: 61,
                max_age_secs: 60
            }
        );

        let mut product_readiness = observed_numa_topology(vec![NumaNodeGroupRange {
            node_id: NumaNodeId(0),
            first_group: GroupNumber(0),
            group_count: 4,
        }]);
        product_readiness.evidence_claim = NumaEvidenceClaim::ProductReadiness;
        assert_eq!(
            validate_numa_allocation_topology(&geo, &product_readiness, 1_000).unwrap_err(),
            NumaTopologyError::ProductReadinessClaim
        );

        let mut missing_consumer = observed_numa_topology(vec![NumaNodeGroupRange {
            node_id: NumaNodeId(0),
            first_group: GroupNumber(0),
            group_count: 4,
        }]);
        missing_consumer
            .downstream_consumers
            .retain(|consumer| consumer != "ffs-core");
        assert_eq!(
            validate_numa_allocation_topology(&geo, &missing_consumer, 1_000).unwrap_err(),
            NumaTopologyError::MissingConsumer {
                consumer: "ffs-core"
            }
        );
    }

    #[test]
    fn numa_allocation_no_hint_keeps_legacy_group_order() {
        let geo = make_geometry();
        let order = allocation_group_order(&geo, &AllocHint::default()).unwrap();
        assert_eq!(
            order,
            vec![
                GroupNumber(0),
                GroupNumber(1),
                GroupNumber(2),
                GroupNumber(3),
            ]
        );
    }

    #[test]
    fn numa_allocation_prefers_requested_node_groups() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let hint = AllocHint {
            numa: Some(balanced_numa_preference(&geo, NumaNodeId(1))),
            ..AllocHint::default()
        };

        let alloc = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &hint).unwrap();
        let (group, _) = geo.absolute_to_group_block(alloc.start);

        assert_eq!(group, GroupNumber(2));
    }

    #[test]
    fn numa_allocation_exhausted_node_falls_back_to_legacy_order() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        groups[2].free_blocks = 0;
        groups[3].free_blocks = 0;
        let hint = AllocHint {
            numa: Some(balanced_numa_preference(&geo, NumaNodeId(1))),
            ..AllocHint::default()
        };

        let alloc = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &hint).unwrap();
        let (group, _) = geo.absolute_to_group_block(alloc.start);

        assert_eq!(group, GroupNumber(0));
    }

    #[test]
    fn numa_allocation_goal_hints_override_preference() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut goal_group_groups = make_groups(&geo);
        let mut goal_block_groups = make_groups(&geo);
        let goal_block = geo.group_block_to_absolute(GroupNumber(1), 17);
        let goal_group_hint = AllocHint {
            goal_group: Some(GroupNumber(0)),
            numa: Some(balanced_numa_preference(&geo, NumaNodeId(1))),
            ..AllocHint::default()
        };
        let goal_block_hint = AllocHint {
            goal_block: Some(goal_block),
            numa: Some(balanced_numa_preference(&geo, NumaNodeId(1))),
            ..AllocHint::default()
        };

        let goal_group_alloc =
            alloc_blocks(&cx, &dev, &geo, &mut goal_group_groups, 1, &goal_group_hint).unwrap();
        let goal_block_alloc =
            alloc_blocks(&cx, &dev, &geo, &mut goal_block_groups, 1, &goal_block_hint).unwrap();
        let (goal_group, _) = geo.absolute_to_group_block(goal_group_alloc.start);
        let (goal_block_group, _) = geo.absolute_to_group_block(goal_block_alloc.start);

        assert_eq!(goal_group, GroupNumber(0));
        assert_eq!(goal_block_group, GroupNumber(1));
    }

    #[test]
    fn numa_allocation_rejects_geometry_mismatched_plan() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut geo = make_geometry();
        let mut groups = make_groups(&geo);
        let hint = AllocHint {
            numa: Some(balanced_numa_preference(&geo, NumaNodeId(1))),
            ..AllocHint::default()
        };
        geo.group_count = 3;

        let err = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &hint).unwrap_err();

        assert!(
            matches!(err, FfsError::InvalidGeometry(message) if message.contains("NUMA allocation plan covers 4 groups but geometry has 3 groups"))
        );
    }

    #[test]
    fn numa_batch_alloc_prefers_node_then_falls_back() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        groups[2].free_blocks = 2;
        groups[3].free_blocks = 0;
        let pctx = make_persist_ctx();
        let hint = AllocHint {
            numa: Some(balanced_numa_preference(&geo, NumaNodeId(1))),
            ..AllocHint::default()
        };

        let allocs =
            alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups, 5, &hint, &pctx).unwrap();
        let groups_allocated = allocs
            .iter()
            .map(|alloc| geo.absolute_to_group_block(alloc.start).0)
            .collect::<Vec<_>>();

        assert_eq!(
            groups_allocated,
            vec![
                GroupNumber(2),
                GroupNumber(2),
                GroupNumber(0),
                GroupNumber(0),
                GroupNumber(0),
            ]
        );
    }

    #[test]
    fn numa_batch_alloc_failure_rolls_back_preferred_node() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        groups[0].free_blocks = 0;
        groups[1].free_blocks = 0;
        groups[2].free_blocks = 2;
        groups[3].free_blocks = 0;
        let pctx = make_persist_ctx();
        let hint = AllocHint {
            numa: Some(balanced_numa_preference(&geo, NumaNodeId(1))),
            ..AllocHint::default()
        };

        let err =
            alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups, 5, &hint, &pctx).unwrap_err();
        let group_two_bitmap = dev.read_block(&cx, groups[2].block_bitmap_block).unwrap();
        let reserved = reserved_blocks_in_group(&geo, &groups, GroupNumber(2));

        assert!(matches!(err, FfsError::NoSpace));
        assert_eq!(groups[2].free_blocks, 2);
        for bit in 0..geo.blocks_in_group(GroupNumber(2)) {
            assert_eq!(
                bitmap_get(group_two_bitmap.as_slice(), bit),
                is_reserved(&reserved, bit),
                "rollback must not leave non-reserved group 2 block {bit} allocated",
            );
        }
    }

    #[test]
    fn group_stats_from_group_desc_maps_all_fields() {
        let gd = Ext4GroupDesc {
            block_bitmap: 100,
            inode_bitmap: 101,
            inode_table: 102,
            free_blocks_count: 500,
            free_inodes_count: 200,
            used_dirs_count: 10,
            itable_unused: 0,
            flags: GD_FLAG_INODE_UNINIT | GD_FLAG_BLOCK_UNINIT,
            checksum: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };
        let gs = GroupStats::from_group_desc(GroupNumber(3), &gd);
        assert_eq!(gs.group, GroupNumber(3));
        assert_eq!(gs.free_blocks, 500);
        assert_eq!(gs.free_inodes, 200);
        assert_eq!(gs.used_dirs, 10);
        assert_eq!(gs.block_bitmap_block, BlockNumber(100));
        assert_eq!(gs.inode_bitmap_block, BlockNumber(101));
        assert_eq!(gs.inode_table_block, BlockNumber(102));
        assert!(gs.block_bitmap_uninit());
        assert!(gs.inode_bitmap_uninit());
    }

    #[test]
    fn representative_allocator_diagnostics_exact_golden_contract() {
        let geo = make_geometry();
        let groups = make_groups(&geo);
        let first_data_block = geo.group_block_to_absolute(GroupNumber(1), 131);
        let hint = AllocHint {
            goal_group: Some(GroupNumber(1)),
            goal_block: Some(first_data_block),
            numa: None,
        };
        let block_alloc = BlockAlloc {
            start: first_data_block,
            count: 4,
        };
        let inode_alloc = InodeAlloc {
            ino: InodeNumber(17),
            group: GroupNumber(1),
        };

        let actual = format!(
            "{:?}\n{:?}\n{:?}\n{:?}\n{}\n{:?}",
            groups[1],
            hint,
            block_alloc,
            inode_alloc,
            first_non_reserved_block(&geo, &groups, GroupNumber(1)),
            reserved_inodes_in_group(&geo, GroupNumber(0)),
        );

        let expected = "\
GroupStats { group: GroupNumber(1), free_blocks: 8192, free_inodes: 2048, used_dirs: 0, block_bitmap_block: BlockNumber(8193), inode_bitmap_block: BlockNumber(8194), inode_table_block: BlockNumber(8195), flags: 0, block_bitmap_csum: 0, inode_bitmap_csum: 0 }
AllocHint { goal_group: Some(GroupNumber(1)), goal_block: Some(BlockNumber(8323)), numa: None }
BlockAlloc { start: BlockNumber(8323), count: 4 }
InodeAlloc { ino: InodeNumber(17), group: GroupNumber(1) }
131
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]";

        assert_eq!(actual, expected);
    }

    // ── Property-based tests (proptest) ────────────────────────────────

    use proptest::prelude::*;

    /// Strategy: generate a bitmap of 1..128 bytes with a valid bit count.
    fn bitmap_strat() -> impl Strategy<Value = (Vec<u8>, u32)> {
        (1_usize..128).prop_flat_map(|byte_len| {
            let max_bits =
                u32::try_from(byte_len * 8).expect("byte_len bound keeps bit length within u32");
            (prop::collection::vec(any::<u8>(), byte_len), 1..=max_bits)
        })
    }

    fn batch_occupied_group_strat() -> impl Strategy<Value = Vec<u32>> {
        prop::collection::vec(0_u32..64, 0..48)
    }

    fn batch_equivalence_hint_from_case(
        geo: &FsGeometry,
        hint_case: u8,
        group_seed: u32,
        rel_seed: u32,
    ) -> AllocHint {
        let group = GroupNumber(group_seed % geo.group_count);
        let rel = rel_seed % geo.blocks_in_group(group);
        match hint_case % 5 {
            0 => AllocHint::default(),
            1 => AllocHint {
                goal_group: Some(group),
                ..AllocHint::default()
            },
            2 => AllocHint {
                goal_block: Some(geo.group_block_to_absolute(group, rel)),
                ..AllocHint::default()
            },
            3 => AllocHint {
                goal_group: Some(group),
                goal_block: Some(geo.group_block_to_absolute(group, rel)),
                numa: None,
            },
            _ => {
                let block_group = GroupNumber((group.0 + 1) % geo.group_count);
                let block_rel = rel_seed % geo.blocks_in_group(block_group);
                AllocHint {
                    goal_group: Some(group),
                    goal_block: Some(geo.group_block_to_absolute(block_group, block_rel)),
                    numa: None,
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn proptest_bitmap_set_get_roundtrip(
            byte_len in 1_usize..64,
            idx_seed in any::<u32>(),
        ) {
            let total_bits =
                u32::try_from(byte_len * 8).expect("byte_len bound keeps bit length within u32");
            let idx = idx_seed % total_bits;
            let mut bm = vec![0u8; byte_len];
            prop_assert!(!bitmap_get(&bm, idx));
            bitmap_set(&mut bm, idx);
            prop_assert!(bitmap_get(&bm, idx));
            bitmap_clear(&mut bm, idx);
            prop_assert!(!bitmap_get(&bm, idx));
        }

        #[test]
        fn proptest_bitmap_count_free_consistency((ref bm, count) in bitmap_strat()) {
            let free = bitmap_count_free(bm, count);
            // Manual count for verification.
            let manual_free =
                (0..count).fold(0_u32, |acc, i| acc + u32::from(!bitmap_get(bm, i)));
            prop_assert_eq!(free, manual_free);
            // Ones + zeros = total.
            let used = (0..count).fold(0_u32, |acc, i| acc + u32::from(bitmap_get(bm, i)));
            prop_assert_eq!(free + used, count);
        }

        #[test]
        fn proptest_bitmap_find_free_matches_naive(
            (ref bm, count) in bitmap_strat(),
            start_seed in any::<u32>(),
        ) {
            // Ground-truth for the word-at-a-time find-free scan: first free bit
            // in [start, count), else in [0, start).
            let start = start_seed % count;
            let naive = (start..count)
                .find(|&i| !bitmap_get(bm, i))
                .or_else(|| (0..start).find(|&i| !bitmap_get(bm, i)));
            prop_assert_eq!(bitmap_find_free(bm, count, start), naive);
        }

        #[test]
        fn proptest_bitmap_find_free_returns_zero_bit(
            (ref bm, count) in bitmap_strat(),
            start_seed in any::<u32>(),
        ) {
            let start = start_seed % count;
            if let Some(pos) = bitmap_find_free(bm, count, start) {
                prop_assert!(pos < count, "found pos {} >= count {}", pos, count);
                prop_assert!(!bitmap_get(bm, pos), "bit {} is set but find_free returned it", pos);
            } else {
                // All bits should be set.
                let free = bitmap_count_free(bm, count);
                prop_assert_eq!(free, 0, "find_free returned None but {} bits are free", free);
            }
        }

        #[test]
        fn proptest_bitmap_find_contiguous_valid_run(
            (ref bm, count) in bitmap_strat(),
            n in 1_u32..32,
            start_seed in any::<u32>(),
        ) {
            let start = start_seed % count;
            if let Some(pos) = bitmap_find_contiguous(bm, count, n, start) {
                prop_assert!(pos + n <= count, "run [{}, {}) exceeds count {}", pos, pos + n, count);
                for i in pos..pos + n {
                    prop_assert!(
                        !bitmap_get(bm, i),
                        "bit {} in contiguous run [{}, {}) is set",
                        i, pos, pos + n,
                    );
                }
            }
        }

        #[test]
        fn proptest_bitmap_find_contiguous_matches_naive_wraparound(
            (ref bm, count) in bitmap_strat(),
            n in 1_u32..32,
            start_seed in any::<u32>(),
        ) {
            let start = start_seed % count;
            let naive_range = |range: std::ops::Range<u32>| {
                range.into_iter().find(|&pos| {
                    pos.checked_add(n)
                        .is_some_and(|end| end <= count && (pos..end).all(|bit| !bitmap_get(bm, bit)))
                })
            };
            let expected = if n > count {
                None
            } else {
                naive_range(start..count).or_else(|| {
                    let pass2_end = start.saturating_add(n).saturating_sub(1).min(count);
                    naive_range(0..pass2_end)
                })
            };
            prop_assert_eq!(bitmap_find_contiguous(bm, count, n, start), expected);
        }

        #[test]
        fn proptest_alloc_free_roundtrip_preserves_free_count(
            num_allocs in 1_u32..8,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let original_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

            let mut allocations = Vec::new();
            for _ in 0..num_allocs {
                match alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &AllocHint::default()) {
                    Ok(a) => allocations.push(a),
                    Err(_) => break,
                }
            }

            let after_alloc_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
            let allocated_count = u32::try_from(allocations.len())
                .expect("allocation count fits in u32 for test bounds");
            prop_assert_eq!(
                after_alloc_free,
                original_free - allocated_count,
                "free count after alloc: expected {}, got {}",
                original_free - allocated_count,
                after_alloc_free,
            );

            // Free all allocated blocks.
            for a in &allocations {
                free_blocks(&cx, &dev, &geo, &mut groups, a.start, a.count).unwrap();
            }

            let final_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
            prop_assert_eq!(
                final_free,
                original_free,
                "free count after free: expected {}, got {}",
                original_free,
                final_free,
            );
        }

        /// Multi-block alloc/free roundtrip with varying block counts.
        #[test]
        fn proptest_multi_block_alloc_free_roundtrip(
            block_count in 1_u32..16,
            num_allocs in 1_u32..5,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let original_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

            let mut allocations = Vec::new();
            let mut total_allocated = 0_u32;
            for _ in 0..num_allocs {
                match alloc_blocks(&cx, &dev, &geo, &mut groups, block_count, &AllocHint::default()) {
                    Ok(a) => {
                        total_allocated += a.count;
                        allocations.push(a);
                    }
                    Err(_) => break,
                }
            }

            let after_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
            prop_assert_eq!(
                after_free,
                original_free - total_allocated,
            );

            for a in &allocations {
                free_blocks(&cx, &dev, &geo, &mut groups, a.start, a.count).unwrap();
            }

            let final_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
            prop_assert_eq!(final_free, original_free);
        }

        /// Allocated blocks are actually marked in the bitmap.
        #[test]
        fn proptest_alloc_marks_bitmap_bits(
            block_count in 1_u32..8,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);

            let alloc = alloc_blocks(
                &cx, &dev, &geo, &mut groups, block_count, &AllocHint::default(),
            ).unwrap();

            // Read the bitmap for the group that owns the allocation.
            let (group, rel_start) = geo.absolute_to_group_block(alloc.start);
            let bitmap_block = groups[group.0 as usize].block_bitmap_block;
            let bm = dev.read_block(&cx, bitmap_block).unwrap();

            for i in 0..alloc.count {
                let bit = rel_start + i;
                prop_assert!(
                    bitmap_get(bm.as_slice(), bit),
                    "bit {} in group {} should be set after alloc",
                    bit, group.0,
                );
            }
        }

        /// No two allocations ever overlap.
        #[test]
        fn proptest_alloc_no_overlaps(
            num_allocs in 2_u32..12,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);

            let mut allocations = Vec::new();
            for _ in 0..num_allocs {
                match alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &AllocHint::default()) {
                    Ok(a) => allocations.push(a),
                    Err(_) => break,
                }
            }

            // Check no two allocations share the same block.
            for i in 0..allocations.len() {
                for j in (i + 1)..allocations.len() {
                    let a = &allocations[i];
                    let b = &allocations[j];
                    let a_end = a.start.0 + u64::from(a.count);
                    let b_end = b.start.0 + u64::from(b.count);
                    let overlaps = a.start.0 < b_end && b.start.0 < a_end;
                    prop_assert!(
                        !overlaps,
                        "allocations {} [{}, {}) and {} [{}, {}) overlap",
                        i, a.start.0, a_end,
                        j, b.start.0, b_end,
                    );
                }
            }
        }

        /// bitmap_find_contiguous with wraparound: if a run is found, it must
        /// consist of contiguous zero bits regardless of the start position.
        #[test]
        fn proptest_find_contiguous_wraparound_valid(
            byte_len in 1_usize..32,
            fill_percent in 0_u8..80,
            n in 1_u32..8,
            start_seed in any::<u32>(),
        ) {
            let total_bits =
                u32::try_from(byte_len * 8).expect("byte_len bound keeps bit length within u32");
            let mut bm = vec![0u8; byte_len];

            // Randomly fill some fraction of bits.
            let bits_to_set = (u32::from(fill_percent) * total_bits) / 100;
            // Deterministic pattern based on fill fraction.
            for i in 0..bits_to_set.min(total_bits) {
                let bit = (i.wrapping_mul(7) + i.wrapping_mul(13)) % total_bits;
                bitmap_set(&mut bm, bit);
            }

            let start = start_seed % total_bits;
            if let Some(pos) = bitmap_find_contiguous(&bm, total_bits, n, start) {
                // Entire run must be within bounds and all bits clear.
                prop_assert!(pos + n <= total_bits);
                for i in pos..pos + n {
                    prop_assert!(
                        !bitmap_get(&bm, i),
                        "bit {} in run [{}, {}) should be clear (start={})",
                        i, pos, pos + n, start,
                    );
                }
            }
        }

        /// GroupStats flag methods correctly detect UNINIT flags.
        #[test]
        fn proptest_groupstats_uninit_flags(flags in any::<u16>()) {
            let gs = GroupStats {
                group: GroupNumber(0),
                free_blocks: 100,
                free_inodes: 100,
                used_dirs: 0,
                block_bitmap_block: BlockNumber(1),
                inode_bitmap_block: BlockNumber(2),
                inode_table_block: BlockNumber(3),
                flags,
                block_bitmap_csum: 0,
                inode_bitmap_csum: 0,
            };
            prop_assert_eq!(gs.block_bitmap_uninit(), flags & GD_FLAG_BLOCK_UNINIT != 0);
            prop_assert_eq!(gs.inode_bitmap_uninit(), flags & GD_FLAG_INODE_UNINIT != 0);
        }

        /// Alloc fails with NoSpace when all groups are completely full.
        #[test]
        fn proptest_alloc_fails_when_all_full(
            block_count in 1_u32..8,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups: Vec<GroupStats> = (0..geo.group_count)
                .map(|g| GroupStats {
                    group: GroupNumber(g),
                    free_blocks: 0,
                    free_inodes: 0,
                    used_dirs: 100,
                    block_bitmap_block: BlockNumber(u64::from(g) * 100 + 1),
                    inode_bitmap_block: BlockNumber(u64::from(g) * 100 + 2),
                    inode_table_block: BlockNumber(u64::from(g) * 100 + 3),
                    flags: 0,
                    block_bitmap_csum: 0,
                    inode_bitmap_csum: 0,
                    })

                .collect();

            let result = alloc_blocks(
                &cx, &dev, &geo, &mut groups, block_count, &AllocHint::default(),
            );
            prop_assert!(result.is_err(), "alloc should fail when all groups are full");
        }

        /// Inode alloc fails when all inodes exhausted.
        #[test]
        fn proptest_inode_alloc_fails_when_exhausted(is_dir in any::<bool>()) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups: Vec<GroupStats> = (0..geo.group_count)
                .map(|g| GroupStats {
                    group: GroupNumber(g),
                    free_blocks: 1000,
                    free_inodes: 0,
                    used_dirs: 100,
                    block_bitmap_block: BlockNumber(u64::from(g) * 100 + 1),
                    inode_bitmap_block: BlockNumber(u64::from(g) * 100 + 2),
                    inode_table_block: BlockNumber(u64::from(g) * 100 + 3),
                    flags: 0,
                    block_bitmap_csum: 0,
                    inode_bitmap_csum: 0,
                    })

                .collect();

            let result = alloc_inode(
                &cx, &dev, &geo, &mut groups, GroupNumber(0), is_dir,
            );
            prop_assert!(result.is_err(), "inode alloc should fail when all inodes exhausted");
        }

        /// Bitmap with all bits set: find_free returns None.
        #[test]
        fn proptest_bitmap_full_find_free_none(
            byte_len in 1_usize..64,
            start_seed in any::<u32>(),
        ) {
            let total_bits =
                u32::try_from(byte_len * 8).expect("byte_len bound keeps bit length within u32");
            let bm = vec![0xFF_u8; byte_len];
            let start = start_seed % total_bits;
            prop_assert_eq!(bitmap_find_free(&bm, total_bits, start), None);
            prop_assert_eq!(bitmap_count_free(&bm, total_bits), 0);
        }

        /// Bitmap with all bits clear: find_free returns start (no wrap needed).
        #[test]
        fn proptest_bitmap_empty_find_free_at_start(
            byte_len in 1_usize..64,
            start_seed in any::<u32>(),
        ) {
            let total_bits =
                u32::try_from(byte_len * 8).expect("byte_len bound keeps bit length within u32");
            let bm = vec![0_u8; byte_len];
            let start = start_seed % total_bits;
            prop_assert_eq!(bitmap_find_free(&bm, total_bits, start), Some(start));
            prop_assert_eq!(bitmap_count_free(&bm, total_bits), total_bits);
        }

        /// AllocHint goal_group is respected when the group has free space.
        #[test]
        fn proptest_alloc_respects_goal_group(
            goal_group in 0_u32..4,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);

            let hint = AllocHint {
                goal_group: Some(GroupNumber(goal_group)),
                ..AllocHint::default()
            };

            let alloc = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &hint).unwrap();
            let (allocated_group, _) = geo.absolute_to_group_block(alloc.start);
            prop_assert_eq!(
                allocated_group.0, goal_group,
                "allocation should land in goal group {} but landed in {}",
                goal_group, allocated_group.0,
            );
        }

        // ── FsGeometry coordinate conversion properties ─────────────

        /// group_block_to_absolute → absolute_to_group_block roundtrip.
        #[test]
        fn proptest_geo_coordinate_roundtrip(
            group_idx in 0_u32..4,
            rel_block_seed in 0_u32..8192,
        ) {
            let geo = make_geometry();
            let group = GroupNumber(group_idx);
            let blocks_in = geo.blocks_in_group(group);
            let rel_block = rel_block_seed % blocks_in;

            let abs = geo.group_block_to_absolute(group, rel_block);
            let (back_group, back_rel) = geo.absolute_to_group_block(abs);
            prop_assert_eq!(back_group, group, "group mismatch");
            prop_assert_eq!(back_rel, rel_block, "relative block mismatch");
        }

        /// blocks_in_group is always <= blocks_per_group.
        #[test]
        fn proptest_blocks_in_group_bounded(group_idx in 0_u32..4) {
            let geo = make_geometry();
            let blocks = geo.blocks_in_group(GroupNumber(group_idx));
            prop_assert!(blocks <= geo.blocks_per_group);
            prop_assert!(blocks > 0);
        }

        /// inodes_in_group is always <= inodes_per_group.
        #[test]
        fn proptest_inodes_in_group_bounded(group_idx in 0_u32..4) {
            let geo = make_geometry();
            let inodes = geo.inodes_in_group(GroupNumber(group_idx));
            prop_assert!(inodes <= geo.inodes_per_group);
            prop_assert!(inodes > 0);
        }

        /// Sum of blocks_in_group across all groups = total_blocks - first_data_block.
        #[test]
        fn proptest_blocks_sum_equals_total(
            bpg in prop::sample::select(vec![1024_u32, 2048, 4096, 8192]),
            total_blocks_mult in 1_u64..=8,
        ) {
            let total_blocks = u64::from(bpg) * total_blocks_mult;
            let group_count = total_blocks.div_ceil(u64::from(bpg));
            if group_count > u64::from(u32::MAX) { return Ok(()); }
            #[expect(clippy::cast_possible_truncation)]
            let gc = group_count as u32;
            let geo = FsGeometry {
                blocks_per_group: bpg,
                inodes_per_group: 256,
                block_size: 4096,
                total_blocks,
                total_inodes: gc * 256,
                first_data_block: 0,
                group_count: gc,
                inode_size: 256,
                desc_size: 32,
                reserved_gdt_blocks: 0,
                first_meta_bg: 0,
                feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
                feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
                feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
                log_groups_per_flex: 0,
                backup_bgs: [0, 0],
                first_inode: 11,
                cluster_ratio: 1,
            };
            let sum: u64 = (0..gc).map(|g| u64::from(geo.blocks_in_group(GroupNumber(g)))).sum();
            prop_assert_eq!(sum, total_blocks);
        }

        // ── Bitmap edge case properties ─────────────────────────────

        /// bitmap_find_contiguous with n=0 always returns Some(0).
        #[test]
        fn proptest_find_contiguous_zero_always_succeeds(
            (ref bm, count) in bitmap_strat(),
            start_seed in any::<u32>(),
        ) {
            let start = start_seed % count;
            let result = bitmap_find_contiguous(bm, count, 0, start);
            prop_assert_eq!(result, Some(0));
        }

        /// bitmap_get beyond bitmap length returns false.
        #[test]
        fn proptest_bitmap_get_oob_is_true(
            byte_len in 1_usize..32,
            beyond in 0_u32..100,
        ) {
            let bm = vec![0xFF_u8; byte_len];
            let total = u32::try_from(byte_len * 8).unwrap();
            let oob_idx = total + beyond;
            prop_assert!(bitmap_get(&bm, oob_idx));
        }

        /// bitmap_set/clear beyond length is a no-op (no panic).
        #[test]
        fn proptest_bitmap_set_clear_oob_noop(
            byte_len in 1_usize..32,
            beyond in 0_u32..100,
        ) {
            let mut bm = vec![0_u8; byte_len];
            let original = bm.clone();
            let total = u32::try_from(byte_len * 8).unwrap();
            let oob_idx = total + beyond;
            bitmap_set(&mut bm, oob_idx);
            prop_assert!(bm == original, "set beyond bounds should not modify bitmap");
            bitmap_clear(&mut bm, oob_idx);
            prop_assert!(bm == original, "clear beyond bounds should not modify bitmap");
        }

        /// Setting a single bit increases count_free by exactly -1.
        #[test]
        fn proptest_set_decreases_free_by_one(
            byte_len in 1_usize..64,
            idx_seed in any::<u32>(),
        ) {
            let total_bits = u32::try_from(byte_len * 8).unwrap();
            let idx = idx_seed % total_bits;
            let mut bm = vec![0u8; byte_len];
            let before = bitmap_count_free(&bm, total_bits);
            bitmap_set(&mut bm, idx);
            let after = bitmap_count_free(&bm, total_bits);
            prop_assert_eq!(after, before - 1);
        }

        /// Clearing a set bit increases count_free by exactly +1.
        #[test]
        fn proptest_clear_increases_free_by_one(
            byte_len in 1_usize..64,
            idx_seed in any::<u32>(),
        ) {
            let total_bits = u32::try_from(byte_len * 8).unwrap();
            let idx = idx_seed % total_bits;
            let mut bm = vec![0xFF_u8; byte_len];
            let before = bitmap_count_free(&bm, total_bits);
            bitmap_clear(&mut bm, idx);
            let after = bitmap_count_free(&bm, total_bits);
            prop_assert_eq!(after, before + 1);
        }

        // ── Alloc/free interleaving property ────────────────────────

        /// Interleaved alloc/free operations maintain free count invariant.
        #[test]
        fn proptest_interleaved_alloc_free_consistent(
            ops in prop::collection::vec(prop::bool::ANY, 1..20),
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let original_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

            let mut allocated = Vec::new();
            let mut net_allocated = 0_u32;

            for do_alloc in &ops {
                if *do_alloc {
                    // Alloc 1 block
                    if let Ok(a) = alloc_blocks(&cx, &dev, &geo, &mut groups, 1, &AllocHint::default()) {
                        net_allocated += a.count;
                        allocated.push(a);
                    }
                } else if let Some(a) = allocated.pop() {
                    // Free last allocated block
                    free_blocks(&cx, &dev, &geo, &mut groups, a.start, a.count).unwrap();
                    net_allocated -= a.count;
                }

                // Invariant: current free = original - net_allocated
                let current_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
                prop_assert_eq!(
                    current_free, original_free - net_allocated,
                    "free count mismatch after op"
                );
            }
        }

        // ── Succinct bitmap properties ──────────────────────────────

        /// SuccinctBitmap rank0 + rank1 = position for all valid positions.
        #[test]
        fn proptest_succinct_rank_sum(
            (ref bm, count) in bitmap_strat(),
        ) {
            let sb = succinct::SuccinctBitmap::build(bm, count);
            // Check at a few positions within the range.
            for pos in [0, count / 4, count / 2, count.saturating_sub(1), count] {
                if pos <= count {
                    let r0 = sb.rank0(pos);
                    let r1 = sb.rank1(pos);
                    prop_assert_eq!(
                        r0 + r1, pos,
                        "rank0({}) + rank1({}) = {} != {}",
                        pos, pos, r0 + r1, pos,
                    );
                }
            }
        }

        /// SuccinctBitmap total ones matches manual popcount.
        #[test]
        fn proptest_succinct_ones_matches_popcount(
            (ref bm, count) in bitmap_strat(),
        ) {
            let sb = succinct::SuccinctBitmap::build(bm, count);
            let manual_ones = (0..count).filter(|&i| bitmap_get(bm, i)).count();
            prop_assert_eq!(
                sb.count_ones() as usize, manual_ones,
                "SuccinctBitmap.count_ones() mismatch"
            );
        }

        /// SuccinctBitmap select0 returns a valid zero-bit position.
        #[test]
        fn proptest_succinct_select0_valid(
            (ref bm, count) in bitmap_strat(),
        ) {
            let sb = succinct::SuccinctBitmap::build(bm, count);
            let zeros = sb.count_zeros();
            if zeros > 0 {
                // Check first and last zero.
                if let Some(pos) = sb.select0(0) {
                    prop_assert!(pos < count, "select0(0) = {} >= count {}", pos, count);
                    prop_assert!(!bitmap_get(bm, pos), "select0(0) points to a set bit");
                }
                if let Some(pos) = sb.select0(zeros - 1) {
                    prop_assert!(pos < count, "select0(last) = {} >= count", pos);
                    prop_assert!(!bitmap_get(bm, pos), "select0(last) points to a set bit");
                }
            }
            // select0 beyond zeros count returns None.
            prop_assert_eq!(sb.select0(zeros), None);
        }

        /// SuccinctBitmap select1 returns a valid one-bit position.
        #[test]
        fn proptest_succinct_select1_valid(
            (ref bm, count) in bitmap_strat(),
        ) {
            let sb = succinct::SuccinctBitmap::build(bm, count);
            let ones = sb.count_ones();
            if ones > 0 {
                if let Some(pos) = sb.select1(0) {
                    prop_assert!(pos < count);
                    prop_assert!(bitmap_get(bm, pos), "select1(0) points to a zero bit");
                }
                if let Some(pos) = sb.select1(ones - 1) {
                    prop_assert!(pos < count);
                    prop_assert!(bitmap_get(bm, pos), "select1(last) points to a zero bit");
                }
            }
            prop_assert_eq!(sb.select1(ones), None);
        }

        /// SuccinctBitmap find_free agrees with bitmap_find_free for start=0.
        #[test]
        fn proptest_succinct_find_free_matches_linear(
            (ref bm, count) in bitmap_strat(),
        ) {
            let sb = succinct::SuccinctBitmap::build(bm, count);
            let linear = bitmap_find_free(bm, count, 0);
            let succinct_result = sb.find_free(0);
            prop_assert_eq!(
                succinct_result, linear,
                "find_free mismatch: succinct={:?}, linear={:?}",
                succinct_result, linear,
            );
        }

        // ── Free blocks validation properties ───────────────────────

        /// Freeing blocks at an out-of-range group returns Corruption error.
        #[test]
        fn proptest_free_blocks_oob_group_errors(
            group_offset in 4_u32..100,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);

            // Build an absolute block in a non-existent group.
            let bad_start = BlockNumber(u64::from(group_offset) * u64::from(geo.blocks_per_group));
            let result = free_blocks(&cx, &dev, &geo, &mut groups, bad_start, 1);
            prop_assert!(result.is_err(), "free_blocks should reject out-of-range group");
        }

        /// Freeing blocks can span groups when the target groups expose data at
        /// the segment boundary.
        #[test]
        fn proptest_free_blocks_cross_boundary_splits_segments(
            count in 2_u32..33,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let mut geo = make_geometry();
            let mut groups = make_groups(&geo);
            geo.feature_ro_compat.0 |= ffs_ondisk::Ext4RoCompatFeatures::SPARSE_SUPER.0;

            let group2_start = u64::from(geo.blocks_per_group) * 2;
            groups[2].block_bitmap_block = BlockNumber(group2_start + 64);
            groups[2].inode_bitmap_block = BlockNumber(group2_start + 65);
            groups[2].inode_table_block = BlockNumber(group2_start + 96);

            let rel_start = geo.blocks_in_group(GroupNumber(1)) - 1;
            let start = geo.group_block_to_absolute(GroupNumber(1), rel_start);
            let cross_count = count.min(32);

            let result = free_blocks(&cx, &dev, &geo, &mut groups, start, cross_count);
            prop_assert!(result.is_ok(), "free_blocks should segment cross-group frees");
        }

        /// `bitmap_find_free` with start >= count is clamped and doesn't panic.
        #[test]
        fn proptest_bitmap_find_free_start_past_count(
            (ref bm, count) in bitmap_strat(),
            excess in 0_u32..1000,
        ) {
            let start = count.saturating_add(excess);
            // Must not panic. Result correctness: wraps to scan 0..count.
            if let Some(pos) = bitmap_find_free(bm, count, start) {
                prop_assert!(pos < count, "found pos {} >= count {}", pos, count);
                prop_assert!(!bitmap_get(bm, pos));
            }
        }

        /// `bitmap_find_contiguous` with start past end still finds runs.
        #[test]
        fn proptest_bitmap_find_contiguous_start_past_count(
            n in 1_u32..8,
        ) {
            let count = 32_u32;
            let bm = vec![0u8; 4]; // all free
            let result = bitmap_find_contiguous(&bm, count, n, count + 100);
            // All bits free, so a contiguous run of n should be found.
            prop_assert!(result.is_some(), "should find {} contiguous in all-free bitmap", n);
            let start = result.unwrap();
            prop_assert!(start + n <= count);
        }

        /// `bitmap_count_free` on a zero-length bitmap returns 0.
        #[test]
        fn proptest_bitmap_count_free_zero_count(ref bm in proptest::collection::vec(any::<u8>(), 0..32)) {
            prop_assert_eq!(bitmap_count_free(bm, 0), 0);
        }

        /// bitmap_find_free on zero-count bitmap returns None.
        #[test]
        fn proptest_bitmap_find_free_zero_count(start in any::<u32>()) {
            let bm = vec![0u8; 4];
            prop_assert!(bitmap_find_free(&bm, 0, start).is_none());
        }

        /// When `count` extends beyond bitmap capacity, out-of-range bits are
        /// treated as allocated and must not inflate free-bit counts.
        #[test]
        fn proptest_bitmap_count_free_overscan_matches_manual(
            bm in proptest::collection::vec(any::<u8>(), 1..32),
            extra in 1_u32..256,
        ) {
            let bit_len = u32::try_from(bm.len() * 8).expect("bitmap bit length fits in u32");
            let count = bit_len.saturating_add(extra);
            let free = bitmap_count_free(&bm, count);
            let manual_free = (0..count).fold(0_u32, |acc, i| acc + u32::from(!bitmap_get(&bm, i)));
            prop_assert_eq!(free, manual_free);
        }

        /// If a contiguous run request exceeds `count`, allocator must return None.
        #[test]
        fn proptest_bitmap_find_contiguous_n_exceeds_count_returns_none(
            (ref bm, count) in bitmap_strat(),
            extra in 1_u32..64,
            start_seed in any::<u32>(),
        ) {
            let n = count.saturating_add(extra);
            let start = if count == 0 { 0 } else { start_seed % count };
            let found = bitmap_find_contiguous(bm, count, n, start);
            prop_assert_eq!(found, None);
        }

        /// Empty bitmap with non-zero `count` should report no free slots.
        #[test]
        fn proptest_empty_bitmap_nonzero_count_has_no_free(
            count in 1_u32..1024,
            start in any::<u32>(),
        ) {
            let bm: Vec<u8> = Vec::new();
            prop_assert_eq!(bitmap_count_free(&bm, count), 0);
            prop_assert_eq!(bitmap_find_free(&bm, count, start), None);
            prop_assert_eq!(bitmap_find_contiguous(&bm, count, 1, start), None);
        }

        /// bitmap_largest_free_run is deterministic for any (bitmap, count).
        /// Guards against any future SIMD/vectorized rewrite that loses
        /// referential transparency.
        #[test]
        fn proptest_bitmap_largest_free_run_is_deterministic(
            (ref bm, count) in bitmap_strat(),
        ) {
            let a = bitmap_largest_free_run(bm, count);
            let b = bitmap_largest_free_run(bm, count);
            prop_assert_eq!(a, b);
        }

        /// Cross-check the BYTE_ZERO_RUNS lookup-table fast path against
        /// a naive bit-by-bit scan over the first `count` bits via
        /// bitmap_get. The two must agree on every input — locks the
        /// algorithm against table or boundary-handling regressions.
        #[test]
        fn proptest_bitmap_largest_free_run_matches_naive_scan(
            (ref bm, count) in bitmap_strat(),
        ) {
            let fast = bitmap_largest_free_run(bm, count);
            let mut naive_best = 0_u32;
            let mut naive_run = 0_u32;
            for i in 0..count {
                if bitmap_get(bm, i) {
                    naive_run = 0;
                } else {
                    naive_run += 1;
                    if naive_run > naive_best {
                        naive_best = naive_run;
                    }
                }
            }
            prop_assert_eq!(
                fast, naive_best,
                "fast={}, naive={} for count={}",
                fast, naive_best, count
            );
        }

        /// The largest free run can never exceed `count` (the number of
        /// bits scanned) nor the total free bit count.
        #[test]
        fn proptest_bitmap_largest_free_run_bounded_by_count_and_free(
            (ref bm, count) in bitmap_strat(),
        ) {
            let largest = bitmap_largest_free_run(bm, count);
            let free = bitmap_count_free(bm, count);
            prop_assert!(
                largest <= count,
                "largest {} > count {}",
                largest, count
            );
            prop_assert!(
                largest <= free,
                "largest {} > free {} (run can't exceed total free)",
                largest, free
            );
        }

        /// Setting a previously-free bit can never increase the largest
        /// free run. Composition MR: monotone-decreasing in set operations.
        #[test]
        fn proptest_bitmap_largest_free_run_monotone_under_set(
            (bm0, count) in bitmap_strat(),
            idx_seed in any::<u32>(),
        ) {
            let before = bitmap_largest_free_run(&bm0, count);
            let mut bm = bm0;
            let idx = idx_seed % count;
            bitmap_set(&mut bm, idx);
            let after = bitmap_largest_free_run(&bm, count);
            prop_assert!(
                after <= before,
                "setting a bit increased largest run: before={}, after={}",
                before, after
            );
        }

        /// All-zero bitmap: the largest free run equals `count` exactly
        /// (every bit in [0, count) is free, so the run spans the whole
        /// window). This pins the lookup-table's full-byte fast path.
        #[test]
        fn proptest_bitmap_largest_free_run_all_zeros_equals_count(
            byte_len in 1_usize..64,
            count_offset in 0_u32..8,
        ) {
            let bm = vec![0_u8; byte_len];
            let max_count = u32::try_from(byte_len * 8).unwrap();
            let count = max_count.saturating_sub(count_offset).max(1);
            prop_assert_eq!(bitmap_largest_free_run(&bm, count), count);
        }

        #[test]
        fn proptest_batch_alloc_matches_repeated_single_persist(
            group0 in batch_occupied_group_strat(),
            group1 in batch_occupied_group_strat(),
            group2 in batch_occupied_group_strat(),
            group3 in batch_occupied_group_strat(),
            request in 1_u32..96,
            hint_case in 0_u8..5,
            group_seed in 0_u32..16,
            rel_seed in 0_u32..64,
        ) {
            let geo = make_batch_equivalence_geometry();
            let hint = batch_equivalence_hint_from_case(&geo, hint_case, group_seed, rel_seed);
            let occupied_by_group = vec![group0, group1, group2, group3];

            assert_batch_single_equivalence(&occupied_by_group, request, &hint);
        }
    }

    // ── Batch allocation tests ────────────────────────────────────────────

    #[test]
    fn batch_vs_single_equivalence_spills_after_goal_group_exhausts() {
        let geo = make_batch_equivalence_geometry();
        let groups = make_batch_equivalence_groups(&geo);
        let mut occupied_by_group = vec![Vec::new(); geo.group_count as usize];
        occupied_by_group[1] =
            occupied_all_allocatable_except(&geo, &groups, GroupNumber(1), &[8, 9, 10]);
        let hint = AllocHint {
            goal_group: Some(GroupNumber(1)),
            ..AllocHint::default()
        };

        assert_batch_single_equivalence(&occupied_by_group, 7, &hint);
    }

    #[test]
    fn batch_vs_single_equivalence_respects_goal_group_over_foreign_goal_block() {
        let geo = make_batch_equivalence_geometry();
        let occupied_by_group = vec![Vec::new(); geo.group_count as usize];
        let hint = AllocHint {
            goal_group: Some(GroupNumber(2)),
            goal_block: Some(geo.group_block_to_absolute(GroupNumber(3), 20)),
            numa: None,
        };

        assert_batch_single_equivalence(&occupied_by_group, 12, &hint);
    }

    #[test]
    fn batch_alloc_insufficient_space_rolls_back_seeded_bitmaps() {
        let geo = make_batch_equivalence_geometry();
        let groups = make_batch_equivalence_groups(&geo);
        let mut occupied_by_group = vec![Vec::new(); geo.group_count as usize];
        occupied_by_group[0] = occupied_all_allocatable_except(&geo, &groups, GroupNumber(0), &[8]);
        occupied_by_group[1] = occupied_all_allocatable_except(&geo, &groups, GroupNumber(1), &[8]);
        occupied_by_group[2] = occupied_all_allocatable_except(&geo, &groups, GroupNumber(2), &[8]);
        occupied_by_group[3] = occupied_all_allocatable_except(&geo, &groups, GroupNumber(3), &[]);

        assert_batch_single_equivalence(&occupied_by_group, 4, &AllocHint::default());
    }

    #[test]
    fn batch_alloc_gdt_write_failure_restores_bitmap_and_group_stats() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        seed_gdt_block(&dev, &pctx, &groups);

        let initial_free = groups[0].free_blocks;
        let bitmap_block = groups[0].block_bitmap_block;
        let initial_bitmap = dev
            .read_block(&cx, bitmap_block)
            .unwrap()
            .as_slice()
            .to_vec();
        let initial_gdt_free = read_gdt_free_blocks(&cx, &dev, &pctx, GroupNumber(0));
        let failing = FailGdtWriteDevice::new(&dev, pctx.gdt_block);

        let err = alloc_blocks_batch_persist(
            &cx,
            &failing,
            &geo,
            &mut groups,
            3,
            &AllocHint::default(),
            &pctx,
        )
        .unwrap_err();

        assert!(matches!(err, FfsError::Io(_)));
        assert_eq!(groups[0].free_blocks, initial_free);
        assert_eq!(
            dev.read_block(&cx, bitmap_block).unwrap().as_slice(),
            initial_bitmap.as_slice()
        );
        assert_eq!(
            read_gdt_free_blocks(&cx, &dev, &pctx, GroupNumber(0)),
            initial_gdt_free
        );
    }

    #[test]
    fn batch_alloc_zero_returns_empty() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        let hint = AllocHint::default();

        let result =
            alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups, 0, &hint, &pctx).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn batch_alloc_single_delegates() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        let hint = AllocHint::default();

        let result =
            alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups, 1, &hint, &pctx).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].count, 1);
    }

    #[test]
    fn batch_alloc_multiple_returns_correct_count() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        let hint = AllocHint::default();

        let n = 10;
        let result =
            alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups, n, &hint, &pctx).unwrap();
        assert_eq!(result.len(), n as usize);

        // All allocations should be single blocks.
        for alloc in &result {
            assert_eq!(alloc.count, 1);
        }

        // No duplicates.
        let mut blocks: Vec<u64> = result.iter().map(|a| a.start.0).collect();
        blocks.sort_unstable();
        blocks.dedup();
        assert_eq!(blocks.len(), n as usize);
    }

    #[test]
    fn batch_alloc_free_space_accounting() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        let hint = AllocHint::default();

        let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

        let n = 20;
        alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups, n, &hint, &pctx).unwrap();

        let after_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
        assert_eq!(initial_free - after_free, n);
    }

    #[test]
    fn batch_alloc_locality_prefers_goal_group() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        let hint = AllocHint {
            goal_group: Some(GroupNumber(2)),
            goal_block: None,
            numa: None,
        };

        let result =
            alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups, 5, &hint, &pctx).unwrap();

        // All blocks should be in group 2 (plenty of space).
        for alloc in &result {
            let (group, _) = geo.absolute_to_group_block(alloc.start);
            assert_eq!(group, GroupNumber(2));
        }
    }

    #[test]
    fn batch_alloc_no_space_returns_error() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        let hint = AllocHint::default();

        // Set all groups to 0 free blocks.
        for g in &mut groups {
            g.free_blocks = 0;
        }

        let err =
            alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups, 5, &hint, &pctx).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn batch_alloc_spills_across_groups() {
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = make_persist_ctx();
        let hint = AllocHint::default();

        // Restrict group 0 to 3 free blocks.
        groups[0].free_blocks = 3;

        let result =
            alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups, 5, &hint, &pctx).unwrap();
        assert_eq!(result.len(), 5);

        // At least some should come from group 0, rest from other groups.
        let from_g0 = result
            .iter()
            .filter(|a| geo.absolute_to_group_block(a.start).0 == GroupNumber(0))
            .count();
        assert!(from_g0 <= 3);
    }

    #[test]
    fn batch_vs_single_equivalence() {
        // Allocate N blocks via batch, then N via single, verify both produce
        // valid non-overlapping allocations with correct free space accounting.
        let cx = Cx::for_testing();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let hint = AllocHint::default();
        let pctx = make_persist_ctx();

        // Batch path.
        let mut groups_batch = make_groups(&geo);
        let batch_result =
            alloc_blocks_batch_persist(&cx, &dev, &geo, &mut groups_batch, 10, &hint, &pctx)
                .unwrap();

        // Single path.
        let mut groups_single = make_groups(&geo);
        let mut single_result = Vec::new();
        for _ in 0..10 {
            single_result.push(
                alloc_blocks_persist(&cx, &dev, &geo, &mut groups_single, 1, &hint, &pctx).unwrap(),
            );
        }

        // Both should allocate exactly 10 blocks.
        assert_eq!(batch_result.len(), 10);
        assert_eq!(single_result.len(), 10);

        // Free space delta should be identical.
        let batch_free: u32 = groups_batch.iter().map(|g| g.free_blocks).sum();
        let single_free: u32 = groups_single.iter().map(|g| g.free_blocks).sum();
        assert_eq!(batch_free, single_free);
    }

    // ── largest_free_run (bd-oqphq) ─────────────────────────────────────

    #[test]
    fn largest_free_run_empty_bitmap_returns_zero() {
        assert_eq!(bitmap_largest_free_run(&[], 0), 0);
        assert_eq!(bitmap_largest_free_run(&[0u8; 0], 8), 0);
    }

    #[test]
    fn largest_free_run_all_zeros_returns_count() {
        let bitmap = [0u8; 16];
        assert_eq!(bitmap_largest_free_run(&bitmap, 128), 128);
        // Partial count smaller than bitmap.
        assert_eq!(bitmap_largest_free_run(&bitmap, 100), 100);
    }

    #[test]
    fn largest_free_run_all_ones_returns_zero() {
        let bitmap = [0xFFu8; 16];
        assert_eq!(bitmap_largest_free_run(&bitmap, 128), 0);
    }

    #[test]
    fn largest_free_run_single_run_in_middle() {
        // 16 bytes, all 0xFF except bytes 4..8 = 0 → 32 free bits.
        let mut bitmap = [0xFFu8; 16];
        for byte in &mut bitmap[4..8] {
            *byte = 0;
        }
        assert_eq!(bitmap_largest_free_run(&bitmap, 128), 32);
    }

    #[test]
    fn largest_free_run_picks_max_of_multiple_runs() {
        // Three runs: 8 free (byte 0), 24 free (bytes 4..7), 16 free (bytes 12..14).
        let mut bitmap = [0xFFu8; 16];
        bitmap[0] = 0; // 8-bit run
        bitmap[4] = 0;
        bitmap[5] = 0;
        bitmap[6] = 0; // 24-bit run
        bitmap[12] = 0;
        bitmap[13] = 0; // 16-bit run
        assert_eq!(bitmap_largest_free_run(&bitmap, 128), 24);
    }

    #[test]
    fn largest_free_run_handles_partial_byte_boundaries() {
        // bytes: 0xF0 0xFF 0x0F → bits 0..4 free, 4..12 used, 12..16 free.
        // Within count=16: longest run is 4.
        let bitmap = [0xF0u8, 0xFF, 0x0F];
        assert_eq!(bitmap_largest_free_run(&bitmap, 16), 4);
    }

    #[test]
    fn largest_free_run_spans_byte_boundary() {
        // bytes: 0xC0 0x03 = bits 0..6 free, 6..10 used, 10..16 free.
        // Wait — bit numbering is LSB-first per bitmap_get. 0xC0 = 0b11000000:
        // bits 0..5 = 0 (free), bits 6..7 = 1 (used).
        // 0x03 = 0b00000011: bits 0..1 = 1 (used), bits 2..7 = 0 (free).
        // So free run at bits 10..16 = 6, free run at bits 0..5 = 6.
        // No span across the boundary because bits 6..9 are used.
        let bitmap = [0xC0u8, 0x03];
        assert_eq!(bitmap_largest_free_run(&bitmap, 16), 6);

        // Now an actual span: 0x80 0x01 = bits 0..6 free, bit 7 used, bit 8 used,
        // bits 9..15 free. Largest = 7 (the right run).
        let bitmap = [0x80u8, 0x01];
        assert_eq!(bitmap_largest_free_run(&bitmap, 16), 7);

        // Span spanning byte boundary: 0x00 0x00 0xFF = 16 free bits, then used.
        let bitmap = [0x00u8, 0x00, 0xFF];
        assert_eq!(bitmap_largest_free_run(&bitmap, 24), 16);
    }

    #[test]
    fn largest_free_run_spans_word_boundary_bit128() {
        let mut bitmap = [0xFFu8; 40];
        for bit in 120..136 {
            bitmap_clear(&mut bitmap, bit);
        }
        assert_eq!(bitmap_largest_free_run(&bitmap, 320), 16);
    }

    #[test]
    fn largest_free_run_count_smaller_than_byte_remainder() {
        // 1 byte with bits 0..3 free, bits 4..7 used. count=8 → run=4.
        let bitmap = [0xF0u8];
        assert_eq!(bitmap_largest_free_run(&bitmap, 8), 4);

        // count=4 (only inspect first nibble; all free) → run=4.
        let bitmap = [0xF0u8];
        assert_eq!(bitmap_largest_free_run(&bitmap, 4), 4);

        // count=3 → run=3 (cap at count).
        let bitmap = [0x00u8];
        assert_eq!(bitmap_largest_free_run(&bitmap, 3), 3);
    }

    #[test]
    fn largest_free_run_full_zero_byte_extends_existing_run() {
        // bytes: 0x80 (bits 0..6 free, bit 7 used) — wait actually 0x80 = 0b10000000:
        // bit 7 = 1, bits 0..6 = 0. So bits 0..6 free → run=7, then bit 7 used breaks.
        // Then 0x00 0x00: 16 free. Then 0xFF: terminates.
        // Total largest = 16.
        let bitmap = [0x80u8, 0x00, 0x00, 0xFF];
        assert_eq!(bitmap_largest_free_run(&bitmap, 32), 16);

        // Now bridge a partial byte into a 0x00 byte: 0x00 0x00 0x80 = 8 free, then 8 free,
        // then bits 0..6 free (continuation). Run = 8 + 8 + 7 = 23.
        let bitmap = [0x00u8, 0x00, 0x80];
        assert_eq!(bitmap_largest_free_run(&bitmap, 24), 23);
    }

    #[test]
    fn largest_free_run_matches_count_free_when_all_runs_equal() {
        // If the whole bitmap is one big free run, the largest run equals
        // bitmap_count_free.
        let bitmap = [0u8; 32];
        let count = 256_u32;
        assert_eq!(
            bitmap_largest_free_run(&bitmap, count),
            bitmap_count_free(&bitmap, count)
        );
    }

    #[test]
    fn bitmap_largest_free_run_golden_report() {
        let cases: &[(&str, &[u8], u32)] = &[
            ("empty_zero", &[], 0),
            ("missing_byte_nonzero_count", &[], 8),
            ("all_used", &[0xFF, 0xFF, 0xFF, 0xFF], 32),
            ("all_free_partial", &[0x00, 0x00, 0x00], 20),
            ("lsb_prefix", &[0xF0], 8),
            ("spans_byte", &[0x80, 0x01], 16),
            ("full_zero_extends", &[0x80, 0x00, 0x00, 0xFF], 32),
            (
                "fragmented",
                &[0x55, 0x33, 0xF0, 0x00, 0x7F, 0xFF, 0x01],
                53,
            ),
            ("truncated_mid_run", &[0x00, 0x00], 24),
        ];

        println!("LARGEST_FREE_RUN_GOLDEN_BEGIN");
        for (name, bitmap, count) in cases {
            let result = bitmap_largest_free_run(bitmap, *count);
            println!("case={name}\tcount={count}\tresult={result}");
        }
        println!("LARGEST_FREE_RUN_GOLDEN_END");
    }
}
