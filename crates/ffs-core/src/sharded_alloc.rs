//! Per-group allocator lock decomposition (bd-bhh0i step 5), **default-OFF**.
//!
//! This is the production primitive matching the Loom-verified decomposition
//! (`tests/bd_bhh0i_lock_decomposition_model.rs`): the single whole-state
//! `RwLock<Ext4AllocState>` that serializes every ext4 mutation is replaced by
//! per-group locks, so disjoint-group creates proceed concurrently. Immutable
//! geometry is NOT held here — it is derived lock-free from the superblock
//! (`FsGeometry::from_superblock`), so this structure holds ONLY the per-group
//! mutable allocation records.
//!
//! Gated behind the `bhh0i_sharded_alloc` feature (default off). With the
//! feature off this module is not compiled and production keeps the single lock,
//! so the sharded path is byte-identical-absent by construction; the mandatory
//! e2fsck-clean cutover gate (step 7) is only reached once this path is wired in
//! and enabled. Building the primitive first lets it be Loom/bench/cargo-verified
//! entirely remote-only before any cutover.

#![allow(dead_code)] // wired into the alloc path in a later bd-bhh0i slice.

use ffs_alloc::GroupStats;
use parking_lot::{Mutex, MutexGuard};

/// One block group's mutable allocation record behind its own lock, cache-line
/// aligned to avoid false sharing between adjacent groups. The
/// `ext4_group_lock_layout` bench measured `#[repr(align(64))]` (Padded) beating
/// the unpadded layout under disjoint-group concurrent writes.
#[repr(align(64))]
struct GroupLock {
    stats: Mutex<GroupStats>,
}

/// Sharded per-group ext4 allocation records: one independently lockable record
/// per block group. A mutation locks only its target group's record, so
/// disjoint-group mutations never contend. A multi-group allocation scan
/// (goal → neighbors → full fallback) acquires group locks one at a time along
/// the scan and never holds two group locks at once, matching the
/// `groups(sorted)` acquisition order the Loom writer projection proves
/// deadlock-free and linearizable.
pub(crate) struct PerGroupAlloc {
    groups: Vec<GroupLock>,
}

impl PerGroupAlloc {
    /// Build the sharded records from the same `Vec<GroupStats>` the single-lock
    /// `Ext4AllocState` holds, moving each group's stats behind its own lock
    /// (no clone; identical initial state).
    pub(crate) fn from_group_stats(groups: Vec<GroupStats>) -> Self {
        Self {
            groups: groups
                .into_iter()
                .map(|stats| GroupLock {
                    stats: Mutex::new(stats),
                })
                .collect(),
        }
    }

    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Lock a single group's record. Callers acquire at most one group lock at a
    /// time during a scan (see the struct doc); acquiring in ascending group
    /// order when more than one is ever needed preserves the sorted-acquisition
    /// invariant the Loom model relies on.
    pub(crate) fn lock_group(&self, group: usize) -> MutexGuard<'_, GroupStats> {
        self.groups[group].stats.lock()
    }

    /// The Part-A multi-group allocation scan. Walks `order` (the goal group →
    /// ±neighbors → full-fallback sequence produced by
    /// `ffs_alloc::allocation_group_order`), locking each candidate group ONE AT
    /// A TIME, and returns the first group where `try_in_group` succeeds. The
    /// group lock is released before advancing, so at most one group lock is held
    /// at any instant — exactly the single-acquisition discipline the Loom writer
    /// projection proves deadlock-free (no two-lock cycle) and linearizable, and
    /// the resolution for the "a request that can't fit in the goal group mutates
    /// a different group" hazard that made naive fixed-target locking wrong.
    ///
    /// `try_in_group(group, &mut stats)` performs the real in-group allocation
    /// (bitmap read/set + count decrement, e.g. via `ffs_alloc::try_alloc_safe`
    /// with the device + geometry captured), returning `Some(result)` on success
    /// (leaving that group mutated) or `None` to fall through to the next group.
    /// Out-of-range group indices in `order` are skipped.
    pub(crate) fn alloc_in_scan_order<T>(
        &self,
        order: impl IntoIterator<Item = usize>,
        mut try_in_group: impl FnMut(usize, &mut GroupStats) -> Option<T>,
    ) -> Option<T> {
        for group in order {
            if group >= self.groups.len() {
                continue;
            }
            let mut stats = self.groups[group].stats.lock();
            if let Some(result) = try_in_group(group, &mut stats) {
                return Some(result);
            }
            // `stats` (the group lock) is dropped here, before the next group —
            // never two group locks at once.
        }
        None
    }

    /// Sum of `free_blocks` and `free_inodes` across every group, each read under
    /// its own lock. Backs the whole-array fold consumers the single lock served
    /// (`ext4_sync_superblock_free_totals` and `statfs`).
    ///
    /// Snapshot semantics: this reads groups one lock at a time, so it is NOT a
    /// globally-atomic instant — with concurrent allocations in flight the totals
    /// can lag by the in-flight per-group deltas. That is acceptable for both
    /// consumers: the superblock total is written at the durability boundary,
    /// where the allocation storm has quiesced and every group's count is final
    /// (so the fold is EXACT there — the state e2fsck checks), and `statfs` is
    /// advisory. It mirrors the single-lock fold's result whenever no mutation is
    /// concurrent, which is the only point either total is persisted or gated.
    pub(crate) fn total_free(&self) -> FreeTotals {
        let mut blocks = 0_u64;
        let mut inodes = 0_u64;
        for group in &self.groups {
            let stats = group.stats.lock();
            blocks += u64::from(stats.free_blocks);
            inodes += u64::from(stats.free_inodes);
        }
        FreeTotals { blocks, inodes }
    }

    /// Clone every group's `GroupStats`, one group-lock at a time — the full
    /// authoritative per-group state (free counts, UNINIT flags, itable_unused,
    /// bitmap locators) the deferred-GDT flush needs. After sharded creates the
    /// single-lock `Ext4AllocState.groups` array is STALE (the sharded path debits
    /// these records + the on-disk GDs, never that array), so the durability-boundary
    /// `ext4_flush_group_descriptors` must source the descriptors from HERE or it
    /// writes stale (still-UNINIT, still-full) descriptors → e2fsck-dirty. Exact at a
    /// quiesced flush boundary (same semantics as [`Self::total_free`]).
    pub(crate) fn snapshot_group_stats(&self) -> Vec<GroupStats> {
        self.groups.iter().map(|g| g.stats.lock().clone()).collect()
    }

    /// Per-group free counts, snapshotted one group-lock at a time — the input a
    /// sharded Orlov directory allocator needs (`orlov_choose_group_for_dir` reads
    /// each group's `free_inodes`/`free_blocks`/`used_dirs` plus the fs-wide
    /// averages to spread directories across groups). Same per-group-instant
    /// snapshot semantics as [`Self::total_free`]: exact at a quiesced point,
    /// advisory under concurrent mutation — fine for a placement heuristic.
    pub(crate) fn group_free_snapshot(&self) -> Vec<GroupFree> {
        self.groups
            .iter()
            .map(|g| {
                let s = g.stats.lock();
                GroupFree {
                    free_blocks: s.free_blocks,
                    free_inodes: s.free_inodes,
                    used_dirs: s.used_dirs,
                }
            })
            .collect()
    }

    /// Sharded Orlov directory placement (bd-bhh0i slice c3): choose the group a
    /// new DIRECTORY inode should target, computed off the lock-free
    /// [`Self::group_free_snapshot`] rather than the single whole-state lock. The
    /// caller feeds the result into [`Self::alloc_inode`] as `target` for
    /// directories (files keep passing their parent group), replacing the
    /// single-lock `orlov_choose_group_for_dir` step. Advisory under concurrency
    /// like every snapshot consumer here — Orlov is a placement heuristic and the
    /// subsequent goal→neighbors→full scan falls through if the chosen group has
    /// since filled. `None` only when no group has a free inode.
    pub(crate) fn choose_dir_group(&self) -> Option<ffs_types::GroupNumber> {
        choose_dir_group_from_snapshot(&self.group_free_snapshot())
    }

    /// Sharded per-group block allocation (bd-bhh0i Part A): walk the
    /// goal→neighbors→full order (`ffs_alloc::allocation_group_order`), locking
    /// ONE group at a time, and allocate `count` blocks in the first group that
    /// can satisfy. Disjoint-group callers never contend. `reserved` is read from
    /// each locked group's own pre-populated cache (filled at `enable_writes`), so
    /// no sibling-group access is needed. `pctx`/`geo` are immutable and supplied
    /// lock-free by the caller. Mirrors the single-lock `alloc_blocks_persist`
    /// result for the same starting state (it composes the identical
    /// `try_alloc_blocks_in_group` core over the identical scan order).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn alloc_blocks(
        &self,
        cx: &asupersync::Cx,
        dev: &dyn ffs_block::BlockDevice,
        geo: &ffs_alloc::FsGeometry,
        hint: &ffs_alloc::AllocHint,
        count: u32,
        pctx: &ffs_alloc::PersistCtx,
    ) -> Result<Option<ffs_alloc::BlockAlloc>, ffs_error::FfsError> {
        let order = ffs_alloc::allocation_group_order(geo, hint)?;
        self.alloc_in_scan_order(order.iter().map(|g| g.0 as usize), |g, stats| {
            // Read this locked group's own pre-populated reserved set. The Arc
            // clone releases the `reserved_cache` borrow before the `&mut stats`
            // call below; empty only if unpopulated (never, under the feature).
            let reserved = stats.reserved_cache.get().cloned().unwrap_or_default();
            match ffs_alloc::try_alloc_blocks_in_group(
                cx,
                dev,
                geo,
                stats,
                ffs_types::GroupNumber(u32::try_from(g).unwrap_or(u32::MAX)),
                count,
                hint,
                pctx,
                &reserved,
            ) {
                Ok(Some(alloc)) => Some(Ok(alloc)), // allocated → stop the scan
                Ok(None) => None,                   // group can't satisfy → continue
                Err(err) => Some(Err(err)),         // real error → stop, propagate
            }
        })
        .transpose()
    }

    /// Sharded per-group block FREE (bd-bhh0i): free `count` blocks starting at
    /// `start`, which MUST lie entirely within one group (a tree-node block or one
    /// same-group extent segment — the only runs the sharded growth/free path
    /// produces). Locks ONLY the owning group and composes
    /// [`ffs_alloc::free_blocks_in_group`] over the locked `&mut GroupStats`
    /// (reading that group's pre-populated `reserved_cache`), mirroring how
    /// [`Self::alloc_blocks`] composes the alloc core — so disjoint-group frees
    /// never contend.
    ///
    /// The single-lock `free_blocks_persist` SPLITS a cross-group run into
    /// per-group segments; this single-group primitive instead REJECTS a run that
    /// would cross the group boundary (`Corruption`) rather than silently mutating
    /// the neighbor group. No sharded caller produces such a run, so this is a
    /// defensive guard, not a behavior change on real inputs. `count == 0` is a
    /// no-op (matching `free_blocks_persist`'s empty-segment result).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn free_blocks(
        &self,
        cx: &asupersync::Cx,
        dev: &dyn ffs_block::BlockDevice,
        geo: &ffs_alloc::FsGeometry,
        start: ffs_types::BlockNumber,
        count: u32,
        pctx: &ffs_alloc::PersistCtx,
    ) -> Result<(), ffs_error::FfsError> {
        if count == 0 {
            return Ok(());
        }
        let (group, rel_start) = geo.absolute_to_group_block(start);
        let gidx = group.0 as usize;
        if gidx >= self.groups.len() {
            return Err(ffs_error::FfsError::Corruption {
                block: start.0,
                detail: "sharded free: block group out of range".into(),
            });
        }
        let group_blocks = geo.blocks_in_group(group);
        match rel_start.checked_add(count) {
            Some(end) if end <= group_blocks => {}
            _ => {
                return Err(ffs_error::FfsError::Corruption {
                    block: start.0,
                    detail: "sharded free: run crosses block-group boundary".into(),
                });
            }
        }
        let mut stats = self.lock_group(gidx);
        // Read this locked group's own pre-populated reserved set. The Arc clone
        // releases the `reserved_cache` borrow before the `&mut stats` call below;
        // empty only if unpopulated (never, under the feature) — same as
        // `alloc_blocks`.
        let reserved = stats.reserved_cache.get().cloned().unwrap_or_default();
        ffs_alloc::free_blocks_in_group(
            cx, dev, geo, &mut stats, group, rel_start, count, pctx, &reserved,
        )
    }

    /// Sharded per-group inode allocation (bd-bhh0i Part A): walk the
    /// target→±neighbors→full order, locking ONE group at a time, and allocate an
    /// inode in the first group that can satisfy. Simpler than `alloc_blocks` —
    /// the inode core computes its own reserved set (`reserved_inodes_in_group` is
    /// geo+group only), so no per-group cache read. The scan order mirrors the
    /// single-lock `alloc_inode_persist` (target, then ±1..=8, then the full
    /// 0..group_count skipping target; neighbors re-appear in the full sweep
    /// exactly as the single-lock loop re-tries them — harmless, already-failed).
    ///
    /// c2 scope: `target` is the caller's group for BOTH files and directories.
    /// Directory Orlov placement (an all-groups above-average-free scan) and the
    /// Part-B contention spread are slice c3 — they need a lock-free free-count
    /// snapshot; `is_directory` is still threaded so `used_dirs` accounting is
    /// correct wherever the inode lands.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn alloc_inode(
        &self,
        cx: &asupersync::Cx,
        dev: &dyn ffs_block::BlockDevice,
        geo: &ffs_alloc::FsGeometry,
        target: ffs_types::GroupNumber,
        is_directory: bool,
        pctx: &ffs_alloc::PersistCtx,
    ) -> Result<Option<ffs_alloc::InodeAlloc>, ffs_error::FfsError> {
        let group_count = geo.group_count;
        let target_idx = target.0;
        let mut order: Vec<usize> = Vec::with_capacity(17 + group_count as usize);
        order.push(target_idx as usize);
        for delta in 1..=8u32 {
            for dir in [1_i64, -1_i64] {
                let g = i64::from(target_idx) + dir * i64::from(delta);
                if g >= 0 && (g as u32) < group_count {
                    order.push(g as usize);
                }
            }
        }
        for g in 0..group_count {
            if g != target_idx {
                order.push(g as usize);
            }
        }
        self.alloc_in_scan_order(order, |g, stats| {
            match ffs_alloc::try_alloc_inode_in_group_persist_core(
                cx,
                dev,
                geo,
                stats,
                ffs_types::GroupNumber(u32::try_from(g).unwrap_or(u32::MAX)),
                is_directory,
                pctx,
            ) {
                Ok(Some(alloc)) => Some(Ok(alloc)), // allocated → stop the scan
                Ok(None) => None,                   // group can't satisfy → continue
                Err(err) => Some(Err(err)),         // real error → stop, propagate
            }
        })
        .transpose()
    }

    /// Sharded per-group inode FREE (bd-bhh0i cutover rollback): free `ino` by
    /// locking ONLY its owning group and composing [`ffs_alloc::free_inode_in_group`]
    /// over the locked `&mut GroupStats` — the inode counterpart to
    /// [`Self::free_blocks`]. The sharded create path allocates the inode lock-free
    /// via [`Self::alloc_inode`]; on a subsequent dir-entry failure this frees it
    /// back under the same per-group lock (the single-lock `free_inode_persist` over
    /// `&mut [GroupStats]` would free it against the wrong structure). `is_dir`
    /// drives the `used_dirs` decrement, mirroring `alloc_inode`'s increment.
    pub(crate) fn free_inode(
        &self,
        cx: &asupersync::Cx,
        dev: &dyn ffs_block::BlockDevice,
        geo: &ffs_alloc::FsGeometry,
        ino: ffs_types::InodeNumber,
        is_dir: bool,
        pctx: &ffs_alloc::PersistCtx,
    ) -> Result<(), ffs_error::FfsError> {
        let group = ffs_types::inode_to_group(ino, geo.inodes_per_group);
        let gidx = group.0 as usize;
        if gidx >= self.groups.len() {
            return Err(ffs_error::FfsError::Corruption {
                block: 0,
                detail: format!("sharded inode free: inode {} group out of range", ino.0),
            });
        }
        let mut stats = self.lock_group(gidx);
        ffs_alloc::free_inode_in_group(cx, dev, geo, &mut stats, group, ino, is_dir, pctx)
    }

    /// Resolve an allocated inode's on-disk location (its inode-table block + byte
    /// offset within that block) from the sharded structure, so the cutover's
    /// inode-write path composes `alloc_inode` → `inode_location` →
    /// `ffs_inode::write_inode_at` WITHOUT reading the single-lock `groups` slice
    /// (self-containment is the point of the decomposition). Byte-identical to the
    /// single-lock `ffs_inode::locate_inode` for the same state — same
    /// `ffs_types::inode_to_group` / `inode_index_in_group` arithmetic, same
    /// `inode_table_block + block_offset`, same `None` guards (invalid ino/geo,
    /// group out of range, block-offset overflow). The ONLY difference: the target
    /// group's `inode_table_block` is read under that group's own lock instead of
    /// from `groups[gidx]`. That field is immutable mkfs layout, so the lock is a
    /// formality — but it keeps the write path entirely off the single-lock groups.
    pub(crate) fn inode_location(
        &self,
        ino: ffs_types::InodeNumber,
        geo: &ffs_alloc::FsGeometry,
    ) -> Option<ffs_inode::InodeLocation> {
        if ino.0 == 0 || geo.inodes_per_group == 0 || geo.block_size == 0 || geo.inode_size == 0 {
            return None;
        }
        let gidx = ffs_types::inode_to_group(ino, geo.inodes_per_group).0 as usize;
        if gidx >= self.groups.len() {
            return None;
        }
        let index = ffs_types::inode_index_in_group(ino, geo.inodes_per_group);
        let byte_in_table = u64::from(index) * u64::from(geo.inode_size);
        let block_offset = byte_in_table / u64::from(geo.block_size);
        let byte_offset = (byte_in_table % u64::from(geo.block_size)) as usize;
        let inode_table_block = self.groups[gidx].stats.lock().inode_table_block.0;
        let block = ffs_types::BlockNumber(inode_table_block.checked_add(block_offset)?);
        Some(ffs_inode::InodeLocation { block, byte_offset })
    }
}

/// Aggregate free counts across all groups (see [`PerGroupAlloc::total_free`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FreeTotals {
    pub(crate) blocks: u64,
    pub(crate) inodes: u64,
}

/// One group's free counts, as the sharded Orlov directory allocator reads them
/// (see [`PerGroupAlloc::group_free_snapshot`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GroupFree {
    pub(crate) free_blocks: u32,
    pub(crate) free_inodes: u32,
    pub(crate) used_dirs: u32,
}

/// The pure Orlov directory-placement decision over a per-group free snapshot
/// (see [`PerGroupAlloc::choose_dir_group`]). Factored out as a free function so
/// it is unit-checkable against the single-lock `orlov_choose_group_for_dir` spec
/// without building a `PerGroupAlloc`. Mirrors that function EXACTLY:
///
///  * fs-wide INTEGER averages of free inodes, free blocks, and used dirs;
///  * keep only groups at/above BOTH the free-inode and free-block average;
///  * among those, take the fewest `used_dirs` — the first qualifying group wins,
///    and the incumbent's `score == best && score <= avg_dirs` clause lets a
///    later, equally-few group replace the earlier one (copied verbatim);
///  * if NONE qualify, fall back to the first group with any free inode;
///  * empty input → `None` (the incumbent's `NoSpace` on empty groups). The
///    incumbent's post-filter fallback can also return `NoSpace`, but that state
///    is unreachable for non-empty input — `best` stays `MAX` only when no group
///    sits above BOTH averages, which forces `avg_free_inodes > 0`, hence some
///    group has a free inode for the fallback to find — mirrored regardless.
///
/// The snapshot index IS the group number: `group_free_snapshot` preserves group
/// order and the allocator indexes `groups[group.0]`, so `groups[i].group == i`.
/// That lets the decision run on the field-only [`GroupFree`] with no group tag,
/// matching the incumbent's `gs.group` under that invariant.
fn choose_dir_group_from_snapshot(snapshot: &[GroupFree]) -> Option<ffs_types::GroupNumber> {
    if snapshot.is_empty() {
        return None;
    }
    let n = snapshot.len() as u64;
    let avg_free_inodes = snapshot
        .iter()
        .map(|g| u64::from(g.free_inodes))
        .sum::<u64>()
        / n;
    let avg_free_blocks = snapshot
        .iter()
        .map(|g| u64::from(g.free_blocks))
        .sum::<u64>()
        / n;
    let avg_dirs = snapshot.iter().map(|g| u64::from(g.used_dirs)).sum::<u64>() / n;

    let mut best_group: u32 = 0;
    let mut best_score = u64::MAX;
    for (idx, g) in snapshot.iter().enumerate() {
        if u64::from(g.free_inodes) < avg_free_inodes {
            continue;
        }
        if u64::from(g.free_blocks) < avg_free_blocks {
            continue;
        }
        let score = u64::from(g.used_dirs);
        if score < best_score || (score == best_score && score <= avg_dirs) {
            best_score = score;
            best_group = u32::try_from(idx).unwrap_or(u32::MAX);
        }
    }

    if best_score == u64::MAX {
        return snapshot
            .iter()
            .position(|g| g.free_inodes > 0)
            .map(|idx| ffs_types::GroupNumber(u32::try_from(idx).unwrap_or(u32::MAX)));
    }
    Some(ffs_types::GroupNumber(best_group))
}

/// Part-B contention spread (bd-bhh0i): choose the group a new inode's allocation
/// scan STARTS from, to spread concurrent creates across DIFFERENT groups — hence
/// different inode-table blocks — dodging the shared-inode-table-block RMW storm
/// that re-serializes Part-A-sharded creates (the "block-2085" storm that killed
/// the two prior naive attempts: siblings packed into one inode-table block whose
/// per-inode content writes then FCW-contend).
///
/// `seed` is the spread source the caller supplies to distribute concurrent
/// creates (e.g. a per-thread/per-CPU counter, or `hash(parent, name)`). `seed ==
/// 0` returns the parent group unchanged, so the single-threaded common path keeps
/// full locality (the child lands beside its parent). Because [`PerGroupAlloc::
/// alloc_inode`] falls through neighbors→full from this start, a spread start that
/// is full still allocates — this only steers PLACEMENT, never correctness.
///
/// PROVISIONAL POLICY: a simple `(parent + seed) mod group_count` round-robin
/// offset. The seed source and whether to spread only under measured contention
/// (vs. accept a small single-thread locality loss) are tuning decisions for the
/// cutover A/B — this function is the mechanism, not the final policy.
pub(crate) fn spread_start_group(
    parent: ffs_types::GroupNumber,
    seed: u32,
    group_count: u32,
) -> ffs_types::GroupNumber {
    if group_count <= 1 {
        return parent;
    }
    // parent.0 is already < group_count (a valid group); the offset wraps within
    // [0, group_count), and seed==0 yields the parent exactly (locality kept).
    ffs_types::GroupNumber((parent.0 % group_count).wrapping_add(seed % group_count) % group_count)
}

#[cfg(test)]
mod spread_tests {
    use super::spread_start_group;
    use ffs_types::GroupNumber;

    #[test]
    fn seed_zero_keeps_parent_locality() {
        for parent in 0..8u32 {
            assert_eq!(
                spread_start_group(GroupNumber(parent), 0, 8),
                GroupNumber(parent),
                "seed 0 must land on the parent group (single-thread locality)"
            );
        }
    }

    #[test]
    fn single_group_fs_always_returns_parent() {
        assert_eq!(spread_start_group(GroupNumber(0), 5, 1), GroupNumber(0));
        assert_eq!(spread_start_group(GroupNumber(0), 0, 1), GroupNumber(0));
    }

    #[test]
    fn distinct_seeds_spread_across_distinct_groups() {
        // A same-parent storm: parent group 2, concurrent creates seeds 0..8 on an
        // 8-group fs must each start in a DISTINCT group (spread → distinct
        // inode-table blocks).
        let starts: std::collections::HashSet<u32> = (0..8u32)
            .map(|seed| spread_start_group(GroupNumber(2), seed, 8).0)
            .collect();
        assert_eq!(
            starts.len(),
            8,
            "8 distinct seeds must give 8 distinct start groups"
        );
    }

    #[test]
    fn result_is_always_in_range() {
        for parent in [0u32, 3, 7] {
            for seed in [0u32, 1, 7, 8, 100, u32::MAX] {
                let g = spread_start_group(GroupNumber(parent), seed, 8).0;
                assert!(
                    g < 8,
                    "start group {g} must be a valid index (< group_count)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_types::{BlockNumber, GroupNumber};
    use std::sync::Arc;

    fn sample_group(n: u32, free_blocks: u32, free_inodes: u32) -> GroupStats {
        GroupStats {
            group: GroupNumber(n),
            free_blocks,
            block_largest_free_run: None,
            free_inodes,
            inode_search_start: 0,
            used_dirs: 0,
            block_bitmap_block: BlockNumber(u64::from(n) * 100 + 1),
            inode_bitmap_block: BlockNumber(u64::from(n) * 100 + 2),
            inode_table_block: BlockNumber(u64::from(n) * 100 + 3),
            flags: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
            reserved_cache: std::sync::OnceLock::new(),
            reserved_confirmed: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn from_group_stats_round_trips_every_group() {
        let stats: Vec<GroupStats> = (0..4).map(|g| sample_group(g, 100 + g, 50 + g)).collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        assert_eq!(sharded.group_count(), 4);
        for g in 0..4u32 {
            let rec = sharded.lock_group(g as usize);
            assert_eq!(rec.group, GroupNumber(g));
            assert_eq!(rec.free_blocks, 100 + g);
            assert_eq!(rec.free_inodes, 50 + g);
            assert_eq!(rec.inode_table_block, BlockNumber(u64::from(g) * 100 + 3));
        }
    }

    #[test]
    fn disjoint_groups_mutate_concurrently_without_lost_updates() {
        let stats: Vec<GroupStats> = (0..8).map(|g| sample_group(g, 1_000, 1_000)).collect();
        let sharded = Arc::new(PerGroupAlloc::from_group_stats(stats));
        // Each thread owns a distinct group and decrements its free counts; with
        // per-group locks these never contend, and no update is lost.
        let handles: Vec<_> = (0..8u32)
            .map(|g| {
                let sharded = Arc::clone(&sharded);
                std::thread::spawn(move || {
                    for _ in 0..1_000 {
                        let mut rec = sharded.lock_group(g as usize);
                        rec.free_blocks -= 1;
                        rec.free_inodes -= 1;
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }
        for g in 0..8u32 {
            let rec = sharded.lock_group(g as usize);
            assert_eq!(rec.free_blocks, 0, "group {g} lost a block update");
            assert_eq!(rec.free_inodes, 0, "group {g} lost an inode update");
        }
    }

    /// Try to allocate `want` blocks from a group: succeed (decrement) iff it has
    /// enough, returning the group index; a stand-in for `try_alloc_safe`.
    fn try_take(want: u32) -> impl FnMut(usize, &mut GroupStats) -> Option<usize> {
        move |g, stats| {
            if stats.free_blocks >= want {
                stats.free_blocks -= want;
                Some(g)
            } else {
                None
            }
        }
    }

    #[test]
    fn scan_stops_at_first_satisfying_group_and_mutates_only_it() {
        let stats: Vec<GroupStats> = [0u32, 0, 5, 10]
            .into_iter()
            .enumerate()
            .map(|(g, fb)| sample_group(g as u32, fb, 0))
            .collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        // Order 0,1,2,3: groups 0,1 have 0 free (fail), group 2 has 5 >= 3 -> take.
        let hit = sharded.alloc_in_scan_order(0..4, try_take(3));
        assert_eq!(hit, Some(2));
        assert_eq!(sharded.lock_group(0).free_blocks, 0);
        assert_eq!(sharded.lock_group(1).free_blocks, 0);
        assert_eq!(
            sharded.lock_group(2).free_blocks,
            2,
            "group 2 should be debited"
        );
        assert_eq!(
            sharded.lock_group(3).free_blocks,
            10,
            "group 3 untouched (scan stopped)"
        );
    }

    #[test]
    fn scan_honors_order_goal_group_first() {
        let stats: Vec<GroupStats> = [4u32, 4, 4, 4]
            .into_iter()
            .enumerate()
            .map(|(g, fb)| sample_group(g as u32, fb, 0))
            .collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        // Goal group 2 first: it satisfies, so it (not group 0) is debited.
        let hit = sharded.alloc_in_scan_order([2usize, 0, 1, 3], try_take(3));
        assert_eq!(hit, Some(2));
        assert_eq!(sharded.lock_group(2).free_blocks, 1);
        assert_eq!(
            sharded.lock_group(0).free_blocks,
            4,
            "goal group won; others untouched"
        );
    }

    #[test]
    fn scan_returns_none_and_mutates_nothing_when_no_group_fits() {
        let stats: Vec<GroupStats> = [2u32, 1, 2]
            .into_iter()
            .enumerate()
            .map(|(g, fb)| sample_group(g as u32, fb, 0))
            .collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        let hit = sharded.alloc_in_scan_order(0..3, try_take(3));
        assert_eq!(hit, None);
        for g in 0..3usize {
            let expect = [2u32, 1, 2][g];
            assert_eq!(
                sharded.lock_group(g).free_blocks,
                expect,
                "group {g} must be unchanged"
            );
        }
    }

    #[test]
    fn scan_skips_out_of_range_group_indices() {
        let stats: Vec<GroupStats> = [0u32, 5]
            .into_iter()
            .enumerate()
            .map(|(g, fb)| sample_group(g as u32, fb, 0))
            .collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        // 99 is out of range (skipped), 0 fails, 1 satisfies.
        let hit = sharded.alloc_in_scan_order([99usize, 0, 1], try_take(3));
        assert_eq!(hit, Some(1));
        assert_eq!(sharded.lock_group(1).free_blocks, 2);
    }

    #[test]
    fn total_free_sums_all_groups() {
        let stats: Vec<GroupStats> = (0..4).map(|g| sample_group(g, 100 + g, 10 + g)).collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        // blocks = 100+101+102+103 = 406; inodes = 10+11+12+13 = 46.
        assert_eq!(
            sharded.total_free(),
            FreeTotals {
                blocks: 406,
                inodes: 46
            }
        );
    }

    #[test]
    fn total_free_reflects_post_allocation_state() {
        let stats: Vec<GroupStats> = (0..3).map(|g| sample_group(g, 50, 5)).collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        assert_eq!(
            sharded.total_free(),
            FreeTotals {
                blocks: 150,
                inodes: 15
            }
        );
        // Debit 7 blocks from whichever group the scan commits to.
        assert!(sharded.alloc_in_scan_order(0..3, try_take(7)).is_some());
        assert_eq!(
            sharded.total_free(),
            FreeTotals {
                blocks: 143,
                inodes: 15
            }
        );
    }

    #[test]
    fn group_free_snapshot_reports_every_group() {
        let mut stats: Vec<GroupStats> = (0..3).map(|g| sample_group(g, 100 + g, 10 + g)).collect();
        stats[1].used_dirs = 4;
        let sharded = PerGroupAlloc::from_group_stats(stats);
        let snap = sharded.group_free_snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(
            snap[0],
            GroupFree {
                free_blocks: 100,
                free_inodes: 10,
                used_dirs: 0
            }
        );
        assert_eq!(
            snap[1],
            GroupFree {
                free_blocks: 101,
                free_inodes: 11,
                used_dirs: 4
            }
        );
        assert_eq!(
            snap[2],
            GroupFree {
                free_blocks: 102,
                free_inodes: 12,
                used_dirs: 0
            }
        );
    }

    #[test]
    fn group_free_snapshot_reflects_post_allocation() {
        let stats: Vec<GroupStats> = [10u32, 10, 10]
            .into_iter()
            .enumerate()
            .map(|(g, fb)| sample_group(g as u32, fb, 5))
            .collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        // Debit 4 blocks from group 1 specifically (single-group scan order).
        assert_eq!(sharded.alloc_in_scan_order([1usize], try_take(4)), Some(1));
        let snap = sharded.group_free_snapshot();
        assert_eq!(snap[0].free_blocks, 10);
        assert_eq!(
            snap[1].free_blocks, 6,
            "group 1 snapshot must show the debit"
        );
        assert_eq!(snap[2].free_blocks, 10);
    }

    fn gf(free_blocks: u32, free_inodes: u32, used_dirs: u32) -> GroupFree {
        GroupFree {
            free_blocks,
            free_inodes,
            used_dirs,
        }
    }

    #[test]
    fn choose_dir_empty_snapshot_is_none() {
        assert_eq!(choose_dir_group_from_snapshot(&[]), None);
        // And through the whole primitive on a zero-group allocator.
        let sharded = PerGroupAlloc::from_group_stats(Vec::new());
        assert_eq!(sharded.choose_dir_group(), None);
    }

    #[test]
    fn choose_dir_all_equal_picks_last_group_via_tie_break() {
        // Every group identical: all qualify and all have equal dirs == avg_dirs
        // (0 == 0), so the incumbent's `score == best && score <= avg_dirs` clause
        // fires for EACH later group, walking the winner all the way to the LAST
        // group. A faithful mirror of orlov_choose_group_for_dir's real (and
        // non-obvious) all-equal behavior: last-qualifying-wins, NOT first. This
        // guard exists precisely to pin that surprise.
        let snap = vec![gf(100, 50, 0); 4];
        assert_eq!(choose_dir_group_from_snapshot(&snap), Some(GroupNumber(3)));
    }

    #[test]
    fn choose_dir_prefers_only_group_above_both_averages() {
        // avg_blocks = avg_inodes = (10+10+200+10)/4 = 57; only group 2 clears
        // BOTH averages, so it is chosen despite equal (0) dir counts.
        let snap = vec![gf(10, 10, 0), gf(10, 10, 0), gf(200, 200, 0), gf(10, 10, 0)];
        assert_eq!(choose_dir_group_from_snapshot(&snap), Some(GroupNumber(2)));
    }

    #[test]
    fn choose_dir_breaks_ties_by_fewest_used_dirs() {
        // Both groups qualify (identical free counts, at the average); the one
        // with fewer directories wins (score 2 < 7).
        let snap = vec![gf(100, 100, 7), gf(100, 100, 2)];
        assert_eq!(choose_dir_group_from_snapshot(&snap), Some(GroupNumber(1)));
    }

    #[test]
    fn choose_dir_equal_dirs_prefers_later_group_at_or_below_avg() {
        // Three qualifying groups with EQUAL dirs (5). avg_dirs = 15/3 = 5, so the
        // incumbent's `score == best && score <= avg_dirs` (5 <= 5) clause fires
        // for each, letting the LAST equally-few group replace the prior ones.
        let snap = vec![gf(100, 100, 5), gf(100, 100, 5), gf(100, 100, 5)];
        assert_eq!(choose_dir_group_from_snapshot(&snap), Some(GroupNumber(2)));
    }

    #[test]
    fn choose_dir_equal_dirs_keeps_earlier_group_above_avg() {
        // Two qualifying groups tied at 5 dirs, plus a below-average group (1,1,0)
        // that is FILTERED OUT of selection yet still drags avg_dirs down to
        // 10/3 = 3. Now the tied score 5 > avg_dirs, so `score <= avg_dirs` is
        // false and the EARLIER group 0 is kept — the other half of the clause.
        let snap = vec![gf(100, 100, 5), gf(100, 100, 5), gf(1, 1, 0)];
        assert_eq!(choose_dir_group_from_snapshot(&snap), Some(GroupNumber(0)));
    }

    #[test]
    fn choose_dir_falls_back_to_first_free_when_none_above_both_averages() {
        // Split profile: group 0 high-inode/low-block, group 1 low-inode/high-
        // block. avg_inodes = avg_blocks = 5, so NEITHER group clears both
        // averages; the main loop selects nothing and the incumbent falls back to
        // the first group with a free inode (group 0).
        let snap = vec![gf(0, 10, 0), gf(10, 0, 0)];
        assert_eq!(choose_dir_group_from_snapshot(&snap), Some(GroupNumber(0)));
    }

    #[test]
    fn choose_dir_group_runs_through_the_snapshot() {
        // End-to-end through the method: equal free counts (all qualify), so the
        // emptiest group by dir count (group 1) is chosen.
        let mut stats: Vec<GroupStats> = (0..3).map(|g| sample_group(g, 100, 100)).collect();
        stats[0].used_dirs = 9;
        stats[1].used_dirs = 1;
        stats[2].used_dirs = 9;
        let sharded = PerGroupAlloc::from_group_stats(stats);
        assert_eq!(sharded.choose_dir_group(), Some(GroupNumber(1)));
    }
}
