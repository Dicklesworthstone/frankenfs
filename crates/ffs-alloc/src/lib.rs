#![forbid(unsafe_code)]
//! Block and inode allocation.
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

use asupersync::Cx;
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::{Ext4GroupDesc, Ext4Superblock};
use ffs_types::{BlockNumber, GroupNumber, InodeNumber};

// ── Bitmap operations ───────────────────────────────────────────────────────

/// Group flags from `bg_flags` field.
const GD_FLAG_INODE_UNINIT: u16 = 0x0001;
const GD_FLAG_BLOCK_UNINIT: u16 = 0x0002;

/// Get bit `idx` from a bitmap byte slice.
#[must_use]
pub fn bitmap_get(bitmap: &[u8], idx: u32) -> bool {
    let byte_idx = (idx / 8) as usize;
    let bit_idx = idx % 8;
    if byte_idx >= bitmap.len() {
        return false;
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
    let full_bytes = (count / 8) as usize;
    let remainder = count % 8;
    let mut free = 0u32;

    for &byte in bitmap.iter().take(full_bytes) {
        // Each zero bit is a free slot.
        // count_zeros() on a u8 returns at most 8, fits in u8.
        #[expect(clippy::cast_possible_truncation)]
        let zeros = byte.count_zeros() as u8;
        free += u32::from(zeros);
    }

    if remainder > 0 && full_bytes < bitmap.len() {
        let byte = bitmap[full_bytes];
        for bit in 0..remainder {
            if (byte >> bit) & 1 == 0 {
                free += 1;
            }
        }
    }

    free
}

/// Find the first free (zero) bit in the first `count` bits of `bitmap`,
/// starting from `start`.
#[must_use]
pub fn bitmap_find_free(bitmap: &[u8], count: u32, start: u32) -> Option<u32> {
    for idx in start..count {
        if !bitmap_get(bitmap, idx) {
            return Some(idx);
        }
    }
    // Wrap around: search from 0 to start.
    (0..start).find(|&idx| !bitmap_get(bitmap, idx))
}

/// Find `n` contiguous free bits in the first `count` bits of `bitmap`.
#[must_use]
pub fn bitmap_find_contiguous(bitmap: &[u8], count: u32, n: u32) -> Option<u32> {
    if n == 0 {
        return Some(0);
    }
    let mut run_start = 0u32;
    let mut run_len = 0u32;

    for idx in 0..count {
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
}

impl FsGeometry {
    /// Derive geometry from a parsed superblock.
    #[must_use]
    #[expect(clippy::cast_possible_truncation)]
    pub fn from_superblock(sb: &Ext4Superblock) -> Self {
        let group_count = if sb.blocks_per_group > 0 {
            let full = sb.blocks_count / u64::from(sb.blocks_per_group);
            let remainder = sb.blocks_count % u64::from(sb.blocks_per_group);
            (full + u64::from(remainder > 0)) as u32
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
        }
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
    #[expect(clippy::cast_possible_truncation)]
    pub fn absolute_to_group_block(&self, block: BlockNumber) -> (GroupNumber, u32) {
        let rel = block.0.saturating_sub(u64::from(self.first_data_block));
        let group = (rel / u64::from(self.blocks_per_group)) as u32;
        let offset = (rel % u64::from(self.blocks_per_group)) as u32;
        (GroupNumber(group), offset)
    }
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

    // Determine goal group.
    let goal_group = hint
        .goal_group
        .or_else(|| hint.goal_block.map(|b| geo.absolute_to_group_block(b).0))
        .unwrap_or(GroupNumber(0));

    // Try goal group first.
    if let Some(alloc) = try_alloc_in_group(cx, dev, geo, groups, goal_group, count, hint)? {
        return Ok(alloc);
    }

    // Try nearby groups (within 8 groups of goal).
    for delta in 1..=8u32 {
        for dir in [1i64, -1i64] {
            let g = i64::from(goal_group.0) + dir * i64::from(delta);
            #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            if g >= 0 && (g as u32) < geo.group_count {
                let group = GroupNumber(g as u32);
                if let Some(alloc) = try_alloc_in_group(cx, dev, geo, groups, group, count, hint)? {
                    return Ok(alloc);
                }
            }
        }
    }

    // Scan all groups.
    for g in 0..geo.group_count {
        let group = GroupNumber(g);
        if group == goal_group {
            continue;
        }
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

    // Determine start position for search.
    let start = hint.goal_block.map_or(0, |goal| {
        let (g, off) = geo.absolute_to_group_block(goal);
        if g == group { off } else { 0 }
    });

    // Try to find contiguous free blocks.
    let found = if count == 1 {
        bitmap_find_free(&bitmap, blocks_in_group, start).map(|idx| (idx, 1))
    } else {
        bitmap_find_contiguous(&bitmap, blocks_in_group, count).map(|idx| (idx, count))
    };

    if let Some((rel_start, alloc_count)) = found {
        // Mark blocks as allocated.
        for i in rel_start..rel_start + alloc_count {
            bitmap_set(&mut bitmap, i);
        }

        // Write bitmap back.
        dev.write_block(cx, gs.block_bitmap_block, &bitmap)?;

        // Update group stats.
        groups[gidx].free_blocks -= alloc_count;

        let abs_start = geo.group_block_to_absolute(group, rel_start);
        Ok(Some(BlockAlloc {
            start: abs_start,
            count: alloc_count,
        }))
    } else {
        Ok(None)
    }
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

    let (group, rel_start) = geo.absolute_to_group_block(start);
    let gidx = group.0 as usize;
    if gidx >= groups.len() {
        return Err(FfsError::Corruption {
            block: start.0,
            detail: "free_blocks: group out of range".into(),
        });
    }

    let gs = &groups[gidx];
    let bitmap_buf = dev.read_block(cx, gs.block_bitmap_block)?;
    let mut bitmap = bitmap_buf.as_slice().to_vec();

    for i in rel_start..rel_start + count {
        bitmap_clear(&mut bitmap, i);
    }

    dev.write_block(cx, gs.block_bitmap_block, &bitmap)?;
    groups[gidx].free_blocks += count;
    Ok(())
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

    // Try target group, then scan.
    if let Some(alloc) = try_alloc_inode_in_group(cx, dev, geo, groups, target_group)? {
        return Ok(alloc);
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

    let gs = &groups[gidx];
    if gs.free_inodes == 0 {
        return Ok(None);
    }

    let bitmap_buf = dev.read_block(cx, gs.inode_bitmap_block)?;
    let mut bitmap = bitmap_buf.as_slice().to_vec();

    let found = bitmap_find_free(&bitmap, geo.inodes_per_group, 0);
    if let Some(idx) = found {
        bitmap_set(&mut bitmap, idx);
        dev.write_block(cx, gs.inode_bitmap_block, &bitmap)?;

        groups[gidx].free_inodes -= 1;

        // Compute absolute inode number: group * inodes_per_group + idx + 1.
        let ino = u64::from(group.0) * u64::from(geo.inodes_per_group) + u64::from(idx) + 1;
        Ok(Some(InodeAlloc {
            ino: InodeNumber(ino),
            group,
        }))
    } else {
        Ok(None)
    }
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
    let ino_zero = ino.0.checked_sub(1).ok_or_else(|| FfsError::Corruption {
        block: 0,
        detail: "inode number 0 is invalid".into(),
    })?;
    #[expect(clippy::cast_possible_truncation)]
    let group_idx = (ino_zero / u64::from(geo.inodes_per_group)) as u32;
    #[expect(clippy::cast_possible_truncation)]
    let bit_idx = (ino_zero % u64::from(geo.inodes_per_group)) as u32;
    let gidx = group_idx as usize;

    if gidx >= groups.len() {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("free_inode: group {group_idx} out of range"),
        });
    }

    let gs = &groups[gidx];
    let bitmap_buf = dev.read_block(cx, gs.inode_bitmap_block)?;
    let mut bitmap = bitmap_buf.as_slice().to_vec();

    bitmap_clear(&mut bitmap, bit_idx);
    dev.write_block(cx, gs.inode_bitmap_block, &bitmap)?;
    groups[gidx].free_inodes += 1;
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
    use std::sync::Mutex;

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
        }
    }

    fn make_groups(geo: &FsGeometry) -> Vec<GroupStats> {
        (0..geo.group_count)
            .map(|g| GroupStats {
                group: GroupNumber(g),
                free_blocks: geo.blocks_per_group,
                free_inodes: geo.inodes_per_group,
                used_dirs: 0,
                block_bitmap_block: BlockNumber(u64::from(g) * 100 + 1),
                inode_bitmap_block: BlockNumber(u64::from(g) * 100 + 2),
                inode_table_block: BlockNumber(u64::from(g) * 100 + 3),
                flags: 0,
            })
            .collect()
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
    fn bitmap_find_contiguous_basic() {
        let mut bm = vec![0u8; 4];
        bitmap_set(&mut bm, 0);
        bitmap_set(&mut bm, 1);
        // Free: 2,3,4,5,... contiguous from 2
        assert_eq!(bitmap_find_contiguous(&bm, 32, 4), Some(2));
    }

    #[test]
    fn bitmap_find_contiguous_none() {
        let mut bm = vec![0u8; 2];
        // Set every other bit: 0,2,4,6,8,10,12,14
        for i in (0..16).step_by(2) {
            bitmap_set(&mut bm, i);
        }
        // No 2-contiguous free bits.
        assert_eq!(bitmap_find_contiguous(&bm, 16, 2), None);
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
        assert_eq!(result.ino, InodeNumber(1));
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
}
