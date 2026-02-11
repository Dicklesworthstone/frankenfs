#![forbid(unsafe_code)]
//! Extent mapping: logical block to physical block resolution.
//!
//! Resolves file logical offsets to physical block addresses via the
//! extent B+tree, allocates new extents, and detects holes (unwritten
//! regions) in file mappings.
//!
//! ## Modules (logical, single file)
//!
//! - **map**: `map_logical_to_physical` — walk the tree to produce mappings.
//! - **allocate**: `allocate_extent` — alloc blocks and insert into tree.
//! - **truncate**: `truncate_extents` — remove extents beyond a boundary.
//! - **punch**: `punch_hole` — remove mappings without changing file size.
//! - **unwritten**: `mark_written` — clear unwritten flag on extents.

use asupersync::Cx;
use ffs_alloc::{AllocHint, BlockAlloc, FsGeometry, GroupStats};
use ffs_block::BlockDevice;
use ffs_btree::{BlockAllocator, SearchResult};
use ffs_error::{FfsError, Result};
use ffs_ondisk::Ext4Extent;
use ffs_types::BlockNumber;

// ── Constants ────────────────────────────────────────────────────────────────

/// Bit 15 set in raw_len indicates unwritten extent.
const UNWRITTEN_FLAG: u16 = 1_u16 << 15;

// ── Extent mapping ──────────────────────────────────────────────────────────

/// A mapping of logical blocks to physical blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentMapping {
    pub logical_start: u32,
    pub physical_start: u64,
    pub count: u32,
    pub unwritten: bool,
}

/// Map a range of logical blocks to physical blocks.
///
/// Returns a list of mappings covering the requested range. Holes are
/// represented as mappings with `physical_start == 0`.
pub fn map_logical_to_physical(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &[u8; 60],
    logical_start: u32,
    count: u32,
) -> Result<Vec<ExtentMapping>> {
    let mut mappings = Vec::new();
    let mut pos = logical_start;
    let end = logical_start.saturating_add(count);

    while pos < end {
        cx_checkpoint(cx)?;
        let result = ffs_btree::search(cx, dev, root_bytes, pos)?;
        match result {
            SearchResult::Found {
                extent,
                offset_in_extent,
            } => {
                let actual_len = u32::from(extent.actual_len());
                let remaining_in_extent = actual_len.saturating_sub(offset_in_extent);
                let to_map = remaining_in_extent.min(end - pos);
                mappings.push(ExtentMapping {
                    logical_start: pos,
                    physical_start: extent.physical_start + u64::from(offset_in_extent),
                    count: to_map,
                    unwritten: extent.is_unwritten(),
                });
                pos += to_map;
            }
            SearchResult::Hole { hole_len } => {
                let to_map = hole_len.min(end - pos);
                mappings.push(ExtentMapping {
                    logical_start: pos,
                    physical_start: 0,
                    count: to_map,
                    unwritten: false,
                });
                pos += to_map;
            }
        }
    }

    Ok(mappings)
}

// ── Allocate ────────────────────────────────────────────────────────────────

/// Bridge between ffs-alloc block allocation and ffs-btree's `BlockAllocator` trait.
///
/// This adapter lets the B+tree allocate/free blocks for tree nodes (index/leaf
/// blocks) using the full ffs-alloc group-based allocator.
pub struct GroupBlockAllocator<'a> {
    pub cx: &'a Cx,
    pub dev: &'a dyn BlockDevice,
    pub geo: &'a FsGeometry,
    pub groups: &'a mut [GroupStats],
    pub hint: AllocHint,
}

impl BlockAllocator for GroupBlockAllocator<'_> {
    fn alloc_block(&mut self, cx: &Cx) -> Result<BlockNumber> {
        let alloc = ffs_alloc::alloc_blocks(cx, self.dev, self.geo, self.groups, 1, &self.hint)?;
        // Update hint to prefer contiguous allocation.
        self.hint.goal_block = Some(BlockNumber(alloc.start.0 + 1));
        Ok(alloc.start)
    }

    fn free_block(&mut self, cx: &Cx, block: BlockNumber) -> Result<()> {
        ffs_alloc::free_blocks(cx, self.dev, self.geo, self.groups, block, 1)
    }
}

/// Allocate and map `count` contiguous logical blocks starting at `logical_start`.
///
/// Allocates physical blocks via `ffs-alloc`, then inserts the extent into the
/// B+tree via `ffs-btree::insert`. The `hint` guides physical placement
/// (goal = after last extent for contiguity).
///
/// Returns the mapping for the newly allocated extent.
#[expect(clippy::too_many_arguments)]
pub fn allocate_extent(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    logical_start: u32,
    count: u32,
    hint: &AllocHint,
) -> Result<ExtentMapping> {
    cx_checkpoint(cx)?;

    if count == 0 || count > u32::from(u16::MAX >> 1) {
        return Err(FfsError::Format(
            "extent count must be 1..=32767".into(),
        ));
    }

    // Allocate physical blocks.
    let BlockAlloc { start, count: allocated } =
        ffs_alloc::alloc_blocks(cx, dev, geo, groups, count, hint)?;

    // Build the extent.
    #[expect(clippy::cast_possible_truncation)]
    let extent = Ext4Extent {
        logical_block: logical_start,
        raw_len: allocated as u16,
        physical_start: start.0,
    };

    // Insert into tree. Use a GroupBlockAllocator for tree node allocation.
    let tree_hint = AllocHint {
        goal_group: hint.goal_group,
        goal_block: Some(BlockNumber(start.0 + u64::from(allocated))),
    };
    let mut tree_alloc = GroupBlockAllocator {
        cx,
        dev,
        geo,
        groups,
        hint: tree_hint,
    };
    ffs_btree::insert(cx, dev, root_bytes, extent, &mut tree_alloc)?;

    Ok(ExtentMapping {
        logical_start,
        physical_start: start.0,
        count: allocated,
        unwritten: false,
    })
}

/// Allocate an extent with the unwritten flag set (for fallocate mode=0).
///
/// Same as `allocate_extent` but marks the extent as unwritten (uninitialized).
/// Reads from unwritten extents return zeroes until `mark_written` is called.
#[expect(clippy::too_many_arguments)]
pub fn allocate_unwritten_extent(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    logical_start: u32,
    count: u32,
    hint: &AllocHint,
) -> Result<ExtentMapping> {
    cx_checkpoint(cx)?;

    if count == 0 || count > u32::from(u16::MAX >> 1) {
        return Err(FfsError::Format(
            "extent count must be 1..=32767".into(),
        ));
    }

    let BlockAlloc { start, count: allocated } =
        ffs_alloc::alloc_blocks(cx, dev, geo, groups, count, hint)?;

    #[expect(clippy::cast_possible_truncation)]
    let extent = Ext4Extent {
        logical_block: logical_start,
        raw_len: (allocated as u16) | UNWRITTEN_FLAG,
        physical_start: start.0,
    };

    let tree_hint = AllocHint {
        goal_group: hint.goal_group,
        goal_block: Some(BlockNumber(start.0 + u64::from(allocated))),
    };
    let mut tree_alloc = GroupBlockAllocator {
        cx,
        dev,
        geo,
        groups,
        hint: tree_hint,
    };
    ffs_btree::insert(cx, dev, root_bytes, extent, &mut tree_alloc)?;

    Ok(ExtentMapping {
        logical_start,
        physical_start: start.0,
        count: allocated,
        unwritten: true,
    })
}

// ── Truncate ────────────────────────────────────────────────────────────────

/// Truncate the extent tree: remove all mappings beyond `new_logical_end`.
///
/// Returns the total number of physical blocks freed.
pub fn truncate_extents(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    new_logical_end: u32,
) -> Result<u64> {
    cx_checkpoint(cx)?;

    // Collect all extents first via walk.
    let mut extents = Vec::new();
    ffs_btree::walk(cx, dev, root_bytes, &mut |ext: &Ext4Extent| {
        extents.push(*ext);
        Ok(())
    })?;

    let mut total_freed = 0u64;

    for ext in &extents {
        let ext_start = ext.logical_block;
        let ext_len = u32::from(ext.actual_len());
        let ext_end = ext_start.saturating_add(ext_len);

        if ext_start >= new_logical_end {
            // Fully beyond truncation point: remove and free all blocks.
            let freed =
                ffs_btree::delete_range(cx, dev, root_bytes, ext_start, ext_len)?;
            for f in &freed {
                ffs_alloc::free_blocks(
                    cx,
                    dev,
                    geo,
                    groups,
                    BlockNumber(f.physical_start),
                    u32::from(f.count),
                )?;
                total_freed += u64::from(f.count);
            }
        } else if ext_end > new_logical_end {
            // Partially beyond: remove tail portion.
            let keep_len = new_logical_end - ext_start;
            let remove_start = ext_start + keep_len;
            let remove_count = ext_end - new_logical_end;
            let freed =
                ffs_btree::delete_range(cx, dev, root_bytes, remove_start, remove_count)?;
            for f in &freed {
                ffs_alloc::free_blocks(
                    cx,
                    dev,
                    geo,
                    groups,
                    BlockNumber(f.physical_start),
                    u32::from(f.count),
                )?;
                total_freed += u64::from(f.count);
            }
        }
        // Fully before truncation point: keep.
    }

    Ok(total_freed)
}

// ── Punch hole ──────────────────────────────────────────────────────────────

/// Punch a hole in the extent tree: remove mappings in the range
/// `[logical_start, logical_start + count)` without changing file size.
///
/// Returns the total number of physical blocks freed.
pub fn punch_hole(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    logical_start: u32,
    count: u32,
) -> Result<u64> {
    cx_checkpoint(cx)?;

    let freed_ranges = ffs_btree::delete_range(cx, dev, root_bytes, logical_start, count)?;
    let mut total_freed = 0u64;

    for f in &freed_ranges {
        ffs_alloc::free_blocks(
            cx,
            dev,
            geo,
            groups,
            BlockNumber(f.physical_start),
            u32::from(f.count),
        )?;
        total_freed += u64::from(f.count);
    }

    Ok(total_freed)
}

// ── Unwritten extent handling ───────────────────────────────────────────────

/// Mark extents in the range `[logical_start, logical_start + count)` as written.
///
/// Clears the unwritten flag (bit 15 of `ee_len`) on extents that overlap the
/// range. May split extents at range boundaries if they only partially overlap.
///
/// This is used when data is first written to a preallocated (unwritten) region.
pub fn mark_written(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    logical_start: u32,
    count: u32,
) -> Result<()> {
    cx_checkpoint(cx)?;

    let range_end = logical_start.saturating_add(count);

    // Collect unwritten extents overlapping the range.
    let mut unwritten_extents = Vec::new();
    ffs_btree::walk(cx, dev, root_bytes, &mut |ext: &Ext4Extent| {
        if ext.is_unwritten() {
            let ext_end = ext.logical_block.saturating_add(u32::from(ext.actual_len()));
            if ext.logical_block < range_end && ext_end > logical_start {
                unwritten_extents.push(*ext);
            }
        }
        Ok(())
    })?;

    for ext in unwritten_extents {
        let ext_len = u32::from(ext.actual_len());
        let ext_end = ext.logical_block.saturating_add(ext_len);

        // All branches start by removing the old extent.
        ffs_btree::delete_range(cx, dev, root_bytes, ext.logical_block, ext_len)?;

        // Build replacement extents based on overlap type.
        let replacements =
            split_for_mark_written(&ext, logical_start, range_end, ext_end, count);

        let mut tree_alloc = GroupBlockAllocator {
            cx,
            dev,
            geo,
            groups,
            hint: AllocHint::default(),
        };
        for replacement in replacements {
            ffs_btree::insert(cx, dev, root_bytes, replacement, &mut tree_alloc)?;
        }
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build replacement extents when marking a portion of an unwritten extent as written.
#[expect(clippy::cast_possible_truncation)]
fn split_for_mark_written(
    ext: &Ext4Extent,
    mark_start: u32,
    mark_end: u32,
    ext_end: u32,
    mark_count: u32,
) -> Vec<Ext4Extent> {
    let mut out = Vec::with_capacity(3);

    if ext.logical_block >= mark_start && ext_end <= mark_end {
        // Fully within: just clear unwritten flag.
        out.push(Ext4Extent {
            logical_block: ext.logical_block,
            raw_len: ext.actual_len(),
            physical_start: ext.physical_start,
        });
    } else if ext.logical_block < mark_start && ext_end > mark_end {
        // Spans entire range: left-unwritten, middle-written, right-unwritten.
        let left_len = (mark_start - ext.logical_block) as u16;
        out.push(Ext4Extent {
            logical_block: ext.logical_block,
            raw_len: left_len | UNWRITTEN_FLAG,
            physical_start: ext.physical_start,
        });
        let mid_len = mark_count as u16;
        out.push(Ext4Extent {
            logical_block: mark_start,
            raw_len: mid_len,
            physical_start: ext.physical_start + u64::from(mark_start - ext.logical_block),
        });
        let right_len = (ext_end - mark_end) as u16;
        out.push(Ext4Extent {
            logical_block: mark_end,
            raw_len: right_len | UNWRITTEN_FLAG,
            physical_start: ext.physical_start + u64::from(mark_end - ext.logical_block),
        });
    } else if ext.logical_block < mark_start {
        // Starts before: unwritten prefix + written suffix.
        let prefix_len = (mark_start - ext.logical_block) as u16;
        out.push(Ext4Extent {
            logical_block: ext.logical_block,
            raw_len: prefix_len | UNWRITTEN_FLAG,
            physical_start: ext.physical_start,
        });
        let suffix_len = (ext_end - mark_start) as u16;
        out.push(Ext4Extent {
            logical_block: mark_start,
            raw_len: suffix_len,
            physical_start: ext.physical_start + u64::from(prefix_len),
        });
    } else {
        // Starts within range, extends beyond: written prefix + unwritten suffix.
        let written_len = (mark_end - ext.logical_block) as u16;
        out.push(Ext4Extent {
            logical_block: ext.logical_block,
            raw_len: written_len,
            physical_start: ext.physical_start,
        });
        let unwritten_len = (ext_end - mark_end) as u16;
        out.push(Ext4Extent {
            logical_block: mark_end,
            raw_len: unwritten_len | UNWRITTEN_FLAG,
            physical_start: ext.physical_start + u64::from(written_len),
        });
    }

    out
}

fn cx_checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[expect(clippy::match_wildcard_for_single_variants)]
mod tests {
    use super::*;
    use ffs_block::BlockBuf;
    use ffs_types::GroupNumber;
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
            blocks.get(&block.0).map_or_else(
                || Ok(BlockBuf::new(vec![0u8; self.block_size as usize])),
                |data| Ok(BlockBuf::new(data.clone())),
            )
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

    fn empty_root() -> [u8; 60] {
        let mut root = [0u8; 60];
        // Magic.
        root[0] = 0x0A;
        root[1] = 0xF3;
        // entries = 0.
        root[2] = 0;
        root[3] = 0;
        // max_entries = 4.
        root[4] = 4;
        root[5] = 0;
        // depth = 0.
        root[6] = 0;
        root[7] = 0;
        root
    }

    // ── Map tests ────────────────────────────────────────────────────────

    #[test]
    fn map_empty_tree_returns_hole() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let root = empty_root();

        let mappings = map_logical_to_physical(&cx, &dev, &root, 0, 10).unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].physical_start, 0);
        assert_eq!(mappings[0].count, 10);
    }

    #[test]
    fn map_single_extent() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        let hint = AllocHint::default();
        allocate_extent(&cx, &dev, &mut root, &geo, &mut groups, 0, 5, &hint).unwrap();

        let mappings = map_logical_to_physical(&cx, &dev, &root, 0, 10).unwrap();
        assert_eq!(mappings.len(), 2);
        // First mapping: the allocated extent.
        assert_eq!(mappings[0].logical_start, 0);
        assert_eq!(mappings[0].count, 5);
        assert!(!mappings[0].unwritten);
        // Second mapping: hole after the extent.
        assert_eq!(mappings[1].logical_start, 5);
        assert_eq!(mappings[1].physical_start, 0);
    }

    // ── Allocate tests ──────────────────────────────────────────────────

    #[test]
    fn allocate_single_extent() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        let mapping =
            allocate_extent(&cx, &dev, &mut root, &geo, &mut groups, 0, 10, &AllocHint::default())
                .unwrap();
        assert_eq!(mapping.logical_start, 0);
        assert_eq!(mapping.count, 10);
        assert!(!mapping.unwritten);
    }

    #[test]
    fn allocate_two_extents() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        let m1 =
            allocate_extent(&cx, &dev, &mut root, &geo, &mut groups, 0, 5, &AllocHint::default())
                .unwrap();
        let m2 = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            5,
            5,
            &AllocHint {
                goal_block: Some(BlockNumber(m1.physical_start + 5)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(m2.logical_start, 5);
        assert_eq!(m2.count, 5);

        // Walk should find both extents.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| { count += 1; Ok(()) }).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn allocate_unwritten_extent_flag() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        let mapping = allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
        )
        .unwrap();
        assert!(mapping.unwritten);

        // Verify via search that the extent is marked unwritten.
        let result = ffs_btree::search(&cx, &dev, &root, 0).unwrap();
        match result {
            SearchResult::Found { extent, .. } => assert!(extent.is_unwritten()),
            SearchResult::Hole { .. } => panic!("expected found"),
        }
    }

    // ── Truncate tests ──────────────────────────────────────────────────

    #[test]
    fn truncate_removes_tail() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        // Allocate blocks 0-9 and 10-19.
        allocate_extent(&cx, &dev, &mut root, &geo, &mut groups, 0, 10, &AllocHint::default())
            .unwrap();
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            10,
            10,
            &AllocHint::default(),
        )
        .unwrap();

        let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

        // Truncate at logical block 10 — should remove second extent.
        let freed =
            truncate_extents(&cx, &dev, &mut root, &geo, &mut groups, 10).unwrap();
        assert_eq!(freed, 10);

        let after_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
        assert_eq!(after_free, initial_free + 10);

        // Only first extent should remain.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| { count += 1; Ok(()) }).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn truncate_to_zero_frees_all() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        allocate_extent(&cx, &dev, &mut root, &geo, &mut groups, 0, 10, &AllocHint::default())
            .unwrap();

        let freed =
            truncate_extents(&cx, &dev, &mut root, &geo, &mut groups, 0).unwrap();
        assert_eq!(freed, 10);

        // Tree should be empty.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| { count += 1; Ok(()) }).unwrap();
        assert_eq!(count, 0);
    }

    // ── Punch hole tests ────────────────────────────────────────────────

    #[test]
    fn punch_hole_frees_blocks() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        allocate_extent(&cx, &dev, &mut root, &geo, &mut groups, 0, 10, &AllocHint::default())
            .unwrap();

        let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

        // Punch hole in blocks 3-6 (4 blocks).
        let freed =
            punch_hole(&cx, &dev, &mut root, &geo, &mut groups, 3, 4).unwrap();
        assert!(freed > 0);

        let after_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
        assert!(after_free > initial_free);
    }

    #[test]
    fn punch_hole_in_empty_tree_is_noop() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        let freed =
            punch_hole(&cx, &dev, &mut root, &geo, &mut groups, 0, 10).unwrap();
        assert_eq!(freed, 0);
    }

    // ── Mark written tests ──────────────────────────────────────────────

    #[test]
    fn mark_written_clears_unwritten_flag() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        // Allocate unwritten extent at blocks 0-9.
        allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
        )
        .unwrap();

        // Verify unwritten.
        match ffs_btree::search(&cx, &dev, &root, 0).unwrap() {
            SearchResult::Found { extent, .. } => assert!(extent.is_unwritten()),
            _ => panic!("expected found"),
        }

        // Mark entire range as written.
        mark_written(&cx, &dev, &mut root, &geo, &mut groups, 0, 10).unwrap();

        // Verify now written.
        match ffs_btree::search(&cx, &dev, &root, 0).unwrap() {
            SearchResult::Found { extent, .. } => assert!(!extent.is_unwritten()),
            _ => panic!("expected found"),
        }
    }

    #[test]
    fn mark_written_partial_splits_extent() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        // Allocate unwritten extent at blocks 0-9.
        allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
        )
        .unwrap();

        // Mark blocks 3-6 as written (partial range).
        mark_written(&cx, &dev, &mut root, &geo, &mut groups, 3, 4).unwrap();

        // Block 0 should still be unwritten.
        match ffs_btree::search(&cx, &dev, &root, 0).unwrap() {
            SearchResult::Found { extent, .. } => assert!(extent.is_unwritten()),
            _ => panic!("expected found at block 0"),
        }

        // Block 4 should be written.
        match ffs_btree::search(&cx, &dev, &root, 4).unwrap() {
            SearchResult::Found { extent, .. } => assert!(!extent.is_unwritten()),
            _ => panic!("expected found at block 4"),
        }

        // Block 8 should still be unwritten.
        match ffs_btree::search(&cx, &dev, &root, 8).unwrap() {
            SearchResult::Found { extent, .. } => assert!(extent.is_unwritten()),
            _ => panic!("expected found at block 8"),
        }

        // Should have 3 extents now: [0-2] unwritten, [3-6] written, [7-9] unwritten.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| { count += 1; Ok(()) }).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn allocate_zero_count_fails() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        let result =
            allocate_extent(&cx, &dev, &mut root, &geo, &mut groups, 0, 0, &AllocHint::default());
        assert!(result.is_err());
    }
}
