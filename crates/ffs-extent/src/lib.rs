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

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap},
};

use asupersync::Cx;
use ffs_alloc::{AllocHint, BlockAlloc, FsGeometry, GroupStats};
use ffs_block::BlockDevice;
use ffs_btree::{BlockAllocator, SearchResult};
use ffs_error::{FfsError, Result};
use ffs_ondisk::{EXT_INIT_MAX_LEN, Ext4Extent, Ext4ExtentHeader, ExtentTree, parse_extent_tree};
use ffs_types::BlockNumber;
use parking_lot::RwLock;

// ── Constants ────────────────────────────────────────────────────────────────

/// Bit 15 set in raw_len indicates unwritten extent.
const UNWRITTEN_FLAG: u16 = 1_u16 << 15;
/// ext4 kernel limit for extent tree depth.
const MAX_EXTENT_TREE_DEPTH: u16 = 5;
/// One-past-the-end of ext4's 32-bit logical block address space.
const LOGICAL_BLOCK_SPACE: u64 = 1_u64 << 32;

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
    count: u64,
) -> Result<Vec<ExtentMapping>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let (root_header, root_tree) =
        parse_and_validate_root_header("map_logical_to_physical", root_bytes)?;

    let end = checked_logical_range_end("map_logical_to_physical", logical_start, count)?;

    if count == 1 {
        return map_single_logical_to_physical(cx, dev, &root_header, &root_tree, logical_start);
    }

    map_logical_range_by_walk(cx, dev, root_bytes, logical_start, end)
}

fn map_single_logical_to_physical(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_header: &Ext4ExtentHeader,
    root_tree: &ExtentTree,
    logical_block: u32,
) -> Result<Vec<ExtentMapping>> {
    cx_checkpoint(cx)?;
    let result = ffs_btree::search_parsed_root(cx, dev, root_header, root_tree, logical_block)?;
    Ok(vec![single_mapping_from_search_result(
        "map_logical_to_physical",
        logical_block,
        &result,
    )?])
}

fn map_logical_range_by_walk(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &[u8; 60],
    logical_start: u32,
    end: u64,
) -> Result<Vec<ExtentMapping>> {
    let mut mappings = Vec::new();
    let mut pos = u64::from(logical_start);

    ffs_btree::walk_range(
        cx,
        dev,
        root_bytes,
        logical_start,
        end.saturating_sub(pos),
        &mut |extent: &Ext4Extent| {
            if pos >= end {
                return Ok(());
            }

            let actual_len = u32::from(extent.actual_len());
            let extent_start = u64::from(extent.logical_block);
            let extent_end = extent_start.saturating_add(u64::from(actual_len));
            if extent_end <= pos {
                return Ok(());
            }

            if extent_start > pos {
                let hole_end = extent_start.min(end);
                append_hole_mappings(cx, &mut mappings, pos, hole_end)?;
                pos = hole_end;
                if pos >= end {
                    return Ok(());
                }
            }

            let map_start = pos.max(extent_start);
            let map_end = extent_end.min(end);
            if map_start >= map_end {
                return Ok(());
            }

            cx_checkpoint(cx)?;
            validate_physical_span("map_logical_to_physical", extent.physical_start, actual_len)?;
            let mapping_count = u32::try_from(map_end - map_start).map_err(|_| {
                FfsError::InvalidGeometry(format!(
                    "map_logical_to_physical: extent chunk length {} exceeds u32",
                    map_end - map_start
                ))
            })?;
            let mapping_start = u32::try_from(map_start).map_err(|_| {
                FfsError::InvalidGeometry(format!(
                    "map_logical_to_physical: logical position {map_start} exceeds u32 block range"
                ))
            })?;
            mappings.push(ExtentMapping {
                logical_start: mapping_start,
                physical_start: checked_physical_add(
                    "map_logical_to_physical",
                    extent.physical_start,
                    map_start - extent_start,
                )?,
                count: mapping_count,
                unwritten: extent.is_unwritten(),
            });
            pos = map_end;
            Ok(())
        },
    )?;

    append_hole_mappings(cx, &mut mappings, pos, end)?;
    Ok(mappings)
}

fn append_hole_mappings(
    cx: &Cx,
    mappings: &mut Vec<ExtentMapping>,
    mut start: u64,
    end: u64,
) -> Result<()> {
    while start < end {
        cx_checkpoint(cx)?;
        let to_map = (end - start).min(u64::from(u32::MAX));
        if to_map == 0 {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "map_logical_to_physical: zero-length hole traversal at logical block {start}"
                ),
            });
        }
        let logical_start = u32::try_from(start).map_err(|_| {
            FfsError::InvalidGeometry(format!(
                "map_logical_to_physical: hole position {start} exceeds u32 block range"
            ))
        })?;
        let hole_count = u32::try_from(to_map).map_err(|_| {
            FfsError::InvalidGeometry(format!(
                "map_logical_to_physical: hole chunk length {to_map} exceeds u32"
            ))
        })?;
        mappings.push(ExtentMapping {
            logical_start,
            physical_start: 0,
            count: hole_count,
            unwritten: false,
        });
        start += to_map;
    }
    Ok(())
}

#[cfg(test)]
fn map_logical_range_by_search(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &[u8; 60],
    logical_start: u32,
    count: u64,
) -> Result<Vec<ExtentMapping>> {
    let mut mappings = Vec::new();
    let mut pos = u64::from(logical_start);
    let end = checked_logical_range_end("map_logical_to_physical", logical_start, count)?;

    while pos < end {
        cx_checkpoint(cx)?;
        let logical_block = u32::try_from(pos).map_err(|_| {
            FfsError::InvalidGeometry(format!(
                "map_logical_to_physical: logical position {pos} exceeds u32 block range"
            ))
        })?;
        let result = ffs_btree::search(cx, dev, root_bytes, logical_block)?;
        match result {
            SearchResult::Found {
                extent,
                offset_in_extent,
            } => {
                let actual_len = u32::from(extent.actual_len());
                let remaining_in_extent = u64::from(actual_len.saturating_sub(offset_in_extent));
                let to_map = remaining_in_extent.min(end - pos).min(u64::from(u32::MAX));
                if to_map == 0 {
                    return Err(FfsError::Corruption {
                        block: 0,
                        detail: format!(
                            "map_logical_to_physical: zero-length extent traversal at logical block {pos}"
                        ),
                    });
                }
                validate_physical_span(
                    "map_logical_to_physical",
                    extent.physical_start,
                    actual_len,
                )?;
                let mapping_count = u32::try_from(to_map).map_err(|_| {
                    FfsError::InvalidGeometry(format!(
                        "map_logical_to_physical: extent chunk length {to_map} exceeds u32"
                    ))
                })?;
                mappings.push(ExtentMapping {
                    logical_start: logical_block,
                    physical_start: checked_physical_add(
                        "map_logical_to_physical",
                        extent.physical_start,
                        u64::from(offset_in_extent),
                    )?,
                    count: mapping_count,
                    unwritten: extent.is_unwritten(),
                });
                pos += to_map;
            }
            SearchResult::Hole { hole_len } => {
                let to_map = hole_len.min(end - pos).min(u64::from(u32::MAX));
                if to_map == 0 {
                    return Err(FfsError::Corruption {
                        block: 0,
                        detail: format!(
                            "map_logical_to_physical: zero-length hole traversal at logical block {pos}"
                        ),
                    });
                }
                let hole_start = u32::try_from(pos).map_err(|_| {
                    FfsError::InvalidGeometry(format!(
                        "map_logical_to_physical: hole position {pos} exceeds u32 block range"
                    ))
                })?;
                let hole_count = u32::try_from(to_map).map_err(|_| {
                    FfsError::InvalidGeometry(format!(
                        "map_logical_to_physical: hole chunk length {to_map} exceeds u32"
                    ))
                })?;
                mappings.push(ExtentMapping {
                    logical_start: hole_start,
                    physical_start: 0,
                    count: hole_count,
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
    pub pctx: &'a ffs_alloc::PersistCtx,
    /// Owning inode number — keys the external extent-block CRC32C tail.
    pub ino: u32,
    /// Owning inode `i_generation` — second key for the extent-block CRC32C.
    pub generation: u32,
}

/// Identifies the inode that owns an extent tree.
///
/// External (depth >= 1) extent-tree blocks are stamped with the
/// `metadata_csum` CRC32C tail keyed on the inode number and its
/// `i_generation` (see `ffs_ondisk::ext4::stamp_extent_block_checksum`).
#[derive(Clone, Copy, Debug, Default)]
pub struct ExtentOwner {
    pub ino: u32,
    pub generation: u32,
}

impl BlockAllocator for GroupBlockAllocator<'_> {
    fn alloc_block(&mut self, cx: &Cx) -> Result<BlockNumber> {
        let alloc = ffs_alloc::alloc_blocks_persist(
            cx,
            self.dev,
            self.geo,
            self.groups,
            1,
            &self.hint,
            self.pctx,
        )?;
        // Update hint to prefer contiguous allocation.
        self.hint.goal_block = alloc.start.0.checked_add(1).map(BlockNumber);
        Ok(alloc.start)
    }

    fn free_block(&mut self, cx: &Cx, block: BlockNumber) -> Result<()> {
        ffs_alloc::free_blocks_persist(cx, self.dev, self.geo, self.groups, block, 1, self.pctx)
    }

    fn finalize_node(&self, block: &mut [u8]) {
        // External extent-tree nodes carry a CRC32C tail on metadata_csum
        // filesystems, keyed on the filesystem csum seed plus the owning
        // inode's number and generation. The inode `i_block` root is covered
        // by the inode checksum instead and never reaches this hook.
        if self.pctx.has_metadata_csum {
            ffs_ondisk::ext4::stamp_extent_block_checksum(
                block,
                self.pctx.csum_seed,
                self.ino,
                self.generation,
            );
        }
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
    pctx: &ffs_alloc::PersistCtx,
    owner: ExtentOwner,
) -> Result<ExtentMapping> {
    cx_checkpoint(cx)?;

    if count == 0 || count > u32::from(EXT_INIT_MAX_LEN) {
        return Err(FfsError::Format(format!(
            "extent count must be 1..={EXT_INIT_MAX_LEN}"
        )));
    }
    validate_root_header("allocate_extent", root_bytes)?;

    // Allocate physical blocks.
    let BlockAlloc {
        start,
        count: allocated,
    } = ffs_alloc::alloc_blocks_persist(cx, dev, geo, groups, count, hint, pctx)?;

    let extent_len = encode_written_len("allocate_extent", u64::from(allocated))?;

    // Build the extent.
    let extent = Ext4Extent {
        logical_block: logical_start,
        raw_len: extent_len,
        physical_start: start.0,
    };

    // Insert into tree. Use a GroupBlockAllocator for tree node allocation.
    let tree_hint = AllocHint {
        goal_group: hint.goal_group,
        goal_block: start.0.checked_add(u64::from(allocated)).map(BlockNumber),
        numa: hint.numa.clone(),
    };
    let mut tree_alloc = GroupBlockAllocator {
        cx,
        dev,
        geo,
        groups,
        hint: tree_hint,
        pctx,
        ino: owner.ino,
        generation: owner.generation,
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
    pctx: &ffs_alloc::PersistCtx,
    owner: ExtentOwner,
) -> Result<ExtentMapping> {
    cx_checkpoint(cx)?;

    if count == 0 || count > u32::from(u16::MAX >> 1) {
        return Err(FfsError::Format("extent count must be 1..=32767".into()));
    }
    validate_root_header("allocate_unwritten_extent", root_bytes)?;

    let BlockAlloc {
        start,
        count: allocated,
    } = ffs_alloc::alloc_blocks_persist(cx, dev, geo, groups, count, hint, pctx)?;

    let raw_len = encode_unwritten_len("allocate_unwritten_extent", u64::from(allocated))?;

    let extent = Ext4Extent {
        logical_block: logical_start,
        raw_len,
        physical_start: start.0,
    };

    let tree_hint = AllocHint {
        goal_group: hint.goal_group,
        goal_block: start.0.checked_add(u64::from(allocated)).map(BlockNumber),
        numa: hint.numa.clone(),
    };
    let mut tree_alloc = GroupBlockAllocator {
        cx,
        dev,
        geo,
        groups,
        hint: tree_hint,
        pctx,
        ino: owner.ino,
        generation: owner.generation,
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
#[expect(clippy::too_many_arguments)]
pub fn truncate_extents(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    new_logical_end: u32,
    pctx: &ffs_alloc::PersistCtx,
    owner: ExtentOwner,
) -> Result<u64> {
    cx_checkpoint(cx)?;
    validate_root_header("truncate_extents", root_bytes)?;

    let mut total_freed = 0u64;

    let freed_ranges = {
        let mut tree_alloc = GroupBlockAllocator {
            cx,
            dev,
            geo,
            groups,
            hint: AllocHint::default(),
            pctx,
            ino: owner.ino,
            generation: owner.generation,
        };
        let count_to_delete = (1_u64 << 32).saturating_sub(u64::from(new_logical_end));
        ffs_btree::delete_range(
            cx,
            dev,
            root_bytes,
            new_logical_end,
            count_to_delete,
            &mut tree_alloc,
        )?
    };

    for f in &freed_ranges {
        ffs_alloc::free_blocks_persist(
            cx,
            dev,
            geo,
            groups,
            BlockNumber(f.physical_start),
            u32::from(f.count),
            pctx,
        )?;
        total_freed += u64::from(f.count);
    }

    Ok(total_freed)
}

// ── Punch hole ──────────────────────────────────────────────────────────────

/// Punch a hole in the extent tree: remove mappings in the range
/// `[logical_start, logical_start + count)` without changing file size.
///
/// Returns the total number of physical blocks freed.
#[allow(clippy::too_many_arguments)]
pub fn punch_hole(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    logical_start: u32,
    count: u64,
    pctx: &ffs_alloc::PersistCtx,
    owner: ExtentOwner,
) -> Result<u64> {
    if count == 0 {
        return Ok(0);
    }
    cx_checkpoint(cx)?;
    validate_root_header("punch_hole", root_bytes)?;

    let hole_end = checked_logical_range_end("punch_hole", logical_start, count)?;

    // Collect extents overlapping the hole.
    let mut overlapping = Vec::new();
    ffs_btree::walk(cx, dev, root_bytes, &mut |ext: &Ext4Extent| {
        let ext_len = u32::from(ext.actual_len());
        let ext_start = u64::from(ext.logical_block);
        let ext_end = ext_start.saturating_add(u64::from(ext_len));

        if ext_start < hole_end && ext_end > u64::from(logical_start) {
            overlapping.push(*ext);
        }
        Ok(())
    })?;

    let mut total_freed = 0u64;

    for ext in overlapping {
        let mut tree_alloc = GroupBlockAllocator {
            cx,
            dev,
            geo,
            groups,
            hint: AllocHint::default(),
            pctx,
            ino: owner.ino,
            generation: owner.generation,
        };

        let ext_len = u32::from(ext.actual_len());

        // Delete the original extent entirely to avoid splitting it in place.
        ffs_btree::delete_range(
            cx,
            dev,
            root_bytes,
            ext.logical_block,
            u64::from(ext_len),
            &mut tree_alloc,
        )?;

        // Trim the extent against the hole.
        let (remaining, freed) =
            ffs_btree::trim_extents(vec![ext], u64::from(logical_start), hole_end)?;

        // Re-insert the remaining pieces (handles node splitting naturally).
        for r in remaining {
            ffs_btree::insert(cx, dev, root_bytes, r, &mut tree_alloc)?;
        }

        // Free the physical blocks.
        for f in freed {
            ffs_alloc::free_blocks_persist(
                cx,
                dev,
                geo,
                groups,
                BlockNumber(f.physical_start),
                u32::from(f.count),
                pctx,
            )?;
            total_freed += u64::from(f.count);
        }
    }

    Ok(total_freed)
}

/// Collapse the logical range `[logical_start, logical_start + count)`.
///
/// Frees and removes all extents inside the range, then shifts every
/// extent past the cut left by `count` blocks so the file shrinks by
/// exactly that span with no hole left behind. Mirrors
/// `fs/ext4/extents.c::ext4_collapse_range`. Both `logical_start` and
/// `count` must be block-aligned in the caller — this helper operates
/// in units of logical blocks. Returns the number of physical blocks
/// freed in the inner range (does not change file size — the caller
/// must subtract `count * block_size` from `inode.size`).
#[allow(clippy::too_many_arguments)]
pub fn collapse_range(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    logical_start: u32,
    count: u32,
    pctx: &ffs_alloc::PersistCtx,
    owner: ExtentOwner,
) -> Result<u64> {
    if count == 0 {
        return Ok(0);
    }
    cx_checkpoint(cx)?;
    validate_root_header("collapse_range", root_bytes)?;
    let cut = checked_logical_range_end("collapse_range", logical_start, u64::from(count))?;

    // Phase 1: free + delete extents in [start, start+count). punch_hole
    // also splits any extent that straddles the cut so the right-hand
    // remainder is parked on a clean boundary at start+count, ready to
    // be shifted in phase 3.
    let freed = punch_hole(
        cx,
        dev,
        root_bytes,
        geo,
        groups,
        logical_start,
        u64::from(count),
        pctx,
        owner,
    )?;

    // Phase 2: snapshot the tail before mutating the tree. We cannot
    // delete during walk() because the visitor only sees a read-only
    // view of each extent.
    let mut tail: Vec<Ext4Extent> = Vec::new();
    ffs_btree::walk(cx, dev, root_bytes, &mut |ext: &Ext4Extent| {
        if u64::from(ext.logical_block) >= cut {
            tail.push(*ext);
        }
        Ok(())
    })?;

    // Phase 3: delete-then-reinsert each tail extent at its shifted
    // logical_block. Physical blocks are kept — only the logical
    // mapping moves. count fits in u32 by precondition; the subtraction
    // is overflow-safe because we filtered for ext.logical_block >= cut
    // and cut >= count.
    let mut tree_alloc = GroupBlockAllocator {
        cx,
        dev,
        geo,
        groups,
        hint: AllocHint::default(),
        pctx,
        ino: owner.ino,
        generation: owner.generation,
    };
    for ext in &tail {
        ffs_btree::delete_range(
            cx,
            dev,
            root_bytes,
            ext.logical_block,
            u64::from(ext.actual_len()),
            &mut tree_alloc,
        )?;
    }
    for ext in tail {
        let new_logical = ext.logical_block.saturating_sub(count);
        ffs_btree::insert(
            cx,
            dev,
            root_bytes,
            Ext4Extent {
                logical_block: new_logical,
                ..ext
            },
            &mut tree_alloc,
        )?;
    }

    Ok(freed)
}

/// Insert a hole at the logical range `[logical_start, logical_start + count)`.
///
/// The mirror of [`collapse_range`]. Shifts every extent past the cut
/// right by `count` blocks, leaving an unallocated sparse hole behind.
/// No physical blocks are allocated — reads in the new hole return
/// zeroes until the caller writes through it. Mirrors
/// `fs/ext4/extents.c::ext4_insert_range`. Both `logical_start` and
/// `count` must be block-aligned in the caller; this helper operates
/// in units of logical blocks. Returns Ok(()) on success — the caller
/// must add `count * block_size` to `inode.size`.
#[allow(clippy::too_many_arguments)]
pub fn insert_range(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    logical_start: u32,
    count: u32,
    pctx: &ffs_alloc::PersistCtx,
    owner: ExtentOwner,
) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    cx_checkpoint(cx)?;
    validate_root_header("insert_range", root_bytes)?;
    checked_logical_range_end("insert_range", logical_start, u64::from(count))?;

    // Preflight all extents that will move right. The operation is destructive
    // after this point, so reject logical-space overflow before splitting or
    // deleting any existing mapping.
    let cut = u64::from(logical_start);
    let mut straddler: Option<Ext4Extent> = None;
    ffs_btree::walk(cx, dev, root_bytes, &mut |ext: &Ext4Extent| {
        let ext_start = u64::from(ext.logical_block);
        let ext_end = ext_start.saturating_add(u64::from(u32::from(ext.actual_len())));
        if ext_end > cut {
            validate_shifted_extent_fits_logical_space("insert_range", ext, count)?;
        }
        if ext_start < cut && ext_end > cut {
            straddler = Some(*ext);
        }
        Ok(())
    })?;

    // Split a straddling extent; zero-length punch_hole cannot do it.
    let mut tree_alloc = GroupBlockAllocator {
        cx,
        dev,
        geo,
        groups,
        hint: AllocHint::default(),
        pctx,
        ino: owner.ino,
        generation: owner.generation,
    };

    if let Some(ext) = straddler {
        split_insert_range_straddler(cx, dev, root_bytes, cut, ext, &mut tree_alloc)?;
    }

    // Snapshot the post-split tail before shifting it right by count.
    let mut tail: Vec<Ext4Extent> = Vec::new();
    ffs_btree::walk(cx, dev, root_bytes, &mut |ext: &Ext4Extent| {
        if u64::from(ext.logical_block) >= cut {
            tail.push(*ext);
        }
        Ok(())
    })?;

    // Move right-to-left so shifted extents cannot collide.
    tail.sort_by_key(|ext| std::cmp::Reverse(ext.logical_block));
    for ext in &tail {
        ffs_btree::delete_range(
            cx,
            dev,
            root_bytes,
            ext.logical_block,
            u64::from(u32::from(ext.actual_len())),
            &mut tree_alloc,
        )?;
    }
    for ext in tail {
        let new_logical = ext.logical_block.checked_add(count).ok_or_else(|| {
            ffs_error::FfsError::Format("insert_range: shifted logical_block overflows u32".into())
        })?;
        ffs_btree::insert(
            cx,
            dev,
            root_bytes,
            Ext4Extent {
                logical_block: new_logical,
                ..ext
            },
            &mut tree_alloc,
        )?;
    }

    Ok(())
}

fn split_insert_range_straddler(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    cut: u64,
    ext: Ext4Extent,
    tree_alloc: &mut dyn BlockAllocator,
) -> Result<()> {
    let ext_start = u64::from(ext.logical_block);
    let ext_len = u64::from(u32::from(ext.actual_len()));
    let ext_end = ext_start + ext_len;
    ffs_btree::delete_range(cx, dev, root_bytes, ext.logical_block, ext_len, tree_alloc)?;

    let left_len_u32 = u32::try_from(cut - ext_start)
        .map_err(|_| ffs_error::FfsError::Format("insert_range: split width exceeds u32".into()))?;
    let right_len_u32 = u32::try_from(ext_end - cut)
        .map_err(|_| ffs_error::FfsError::Format("insert_range: split tail exceeds u32".into()))?;
    let unwritten = ext.is_unwritten();
    let left = Ext4Extent {
        logical_block: ext.logical_block,
        raw_len: encode_split_extent_len("insert_range split left", left_len_u32, unwritten)?,
        physical_start: ext.physical_start,
    };
    let right = Ext4Extent {
        logical_block: u32::try_from(cut)
            .map_err(|_| ffs_error::FfsError::Format("insert_range: cut exceeds u32".into()))?,
        raw_len: encode_split_extent_len("insert_range split right", right_len_u32, unwritten)?,
        physical_start: checked_physical_add(
            "insert_range split tail",
            ext.physical_start,
            u64::from(left_len_u32),
        )?,
    };
    ffs_btree::insert(cx, dev, root_bytes, left, tree_alloc)?;
    ffs_btree::insert(cx, dev, root_bytes, right, tree_alloc)
}

// ── Unwritten extent handling ───────────────────────────────────────────────

/// Mark extents in the range `[logical_start, logical_start + count)` as written.
///
/// Clears the unwritten flag (bit 15 of `ee_len`) on extents that overlap the
/// range. May split extents at range boundaries if they only partially overlap.
///
/// This is used when data is first written to a preallocated (unwritten) region.
#[allow(clippy::too_many_arguments)]
pub fn mark_written(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &mut [u8; 60],
    geo: &FsGeometry,
    groups: &mut [GroupStats],
    logical_start: u32,
    count: u32,
    pctx: &ffs_alloc::PersistCtx,
    owner: ExtentOwner,
) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    cx_checkpoint(cx)?;
    validate_root_header("mark_written", root_bytes)?;

    let range_end = checked_logical_range_end("mark_written", logical_start, u64::from(count))?;

    // Collect unwritten extents overlapping the range.
    let mut unwritten_extents = Vec::new();
    ffs_btree::walk(cx, dev, root_bytes, &mut |ext: &Ext4Extent| {
        if ext.is_unwritten() {
            let ext_end = u64::from(ext.logical_block) + u64::from(ext.actual_len());
            if u64::from(ext.logical_block) < range_end && ext_end > u64::from(logical_start) {
                unwritten_extents.push(*ext);
            }
        }
        Ok(())
    })?;

    for ext in unwritten_extents {
        let ext_len = u32::from(ext.actual_len());
        let ext_end = u64::from(ext.logical_block) + u64::from(ext_len);

        let mut tree_alloc = GroupBlockAllocator {
            cx,
            dev,
            geo,
            groups,
            hint: AllocHint::default(),
            pctx,
            ino: owner.ino,
            generation: owner.generation,
        };

        // All branches start by removing the old extent.
        ffs_btree::delete_range(
            cx,
            dev,
            root_bytes,
            ext.logical_block,
            u64::from(ext_len),
            &mut tree_alloc,
        )?;

        // Build replacement extents based on overlap type.
        let replacements = split_for_mark_written(&ext, logical_start, range_end, ext_end)?;

        for replacement in replacements {
            ffs_btree::insert(cx, dev, root_bytes, replacement, &mut tree_alloc)?;
        }
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build replacement extents when marking a portion of an unwritten extent as written.
fn split_for_mark_written<M, E>(
    ext: &Ext4Extent,
    mark_start: u32,
    mark_end: M,
    ext_end: E,
) -> Result<Vec<Ext4Extent>>
where
    M: Into<u64>,
    E: Into<u64>,
{
    let mark_start_u64 = u64::from(mark_start);
    let mark_end = mark_end.into();
    let ext_start = u64::from(ext.logical_block);
    let ext_end = ext_end.into();
    let mut out = Vec::with_capacity(3);

    if mark_end <= mark_start_u64 || ext_end <= ext_start {
        return Err(FfsError::InvalidGeometry(format!(
            "mark_written: invalid split range ext=[{ext_start}, {ext_end}) mark=[{mark_start}, {mark_end})"
        )));
    }

    if ext_start >= mark_start_u64 && ext_end <= mark_end {
        // Fully within: just clear unwritten flag.
        out.push(Ext4Extent {
            logical_block: ext.logical_block,
            raw_len: encode_written_len("mark_written full overlap", u64::from(ext.actual_len()))?,
            physical_start: ext.physical_start,
        });
    } else if ext_start < mark_start_u64 && ext_end > mark_end {
        // Spans entire range: left-unwritten, middle-written, right-unwritten.
        let left_raw_len = encode_unwritten_len(
            "mark_written left unwritten prefix",
            mark_start_u64 - ext_start,
        )?;
        out.push(Ext4Extent {
            logical_block: ext.logical_block,
            raw_len: left_raw_len,
            physical_start: ext.physical_start,
        });
        let mid_len = encode_written_len("mark_written written middle", mark_end - mark_start_u64)?;
        out.push(Ext4Extent {
            logical_block: mark_start,
            raw_len: mid_len,
            physical_start: checked_physical_add(
                "mark_written written middle",
                ext.physical_start,
                u64::from(mark_start - ext.logical_block),
            )?,
        });
        let right_raw_len =
            encode_unwritten_len("mark_written right unwritten suffix", ext_end - mark_end)?;
        let right_logical_block = u32::try_from(mark_end).map_err(|_| {
            FfsError::InvalidGeometry(format!(
                "mark_written: right-hand split start {mark_end} exceeds u32 block range"
            ))
        })?;
        out.push(Ext4Extent {
            logical_block: right_logical_block,
            raw_len: right_raw_len,
            physical_start: checked_physical_add(
                "mark_written right unwritten suffix",
                ext.physical_start,
                mark_end - ext_start,
            )?,
        });
    } else if ext_start < mark_start_u64 {
        // Starts before: unwritten prefix + written suffix.
        let prefix_raw_len =
            encode_unwritten_len("mark_written unwritten prefix", mark_start_u64 - ext_start)?;
        out.push(Ext4Extent {
            logical_block: ext.logical_block,
            raw_len: prefix_raw_len,
            physical_start: ext.physical_start,
        });
        let suffix_len =
            encode_written_len("mark_written written suffix", ext_end - mark_start_u64)?;
        out.push(Ext4Extent {
            logical_block: mark_start,
            raw_len: suffix_len,
            physical_start: checked_physical_add(
                "mark_written written suffix",
                ext.physical_start,
                mark_start_u64 - ext_start,
            )?,
        });
    } else {
        // Starts within range, extends beyond: written prefix + unwritten suffix.
        let written_len = encode_written_len("mark_written written prefix", mark_end - ext_start)?;
        out.push(Ext4Extent {
            logical_block: ext.logical_block,
            raw_len: written_len,
            physical_start: ext.physical_start,
        });
        let unwritten_raw_len =
            encode_unwritten_len("mark_written unwritten suffix", ext_end - mark_end)?;
        let right_logical_block = u32::try_from(mark_end).map_err(|_| {
            FfsError::InvalidGeometry(format!(
                "mark_written: right-hand split start {mark_end} exceeds u32 block range"
            ))
        })?;
        out.push(Ext4Extent {
            logical_block: right_logical_block,
            raw_len: unwritten_raw_len,
            physical_start: checked_physical_add(
                "mark_written unwritten suffix",
                ext.physical_start,
                mark_end - ext_start,
            )?,
        });
    }

    Ok(out)
}

fn checked_physical_add(op: &str, physical_start: u64, offset: u64) -> Result<u64> {
    physical_start.checked_add(offset).ok_or_else(|| {
        FfsError::InvalidGeometry(format!(
            "{op}: physical block {physical_start}+{offset} overflows u64"
        ))
    })
}

fn physical_span_fits(physical_start: u64, count: u32) -> bool {
    count != 0
        && physical_start
            .checked_add(u64::from(count.saturating_sub(1)))
            .is_some()
}

fn validate_physical_span(op: &str, physical_start: u64, count: u32) -> Result<()> {
    if physical_span_fits(physical_start, count) {
        return Ok(());
    }
    Err(FfsError::InvalidGeometry(format!(
        "{op}: physical extent [{physical_start}, +{count}) exceeds u64 block space"
    )))
}

fn encode_written_len(label: &str, len: u64) -> Result<u16> {
    if len == 0 {
        return Err(FfsError::InvalidGeometry(format!(
            "{label}: extent length must be nonzero"
        )));
    }
    if len > u64::from(EXT_INIT_MAX_LEN) {
        return Err(FfsError::InvalidGeometry(format!(
            "{label}: written extent length {len} exceeds {EXT_INIT_MAX_LEN}"
        )));
    }
    u16::try_from(len)
        .map_err(|_| FfsError::InvalidGeometry(format!("{label}: extent length {len} exceeds u16")))
}

fn encode_unwritten_len(label: &str, len: u64) -> Result<u16> {
    let max_unwritten_len = EXT_INIT_MAX_LEN - 1;
    if len == 0 {
        return Err(FfsError::InvalidGeometry(format!(
            "{label}: unwritten extent length must be nonzero"
        )));
    }
    if len > u64::from(max_unwritten_len) {
        return Err(FfsError::InvalidGeometry(format!(
            "{label}: unwritten extent length {len} exceeds {max_unwritten_len}"
        )));
    }
    let len = u16::try_from(len).map_err(|_| {
        FfsError::InvalidGeometry(format!(
            "{label}: unwritten extent length {len} exceeds u16"
        ))
    })?;
    Ok(len | UNWRITTEN_FLAG)
}

fn encode_split_extent_len(label: &str, len: u32, unwritten: bool) -> Result<u16> {
    if unwritten {
        encode_unwritten_len(label, u64::from(len))
    } else {
        encode_written_len(label, u64::from(len))
    }
}

fn cx_checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn checked_logical_range_end(op: &str, logical_start: u32, count: u64) -> Result<u64> {
    let start = u64::from(logical_start);
    let Some(end) = start.checked_add(count) else {
        return Err(FfsError::InvalidGeometry(format!(
            "{op}: logical range {logical_start}+{count} overflows u64"
        )));
    };
    if end > LOGICAL_BLOCK_SPACE {
        return Err(FfsError::InvalidGeometry(format!(
            "{op}: logical range [{logical_start}, {end}) exceeds ext4 32-bit block space"
        )));
    }
    Ok(end)
}

fn validate_shifted_extent_fits_logical_space(
    op: &str,
    ext: &Ext4Extent,
    shift_blocks: u32,
) -> Result<()> {
    let ext_start = u64::from(ext.logical_block);
    let ext_end = ext_start
        .checked_add(u64::from(ext.actual_len()))
        .ok_or_else(|| {
            FfsError::InvalidGeometry(format!(
                "{op}: extent ending after logical block {} overflows u64",
                ext.logical_block
            ))
        })?;
    let shifted_end = ext_end
        .checked_add(u64::from(shift_blocks))
        .ok_or_else(|| {
            FfsError::InvalidGeometry(format!(
                "{op}: shifting extent ending at {ext_end} by {shift_blocks} blocks overflows u64"
            ))
        })?;
    if shifted_end > LOGICAL_BLOCK_SPACE {
        return Err(FfsError::InvalidGeometry(format!(
            "{op}: shifting extent ending at {ext_end} by {shift_blocks} blocks exceeds ext4 32-bit block space"
        )));
    }
    Ok(())
}

fn parse_and_validate_root_header(
    op: &str,
    root_bytes: &[u8; 60],
) -> Result<(Ext4ExtentHeader, ExtentTree)> {
    let (header, tree) = parse_extent_tree(root_bytes).map_err(|err| FfsError::Corruption {
        block: 0,
        detail: format!("{op}: invalid root extent header: {err}"),
    })?;
    if header.depth > MAX_EXTENT_TREE_DEPTH {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!(
                "{op}: extent root depth {} exceeds ext4 limit {MAX_EXTENT_TREE_DEPTH}",
                header.depth
            ),
        });
    }
    if header.depth > 0 && header.entries == 0 {
        return Err(FfsError::Corruption {
            block: 0,
            detail: format!("{op}: non-leaf extent root has zero entries"),
        });
    }
    if let ExtentTree::Leaf(extents) = &tree {
        if extents.iter().any(|ext| ext.actual_len() == 0) {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!("{op}: leaf extent with zero length"),
            });
        }
    }
    Ok((header, tree))
}

fn validate_root_header(op: &str, root_bytes: &[u8; 60]) -> Result<()> {
    parse_and_validate_root_header(op, root_bytes).map(|_| ())
}

// ── Extent cache ────────────────────────────────────────────────────────────

/// Default maximum number of cached extent entries.
const DEFAULT_EXTENT_CACHE_CAPACITY: usize = 1024;

/// Thread-safe LRU-like cache for extent tree lookups.
///
/// Stores resolved `ExtentMapping` entries keyed by `logical_start`, allowing
/// fast range-based lookup. Sequential reads benefit enormously because
/// consecutive blocks typically fall within the same extent.
///
/// # Invalidation
///
/// Callers must invoke [`Self::invalidate_range`] when the extent tree is mutated
/// (write, truncate, punch hole, mark written). A monotonic generation counter
/// allows cheap bulk invalidation via [`Self::invalidate_all`].
///
/// # Thread safety
///
/// All operations acquire a `parking_lot::RwLock`: reads take a shared lock,
/// mutations take an exclusive lock. The critical sections are small (BTreeMap
/// lookups / inserts), so contention is minimal.
pub struct ExtentCache {
    inner: RwLock<ExtentCacheInner>,
}

struct ExtentCacheInner {
    /// Entries keyed by `(namespace, logical_start)`.
    ///
    /// The namespace is a caller-provided scope identifier (typically an inode
    /// number) that prevents cross-scope cache pollution when a single cache
    /// instance is shared across many objects.
    entries: BTreeMap<(u64, u32), CacheEntry>,
    /// Lazy min-heap of `(last_access, key)` eviction candidates.
    ///
    /// `BinaryHeap` does not support arbitrary removal, so lookup and insert
    /// push fresh states and eviction discards stale heap rows until it reaches
    /// a row matching the current cache entry. The tuple matches the previous
    /// scan tie-break: oldest access first, then lexicographically smallest key.
    eviction_heap: BinaryHeap<Reverse<(u64, (u64, u32))>>,
    /// Maximum number of entries before eviction.
    capacity: usize,
    /// Monotonically increasing generation; bumped on bulk invalidation.
    generation: u64,
    /// Running counters for observability.
    hits: u64,
    misses: u64,
    evictions: u64,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    mapping: ExtentMapping,
    generation: u64,
    /// Logical clock for LRU eviction (higher = more recent).
    last_access: u64,
}

/// Snapshot of cache performance counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub entries: usize,
    pub capacity: usize,
    pub generation: u64,
}

impl ExtentCacheStats {
    /// Hit rate as a fraction in `[0.0, 1.0]`. Returns 0.0 if no lookups.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        if self.hits == 0 && self.misses == 0 {
            return 0.0;
        }
        let hits = self.hits as f64;
        let total = hits + self.misses as f64;
        hits / total
    }
}

impl ExtentCache {
    /// Create a new cache with the default capacity (1024 entries).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_EXTENT_CACHE_CAPACITY)
    }

    /// Create a new cache with the given maximum entry count.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(ExtentCacheInner {
                entries: BTreeMap::new(),
                eviction_heap: BinaryHeap::with_capacity(capacity),
                capacity,
                generation: 0,
                hits: 0,
                misses: 0,
                evictions: 0,
            }),
        }
    }

    /// Look up a logical block in the cache within the given namespace.
    ///
    /// The `ns` parameter scopes the lookup to a specific object (typically
    /// an inode number). This prevents cross-inode cache pollution when a
    /// single cache instance is shared across many objects.
    ///
    /// Returns `Some(mapping)` if a cached extent covers `logical_block`.
    /// The returned mapping is adjusted to reflect the exact position within
    /// the extent.
    pub fn lookup(&self, ns: u64, logical_block: u32) -> Option<ExtentMapping> {
        let mut inner = self.inner.write();
        let current_gen = inner.generation;

        // Find the last entry in this namespace with logical_start <= logical_block.
        let candidate = inner
            .entries
            .range(..=(ns, logical_block))
            .next_back()
            .filter(|&(&(entry_ns, _), _)| entry_ns == ns)
            .map(|(&k, e)| (k, e.mapping, e.generation));

        let Some((key, mapping, entry_gen)) = candidate else {
            inner.misses = inner.misses.saturating_add(1);
            return None;
        };

        let extent_end = u64::from(mapping.logical_start) + u64::from(mapping.count);
        if u64::from(logical_block) < extent_end && entry_gen == current_gen {
            let offset = logical_block - mapping.logical_start;
            let physical_start = if mapping.physical_start == 0 {
                0
            } else if let Some(physical_start) =
                mapping.physical_start.checked_add(u64::from(offset))
            {
                physical_start
            } else {
                inner.misses = inner.misses.saturating_add(1);
                inner.entries.remove(&key);
                return None;
            };
            inner.hits = inner.hits.saturating_add(1);
            let clock = inner.hits.saturating_add(inner.misses);
            if let Some(e) = inner.entries.get_mut(&key) {
                e.last_access = clock;
            }
            if inner.entries.len() >= inner.capacity && inner.capacity != 0 {
                push_eviction_state(&mut inner, key, clock);
            }
            Some(ExtentMapping {
                logical_start: logical_block,
                physical_start,
                count: mapping.count - offset,
                unwritten: mapping.unwritten,
            })
        } else {
            inner.misses = inner.misses.saturating_add(1);
            // Stale entry — remove it.
            if entry_gen != current_gen {
                inner.entries.remove(&key);
            }
            None
        }
    }

    /// Insert a resolved extent mapping into the cache within the given namespace.
    ///
    /// If the cache is at capacity, the least-recently-used entry is evicted.
    pub fn insert(&self, ns: u64, mapping: ExtentMapping) {
        let mut inner = self.inner.write();
        if inner.capacity == 0
            || mapping.count == 0
            || (mapping.physical_start != 0
                && !physical_span_fits(mapping.physical_start, mapping.count))
        {
            return;
        }

        let access_clock = inner.hits.saturating_add(inner.misses);
        let current_gen = inner.generation;

        let key = (ns, mapping.logical_start);

        // Evict if at capacity and this is a new key.
        if inner.entries.len() >= inner.capacity && !inner.entries.contains_key(&key) {
            evict_lru_entry(&mut inner);
        }

        inner.entries.insert(
            key,
            CacheEntry {
                mapping,
                generation: current_gen,
                last_access: access_clock,
            },
        );
        push_eviction_state(&mut inner, key, access_clock);
    }

    /// Invalidate all cached entries in the given namespace whose range overlaps
    /// `[logical_start, logical_start + count)`.
    pub fn invalidate_range(&self, ns: u64, logical_start: u32, count: u64) {
        if count == 0 {
            return;
        }
        let range_end = u64::from(logical_start).saturating_add(count);
        let range_end_u32 = u32::try_from(range_end).unwrap_or(u32::MAX);
        let mut inner = self.inner.write();

        // Collect keys to remove: entries in this namespace whose extent overlaps the range.
        let to_remove: Vec<(u64, u32)> = inner
            .entries
            .range((ns, 0)..=(ns, range_end_u32))
            .filter(|&(&(entry_ns, _), e)| {
                if entry_ns != ns {
                    return false;
                }
                let ext_end = u64::from(e.mapping.logical_start) + u64::from(e.mapping.count);
                let ext_start = u64::from(e.mapping.logical_start);
                ext_start < range_end && ext_end > u64::from(logical_start)
            })
            .map(|(&k, _)| k)
            .collect();

        for k in to_remove {
            inner.entries.remove(&k);
        }
        compact_eviction_heap_if_needed(&mut inner);
    }

    /// Invalidate all entries (bulk reset). Bumps the generation counter so
    /// stale entries are lazily discarded on lookup.
    pub fn invalidate_all(&self) {
        let mut inner = self.inner.write();
        inner.entries.clear();
        inner.eviction_heap.clear();
        inner.generation = inner.generation.saturating_add(1);
    }

    /// Return a snapshot of cache performance counters.
    pub fn stats(&self) -> ExtentCacheStats {
        let inner = self.inner.read();
        ExtentCacheStats {
            hits: inner.hits,
            misses: inner.misses,
            evictions: inner.evictions,
            entries: inner.entries.len(),
            capacity: inner.capacity,
            generation: inner.generation,
        }
    }

    /// Reset performance counters (entries and generation are preserved).
    pub fn reset_stats(&self) {
        let mut inner = self.inner.write();
        inner.hits = 0;
        inner.misses = 0;
        inner.evictions = 0;
    }
}

fn push_eviction_state(inner: &mut ExtentCacheInner, key: (u64, u32), last_access: u64) {
    inner.eviction_heap.push(Reverse((last_access, key)));
    compact_eviction_heap_if_needed(inner);
}

fn evict_lru_entry(inner: &mut ExtentCacheInner) {
    while let Some(Reverse((last_access, key))) = inner.eviction_heap.pop() {
        if inner
            .entries
            .get(&key)
            .is_some_and(|entry| entry.last_access == last_access)
        {
            inner.entries.remove(&key);
            inner.evictions = inner.evictions.saturating_add(1);
            return;
        }
    }

    let victim_key = inner
        .entries
        .iter()
        .min_by_key(|(key, entry)| (entry.last_access, **key))
        .map(|(key, _)| *key);
    if let Some(key) = victim_key {
        inner.entries.remove(&key);
        inner.evictions = inner.evictions.saturating_add(1);
    }
}

fn compact_eviction_heap_if_needed(inner: &mut ExtentCacheInner) {
    let live_entries = inner.entries.len();
    if live_entries == 0 {
        inner.eviction_heap.clear();
        return;
    }

    let max_lazy_rows = live_entries.saturating_mul(4).max(64);
    if inner.eviction_heap.len() <= max_lazy_rows {
        return;
    }

    inner.eviction_heap.clear();
    inner.eviction_heap.extend(
        inner
            .entries
            .iter()
            .map(|(&key, entry)| Reverse((entry.last_access, key))),
    );
}

impl Default for ExtentCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cached variant of [`map_logical_to_physical`].
///
/// Checks the `cache` first; on miss, performs the full tree walk and populates
/// the cache with the resolved mappings. The `ns` parameter scopes cache
/// entries to a specific object (typically an inode number).
pub fn cached_map_logical_to_physical(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &[u8; 60],
    logical_start: u32,
    count: u64,
    cache: &ExtentCache,
    ns: u64,
) -> Result<Vec<ExtentMapping>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    // Fast path: single-block lookup that hits cache.
    if count == 1 {
        if let Some(hit) = cache.lookup(ns, logical_start) {
            return Ok(vec![ExtentMapping {
                logical_start,
                physical_start: hit.physical_start,
                count: 1,
                unwritten: hit.unwritten,
            }]);
        }
    }

    if count == 1 {
        return cached_single_block_miss(cx, dev, root_bytes, logical_start, cache, ns);
    }

    // Full tree walk (miss path).
    let mappings = map_logical_to_physical(cx, dev, root_bytes, logical_start, count)?;

    // Populate cache with resolved mappings.
    for m in &mappings {
        cache.insert(ns, *m);
    }

    Ok(mappings)
}

fn cached_single_block_miss(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root_bytes: &[u8; 60],
    logical_start: u32,
    cache: &ExtentCache,
    ns: u64,
) -> Result<Vec<ExtentMapping>> {
    validate_root_header("map_logical_to_physical", root_bytes)?;
    let _end = checked_logical_range_end("map_logical_to_physical", logical_start, 1)?;

    cx_checkpoint(cx)?;
    let window = ffs_btree::search_with_leaf_window(cx, dev, root_bytes, logical_start)?;
    let mapping = single_mapping_from_search_result(
        "map_logical_to_physical",
        logical_start,
        &window.result,
    )?;

    cache_valid_leaf_extents(cache, ns, &window.extents);
    if let SearchResult::Hole { hole_len } = window.result {
        cache_hole_interval(cache, ns, logical_start, hole_len);
    }

    Ok(vec![mapping])
}

fn single_mapping_from_search_result(
    op: &str,
    logical_start: u32,
    result: &SearchResult,
) -> Result<ExtentMapping> {
    match result {
        SearchResult::Found {
            extent,
            offset_in_extent,
        } => {
            let actual_len = u32::from(extent.actual_len());
            validate_physical_span(op, extent.physical_start, actual_len)?;
            Ok(ExtentMapping {
                logical_start,
                physical_start: checked_physical_add(
                    op,
                    extent.physical_start,
                    u64::from(*offset_in_extent),
                )?,
                count: 1,
                unwritten: extent.is_unwritten(),
            })
        }
        SearchResult::Hole { .. } => Ok(ExtentMapping {
            logical_start,
            physical_start: 0,
            count: 1,
            unwritten: false,
        }),
    }
}

fn cache_valid_leaf_extents(cache: &ExtentCache, ns: u64, extents: &[Ext4Extent]) {
    for extent in extents {
        let count = u32::from(extent.actual_len());
        if count == 0
            || validate_physical_span("map_logical_to_physical", extent.physical_start, count)
                .is_err()
        {
            continue;
        }
        cache.insert(
            ns,
            ExtentMapping {
                logical_start: extent.logical_block,
                physical_start: extent.physical_start,
                count,
                unwritten: extent.is_unwritten(),
            },
        );
    }
}

fn cache_hole_interval(cache: &ExtentCache, ns: u64, logical_start: u32, hole_len: u64) {
    let remaining_space = LOGICAL_BLOCK_SPACE.saturating_sub(u64::from(logical_start));
    let count = hole_len.min(remaining_space).min(u64::from(u32::MAX));
    let Ok(count) = u32::try_from(count) else {
        return;
    };
    if count == 0 {
        return;
    }
    cache.insert(
        ns,
        ExtentMapping {
            logical_start,
            physical_start: 0,
            count,
            unwritten: false,
        },
    );
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_block::BlockBuf;
    use ffs_types::GroupNumber;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    struct MemBlockDevice {
        block_size: u32,
        blocks: Mutex<HashMap<u64, Vec<u8>>>,
        read_counts: Mutex<HashMap<u64, u64>>,
    }

    impl MemBlockDevice {
        fn new(block_size: u32) -> Self {
            Self {
                block_size,
                blocks: Mutex::new(HashMap::new()),
                read_counts: Mutex::new(HashMap::new()),
            }
        }

        fn clear_read_counts(&self) {
            self.read_counts.lock().clear();
        }

        fn total_reads(&self) -> u64 {
            self.read_counts.lock().values().sum()
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            *self.read_counts.lock().entry(block.0).or_insert(0) += 1;
            let blocks = self.blocks.lock();
            blocks.get(&block.0).map_or_else(
                || Ok(BlockBuf::new(vec![0u8; self.block_size as usize])),
                |data| Ok(BlockBuf::new(data.clone())),
            )
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            self.blocks.lock().insert(block.0, data.to_vec());
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
            desc_size: 32,
            reserved_gdt_blocks: 0,
            feature_compat: ffs_ondisk::Ext4CompatFeatures(0),
            feature_incompat: ffs_ondisk::Ext4IncompatFeatures(0),
            feature_ro_compat: ffs_ondisk::Ext4RoCompatFeatures(0),
            log_groups_per_flex: 0,
            backup_bgs: [0, 0],
            first_meta_bg: 0,
            first_inode: 11,
            cluster_ratio: 1,
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
                block_bitmap_csum: 0,
                inode_bitmap_csum: 0,
            })
            .collect()
    }

    fn assert_invalid_logical_range<T: std::fmt::Debug>(result: Result<T>, op: &str) {
        let err = result.expect_err("logical range past ext4 block space should fail");
        let msg = format!("{err}");
        assert!(
            matches!(err, FfsError::InvalidGeometry(_)),
            "expected InvalidGeometry, got {err:?}"
        );
        assert!(
            msg.contains(op) && msg.contains("exceeds ext4 32-bit block space"),
            "error should identify the rejected {op} logical range: {msg}"
        );
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

    fn mock_pctx() -> ffs_alloc::PersistCtx {
        ffs_alloc::PersistCtx {
            // Keep GDT writes off the group-0 block bitmap block (1) used by this fixture.
            gdt_block: BlockNumber(50),
            desc_size: 32,
            has_metadata_csum: false,
            uuid: [0; 16],
            csum_seed: 0,
            group_desc_checksum_kind: ffs_ondisk::ext4::Ext4GroupDescChecksumKind::None,
            blocks_per_group: 32768,
            inodes_per_group: 2048,
        }
    }

    fn found_extent(
        cx: &Cx,
        dev: &dyn BlockDevice,
        root: &[u8; 60],
        logical_block: u32,
    ) -> Result<Option<Ext4Extent>> {
        match ffs_btree::search(cx, dev, root, logical_block)? {
            SearchResult::Found { extent, .. } => Ok(Some(extent)),
            SearchResult::Hole { .. } => Ok(None),
        }
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

        let pctx = mock_pctx();
        let hint = AllocHint::default();
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            5,
            &hint,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

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

    #[test]
    fn representative_extent_mapping_exact_golden_contract() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let written = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            3,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        let unwritten = allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            5,
            2,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        let mappings = map_logical_to_physical(&cx, &dev, &root, 0, 9).unwrap();

        let actual = format!(
            "{written:?}\n{unwritten:?}\n{mappings:?}\n{}",
            groups[0].free_blocks
        );

        let expected = "\
ExtentMapping { logical_start: 0, physical_start: 131, count: 3, unwritten: false }
ExtentMapping { logical_start: 5, physical_start: 134, count: 2, unwritten: true }
[ExtentMapping { logical_start: 0, physical_start: 131, count: 3, unwritten: false }, ExtentMapping { logical_start: 3, physical_start: 0, count: 2, unwritten: false }, ExtentMapping { logical_start: 5, physical_start: 134, count: 2, unwritten: true }, ExtentMapping { logical_start: 7, physical_start: 0, count: 2, unwritten: false }]
8187";

        assert_eq!(actual, expected);
    }

    #[test]
    fn map_rejects_root_depth_above_ext4_limit() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut root = empty_root();
        root[2..4].copy_from_slice(&1_u16.to_le_bytes());
        root[6..8].copy_from_slice(&6_u16.to_le_bytes());

        let result = map_logical_to_physical(&cx, &dev, &root, 0, 1);
        match result.expect_err("expected Corruption for excessive root depth") {
            FfsError::Corruption { detail, .. } => {
                assert!(detail.contains("exceeds ext4 limit"));
            }
            other => assert!(
                matches!(other, FfsError::Corruption { .. }),
                "expected Corruption for excessive root depth"
            ),
        }
    }

    #[test]
    fn map_rejects_zero_length_extent_entry() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut root = empty_root();
        root[2..4].copy_from_slice(&1_u16.to_le_bytes()); // entries
        root[6..8].copy_from_slice(&0_u16.to_le_bytes()); // depth
        // first leaf extent at offset 12: logical=0, raw_len=0 (corrupt), physical=123
        root[12..16].copy_from_slice(&0_u32.to_le_bytes());
        root[16..18].copy_from_slice(&0_u16.to_le_bytes());
        root[18..20].copy_from_slice(&0_u16.to_le_bytes());
        root[20..24].copy_from_slice(&123_u32.to_le_bytes());

        let result = map_logical_to_physical(&cx, &dev, &root, 0, 1);
        match result.expect_err("expected Corruption for zero-length extent") {
            FfsError::Corruption { detail, .. } => {
                assert!(detail.contains("extent_entries.ee_len"));
                assert!(detail.contains("extent length must be non-zero"));
            }
            other => assert!(
                matches!(other, FfsError::Corruption { .. }),
                "expected Corruption for zero-length extent"
            ),
        }
    }

    #[test]
    fn map_accepts_final_logical_block() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let root = empty_root();

        let mappings = map_logical_to_physical(&cx, &dev, &root, u32::MAX, 1).unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].logical_start, u32::MAX);
        assert_eq!(mappings[0].count, 1);
        assert_eq!(mappings[0].physical_start, 0);
    }

    #[test]
    fn map_rejects_range_past_logical_block_space() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let root = empty_root();

        let result = map_logical_to_physical(&cx, &dev, &root, u32::MAX, 2);
        assert!(matches!(result, Err(FfsError::InvalidGeometry(_))));
    }

    // ── Allocate tests ──────────────────────────────────────────────────

    #[test]
    fn allocate_single_extent() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();

        let pctx = mock_pctx();
        let mapping = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
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
        let pctx = mock_pctx();

        let m1 = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
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
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(m2.logical_start, 5);
        assert_eq!(m2.count, 5);

        // Walk should find both extents.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn allocate_extent_rejects_non_leaf_root_with_zero_entries() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Non-leaf root must have at least one index entry.
        root[2..4].copy_from_slice(&0_u16.to_le_bytes());
        root[6..8].copy_from_slice(&1_u16.to_le_bytes());

        let result = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            1,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        );
        match result.expect_err("expected Corruption for invalid non-leaf root") {
            FfsError::Corruption { detail, .. } => {
                assert!(detail.contains("non-leaf extent root has zero entries"));
            }
            other => assert!(
                matches!(other, FfsError::Corruption { .. }),
                "expected Corruption for invalid non-leaf root"
            ),
        }
    }

    #[test]
    fn allocate_unwritten_extent_flag() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let mapping = allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert!(mapping.unwritten);

        // Verify via search that the extent is marked unwritten.
        let extent = found_extent(&cx, &dev, &root, 0)
            .unwrap()
            .expect("expected allocated extent");
        assert!(extent.is_unwritten());
    }

    // ── Truncate tests ──────────────────────────────────────────────────

    #[test]
    fn truncate_removes_tail() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate blocks 0-9 and 10-19.
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
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
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

        // Truncate at logical block 10 — should remove second extent.
        let freed = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 10);

        let after_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
        assert_eq!(after_free, initial_free + 10);

        // Only first extent should remain.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn truncate_to_zero_frees_all() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let freed = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 10);

        // Tree should be empty.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| {
            count += 1;
            Ok(())
        })
        .unwrap();
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
        let pctx = mock_pctx();

        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

        // Punch hole in blocks 3-6 (4 blocks).
        let freed = punch_hole(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            3,
            4,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
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
        let pctx = mock_pctx();

        let freed = punch_hole(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 0);
    }

    #[test]
    fn punch_hole_rejects_range_past_logical_block_space() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let result = punch_hole(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            u32::MAX,
            2,
            &pctx,
            ExtentOwner::default(),
        );
        assert_invalid_logical_range(result, "punch_hole");
    }

    #[test]
    fn punch_hole_splits_extent_preserving_neighbors() {
        // Allocate [0-9] and [20-29], then punch [2-4] in the first extent.
        // Expected result: [0-1] mapped, [2-4] hole, [5-9] mapped, [10-19] hole, [20-29] mapped.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            20,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let freed = punch_hole(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            2,
            3,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 3);

        let mappings = map_logical_to_physical(&cx, &dev, &root, 0, 30).unwrap();
        // First extent should be split: [0-1] mapped, then a hole, then [5-9] mapped.
        // Then [10-19] hole between the two original extents, then [20-29] mapped.
        assert!(
            mappings.len() >= 4,
            "expected at least 4 segments, got {}",
            mappings.len()
        );

        // Verify the punch-holed region is indeed a hole.
        let hole_segment = mappings
            .iter()
            .find(|m| m.logical_start <= 2 && m.logical_start + m.count > 2);
        if let Some(seg) = hole_segment {
            assert_eq!(
                seg.physical_start, 0,
                "punched region should be a hole (physical=0)"
            );
        }
    }

    // ── Mark written tests ──────────────────────────────────────────────

    #[test]
    fn mark_written_clears_unwritten_flag() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

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
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Verify unwritten.
        let extent = found_extent(&cx, &dev, &root, 0)
            .unwrap()
            .expect("expected unwritten extent");
        assert!(extent.is_unwritten());

        // Mark entire range as written.
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Verify now written.
        let extent = found_extent(&cx, &dev, &root, 0)
            .unwrap()
            .expect("expected written extent");
        assert!(!extent.is_unwritten());
    }

    #[test]
    fn mark_written_covers_final_logical_block() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            u32::MAX,
            1,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            u32::MAX,
            1,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let extent = found_extent(&cx, &dev, &root, u32::MAX)
            .unwrap()
            .expect("expected final block extent to remain searchable");
        assert_eq!(extent.logical_block, u32::MAX);
        assert_eq!(extent.actual_len(), 1);
        assert!(!extent.is_unwritten());
    }

    #[test]
    fn mark_written_rejects_range_past_logical_block_space() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let result = mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            u32::MAX,
            2,
            &pctx,
            ExtentOwner::default(),
        );
        assert!(matches!(result, Err(FfsError::InvalidGeometry(_))));
    }

    #[test]
    fn mark_written_partial_splits_extent() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

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
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Mark blocks 3-6 as written (partial range).
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            3,
            4,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Block 0 should still be unwritten.
        let extent = found_extent(&cx, &dev, &root, 0)
            .unwrap()
            .expect("expected extent at block 0");
        assert!(extent.is_unwritten());

        // Block 4 should be written.
        let extent = found_extent(&cx, &dev, &root, 4)
            .unwrap()
            .expect("expected extent at block 4");
        assert!(!extent.is_unwritten());

        // Block 8 should still be unwritten.
        let extent = found_extent(&cx, &dev, &root, 8)
            .unwrap()
            .expect("expected extent at block 8");
        assert!(extent.is_unwritten());

        // Should have 3 extents now: [0-2] unwritten, [3-6] written, [7-9] unwritten.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn allocate_zero_count_fails() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let result = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            0,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn allocate_over_max_count_fails() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Max valid extent count is 32767 (15 bits minus unwritten flag).
        let result = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            32768,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn map_hole_between_two_extents() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate blocks 0-4 and 10-14 (gap at 5-9).
        let m1 = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        let m2 = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            10,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let mappings = map_logical_to_physical(&cx, &dev, &root, 0, 15).unwrap();
        // Should be: [0-4] mapped, [5-9] hole, [10-14] mapped.
        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings[0].physical_start, m1.physical_start);
        assert_eq!(mappings[0].count, 5);
        assert_eq!(mappings[1].logical_start, 5);
        assert_eq!(mappings[1].count, 5); // hole
        assert_eq!(mappings[2].physical_start, m2.physical_start);
        assert_eq!(mappings[2].count, 5);
    }

    #[test]
    fn map_depth1_range_matches_repeated_search_and_reads_leaf_once() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        for logical in 0..100_u32 {
            allocate_extent(
                &cx,
                &dev,
                &mut root,
                &geo,
                &mut groups,
                logical,
                1,
                &AllocHint::default(),
                &pctx,
                ExtentOwner::default(),
            )
            .unwrap();
        }

        dev.clear_read_counts();
        let expected = map_logical_range_by_search(&cx, &dev, &root, 10, 50).unwrap();
        let repeated_search_reads = dev.total_reads();

        dev.clear_read_counts();
        let actual = map_logical_to_physical(&cx, &dev, &root, 10, 50).unwrap();
        let range_walk_reads = dev.total_reads();

        assert_eq!(actual, expected);
        assert_eq!(range_walk_reads, 1);
        assert!(repeated_search_reads > range_walk_reads);
    }

    #[test]
    fn truncate_empty_tree_is_noop() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let freed = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 0);
    }

    #[test]
    fn map_partial_extent_overlap() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate blocks 0-9.
        let m = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Query just blocks 3-7 (within the extent).
        let mappings = map_logical_to_physical(&cx, &dev, &root, 3, 5).unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].logical_start, 3);
        assert_eq!(mappings[0].count, 5);
        assert_eq!(mappings[0].physical_start, m.physical_start + 3);
    }

    #[test]
    fn split_for_mark_written_full_overlap() {
        // Extent [0, 10) fully within mark range [0, 10) → single written extent.
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x0A | UNWRITTEN_FLAG,
            physical_start: 100,
        };
        let out = split_for_mark_written(&ext, 0, 10_u64, 10_u64).unwrap();
        assert_eq!(out.len(), 1);
        assert!(!out[0].is_unwritten());
        assert_eq!(out[0].actual_len(), 10);
    }

    #[test]
    fn split_for_mark_written_left_unwritten() {
        // Extent [0, 10), mark [5, 10) → [0,5) unwritten + [5,10) written.
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x0A | UNWRITTEN_FLAG,
            physical_start: 100,
        };
        let out = split_for_mark_written(&ext, 5, 10_u64, 10_u64).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out[0].is_unwritten());
        assert_eq!(out[0].actual_len(), 5);
        assert_eq!(out[0].physical_start, 100);
        assert!(!out[1].is_unwritten());
        assert_eq!(out[1].actual_len(), 5);
        assert_eq!(out[1].physical_start, 105);
    }

    #[test]
    fn split_for_mark_written_right_unwritten() {
        // Extent [0, 10), mark [0, 5) → [0,5) written + [5,10) unwritten.
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x0A | UNWRITTEN_FLAG,
            physical_start: 100,
        };
        let out = split_for_mark_written(&ext, 0, 5_u64, 10_u64).unwrap();
        assert_eq!(out.len(), 2);
        assert!(!out[0].is_unwritten());
        assert_eq!(out[0].actual_len(), 5);
        assert_eq!(out[0].physical_start, 100);
        assert!(out[1].is_unwritten());
        assert_eq!(out[1].actual_len(), 5);
        assert_eq!(out[1].physical_start, 105);
    }

    #[test]
    fn split_for_mark_written_three_way() {
        // Extent [0, 10), mark [3, 7) → [0,3) unwritten + [3,7) written + [7,10) unwritten.
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x0A | UNWRITTEN_FLAG,
            physical_start: 100,
        };
        let out = split_for_mark_written(&ext, 3, 7_u64, 10_u64).unwrap();
        assert_eq!(out.len(), 3);
        assert!(out[0].is_unwritten());
        assert_eq!(out[0].logical_block, 0);
        assert_eq!(out[0].actual_len(), 3);
        assert!(!out[1].is_unwritten());
        assert_eq!(out[1].logical_block, 3);
        assert_eq!(out[1].actual_len(), 4);
        assert!(out[2].is_unwritten());
        assert_eq!(out[2].logical_block, 7);
        assert_eq!(out[2].actual_len(), 3);
    }

    #[test]
    fn split_for_mark_written_rejects_physical_overflow() {
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x14 | UNWRITTEN_FLAG,
            physical_start: u64::MAX - 4,
        };

        let err = split_for_mark_written(&ext, 5, 15_u64, 20_u64).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("physical block") && msg.contains("overflows u64"),
            "error should explain the physical address overflow: {msg}"
        );
    }

    #[test]
    fn extent_mapping_equality() {
        let a = ExtentMapping {
            logical_start: 0,
            physical_start: 100,
            count: 5,
            unwritten: false,
        };
        let b = a;
        assert_eq!(a, b);

        let c = ExtentMapping {
            unwritten: true,
            ..a
        };
        assert_ne!(a, c);
    }

    // ── Additional edge-case tests ──────────────────────────────────

    #[test]
    fn mark_written_on_already_written_is_noop() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate a regular (already-written) extent.
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // mark_written should be a no-op since the extent is already written.
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Verify the extent is still there and still written.
        let extent = found_extent(&cx, &dev, &root, 0)
            .unwrap()
            .expect("expected written extent");
        assert!(!extent.is_unwritten());
        assert_eq!(extent.actual_len(), 10);

        // Should still be exactly 1 extent.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn mark_written_on_empty_tree_is_noop() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // mark_written on empty tree should succeed with no changes.
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Tree should still be empty.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn punch_hole_in_unwritten_extent() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

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
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

        // Punch hole in blocks 3-6 within the unwritten extent.
        let freed = punch_hole(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            3,
            4,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert!(freed > 0);

        let after_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
        assert!(after_free > initial_free);

        // Blocks 0-2 should still be mapped (unwritten).
        let extent = found_extent(&cx, &dev, &root, 0)
            .unwrap()
            .expect("expected unwritten extent at block 0");
        assert!(extent.is_unwritten());

        // Blocks 3-6 should be a hole.
        let mappings = map_logical_to_physical(&cx, &dev, &root, 3, 1).unwrap();
        assert_eq!(
            mappings[0].physical_start, 0,
            "punched region in unwritten extent should be a hole"
        );
    }

    // ── Error-path tests ───────────────────────────────────────────────

    #[test]
    fn allocate_unwritten_zero_count_fails() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let result = allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            0,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        );
        assert!(
            matches!(result, Err(FfsError::Format(_))),
            "allocate_unwritten_extent with count=0 should return Format error"
        );
    }

    #[test]
    fn allocate_unwritten_over_max_count_fails() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let result = allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            32768,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        );
        assert!(
            matches!(result, Err(FfsError::Format(_))),
            "allocate_unwritten_extent with count=32768 should return Format error"
        );
    }

    #[test]
    fn allocate_extent_no_space_fails() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Mark all groups as having 0 free blocks.
        for g in &mut groups {
            g.free_blocks = 0;
        }

        let result = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        );
        assert!(
            matches!(result, Err(FfsError::NoSpace)),
            "allocate_extent with no free blocks should return NoSpace"
        );
    }

    #[test]
    fn allocate_unwritten_no_space_fails() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Mark all groups as having 0 free blocks.
        for g in &mut groups {
            g.free_blocks = 0;
        }

        let result = allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        );
        assert!(
            matches!(result, Err(FfsError::NoSpace)),
            "allocate_unwritten_extent with no free blocks should return NoSpace"
        );
    }

    // ── Multiple overlapping unwritten extents ──────────────────────────

    #[test]
    fn mark_written_across_two_unwritten_extents() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate two adjacent unwritten extents: [0-4] and [5-9].
        allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            5,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Both should be unwritten.
        let extent = found_extent(&cx, &dev, &root, 2)
            .unwrap()
            .expect("expected unwritten extent at block 2");
        assert!(extent.is_unwritten());
        let extent = found_extent(&cx, &dev, &root, 7)
            .unwrap()
            .expect("expected unwritten extent at block 7");
        assert!(extent.is_unwritten());

        // Mark blocks 3-7 as written, spanning both extents.
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            3,
            5,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Block 1 should still be unwritten (left residual of first extent).
        let extent = found_extent(&cx, &dev, &root, 1)
            .unwrap()
            .expect("expected extent at block 1");
        assert!(extent.is_unwritten(), "block 1 should remain unwritten");

        // Block 4 should now be written (was in first extent, within mark range).
        let extent = found_extent(&cx, &dev, &root, 4)
            .unwrap()
            .expect("expected extent at block 4");
        assert!(
            !extent.is_unwritten(),
            "block 4 should be written after mark_written"
        );

        // Block 6 should now be written (was in second extent, within mark range).
        let extent = found_extent(&cx, &dev, &root, 6)
            .unwrap()
            .expect("expected extent at block 6");
        assert!(
            !extent.is_unwritten(),
            "block 6 should be written after mark_written"
        );

        // Block 9 should still be unwritten (right residual of second extent).
        let extent = found_extent(&cx, &dev, &root, 9)
            .unwrap()
            .expect("expected extent at block 9");
        assert!(extent.is_unwritten(), "block 9 should remain unwritten");
    }

    #[test]
    fn mark_written_across_three_unwritten_extents() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate three adjacent unwritten extents: [0-3], [4-7], [8-11].
        for i in 0..3 {
            allocate_unwritten_extent(
                &cx,
                &dev,
                &mut root,
                &geo,
                &mut groups,
                i * 4,
                4,
                &AllocHint::default(),
                &pctx,
                ExtentOwner::default(),
            )
            .unwrap();
        }

        // Mark the entire range as written.
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            12,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // All blocks should now be written.
        for block in [0, 3, 4, 7, 8, 11] {
            let extent = found_extent(&cx, &dev, &root, block)
                .unwrap()
                .expect("expected extent after mark_written");
            assert!(
                !extent.is_unwritten(),
                "block {block} should be written after mark_written"
            );
        }
    }

    #[test]
    fn mark_written_partial_across_two_unwritten_extents() {
        // Mark a range that starts in the middle of one unwritten extent
        // and ends in the middle of another.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // [0-9] unwritten, [10-19] unwritten.
        allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            10,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Mark [7-13] as written — spans tail of first, head of second.
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            7,
            7,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Blocks 0-6: unwritten (left residual of first extent).
        let extent = found_extent(&cx, &dev, &root, 3)
            .unwrap()
            .expect("expected unwritten at block 3");
        assert!(extent.is_unwritten());

        // Blocks 7-9: written (right part of first extent, within mark range).
        let extent = found_extent(&cx, &dev, &root, 8)
            .unwrap()
            .expect("expected written at block 8");
        assert!(!extent.is_unwritten());

        // Blocks 10-13: written (left part of second extent, within mark range).
        let extent = found_extent(&cx, &dev, &root, 11)
            .unwrap()
            .expect("expected written at block 11");
        assert!(!extent.is_unwritten());

        // Blocks 14-19: unwritten (right residual of second extent).
        let extent = found_extent(&cx, &dev, &root, 16)
            .unwrap()
            .expect("expected unwritten at block 16");
        assert!(extent.is_unwritten());
    }

    // ── Lifecycle / integration tests ───────────────────────────────────

    #[test]
    fn unwritten_lifecycle_allocate_mark_truncate() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

        // Step 1: allocate unwritten extent at blocks 0-9.
        let mapping = allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert!(mapping.unwritten);

        // Step 2: mark blocks 0-4 as written.
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            5,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Verify: blocks 0-4 written, blocks 5-9 still unwritten.
        let extent = found_extent(&cx, &dev, &root, 2)
            .unwrap()
            .expect("expected written extent at block 2");
        assert!(!extent.is_unwritten());
        let extent = found_extent(&cx, &dev, &root, 7)
            .unwrap()
            .expect("expected unwritten extent at block 7");
        assert!(extent.is_unwritten());

        // Step 3: truncate at block 5 — should remove the unwritten tail.
        let freed = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            5,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 5);

        // Only the written extent [0-4] should remain.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |ext: &Ext4Extent| {
            assert!(!ext.is_unwritten());
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);

        // Step 4: truncate everything.
        let freed = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 5);

        // All blocks should be freed.
        let final_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
        assert_eq!(final_free, initial_free);
    }

    // ── Adversarial / hardening tests ─────────────────────────────────

    #[test]
    fn corrupted_root_magic_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut root = [0u8; 60];
        // Set invalid magic bytes (not 0xF30A).
        root[0] = 0xDE;
        root[1] = 0xAD;
        root[2] = 0; // entries = 0
        root[3] = 0;
        root[4] = 4; // max_entries = 4
        root[5] = 0;
        root[6] = 0; // depth = 0
        root[7] = 0;

        let result = map_logical_to_physical(&cx, &dev, &root, 0, 10);
        assert!(result.is_err(), "bad magic should fail");
    }

    #[test]
    fn all_zeros_root_returns_error() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let root = [0u8; 60];

        let result = map_logical_to_physical(&cx, &dev, &root, 0, 10);
        assert!(result.is_err(), "all-zeros root should fail (bad magic)");
    }

    #[test]
    fn allocate_max_valid_count() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // 32767 is max valid extent count (u16::MAX >> 1).
        // This will fail with NoSpace since our test geometry doesn't have enough,
        // but it should NOT fail with a Format error.
        let result = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            32767,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        );
        // Should be NoSpace (not enough blocks) or Ok, but NOT Format.
        assert!(
            !matches!(result, Err(FfsError::Format(_))),
            "32767 is a valid count, should not get Format error"
        );
    }

    #[test]
    fn punch_hole_exact_extent_boundaries() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate [0-9].
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Punch exactly the full extent.
        let freed = punch_hole(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 10);

        // Tree should be empty.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 0, "punching full extent should leave empty tree");
    }

    #[test]
    fn collapse_range_rejects_range_past_logical_block_space() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let result = collapse_range(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            u32::MAX,
            2,
            &pctx,
            ExtentOwner::default(),
        );
        assert_invalid_logical_range(result, "collapse_range");
    }

    #[test]
    fn insert_range_rejects_range_past_logical_block_space() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let result = insert_range(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            u32::MAX,
            2,
            &pctx,
            ExtentOwner::default(),
        );
        assert_invalid_logical_range(result, "insert_range");
    }

    #[test]
    fn insert_range_rejects_tail_shift_past_logical_space_without_mutation() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            u32::MAX,
            1,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        let before = map_logical_to_physical(&cx, &dev, &root, u32::MAX, 1).unwrap();

        let err = insert_range(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            1,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                FfsError::InvalidGeometry(msg)
                    if msg.contains("shifting extent ending")
                        && msg.contains("32-bit block space")
            ),
            "expected logical-space overflow, got {err:?}"
        );

        let after = map_logical_to_physical(&cx, &dev, &root, u32::MAX, 1).unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn truncate_is_idempotent() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let freed1 = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed1, 10);

        // Second truncate at same point should free 0.
        let freed2 = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed2, 0, "second truncate should be a noop");
    }

    #[test]
    fn map_beyond_any_extent_returns_pure_hole() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate blocks 0-4.
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Map far beyond any extent.
        let mappings = map_logical_to_physical(&cx, &dev, &root, 1_000_000, 100).unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].physical_start, 0, "should be a hole");
        assert_eq!(mappings[0].count, 100);
    }

    #[test]
    fn map_zero_count_returns_empty() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let root = empty_root();

        let mappings = map_logical_to_physical(&cx, &dev, &root, 0, 0).unwrap();
        assert!(mappings.is_empty(), "map with count=0 should return empty");
    }

    #[test]
    fn punch_hole_zero_count_is_noop() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let freed = punch_hole(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            5,
            0,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 0, "punch_hole with count=0 should free nothing");

        // Extent should still be a single intact extent.
        let mut count = 0;
        ffs_btree::walk(&cx, &dev, &root, &mut |_: &Ext4Extent| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1, "tree should still have exactly 1 extent");
    }

    #[test]
    fn mark_written_zero_count_is_noop() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // mark_written with count=0 should be a noop.
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            5,
            0,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Extent should still be unwritten and intact.
        let extent = found_extent(&cx, &dev, &root, 5)
            .unwrap()
            .expect("expected extent after zero-count mark_written");
        assert!(extent.is_unwritten(), "extent should remain unwritten");
        assert_eq!(extent.actual_len(), 10, "extent should remain full size");
    }

    #[test]
    fn allocate_at_high_logical_offset() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate at a very high logical offset (near u32::MAX).
        let logical = u32::MAX - 100;
        let mapping = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            logical,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(mapping.logical_start, logical);
        assert_eq!(mapping.count, 5);

        // Verify it can be looked up.
        let maps = map_logical_to_physical(&cx, &dev, &root, logical, 5).unwrap();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].logical_start, logical);
        assert_eq!(maps[0].physical_start, mapping.physical_start);
    }

    #[test]
    fn truncate_partial_extent_preserves_prefix() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate [0-19].
        let alloc = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            20,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Truncate at block 10 — should trim the extent, keeping [0-9].
        let freed = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 10, "should free 10 trailing blocks");

        // Blocks 0-9 should still be mapped.
        let maps = map_logical_to_physical(&cx, &dev, &root, 0, 10).unwrap();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].count, 10);
        assert_eq!(maps[0].physical_start, alloc.physical_start);
    }

    // ── Edge-case and error-path tests (bd-27mi) ─────────────────────

    #[test]
    fn allocate_zero_count_rejected() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();
        let err = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            0,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn allocate_count_exceeds_max_rejected() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();
        let err = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            32769,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn allocate_unwritten_zero_count_rejected() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();
        let err = allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            0,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn punch_entire_extent_frees_all() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            20,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let freed = punch_hole(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            20,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 20);

        let final_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
        assert_eq!(final_free, initial_free);

        // Tree should be empty; mapping should return a single hole.
        let maps = map_logical_to_physical(&cx, &dev, &root, 0, 20).unwrap();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].physical_start, 0, "should be a hole");
    }

    #[test]
    fn map_gap_between_extents() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate blocks 0-4 and 10-14, leaving a gap at 5-9.
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            10,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let maps = map_logical_to_physical(&cx, &dev, &root, 0, 15).unwrap();
        // Should be: [0..5 mapped] [5..10 hole] [10..15 mapped]
        assert_eq!(maps.len(), 3);
        assert_ne!(maps[0].physical_start, 0); // mapped
        assert_eq!(maps[0].count, 5);
        assert_eq!(maps[1].physical_start, 0); // hole
        assert_eq!(maps[1].logical_start, 5);
        assert_eq!(maps[1].count, 5);
        assert_ne!(maps[2].physical_start, 0); // mapped
        assert_eq!(maps[2].count, 5);
    }

    #[test]
    fn allocate_then_map_exact_range() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let alloc = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            7,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Map exactly the allocated range — should be a single mapping, no holes.
        let maps = map_logical_to_physical(&cx, &dev, &root, 0, 7).unwrap();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].logical_start, 0);
        assert_eq!(maps[0].physical_start, alloc.physical_start);
        assert_eq!(maps[0].count, 7);
        assert!(!maps[0].unwritten);
    }

    #[test]
    fn validate_root_bad_magic_returns_corruption() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let mut root = [0u8; 60]; // all zeros, bad magic

        let result = map_logical_to_physical(&cx, &dev, &root, 0, 1);
        assert!(matches!(result, Err(FfsError::Corruption { .. })));

        // Also test via allocate path.
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let result = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            1,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        );
        assert!(matches!(result, Err(FfsError::Corruption { .. })));
    }

    #[test]
    fn split_for_mark_written_left_trim() {
        // Mark range starts after extent starts — unwritten prefix + written suffix.
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x0A | UNWRITTEN_FLAG,
            physical_start: 100,
        };
        let parts = split_for_mark_written(&ext, 3, 10_u64, 10_u64).unwrap();
        assert_eq!(parts.len(), 2);
        // Prefix: unwritten [0..3)
        assert!(parts[0].is_unwritten());
        assert_eq!(parts[0].logical_block, 0);
        assert_eq!(parts[0].actual_len(), 3);
        assert_eq!(parts[0].physical_start, 100);
        // Suffix: written [3..10)
        assert!(!parts[1].is_unwritten());
        assert_eq!(parts[1].logical_block, 3);
        assert_eq!(parts[1].actual_len(), 7);
        assert_eq!(parts[1].physical_start, 103);
    }

    #[test]
    fn split_for_mark_written_right_trim() {
        // Mark range ends before extent ends — written prefix + unwritten suffix.
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x0A | UNWRITTEN_FLAG,
            physical_start: 100,
        };
        let parts = split_for_mark_written(&ext, 0, 6_u64, 10_u64).unwrap();
        assert_eq!(parts.len(), 2);
        // Prefix: written [0..6)
        assert!(!parts[0].is_unwritten());
        assert_eq!(parts[0].logical_block, 0);
        assert_eq!(parts[0].actual_len(), 6);
        assert_eq!(parts[0].physical_start, 100);
        // Suffix: unwritten [6..10)
        assert!(parts[1].is_unwritten());
        assert_eq!(parts[1].logical_block, 6);
        assert_eq!(parts[1].actual_len(), 4);
        assert_eq!(parts[1].physical_start, 106);
    }

    #[test]
    fn split_for_mark_written_middle_three_way() {
        // Extent spans mark range — unwritten + written + unwritten.
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x14 | UNWRITTEN_FLAG,
            physical_start: 200,
        };
        let parts = split_for_mark_written(&ext, 5, 15_u64, 20_u64).unwrap();
        assert_eq!(parts.len(), 3);
        // Left: unwritten [0..5)
        assert!(parts[0].is_unwritten());
        assert_eq!(parts[0].logical_block, 0);
        assert_eq!(parts[0].actual_len(), 5);
        assert_eq!(parts[0].physical_start, 200);
        // Middle: written [5..15)
        assert!(!parts[1].is_unwritten());
        assert_eq!(parts[1].logical_block, 5);
        assert_eq!(parts[1].actual_len(), 10);
        assert_eq!(parts[1].physical_start, 205);
        // Right: unwritten [15..20)
        assert!(parts[2].is_unwritten());
        assert_eq!(parts[2].logical_block, 15);
        assert_eq!(parts[2].actual_len(), 5);
        assert_eq!(parts[2].physical_start, 215);
    }

    #[test]
    fn extent_mapping_debug_clone_eq() {
        let m = ExtentMapping {
            logical_start: 0,
            physical_start: 100,
            count: 10,
            unwritten: false,
        };
        let m2 = m;
        assert_eq!(m, m2);
        let _ = format!("{m:?}");
    }

    #[test]
    fn mark_written_on_already_written_extent_is_noop() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Allocate a normal (written) extent.
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // mark_written on a written extent should succeed without changing anything.
        mark_written(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let maps = map_logical_to_physical(&cx, &dev, &root, 0, 10).unwrap();
        assert_eq!(maps.len(), 1);
        assert!(!maps[0].unwritten);
        assert_eq!(maps[0].count, 10);
    }

    #[test]
    fn allocate_at_nonzero_logical_offset() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let m = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            100,
            5,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(m.logical_start, 100);
        assert_eq!(m.count, 5);

        // Map range [0,105): should have hole [0,100) + extent [100,105).
        let maps = map_logical_to_physical(&cx, &dev, &root, 0, 105).unwrap();
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0].physical_start, 0); // hole
        assert_eq!(maps[0].count, 100);
        assert_ne!(maps[1].physical_start, 0); // extent
        assert_eq!(maps[1].logical_start, 100);
        assert_eq!(maps[1].count, 5);
    }

    #[test]
    fn truncate_partial_extent_midway() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            20,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Truncate at block 10 — should free the second half.
        let freed = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert!(freed > 0);

        // Only blocks 0-9 should remain mapped.
        let maps = map_logical_to_physical(&cx, &dev, &root, 0, 20).unwrap();
        let mapped_total: u32 = maps
            .iter()
            .filter(|m| m.physical_start != 0)
            .map(|m| m.count)
            .sum();
        assert_eq!(mapped_total, 10);
    }

    // ── Hardening edge-case tests ────────────────────────────────────

    #[test]
    fn unwritten_flag_is_bit_15() {
        assert_eq!(UNWRITTEN_FLAG, 0x8000);
        assert_eq!(UNWRITTEN_FLAG, 1_u16 << 15);
    }

    #[test]
    fn encode_unwritten_len_rejects_written_boundary() {
        let err = encode_unwritten_len("test", u64::from(EXT_INIT_MAX_LEN)).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("32767"),
            "error should explain the unwritten extent limit: {msg}"
        );
    }

    #[test]
    fn encode_split_extent_len_preserves_written_boundary() {
        let raw_len = encode_split_extent_len("test", u32::from(EXT_INIT_MAX_LEN), false).unwrap();
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len,
            physical_start: 100,
        };

        assert_eq!(raw_len, EXT_INIT_MAX_LEN);
        assert_eq!(ext.actual_len(), EXT_INIT_MAX_LEN);
        assert!(!ext.is_unwritten());
    }

    #[test]
    fn encode_split_extent_len_preserves_unwritten_lengths() {
        let raw_len = encode_split_extent_len("test", 1, true).unwrap();
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len,
            physical_start: 100,
        };

        assert!(raw_len > EXT_INIT_MAX_LEN);
        assert_eq!(ext.actual_len(), 1);
        assert!(ext.is_unwritten());
    }

    #[test]
    fn encode_split_extent_len_rejects_unwritten_boundary() {
        let err = encode_split_extent_len("test", u32::from(EXT_INIT_MAX_LEN), true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("32767"),
            "error should explain the unwritten extent limit: {msg}"
        );
    }

    #[test]
    fn max_extent_tree_depth_is_five() {
        assert_eq!(MAX_EXTENT_TREE_DEPTH, 5);
    }

    #[test]
    fn validate_root_header_accepts_depth_at_limit() {
        // Depth = 5 (MAX_EXTENT_TREE_DEPTH), entries = 1 → should pass validation.
        let mut root = [0u8; 60];
        root[0] = 0x0A; // magic low
        root[1] = 0xF3; // magic high
        root[2] = 1; // entries = 1 (must be > 0 for depth > 0)
        root[3] = 0;
        root[4] = 4; // max_entries = 4
        root[5] = 0;
        root[6] = 5; // depth = 5 (at limit)
        root[7] = 0;
        assert!(validate_root_header("test", &root).is_ok());
    }

    #[test]
    fn validate_root_header_rejects_depth_just_above_limit() {
        let mut root = [0u8; 60];
        root[0] = 0x0A;
        root[1] = 0xF3;
        root[2] = 1; // entries = 1
        root[3] = 0;
        root[4] = 4;
        root[5] = 0;
        root[6] = 6; // depth = 6, one above limit
        root[7] = 0;
        let err = validate_root_header("test", &root).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("depth"), "error should mention depth: {msg}");
    }

    #[test]
    fn validate_root_header_rejects_non_leaf_zero_entries() {
        let mut root = [0u8; 60];
        root[0] = 0x0A;
        root[1] = 0xF3;
        root[2] = 0; // entries = 0
        root[3] = 0;
        root[4] = 4;
        root[5] = 0;
        root[6] = 1; // depth = 1 (non-leaf)
        root[7] = 0;
        let err = validate_root_header("test", &root).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("zero entries"),
            "error should mention zero entries: {msg}"
        );
    }

    #[test]
    fn split_single_block_fully_within() {
        // Single-block extent [10, 11), mark [10, 11) → 1 written extent.
        let ext = Ext4Extent {
            logical_block: 10,
            raw_len: 1 | UNWRITTEN_FLAG,
            physical_start: 500,
        };
        let out = split_for_mark_written(&ext, 10, 11_u64, 11_u64).unwrap();
        assert_eq!(out.len(), 1);
        assert!(!out[0].is_unwritten());
        assert_eq!(out[0].actual_len(), 1);
        assert_eq!(out[0].logical_block, 10);
        assert_eq!(out[0].physical_start, 500);
    }

    #[test]
    fn split_single_block_left_trim() {
        // Extent [10, 11), mark [9, 11) → fully within (ext starts at mark_start boundary).
        // ext.logical_block (10) >= mark_start (9) && ext_end (11) <= mark_end (11)
        let ext = Ext4Extent {
            logical_block: 10,
            raw_len: 1 | UNWRITTEN_FLAG,
            physical_start: 500,
        };
        let out = split_for_mark_written(&ext, 9, 11_u64, 11_u64).unwrap();
        assert_eq!(out.len(), 1);
        assert!(!out[0].is_unwritten());
    }

    #[test]
    fn split_preserves_total_physical_span() {
        // Extent [0, 20), mark [5, 15) → three-way split.
        // Total physical blocks across all parts must equal original.
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x0014 | UNWRITTEN_FLAG,
            physical_start: 1000,
        };
        let parts = split_for_mark_written(&ext, 5, 15_u64, 20_u64).unwrap();
        assert_eq!(parts.len(), 3);
        let total_len: u16 = parts.iter().map(|p| p.actual_len()).sum();
        assert_eq!(total_len, 20);
        // Physical addresses are contiguous.
        assert_eq!(parts[0].physical_start, 1000);
        assert_eq!(parts[1].physical_start, 1005);
        assert_eq!(parts[2].physical_start, 1015);
    }

    #[test]
    fn split_two_block_extent_left_right() {
        // Extent [0, 2), mark [0, 1) → [0,1) written + [1,2) unwritten.
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 2 | UNWRITTEN_FLAG,
            physical_start: 300,
        };
        let out = split_for_mark_written(&ext, 0, 1_u64, 2_u64).unwrap();
        assert_eq!(out.len(), 2);
        assert!(!out[0].is_unwritten());
        assert_eq!(out[0].actual_len(), 1);
        assert_eq!(out[0].physical_start, 300);
        assert!(out[1].is_unwritten());
        assert_eq!(out[1].actual_len(), 1);
        assert_eq!(out[1].physical_start, 301);
    }

    #[test]
    fn extent_mapping_copy_semantics() {
        let m = ExtentMapping {
            logical_start: 42,
            physical_start: 999,
            count: 7,
            unwritten: true,
        };
        let copy = m; // Copy
        assert_eq!(m, copy);
        // Modify through binding — original is unaffected (Copy, not move).
        let mut modified = m;
        modified.count = 0;
        assert_ne!(m, modified);
        assert_eq!(m.count, 7);
    }

    #[test]
    fn extent_mapping_ne_on_each_field() {
        let base = ExtentMapping {
            logical_start: 0,
            physical_start: 100,
            count: 10,
            unwritten: false,
        };
        assert_ne!(
            base,
            ExtentMapping {
                logical_start: 1,
                ..base
            }
        );
        assert_ne!(
            base,
            ExtentMapping {
                physical_start: 101,
                ..base
            }
        );
        assert_ne!(base, ExtentMapping { count: 11, ..base });
        assert_ne!(
            base,
            ExtentMapping {
                unwritten: true,
                ..base
            }
        );
    }

    #[test]
    fn group_block_allocator_alloc_and_free() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();

        let mut alloc = GroupBlockAllocator {
            cx: &cx,
            dev: &dev,
            geo: &geo,
            groups: &mut groups,
            hint: AllocHint::default(),
            pctx: &pctx,
            ino: 0,
            generation: 0,
        };

        let blk = alloc.alloc_block(&cx).unwrap();
        assert!(blk.0 < geo.total_blocks, "allocated block within device");
        // Free it — should not error.
        alloc.free_block(&cx, blk).unwrap();
    }

    #[test]
    fn group_block_allocator_hint_advances_after_alloc() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();

        let mut alloc = GroupBlockAllocator {
            cx: &cx,
            dev: &dev,
            geo: &geo,
            groups: &mut groups,
            hint: AllocHint::default(),
            pctx: &pctx,
            ino: 0,
            generation: 0,
        };

        let blk1 = alloc.alloc_block(&cx).unwrap();
        // After alloc, hint goal_block should be blk1 + 1.
        assert_eq!(alloc.hint.goal_block, Some(BlockNumber(blk1.0 + 1)));
    }

    #[test]
    fn allocate_extent_count_boundary_32768() {
        // Maximum valid count for regular extent is 32768.
        // Cannot test actual allocation of 32768 blocks (insufficient space in test fixture)
        // but can verify that 32769 is rejected.
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        let err = allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            32769,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("32768"), "error should mention limit: {msg}");
    }

    #[test]
    fn allocate_unwritten_extent_count_boundary() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // 32768 should be rejected for unwritten too.
        let err = allocate_unwritten_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            32768,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("32767"), "error should mention limit: {msg}");
    }

    #[test]
    fn map_large_range_produces_single_hole() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let root = empty_root();
        // Map 10000 blocks from empty tree → single contiguous hole.
        let maps = map_logical_to_physical(&cx, &dev, &root, 0, 10_000).unwrap();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].physical_start, 0);
        assert_eq!(maps[0].count, 10_000);
    }

    #[test]
    fn truncate_at_exact_extent_end_frees_nothing() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        // Truncate at logical 10 (extent covers [0, 10)) — nothing to free.
        let freed = truncate_extents(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            10,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
        assert_eq!(freed, 0);

        // All 10 blocks still mapped.
        let maps = map_logical_to_physical(&cx, &dev, &root, 0, 10).unwrap();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].count, 10);
    }

    // ── Proptest property-based tests ─────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// split_for_mark_written output covers all logical blocks of input.
        #[test]
        fn proptest_split_total_blocks_preserved(
            logical_block in 0_u32..1000,
            actual_len in 1_u16..100,
            physical_start in 1_u64..100_000,
            mark_offset in 0_u32..200,
            mark_len in 1_u32..200,
        ) {
            let ext_end = logical_block.saturating_add(u32::from(actual_len));
            let mark_start = logical_block.saturating_add(mark_offset % u32::from(actual_len));
            let mark_end = mark_start.saturating_add(mark_len).min(ext_end + 50);

            // Only test when mark range overlaps the extent.
            prop_assume!(mark_start < ext_end && mark_end > logical_block && mark_end > mark_start);

            let ext = Ext4Extent {
                logical_block,
                raw_len: actual_len | UNWRITTEN_FLAG,
                physical_start,
            };

            let parts =
                split_for_mark_written(&ext, mark_start, mark_end, ext_end).unwrap();
            prop_assert!(!parts.is_empty(), "split should produce at least one extent");

            // Total actual_len of output should equal input actual_len.
            let total_out: u32 = parts.iter().map(|p| u32::from(p.actual_len())).sum();
            prop_assert_eq!(total_out, u32::from(actual_len));
        }

        /// split_for_mark_written output is contiguous and starts at the same logical block.
        #[test]
        fn proptest_split_contiguous_and_aligned(
            logical_block in 0_u32..1000,
            actual_len in 1_u16..100,
            physical_start in 1_u64..100_000,
            mark_offset in 0_u32..200,
            mark_len in 1_u32..200,
        ) {
            let ext_end = logical_block.saturating_add(u32::from(actual_len));
            let mark_start = logical_block.saturating_add(mark_offset % u32::from(actual_len));
            let mark_end = mark_start.saturating_add(mark_len).min(ext_end + 50);
            prop_assume!(mark_start < ext_end && mark_end > logical_block && mark_end > mark_start);

            let ext = Ext4Extent {
                logical_block,
                raw_len: actual_len | UNWRITTEN_FLAG,
                physical_start,
            };

            let parts =
                split_for_mark_written(&ext, mark_start, mark_end, ext_end).unwrap();

            // First part starts at the original logical_block.
            prop_assert_eq!(parts[0].logical_block, logical_block);

            // Parts are contiguous.
            for i in 1..parts.len() {
                let prev_end = parts[i - 1].logical_block + u32::from(parts[i - 1].actual_len());
                prop_assert_eq!(parts[i].logical_block, prev_end);
            }
        }

        /// split_for_mark_written physical addresses are monotonically increasing.
        #[test]
        fn proptest_split_physical_monotonic(
            logical_block in 0_u32..1000,
            actual_len in 1_u16..100,
            physical_start in 1_u64..100_000,
            mark_offset in 0_u32..200,
            mark_len in 1_u32..200,
        ) {
            let ext_end = logical_block.saturating_add(u32::from(actual_len));
            let mark_start = logical_block.saturating_add(mark_offset % u32::from(actual_len));
            let mark_end = mark_start.saturating_add(mark_len).min(ext_end + 50);
            prop_assume!(mark_start < ext_end && mark_end > logical_block && mark_end > mark_start);

            let ext = Ext4Extent {
                logical_block,
                raw_len: actual_len | UNWRITTEN_FLAG,
                physical_start,
            };

            let parts =
                split_for_mark_written(&ext, mark_start, mark_end, ext_end).unwrap();

            // First part starts at the same physical_start.
            prop_assert_eq!(parts[0].physical_start, physical_start);

            // Physical starts are strictly increasing.
            for i in 1..parts.len() {
                prop_assert!(
                    parts[i].physical_start > parts[i - 1].physical_start,
                    "physical_start must be monotonically increasing"
                );
            }
        }

        /// allocate then map: mapping covers the allocated extent with correct physical address.
        #[test]
        fn proptest_allocate_map_roundtrip(
            logical_start in 0_u32..100,
            count in 1_u32..50,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let alloc = allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                logical_start, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            prop_assert_eq!(alloc.logical_start, logical_start);
            prop_assert_eq!(alloc.count, count);

            let maps = map_logical_to_physical(
                &cx, &dev, &root, logical_start, count.into(),
            ).unwrap();

            // Total mapped blocks should equal count.
            let total: u32 = maps.iter().map(|m| m.count).sum();
            prop_assert_eq!(total, count);

            // All mapped blocks should point to the allocated physical range.
            prop_assert_eq!(maps.len(), 1, "single allocation should yield single mapping");
            prop_assert_eq!(maps[0].physical_start, alloc.physical_start);
            prop_assert_eq!(maps[0].count, count);
        }

        /// allocate then truncate: all blocks freed.
        #[test]
        fn proptest_allocate_truncate_frees_all(
            count in 1_u32..50,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

            allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            let freed = truncate_extents(
                &cx, &dev, &mut root, &geo, &mut groups, 0, &pctx,
                ExtentOwner::default(),
            ).unwrap();

            prop_assert_eq!(freed, u64::from(count));

            let final_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
            prop_assert_eq!(final_free, initial_free);
        }

        /// punch_hole is idempotent: second punch frees zero blocks.
        #[test]
        fn proptest_punch_hole_idempotent(
            count in 1_u32..50,
            hole_offset in 0_u32..50,
            hole_len in 1_u32..50,
        ) {
            prop_assume!(hole_offset < count);
            let actual_hole_len = hole_len.min(count - hole_offset);

            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            let freed1 = punch_hole(
                &cx, &dev, &mut root, &geo, &mut groups,
                hole_offset, actual_hole_len.into(), &pctx,
                ExtentOwner::default(),
            ).unwrap();
            prop_assert_eq!(freed1, u64::from(actual_hole_len));

            let freed2 = punch_hole(
                &cx, &dev, &mut root, &geo, &mut groups,
                hole_offset, actual_hole_len.into(), &pctx,
                ExtentOwner::default(),
            ).unwrap();
            prop_assert_eq!(freed2, 0_u64, "second punch of same range should free 0 blocks");
        }

        /// map_logical_to_physical always covers the full requested range.
        #[test]
        fn proptest_map_covers_full_range(
            count in 1_u32..50,
            map_start in 0_u32..100,
            map_count in 1_u32..100,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            // Allocate some blocks at the beginning.
            allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            let maps = map_logical_to_physical(
                &cx, &dev, &root, map_start, map_count.into(),
            ).unwrap();

            // Total mapped blocks (data + holes) must equal the requested count.
            let total: u32 = maps.iter().map(|m| m.count).sum();
            prop_assert_eq!(total, map_count, "total mapped blocks must equal requested count");

            // Mappings must be contiguous and start at map_start.
            if !maps.is_empty() {
                prop_assert_eq!(maps[0].logical_start, map_start);
                for i in 1..maps.len() {
                    let prev_end = maps[i - 1].logical_start + maps[i - 1].count;
                    prop_assert_eq!(maps[i].logical_start, prev_end);
                }
            }
        }

        /// Multiple allocations at different offsets produce non-overlapping physical ranges.
        #[test]
        fn proptest_multi_alloc_no_physical_overlap(
            count_a in 1_u32..20,
            count_b in 1_u32..20,
            gap in 0_u32..30,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let alloc_a = allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count_a,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            let logical_b = count_a + gap;
            let alloc_b = allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                logical_b, count_b,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            // Physical ranges must not overlap.
            let a_end = alloc_a.physical_start + u64::from(alloc_a.count);
            let b_end = alloc_b.physical_start + u64::from(alloc_b.count);
            prop_assert!(
                a_end <= alloc_b.physical_start || b_end <= alloc_a.physical_start,
                "physical ranges must not overlap: A=[{}..{}), B=[{}..{})",
                alloc_a.physical_start, a_end, alloc_b.physical_start, b_end,
            );

            // Mapping the full range should show both extents and any hole between.
            let total_logical = logical_b + count_b;
            let maps = map_logical_to_physical(
                &cx, &dev, &root, 0, total_logical.into(),
            ).unwrap();
            let total_mapped: u32 = maps.iter().map(|m| m.count).sum();
            prop_assert_eq!(total_mapped, total_logical);
        }

        /// Punch hole preserves remaining extent mappings.
        #[test]
        fn proptest_punch_hole_preserves_remaining(
            count in 5_u32..50,
            hole_offset in 1_u32..49,
            hole_len in 1_u32..10,
        ) {
            prop_assume!(hole_offset < count);
            let actual_hole = hole_len.min(count - hole_offset);
            // Ensure there are blocks remaining before the hole.
            prop_assume!(hole_offset > 0);

            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let alloc = allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            punch_hole(
                &cx, &dev, &mut root, &geo, &mut groups,
                hole_offset, actual_hole.into(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            // Blocks before hole should still map to original physical range.
            let pre_maps = map_logical_to_physical(
                &cx, &dev, &root, 0, hole_offset.into(),
            ).unwrap();
            let pre_total: u32 = pre_maps.iter()
                .filter(|m| m.physical_start != 0)
                .map(|m| m.count)
                .sum();
            prop_assert_eq!(
                pre_total, hole_offset,
                "blocks before hole should still be mapped"
            );
            // Physical address should match original allocation.
            prop_assert_eq!(
                pre_maps[0].physical_start, alloc.physical_start,
                "physical address before hole should be unchanged"
            );
        }

        /// Unwritten allocation produces mappings with unwritten flag set.
        #[test]
        fn proptest_unwritten_alloc_flag(
            count in 1_u32..50,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let alloc = allocate_unwritten_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            prop_assert!(alloc.unwritten, "allocate_unwritten_extent must set unwritten=true");

            let maps = map_logical_to_physical(
                &cx, &dev, &root, 0, count.into(),
            ).unwrap();
            prop_assert_eq!(maps.len(), 1);
            prop_assert!(maps[0].unwritten, "mapping of unwritten extent must report unwritten=true");
            prop_assert_eq!(maps[0].physical_start, alloc.physical_start);
        }

        /// mark_written preserves physical addresses and clears unwritten flag.
        #[test]
        fn proptest_mark_written_preserves_physical(
            count in 1_u32..30,
            mark_offset in 0_u32..30,
            mark_len in 1_u32..30,
        ) {
            prop_assume!(mark_offset < count);
            let actual_mark = mark_len.min(count - mark_offset);

            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let alloc = allocate_unwritten_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            mark_written(
                &cx, &dev, &mut root, &geo, &mut groups,
                mark_offset, actual_mark, &pctx,
                ExtentOwner::default(),
            ).unwrap();

            // Map the full range and verify physical addresses are preserved.
            let maps = map_logical_to_physical(
                &cx, &dev, &root, 0, count.into(),
            ).unwrap();

            // All physical addresses should reference the same physical region.
            for m in &maps {
                if m.physical_start != 0 {
                    let expected_phys = alloc.physical_start + u64::from(m.logical_start);
                    prop_assert_eq!(
                        m.physical_start, expected_phys,
                        "physical address at logical {} should be {}",
                        m.logical_start, expected_phys,
                    );
                }
            }

            // Blocks in [mark_offset, mark_offset + actual_mark) should be written.
            let mark_end = mark_offset + actual_mark;
            for m in &maps {
                let m_end = m.logical_start + m.count;
                if m.logical_start >= mark_offset && m_end <= mark_end {
                    prop_assert!(
                        !m.unwritten,
                        "blocks [{}, {}) should be written",
                        m.logical_start, m_end,
                    );
                }
            }

            // Total mapped must equal count (full coverage).
            let total: u32 = maps.iter().map(|m| m.count).sum();
            prop_assert_eq!(total, count);
        }

        /// split_for_mark_written never produces zero-length extents.
        #[test]
        fn proptest_split_no_zero_length(
            logical_block in 0_u32..1000,
            actual_len in 1_u16..100,
            physical_start in 1_u64..100_000,
            mark_offset in 0_u32..200,
            mark_len in 1_u32..200,
        ) {
            let ext_end = logical_block.saturating_add(u32::from(actual_len));
            let mark_start = logical_block.saturating_add(mark_offset % u32::from(actual_len));
            let mark_end = mark_start.saturating_add(mark_len).min(ext_end + 50);
            prop_assume!(mark_start < ext_end && mark_end > logical_block && mark_end > mark_start);

            let ext = Ext4Extent {
                logical_block,
                raw_len: actual_len | UNWRITTEN_FLAG,
                physical_start,
            };

            let parts =
                split_for_mark_written(&ext, mark_start, mark_end, ext_end).unwrap();
            for (i, part) in parts.iter().enumerate() {
                prop_assert!(
                    part.actual_len() > 0,
                    "part {} has zero actual_len: {:?}", i, part,
                );
            }
        }

        /// split_for_mark_written: parts in the mark range have unwritten flag cleared;
        /// parts outside the mark range retain it.
        #[test]
        fn proptest_split_flag_correctness(
            logical_block in 0_u32..1000,
            actual_len in 2_u16..100,
            physical_start in 1_u64..100_000,
            mark_offset in 0_u32..200,
            mark_len in 1_u32..200,
        ) {
            let ext_end = logical_block.saturating_add(u32::from(actual_len));
            let mark_start = logical_block.saturating_add(mark_offset % u32::from(actual_len));
            let mark_end = mark_start.saturating_add(mark_len).min(ext_end + 50);
            prop_assume!(mark_start < ext_end && mark_end > logical_block && mark_end > mark_start);

            let ext = Ext4Extent {
                logical_block,
                raw_len: actual_len | UNWRITTEN_FLAG,
                physical_start,
            };

            let parts =
                split_for_mark_written(&ext, mark_start, mark_end, ext_end).unwrap();

            for part in &parts {
                let p_end = part.logical_block + u32::from(part.actual_len());
                // Parts fully inside mark range should be written (no unwritten flag).
                if part.logical_block >= mark_start && p_end <= mark_end {
                    prop_assert!(
                        !part.is_unwritten(),
                        "part [{}, {}) is inside mark range [{}, {}) but has unwritten flag",
                        part.logical_block, p_end, mark_start, mark_end,
                    );
                }
                // Parts fully outside mark range should be unwritten.
                if p_end <= mark_start || part.logical_block >= mark_end {
                    prop_assert!(
                        part.is_unwritten(),
                        "part [{}, {}) is outside mark range [{}, {}) but lacks unwritten flag",
                        part.logical_block, p_end, mark_start, mark_end,
                    );
                }
            }
        }

        /// Block conservation: allocate → punch → total free count is consistent.
        #[test]
        fn proptest_block_conservation_alloc_punch(
            count in 1_u32..50,
            hole_offset in 0_u32..50,
            hole_len in 1_u32..50,
        ) {
            prop_assume!(hole_offset < count);
            let actual_hole = hole_len.min(count - hole_offset);

            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let initial_free: u32 = groups.iter().map(|g| g.free_blocks).sum();

            allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            let after_alloc_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
            prop_assert_eq!(
                after_alloc_free, initial_free - count,
                "free count after alloc"
            );

            let freed = punch_hole(
                &cx, &dev, &mut root, &geo, &mut groups,
                hole_offset, actual_hole.into(), &pctx,
                ExtentOwner::default(),
            ).unwrap();
            prop_assert_eq!(freed, u64::from(actual_hole));

            let after_punch_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
            prop_assert_eq!(
                after_punch_free, initial_free - count + actual_hole,
                "free count after punch: should recover punched blocks"
            );

            // Now truncate everything to free remaining.
            let freed2 = truncate_extents(
                &cx, &dev, &mut root, &geo, &mut groups, 0, &pctx,
                ExtentOwner::default(),
            ).unwrap();
            prop_assert_eq!(
                freed2, u64::from(count - actual_hole),
                "truncate should free remaining blocks"
            );

            let final_free: u32 = groups.iter().map(|g| g.free_blocks).sum();
            prop_assert_eq!(final_free, initial_free, "all blocks should be recovered");
        }

        /// Invariant: mapping a sub-range of an allocated extent returns correct physical offsets.
        ///
        /// After allocating [0, count), mapping [start, start+len) within that range
        /// should produce physical addresses offset from the original allocation base.
        #[test]
        fn proptest_map_subrange_correct_physical_offsets(
            count in 2_u32..60,
            sub_start_frac in 0_u32..100,
            sub_len_frac in 1_u32..100,
        ) {
            let sub_start = sub_start_frac % count;
            let max_len = count - sub_start;
            let sub_len = 1 + (sub_len_frac % max_len);

            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let alloc = allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            // Map sub-range and check physical addresses.
            let maps = map_logical_to_physical(&cx, &dev, &root, sub_start, sub_len.into()).unwrap();
            let total: u32 = maps.iter().map(|m| m.count).sum();
            prop_assert_eq!(total, sub_len, "sub-range should cover requested count");

            for m in &maps {
                if m.physical_start != 0 {
                    let expected = alloc.physical_start + u64::from(m.logical_start);
                    prop_assert_eq!(
                        m.physical_start, expected,
                        "physical offset at logical {} should be base + offset",
                        m.logical_start,
                    );
                }
            }
        }

        /// Invariant: truncate at a partial offset frees only the tail.
        ///
        /// After allocating [0, count), truncating at `cut` should free
        /// exactly `count - cut` blocks and leave [0, cut) intact.
        #[test]
        fn proptest_truncate_partial_preserves_head(
            count in 2_u32..60,
            cut_frac in 1_u32..100,
        ) {
            let cut = 1 + (cut_frac % (count - 1)); // 1..count-1 inclusive
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let alloc = allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            let freed = truncate_extents(
                &cx, &dev, &mut root, &geo, &mut groups, cut, &pctx,
                ExtentOwner::default(),
            ).unwrap();
            prop_assert_eq!(freed, u64::from(count - cut), "freed block count");

            // Head should still map correctly.
            let maps = map_logical_to_physical(&cx, &dev, &root, 0, cut.into()).unwrap();
            let mapped: u32 = maps.iter().filter(|m| m.physical_start != 0).map(|m| m.count).sum();
            prop_assert_eq!(mapped, cut, "head blocks should survive truncation");
            prop_assert_eq!(maps[0].physical_start, alloc.physical_start);

            // Tail should be holes.
            let tail = map_logical_to_physical(&cx, &dev, &root, cut, 1_u64).unwrap();
            prop_assert_eq!(tail[0].physical_start, 0, "truncated block should be hole");
        }

        /// Invariant: mark_written is idempotent on already-written extents.
        ///
        /// Marking the same range written twice should produce identical mappings.
        #[test]
        fn proptest_mark_written_idempotent(
            count in 1_u32..30,
            mark_offset in 0_u32..30,
            mark_len in 1_u32..30,
        ) {
            prop_assume!(mark_offset < count);
            let actual_mark = mark_len.min(count - mark_offset);

            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            allocate_unwritten_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            // First mark_written.
            mark_written(
                &cx, &dev, &mut root, &geo, &mut groups,
                mark_offset, actual_mark, &pctx,
                ExtentOwner::default(),
            ).unwrap();
            let maps1 = map_logical_to_physical(&cx, &dev, &root, 0, count.into()).unwrap();

            // Second mark_written on the same range.
            mark_written(
                &cx, &dev, &mut root, &geo, &mut groups,
                mark_offset, actual_mark, &pctx,
                ExtentOwner::default(),
            ).unwrap();
            let maps2 = map_logical_to_physical(&cx, &dev, &root, 0, count.into()).unwrap();

            prop_assert_eq!(maps1.len(), maps2.len(), "idempotent: same number of mappings");
            for (a, b) in maps1.iter().zip(maps2.iter()) {
                prop_assert_eq!(a, b, "idempotent: mapping should be identical");
            }
        }

        /// Invariant: two disjoint allocations have non-overlapping physical ranges.
        ///
        /// Allocating at two non-overlapping logical ranges should yield
        /// physical ranges that do not intersect.
        #[test]
        fn proptest_disjoint_allocs_non_overlapping_physical(
            count_a in 1_u32..30,
            gap in 0_u32..20,
            count_b in 1_u32..30,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let a = allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count_a,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            let b_offset = count_a + gap;
            let b = allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                b_offset, count_b,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            let a_end = a.physical_start + u64::from(count_a);
            let b_end = b.physical_start + u64::from(count_b);

            // Physical ranges must not overlap.
            prop_assert!(
                a_end <= b.physical_start || b_end <= a.physical_start,
                "physical ranges [{}, {}) and [{}, {}) overlap",
                a.physical_start, a_end, b.physical_start, b_end,
            );
        }

        /// Invariant: punch_hole creates a proper hole visible via map.
        ///
        /// After allocating [0, count), punching [hole_offset, hole_end) should
        /// make those blocks appear as holes (physical_start == 0) while the
        /// surviving prefix remains correctly mapped.
        #[test]
        fn proptest_punch_creates_visible_hole(
            count in 4_u32..40,
            hole_offset in 1_u32..39,
            hole_len in 1_u32..10,
        ) {
            prop_assume!(hole_offset < count);
            let actual_hole = hole_len.min(count - hole_offset);
            prop_assume!(actual_hole > 0);

            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let mut root = empty_root();
            let pctx = mock_pctx();

            let orig = allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                0, count,
                &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            punch_hole(
                &cx, &dev, &mut root, &geo, &mut groups,
                hole_offset, actual_hole.into(), &pctx,
                ExtentOwner::default(),
            ).unwrap();

            // Map the full range.
            let maps = map_logical_to_physical(&cx, &dev, &root, 0, count.into()).unwrap();

            // Prefix [0, hole_offset) should still be physically mapped.
            let prefix_mapped: u32 = maps.iter()
                .filter(|m| m.logical_start < hole_offset && m.physical_start != 0)
                .map(|m| {
                    let m_end = m.logical_start + m.count;
                    let effective_end = m_end.min(hole_offset);
                    effective_end - m.logical_start
                })
                .sum();
            prop_assert_eq!(prefix_mapped, hole_offset, "prefix should survive punch");
            prop_assert_eq!(maps[0].physical_start, orig.physical_start, "prefix physical unchanged");

            // Hole region should have physical_start == 0.
            let hole_end = hole_offset + actual_hole;
            for m in &maps {
                let m_end = m.logical_start + m.count;
                // If this mapping is entirely within the hole range:
                if m.logical_start >= hole_offset && m_end <= hole_end {
                    prop_assert_eq!(
                        m.physical_start, 0,
                        "block [{}, {}) in hole should have physical=0",
                        m.logical_start, m_end,
                    );
                }
            }
        }

        /// Invariant: split produces at most 3 extents for any overlap pattern.
        ///
        /// The `split_for_mark_written` function should produce exactly 1, 2, or 3
        /// extents depending on the overlap pattern. Never 0 or more than 3.
        #[test]
        fn proptest_split_produces_1_to_3_extents(
            logical_block in 0_u32..500,
            actual_len in 1_u16..100,
            physical_start in 1_u64..100_000,
            mark_offset in 0_u32..200,
            mark_len in 1_u32..200,
        ) {
            let ext_end = logical_block.saturating_add(u32::from(actual_len));
            let mark_start = logical_block.saturating_add(mark_offset % u32::from(actual_len));
            let mark_end = mark_start.saturating_add(mark_len).min(ext_end + 50);
            prop_assume!(mark_start < ext_end && mark_end > logical_block && mark_end > mark_start);

            let ext = Ext4Extent {
                logical_block,
                raw_len: actual_len | UNWRITTEN_FLAG,
                physical_start,
            };

            let parts =
                split_for_mark_written(&ext, mark_start, mark_end, ext_end).unwrap();
            prop_assert!(
                (1..=3).contains(&parts.len()),
                "split produced {} extents (expected 1-3)",
                parts.len(),
            );
        }

        // ── ExtentCache metamorphic relations (bd-upa13) ──────────────

        /// MR-1 — Insert/lookup roundtrip: after `insert(ns, m)` for a
        /// mapping with `count >= 1`, `lookup(ns, m.logical_start)`
        /// returns a mapping that preserves the original
        /// `physical_start`, `count`, and `unwritten` flag (the
        /// returned `logical_start` equals the queried block, which
        /// is the same as `m.logical_start` here).
        #[test]
        fn proptest_extent_cache_insert_lookup_roundtrip(
            capacity in 1_usize..=64,
            ns in 0_u64..=8,
            logical_start in 0_u32..=10_000,
            count in 1_u32..=1024,
            physical_start in 1_u64..=100_000,
            unwritten in any::<bool>(),
        ) {
            let cache = ExtentCache::with_capacity(capacity);
            let mapping = ExtentMapping {
                logical_start,
                physical_start,
                count,
                unwritten,
            };
            cache.insert(ns, mapping);
            let hit = cache
                .lookup(ns, logical_start)
                .expect("MR-1: lookup at logical_start must hit after insert");
            prop_assert_eq!(hit.logical_start, logical_start);
            prop_assert_eq!(hit.physical_start, physical_start);
            prop_assert_eq!(hit.count, count);
            prop_assert_eq!(hit.unwritten, unwritten);
        }

        /// MR-2 — Invalidate-range removes overlapping entries: after
        /// `invalidate_range(ns, m.logical_start, m.count)`, lookups
        /// for `m.logical_start` (and the rest of the original range)
        /// return None. Pins the contract that the invalidation
        /// surface covers the entire reported extent.
        #[test]
        fn proptest_extent_cache_invalidate_range_removes_overlapping(
            ns in 0_u64..=8,
            logical_start in 0_u32..=10_000,
            count in 1_u32..=1024,
            physical_start in 1_u64..=100_000,
            unwritten in any::<bool>(),
        ) {
            let cache = ExtentCache::with_capacity(64);
            let mapping = ExtentMapping {
                logical_start,
                physical_start,
                count,
                unwritten,
            };
            cache.insert(ns, mapping);
            cache.invalidate_range(ns, logical_start, u64::from(count));
            prop_assert!(
                cache.lookup(ns, logical_start).is_none(),
                "MR-2: lookup at the invalidated logical_start must return None"
            );
        }

        /// MR-3 — Invalidate-all clears every namespace: after
        /// `invalidate_all()`, every previously-inserted mapping
        /// returns None on lookup, regardless of namespace or insert
        /// ordering.
        #[test]
        fn proptest_extent_cache_invalidate_all_clears_every_namespace(
            seeds in proptest::collection::vec(
                (0_u64..=4_u64, 0_u32..=10_000_u32, 1_u32..=128_u32, 1_u64..=100_000_u64),
                1..=8,
            ),
        ) {
            let cache = ExtentCache::with_capacity(64);
            for (ns, logical_start, count, physical_start) in &seeds {
                cache.insert(
                    *ns,
                    ExtentMapping {
                        logical_start: *logical_start,
                        physical_start: *physical_start,
                        count: *count,
                        unwritten: false,
                    },
                );
            }
            cache.invalidate_all();
            for (ns, logical_start, _count, _physical_start) in &seeds {
                prop_assert!(
                    cache.lookup(*ns, *logical_start).is_none(),
                    "MR-3: lookup must return None after invalidate_all (ns={ns}, ls={logical_start})"
                );
            }
        }

        /// MR-4 — Stats monotonicity: between `reset_stats()` calls,
        /// `hits` and `misses` only ever increase. A miss followed by
        /// a hit grows both counters; neither decreases.
        #[test]
        fn proptest_extent_cache_stats_monotonic(
            ns in 0_u64..=8,
            logical_start in 0_u32..=10_000,
            count in 1_u32..=1024,
            physical_start in 1_u64..=100_000,
            unwritten in any::<bool>(),
        ) {
            let cache = ExtentCache::with_capacity(16);
            let stats0 = cache.stats();
            // First lookup: cache empty → miss.
            let _ = cache.lookup(ns, logical_start);
            let stats1 = cache.stats();
            prop_assert!(
                stats1.hits >= stats0.hits && stats1.misses >= stats0.misses,
                "MR-4: stats counters must not decrease between operations"
            );

            cache.insert(
                ns,
                ExtentMapping {
                    logical_start,
                    physical_start,
                    count,
                    unwritten,
                },
            );
            // Second lookup: hit.
            let _ = cache.lookup(ns, logical_start);
            let stats2 = cache.stats();
            prop_assert!(
                stats2.hits >= stats1.hits && stats2.misses >= stats1.misses,
                "MR-4: stats counters must not decrease between operations"
            );
            prop_assert!(
                stats2.hits > stats1.hits,
                "MR-4: hit lookup must increment the hits counter"
            );
        }

        /// MR-5 — `reset_stats` preserves entries: zeroing the hit
        /// counters does NOT remove cached entries. Lookups
        /// immediately after reset_stats must still hit.
        #[test]
        fn proptest_extent_cache_reset_stats_preserves_entries(
            ns in 0_u64..=8,
            logical_start in 0_u32..=10_000,
            count in 1_u32..=1024,
            physical_start in 1_u64..=100_000,
        ) {
            let cache = ExtentCache::with_capacity(16);
            let mapping = ExtentMapping {
                logical_start,
                physical_start,
                count,
                unwritten: false,
            };
            cache.insert(ns, mapping);
            cache.reset_stats();
            let after = cache.stats();
            prop_assert_eq!(after.hits, 0, "MR-5: reset_stats must zero hits");
            prop_assert_eq!(after.misses, 0, "MR-5: reset_stats must zero misses");
            prop_assert!(
                cache.lookup(ns, logical_start).is_some(),
                "MR-5: cache entries must survive reset_stats"
            );
        }
    }

    // ── ExtentCache unit tests ─────────────────────────────────────────────

    #[test]
    fn cache_miss_on_empty() {
        let cache = ExtentCache::new();
        assert!(cache.lookup(0, 42).is_none());
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn cache_hit_after_insert() {
        let cache = ExtentCache::new();
        let mapping = ExtentMapping {
            logical_start: 100,
            physical_start: 5000,
            count: 50,
            unwritten: false,
        };
        cache.insert(0, mapping);

        // Hit: block in the middle of the extent.
        let hit = cache.lookup(0, 120).unwrap();
        assert_eq!(hit.logical_start, 120);
        assert_eq!(hit.physical_start, 5020);
        assert_eq!(hit.count, 30); // remaining in extent

        // Hit: block at start.
        let hit = cache.lookup(0, 100).unwrap();
        assert_eq!(hit.logical_start, 100);
        assert_eq!(hit.physical_start, 5000);

        // Miss: just past the end.
        assert!(cache.lookup(0, 150).is_none());

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn cache_insert_rejects_overflowing_physical_span() {
        let cache = ExtentCache::new();
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 0,
                physical_start: u64::MAX,
                count: 2,
                unwritten: false,
            },
        );

        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert!(cache.lookup(0, 0).is_none());
    }

    #[test]
    fn cache_hit_at_final_logical_block() {
        let cache = ExtentCache::new();
        cache.insert(
            0,
            ExtentMapping {
                logical_start: u32::MAX,
                physical_start: 9000,
                count: 1,
                unwritten: false,
            },
        );

        let hit = cache.lookup(0, u32::MAX).unwrap();
        assert_eq!(hit.logical_start, u32::MAX);
        assert_eq!(hit.physical_start, 9000);
        assert_eq!(hit.count, 1);
    }

    #[test]
    fn cache_hole_mapping() {
        let cache = ExtentCache::new();
        // Hole: physical_start == 0.
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 200,
                physical_start: 0,
                count: 10,
                unwritten: false,
            },
        );
        let hit = cache.lookup(0, 205).unwrap();
        assert_eq!(hit.physical_start, 0); // Hole stays as hole.
    }

    #[test]
    fn cache_unwritten_flag_preserved() {
        let cache = ExtentCache::new();
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 0,
                physical_start: 1000,
                count: 100,
                unwritten: true,
            },
        );
        let hit = cache.lookup(0, 50).unwrap();
        assert!(hit.unwritten);
    }

    #[test]
    fn cache_invalidate_range_removes_overlapping() {
        let cache = ExtentCache::new();
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 0,
                physical_start: 1000,
                count: 100,
                unwritten: false,
            },
        );
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 200,
                physical_start: 2000,
                count: 50,
                unwritten: false,
            },
        );
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 300,
                physical_start: 3000,
                count: 50,
                unwritten: false,
            },
        );

        // Invalidate range [50, 210): should remove first two, keep third.
        cache.invalidate_range(0, 50, 160);

        assert!(cache.lookup(0, 50).is_none());
        assert!(cache.lookup(0, 200).is_none());
        assert!(cache.lookup(0, 320).is_some()); // third extent still valid
    }

    #[test]
    fn cache_invalidate_all_bumps_generation() {
        let cache = ExtentCache::new();
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 0,
                physical_start: 1000,
                count: 100,
                unwritten: false,
            },
        );
        assert!(cache.lookup(0, 50).is_some());

        cache.invalidate_all();
        assert!(cache.lookup(0, 50).is_none());
        assert_eq!(cache.stats().generation, 1);
    }

    #[test]
    fn cache_eviction_at_capacity() {
        let cache = ExtentCache::with_capacity(3);
        for i in 0..3 {
            cache.insert(
                0,
                ExtentMapping {
                    logical_start: i * 100,
                    physical_start: u64::from(i) * 1000,
                    count: 50,
                    unwritten: false,
                },
            );
        }
        assert_eq!(cache.stats().entries, 3);

        // Access entry 0 and 2 to make entry 1 the LRU victim.
        let _ = cache.lookup(0, 0);
        let _ = cache.lookup(0, 200);

        // Insert a 4th entry — should evict entry 1 (lowest last_access).
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 500,
                physical_start: 9000,
                count: 10,
                unwritten: false,
            },
        );

        assert_eq!(cache.stats().entries, 3);
        assert_eq!(cache.stats().evictions, 1);
        // Entry 1 (logical_start=100) should be evicted.
        assert!(cache.lookup(0, 110).is_none());
        // Entry 0 and 2 should survive.
        assert!(cache.lookup(0, 10).is_some());
        assert!(cache.lookup(0, 210).is_some());
    }

    #[test]
    fn cache_zero_capacity_never_stores_entries() {
        let cache = ExtentCache::with_capacity(0);
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 10,
                physical_start: 1000,
                count: 5,
                unwritten: false,
            },
        );

        assert_eq!(cache.stats().entries, 0);
        assert!(cache.lookup(0, 10).is_none());

        let stats = cache.stats();
        assert_eq!(stats.capacity, 0);
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.evictions, 0);
    }

    #[test]
    fn cache_stats_reset() {
        let cache = ExtentCache::new();
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 0,
                physical_start: 1000,
                count: 10,
                unwritten: false,
            },
        );
        let _ = cache.lookup(0, 5);
        let _ = cache.lookup(0, 99);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);

        cache.reset_stats();
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        // Entries preserved.
        assert_eq!(stats.entries, 1);
    }

    #[test]
    fn cache_hit_rate_calculation() {
        let stats = ExtentCacheStats {
            hits: 90,
            misses: 10,
            evictions: 0,
            entries: 5,
            capacity: 1024,
            generation: 0,
        };
        let rate = stats.hit_rate();
        assert!((rate - 0.9).abs() < 1e-10);

        let empty_stats = ExtentCacheStats {
            hits: 0,
            misses: 0,
            evictions: 0,
            entries: 0,
            capacity: 1024,
            generation: 0,
        };
        assert!(empty_stats.hit_rate().abs() <= f64::EPSILON);

        let saturated_stats = ExtentCacheStats {
            hits: u64::MAX,
            misses: u64::MAX,
            evictions: 0,
            entries: 0,
            capacity: 1024,
            generation: 0,
        };
        assert!((saturated_stats.hit_rate() - 0.5).abs() <= f64::EPSILON);
    }

    #[test]
    fn cache_counters_saturate_at_numeric_limits() {
        let cache = ExtentCache::with_capacity(1);
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 0,
                physical_start: 1000,
                count: 1,
                unwritten: false,
            },
        );

        {
            let mut inner = cache.inner.write();
            inner.hits = u64::MAX;
            inner.misses = u64::MAX;
            inner.evictions = u64::MAX;
            inner.generation = u64::MAX;
            inner
                .entries
                .get_mut(&(0, 0))
                .expect("seed cache entry")
                .generation = u64::MAX;
        }

        assert!(cache.lookup(0, 0).is_some());
        assert!(cache.lookup(0, 99).is_none());
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 10,
                physical_start: 2000,
                count: 1,
                unwritten: false,
            },
        );
        cache.invalidate_all();

        let stats = cache.stats();
        assert_eq!(stats.hits, u64::MAX);
        assert_eq!(stats.misses, u64::MAX);
        assert_eq!(stats.evictions, u64::MAX);
        assert_eq!(stats.generation, u64::MAX);
    }

    #[test]
    fn cached_map_single_block_hits_cache() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let root = empty_root();

        let cache = ExtentCache::new();
        // Pre-populate cache.
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 0,
                physical_start: 5000,
                count: 100,
                unwritten: false,
            },
        );

        // Single-block lookup should hit cache without touching the tree.
        let result = cached_map_logical_to_physical(&cx, &dev, &root, 50, 1, &cache, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].physical_start, 5050);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn cached_map_populates_on_miss() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let mut root = empty_root();

        // Allocate an extent so the tree has something.
        allocate_extent(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            0,
            10,
            &AllocHint::default(),
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();

        let cache = ExtentCache::new();

        // First call with count=10: miss + populates cache with full extent.
        let result = cached_map_logical_to_physical(&cx, &dev, &root, 0, 10, &cache, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert_ne!(result[0].physical_start, 0);
        assert_eq!(cache.stats().misses, 0); // count != 1, no single-block lookup
        assert!(cache.stats().entries > 0);

        // Second call: single-block should hit cache.
        let result2 = cached_map_logical_to_physical(&cx, &dev, &root, 5, 1, &cache, 0).unwrap();
        assert_eq!(result2.len(), 1);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn cached_single_block_miss_populates_searched_leaf_window() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let pctx = mock_pctx();
        let mut root = empty_root();

        for logical in 0..100_u32 {
            allocate_extent(
                &cx,
                &dev,
                &mut root,
                &geo,
                &mut groups,
                logical,
                1,
                &AllocHint::default(),
                &pctx,
                ExtentOwner::default(),
            )
            .unwrap();
        }

        let cache = ExtentCache::new();
        let expected_first = map_logical_to_physical(&cx, &dev, &root, 10, 1).unwrap();
        let expected_second = map_logical_to_physical(&cx, &dev, &root, 11, 1).unwrap();

        dev.clear_read_counts();
        let first = cached_map_logical_to_physical(&cx, &dev, &root, 10, 1, &cache, 0).unwrap();
        assert_eq!(first, expected_first);
        assert_eq!(first[0].count, 1);
        assert_eq!(dev.total_reads(), 1);
        assert!(
            cache.stats().entries > 1,
            "a single-block miss should cache neighboring leaf extents"
        );

        dev.clear_read_counts();
        let second = cached_map_logical_to_physical(&cx, &dev, &root, 11, 1, &cache, 0).unwrap();
        assert_eq!(second, expected_second);
        assert_eq!(second[0].count, 1);
        assert_eq!(
            dev.total_reads(),
            0,
            "adjacent block should be served from the searched leaf window"
        );
    }

    #[test]
    fn cache_invalidation_after_truncate() {
        let cache = ExtentCache::new();

        // Manually populate cache with a single extent covering blocks 0-19.
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 0,
                physical_start: 5000,
                count: 20,
                unwritten: false,
            },
        );
        assert!(cache.lookup(0, 15).is_some());
        assert!(cache.lookup(0, 5).is_some());

        // Invalidate the truncated range (blocks 10+).
        cache.invalidate_range(0, 10, u64::from(u32::MAX) - 10);

        // The original extent [0,20) overlapped [10,MAX) so it's removed entirely.
        // This is correct: the cache takes a conservative approach of removing
        // any extent that overlaps the invalidated range.
        assert!(cache.lookup(0, 15).is_none());
        assert!(cache.lookup(0, 5).is_none()); // removed because extent [0,20) overlapped

        // After re-populating just [0,10), it should work again.
        cache.insert(
            0,
            ExtentMapping {
                logical_start: 0,
                physical_start: 5000,
                count: 10,
                unwritten: false,
            },
        );
        assert!(cache.lookup(0, 5).is_some());
        assert!(cache.lookup(0, 12).is_none());
    }

    #[test]
    fn cache_concurrent_read_write() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(ExtentCache::with_capacity(256));

        // Spawn readers.
        let mut handles = vec![];
        for t in 0..4 {
            let c = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0..1000 {
                    let block = (t * 1000 + i) % 500;
                    let _ = c.lookup(0, block);
                }
            }));
        }

        // Spawn writers.
        for t in 0u32..2 {
            let c = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0u32..500 {
                    c.insert(
                        0,
                        ExtentMapping {
                            logical_start: t * 500 + i,
                            physical_start: 1000 + u64::from(t * 500 + i),
                            count: 10,
                            unwritten: false,
                        },
                    );
                }
            }));
        }

        // Spawn invalidator.
        {
            let c = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    c.invalidate_range(0, i * 10, 10);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // No panics = success. Verify stats are consistent.
        let stats = cache.stats();
        assert!(stats.hits + stats.misses > 0);
    }

    // ── Namespace isolation tests ──────────────────────────────────────

    #[test]
    fn cache_namespace_isolation_prevents_cross_inode_pollution() {
        let cache = ExtentCache::new();

        // Inode A (ns=100): block 0 maps to physical 5000.
        cache.insert(
            100,
            ExtentMapping {
                logical_start: 0,
                physical_start: 5000,
                count: 10,
                unwritten: false,
            },
        );

        // Inode B (ns=200): block 0 maps to physical 9000.
        cache.insert(
            200,
            ExtentMapping {
                logical_start: 0,
                physical_start: 9000,
                count: 10,
                unwritten: false,
            },
        );

        // Lookup inode A's block 0 — must return phys 5000, NOT 9000.
        let hit_a = cache.lookup(100, 0).unwrap();
        assert_eq!(hit_a.physical_start, 5000);

        // Lookup inode B's block 0 — must return phys 9000.
        let hit_b = cache.lookup(200, 0).unwrap();
        assert_eq!(hit_b.physical_start, 9000);

        // Lookup inode C (ns=300) — no entry, must miss.
        assert!(cache.lookup(300, 0).is_none());
    }

    #[test]
    fn cache_namespace_invalidation_is_scoped() {
        let cache = ExtentCache::new();

        cache.insert(
            10,
            ExtentMapping {
                logical_start: 0,
                physical_start: 1000,
                count: 50,
                unwritten: false,
            },
        );
        cache.insert(
            20,
            ExtentMapping {
                logical_start: 0,
                physical_start: 2000,
                count: 50,
                unwritten: false,
            },
        );

        // Invalidate ns=10 range [0, 50) — should NOT affect ns=20.
        cache.invalidate_range(10, 0, 50);

        assert!(cache.lookup(10, 25).is_none());
        assert!(cache.lookup(20, 25).is_some());
    }

    #[test]
    fn cache_invalidate_all_clears_all_namespaces() {
        let cache = ExtentCache::new();

        cache.insert(
            1,
            ExtentMapping {
                logical_start: 0,
                physical_start: 100,
                count: 10,
                unwritten: false,
            },
        );
        cache.insert(
            2,
            ExtentMapping {
                logical_start: 0,
                physical_start: 200,
                count: 10,
                unwritten: false,
            },
        );

        cache.invalidate_all();

        assert!(cache.lookup(1, 0).is_none());
        assert!(cache.lookup(2, 0).is_none());
    }

    #[test]
    fn punch_hole_full_root_overflow() {
        let cx = test_cx();
        let dev = MemBlockDevice::new(4096);
        let geo = make_geometry();
        let mut groups = make_groups(&geo);
        let mut root = empty_root();
        let pctx = mock_pctx();

        // Fill the root node (max entries = 4)
        for i in 0..4 {
            allocate_extent(
                &cx,
                &dev,
                &mut root,
                &geo,
                &mut groups,
                i * 10,
                5,
                &AllocHint::default(),
                &pctx,
                ExtentOwner::default(),
            )
            .unwrap();
        }

        // Punching a hole in the middle of the first extent [0..5]
        // This splits it into two, making 5 total entries in the tree.
        // It must handle root split properly.
        punch_hole(
            &cx,
            &dev,
            &mut root,
            &geo,
            &mut groups,
            2,
            1,
            &pctx,
            ExtentOwner::default(),
        )
        .unwrap();
    }

    // bd-4fy6y: metamorphic relation — cached_map_logical_to_physical
    // must return semantically identical results to map_logical_to_physical
    // regardless of cache state. Existing tests cover individual cache
    // hit/miss/invalidate scenarios but no proptest sweeps (start, count)
    // ranges asserting result equivalence. A regression in the cache-hit
    // fast path arithmetic (wrong physical_start, mishandled unwritten
    // flag, off-by-one cross extent boundary) would silently corrupt
    // every cached read but pass the existing fixed-input tests.
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config { cases: 32, ..proptest::test_runner::Config::default() })]

        #[test]
        fn cached_map_logical_to_physical_agrees_with_uncached(
            extent_start in 0_u32..100,
            extent_len in 1_u32..50,
            query_start in 0_u32..150,
            query_count in 1_u64..30,
            hit_offset in 0_u32..50,
        ) {
            let cx = test_cx();
            let dev = MemBlockDevice::new(4096);
            let geo = make_geometry();
            let mut groups = make_groups(&geo);
            let pctx = mock_pctx();
            let mut root = empty_root();

            // Allocate one extent so the tree has something to walk.
            allocate_extent(
                &cx, &dev, &mut root, &geo, &mut groups,
                extent_start, extent_len, &AllocHint::default(), &pctx,
                ExtentOwner::default(),
            )
            .expect("allocate test extent");

            // Reference: uncached lookup.
            let uncached = map_logical_to_physical(
                &cx, &dev, &root, query_start, query_count,
            )
            .expect("uncached lookup");

            // Variant 1: cached lookup with empty cache (forces miss path,
            // then populates).
            let cache_empty = ExtentCache::new();
            let cached_miss = cached_map_logical_to_physical(
                &cx, &dev, &root, query_start, query_count, &cache_empty, 0,
            )
            .expect("cached miss path");
            proptest::prop_assert_eq!(
                &cached_miss,
                &uncached,
                "MR-1: cached(miss) must equal uncached"
            );

            // Variant 2: prepopulate the cache with the allocated extent, then
            // force the single-block fast path at a generated point inside it.
            let cache_warm = ExtentCache::new();
            let _ = cached_map_logical_to_physical(
                &cx,
                &dev,
                &root,
                extent_start,
                u64::from(extent_len),
                &cache_warm,
                7,
            )
            .expect("cached warm path");
            let hit_logical = extent_start + (hit_offset % extent_len);
            let uncached_hit = map_logical_to_physical(
                &cx, &dev, &root, hit_logical, 1,
            )
            .expect("uncached single-block hit");
            let cached_hit = cached_map_logical_to_physical(
                &cx, &dev, &root, hit_logical, 1, &cache_warm, 7,
            )
            .expect("cached single-block hit");
            proptest::prop_assert_eq!(
                &cached_hit,
                &uncached_hit,
                "MR-2: cached(warm single-block hit) must equal uncached"
            );
        }
    }
}
