//! Exercise the real extent allocator, CoW tree, and disk serializer. These are
//! reservation/serialization regressions, not mounted or power-loss tests.

use super::*;
use ffs_btrfs::writeback::DiskWritebackContext;
use ffs_btrfs::{
    BTRFS_BLOCK_GROUP_DATA, BTRFS_BLOCK_GROUP_METADATA, BtrfsBlockGroupItem,
    BtrfsKey,
};
use std::collections::BTreeSet;

const NODE: u32 = 4096;
const BASE: u64 = 1024 * 1024;
const GENERATION: u64 = 9;

fn allocator(bytes: u64) -> BtrfsExtentAllocator {
    let mut allocator = BtrfsExtentAllocator::new(GENERATION).unwrap();
    allocator.set_nodesize(u64::from(NODE));
    allocator.add_block_group(
        BASE,
        BtrfsBlockGroupItem {
            total_bytes: bytes,
            used_bytes: 0,
            flags: BTRFS_BLOCK_GROUP_METADATA,
        },
    );
    allocator
}

fn settle(allocator: &mut BtrfsExtentAllocator) -> PreparedFreeSpaceTree {
    let cx = Cx::for_testing();
    let mut plan = FreeSpaceTreeCow::new(NODE);
    for _ in 0..16 {
        if !plan.reconcile(&cx, allocator, GENERATION).unwrap() {
            return plan.finish(GENERATION).unwrap();
        }
    }
    panic!("free-space reservations did not converge");
}

fn all_items(tree: &InMemoryCowBtrfsTree) -> Vec<(BtrfsKey, Vec<u8>)> {
    tree.range(
        &BtrfsKey { objectid: 0, item_type: 0, offset: 0 },
        &BtrfsKey { objectid: u64::MAX, item_type: u8::MAX, offset: u64::MAX },
    )
    .unwrap()
}

fn assert_final_free_map(allocator: &BtrfsExtentAllocator, prepared: &PreparedFreeSpaceTree) {
    let groups = allocator.free_space_extents().unwrap();
    assert_eq!(all_items(&prepared.tree), build_free_space_tree_items(&groups));
    for &address in prepared.addresses.values() {
        let end = address + u64::from(NODE);
        for group in &groups {
            for &(free_start, length) in &group.free_ranges {
                assert!(end <= free_start || address >= free_start + length,
                    "new FST node {address:#x} was advertised as free");
            }
        }
    }
}

#[test]
fn fresh_reservations_exclude_retired_live_free_space_nodes() {
    let mut allocator = allocator(16 * 1024 * 1024);
    let old = allocator
        .alloc_metadata_for_tree(u64::from(NODE), BTRFS_FREE_SPACE_TREE_OBJECTID, 0)
        .unwrap();
    assert_eq!(allocator.remove_metadata_items_owned_by_roots(&[BTRFS_FREE_SPACE_TREE_OBJECTID]).unwrap(), 1);
    assert!(allocator.is_pinned(old.bytenr));
    let prepared = settle(&mut allocator);
    assert!(!prepared.addresses.values().any(|&address| address == old.bytenr));
    assert!(allocator.is_pinned(old.bytenr));
    assert_final_free_map(&allocator, &prepared);
}

#[test]
fn reservations_describe_their_own_owner_level_and_generation() {
    let mut allocator = allocator(16 * 1024 * 1024);
    let prepared = settle(&mut allocator);
    for &(block, level) in &prepared.order {
        let address = prepared.addresses[&block];
        // This API returns false only when exactly the required skinny item,
        // owner, level, refcount and generation are already materialized.
        assert!(!allocator.ensure_self_metadata_item(
            address, level, BTRFS_FREE_SPACE_TREE_OBJECTID, GENERATION,
        ).unwrap());
    }
    assert_final_free_map(&allocator, &prepared);
}

#[test]
fn a_multilevel_tree_is_fully_reserved_and_serializable() {
    let mut allocator = allocator(16 * 1024 * 1024);
    // Each group contributes at least an INFO and an EXTENT. This forces a
    // multi-level FST independently of the metadata allocator's tree shape.
    for group in 0..300_u64 {
        allocator.add_block_group(
            64 * 1024 * 1024 + group * 1024 * 1024,
            BtrfsBlockGroupItem {
                total_bytes: 1024 * 1024,
                used_bytes: 0,
                flags: BTRFS_BLOCK_GROUP_DATA,
            },
        );
    }
    let prepared = settle(&mut allocator);
    assert!(prepared.tree.root_level() > 0);
    assert!(prepared.order.len() > 1);
    assert_final_free_map(&allocator, &prepared);
    let distinct: BTreeSet<_> = prepared.addresses.values().copied().collect();
    assert_eq!(distinct.len(), prepared.order.len());
    let context = DiskWritebackContext::with_allocated_addresses(
        [0xA5; 16], [0xA5; 16], GENERATION, BTRFS_FREE_SPACE_TREE_OBJECTID,
        NODE, 0, NODE, prepared.addresses.clone(),
    );
    for &(block, level) in &prepared.order {
        let bytes = context.serialize_node(&prepared.tree, block, level).unwrap();
        assert_eq!(bytes.len(), NODE as usize);
        assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), prepared.addresses[&block]);
        assert_eq!(u64::from_le_bytes(bytes[80..88].try_into().unwrap()), GENERATION);
        assert_eq!(u64::from_le_bytes(bytes[88..96].try_into().unwrap()), BTRFS_FREE_SPACE_TREE_OBJECTID);
        assert_eq!(bytes[100], level);
    }
}

#[test]
fn outer_allocations_are_included_when_the_same_pool_is_reconciled_again() {
    let cx = Cx::for_testing();
    let mut allocator = allocator(16 * 1024 * 1024);
    let mut plan = FreeSpaceTreeCow::new(NODE);
    for _ in 0..16 {
        if !plan.reconcile(&cx, &mut allocator, GENERATION).unwrap() {
            break;
        }
    }
    assert!(plan.settled);
    let before = plan.pool.clone();
    let other = allocator.alloc_metadata_for_tree(u64::from(NODE), 1, 0).unwrap();
    // A fixed address pool does not imply an unchanged free map. Always rebuild
    // once the OUTER loop has changed any other tree's allocations.
    assert!(!plan.reconcile(&cx, &mut allocator, GENERATION).unwrap());
    assert_eq!(plan.pool, before);
    let prepared = plan.finish(GENERATION).unwrap();
    assert!(!prepared.addresses.values().any(|&address| address == other.bytenr));
    assert_final_free_map(&allocator, &prepared);
}

#[test]
fn failed_reservation_can_be_rolled_back_with_the_existing_allocator_snapshot() {
    let cx = Cx::for_testing();
    // One metadata block is insufficient for a multi-level FST. The failure
    // must occur AFTER a real allocation, not merely during input validation.
    let mut allocator = allocator(u64::from(NODE));
    for group in 0..100_u64 {
        allocator.add_block_group(
            64 * 1024 * 1024 + group * 1024 * 1024,
            BtrfsBlockGroupItem {
                total_bytes: 1024 * 1024,
                used_bytes: 0,
                flags: BTRFS_BLOCK_GROUP_DATA,
            },
        );
    }
    let free_before = allocator.free_space_extents().unwrap();
    let count_before = allocator.allocated_extent_item_count().unwrap();
    let snapshot = allocator.snapshot();
    let mut plan = FreeSpaceTreeCow::new(NODE);
    assert!(plan.reconcile(&cx, &mut allocator, GENERATION).is_err());
    assert_eq!(plan.pool.len(), 1, "the first reservation must have happened");
    assert!(allocator.allocated_extent_item_count().unwrap() > count_before);
    assert!(plan.finish(GENERATION).is_err());
    allocator.restore(snapshot);
    assert_eq!(allocator.free_space_extents().unwrap(), free_before);
    assert_eq!(allocator.allocated_extent_item_count().unwrap(), count_before);
}

#[test]
fn successful_reservations_and_retirement_are_undone_by_commit_rollback() {
    let mut allocator = allocator(16 * 1024 * 1024);
    let old = allocator.alloc_metadata_for_tree(u64::from(NODE), BTRFS_FREE_SPACE_TREE_OBJECTID, 0).unwrap();
    let before = allocator.free_space_extents().unwrap();
    let count_before = allocator.allocated_extent_item_count().unwrap();
    let pins_before = allocator.pinned_extent_count();
    let snapshot = allocator.snapshot();
    allocator.remove_metadata_items_owned_by_roots(&[BTRFS_FREE_SPACE_TREE_OBJECTID]).unwrap();
    let prepared = settle(&mut allocator);
    assert_ne!(prepared.root_bytenr().unwrap(), old.bytenr);
    allocator.restore(snapshot);
    assert_eq!(allocator.free_space_extents().unwrap(), before);
    assert_eq!(allocator.allocated_extent_item_count().unwrap(), count_before);
    assert_eq!(allocator.pinned_extent_count(), pins_before);
}

#[test]
fn cancellation_invalidates_a_previously_settled_plan_without_new_allocations() {
    let cx = Cx::for_testing();
    let mut allocator = allocator(16 * 1024 * 1024);
    let mut plan = FreeSpaceTreeCow::new(NODE);
    for _ in 0..16 {
        if !plan.reconcile(&cx, &mut allocator, GENERATION).unwrap() {
            break;
        }
    }
    assert!(plan.settled);
    let before = allocator.free_space_extents().unwrap();
    cx.set_cancel_requested(true);
    assert!(matches!(plan.reconcile(&cx, &mut allocator, GENERATION), Err(FfsError::Cancelled)));
    assert!(plan.finish(GENERATION).is_err());
    assert_eq!(allocator.free_space_extents().unwrap(), before);
}

#[test]
fn an_unreconciled_or_changed_plan_cannot_be_published() {
    assert!(FreeSpaceTreeCow::new(NODE).finish(GENERATION).is_err());
    let cx = Cx::for_testing();
    let mut allocator = allocator(16 * 1024 * 1024);
    let mut plan = FreeSpaceTreeCow::new(NODE);
    assert!(plan.reconcile(&cx, &mut allocator, GENERATION).unwrap());
    assert!(plan.finish(GENERATION).is_err());
}

#[test]
fn root_item_publishes_the_new_address_level_generation_and_full_byte_count() {
    let mut allocator = allocator(16 * 1024 * 1024);
    let prepared = settle(&mut allocator);
    // patch_root_commit's existing minimum is 279 bytes; retain that contract.
    for length in [279, 439] {
        let mut data = vec![0; length];
        data[168..176].copy_from_slice(&256_u64.to_le_bytes());
        data[208..216].copy_from_slice(&0x0123_4567_u64.to_le_bytes());
        prepared.patch_root_item(&mut data, GENERATION).unwrap();
        let parsed = ffs_btrfs::parse_root_item(&data).unwrap();
        assert_eq!(parsed.bytenr, prepared.root_bytenr().unwrap());
        assert_eq!(parsed.level, prepared.tree.root_level());
        assert_eq!(parsed.generation, GENERATION);
        assert_eq!(u64::from_le_bytes(data[192..200].try_into().unwrap()), prepared.order.len() as u64 * u64::from(NODE));
        assert_eq!(u64::from_le_bytes(data[168..176].try_into().unwrap()), 256);
        assert_eq!(u64::from_le_bytes(data[208..216].try_into().unwrap()), 0x0123_4567);
        assert_eq!(data.len(), length);
    }
    assert!(prepared.patch_root_item(&mut [0; 100], GENERATION).is_err());
}

#[test]
fn retired_block_is_free_in_new_generation_but_pinned_before_publication() {
    let mut allocator = allocator(16 * 1024 * 1024);
    let old = allocator
        .alloc_metadata_for_tree(u64::from(NODE), BTRFS_FREE_SPACE_TREE_OBJECTID, 0)
        .unwrap();
    allocator
        .remove_metadata_items_owned_by_roots(&[BTRFS_FREE_SPACE_TREE_OBJECTID])
        .unwrap();
    // Retirement removes the key, but the running tally can still charge it.
    // A raw free_space_extents() before accounting recomputation fences off
    // that apparently-untracked prefix. It must NOT survive into the new FST.
    let prepared = settle(&mut allocator);
    assert!(allocator.is_pinned(old.bytenr));
    assert!(all_items(&prepared.tree).iter().any(|(key, value)| {
        key.item_type == ffs_btrfs::BTRFS_ITEM_FREE_SPACE_EXTENT
            && key.objectid <= old.bytenr
            && key.objectid + key.offset >= old.bytenr + u64::from(NODE)
            && value.is_empty()
    }), "new FST still charges a retired block to stale used_bytes");
    assert_eq!(
        allocator.block_group(BASE).unwrap().used_bytes,
        prepared.order.len() as u64 * u64::from(NODE),
    );
    assert_final_free_map(&allocator, &prepared);
}
