//! Copy-on-write publication of the free-space tree (bd-l68g8).
//!
//! The free-space tree describes its own allocation, and allocating its nodes
//! changes the extent tree that describes them. Participate in the SAME bounded
//! reservation fixpoint as EXTENT_TREE and ROOT_TREE; never overwrite the old
//! free-space tree to avoid that dependency. The caller pins retired tree blocks
//! and owns the allocator snapshot until the new superblock is durable.

use asupersync::Cx;
use ffs_btrfs::writeback::WriteDependencyDag;
use ffs_btrfs::{
    BTRFS_FREE_SPACE_TREE_OBJECTID, BlockGroupFreeSpace, BtrfsBTree,
    BtrfsExtentAllocator, BtrfsRootItem, InMemoryCowBtrfsTree,
    build_free_space_tree_items,
};
use ffs_error::{FfsError, Result};
use std::collections::BTreeMap;

use super::btrfs_mutation_to_ffs;

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn build_tree(
    cx: &Cx,
    groups: &[BlockGroupFreeSpace],
    nodesize: u32,
) -> Result<InMemoryCowBtrfsTree> {
    checkpoint(cx)?;
    let budget = usize::try_from(nodesize)
        .ok()
        .and_then(|size| size.checked_sub(ffs_btrfs::BTRFS_HEADER_SIZE))
        .filter(|&size| size >= 64 * 5)
        .ok_or_else(|| FfsError::InvalidGeometry("invalid free-space tree node size".into()))?;
    let mut tree = InMemoryCowBtrfsTree::new((budget / 64).max(5))
        .map_err(|error| btrfs_mutation_to_ffs(&error))?
        .with_node_byte_budget(budget);
    for (key, value) in build_free_space_tree_items(groups) {
        checkpoint(cx)?;
        tree.insert(key, &value)
            .map_err(|error| btrfs_mutation_to_ffs(&error))?;
    }
    checkpoint(cx)?;
    Ok(tree)
}

/// An estimate for the existing pre-allocation chunk-growth planner. The actual
/// allocator and bounded fixpoint, not this estimate, decide whether a commit fits.
pub(super) fn estimated_nodes(
    cx: &Cx,
    allocator: &BtrfsExtentAllocator,
    nodesize: u32,
    generation: u64,
) -> Result<u64> {
    let groups = allocator
        .free_space_extents()
        .map_err(|error| btrfs_mutation_to_ffs(&error))?;
    let tree = build_tree(cx, &groups, nodesize)?;
    let dag = WriteDependencyDag::from_cow_tree(&tree, generation)
        .map_err(|error| btrfs_mutation_to_ffs(&error))?;
    u64::try_from(dag.node_count())
        .map_err(|_| FfsError::InvalidGeometry("free-space tree node count overflow".into()))
}

pub(super) struct FreeSpaceTreeCow {
    nodesize: u32,
    // Position in child-before-parent order, never an ephemeral in-memory id.
    pool: Vec<u64>,
    tree: Option<InMemoryCowBtrfsTree>,
    settled: bool,
}

impl FreeSpaceTreeCow {
    pub(super) fn new(nodesize: u32) -> Self {
        Self {
            nodesize,
            pool: Vec::new(),
            tree: None,
            settled: false,
        }
    }

    /// Rebuild from the current allocation map, then reconcile the addresses
    /// needed to store that tree. Any reservation/retirement/level change forces
    /// another OUTER pass: it can change all three trees' shapes. No device I/O.
    pub(super) fn reconcile(
        &mut self,
        cx: &Cx,
        allocator: &mut BtrfsExtentAllocator,
        generation: u64,
    ) -> Result<bool> {
        self.settled = false;
        checkpoint(cx)?;
        // The running used_bytes can still charge just-retired nodes. Calling
        // free_space_extents alone would turn that stale charge into an
        // untracked-prefix reservation and serialize an incorrect free map.
        // Recompute accounting from the live keys before deriving free ranges.
        // These updates keep BLOCK_GROUP_ITEM lengths/keys unchanged; the outer
        // loop's positional node pools remain valid despite CoW id changes.
        let (_, groups) = allocator
            .sync_accounting_and_free_space()
            .map_err(|error| btrfs_mutation_to_ffs(&error))?;
        let tree = build_tree(cx, &groups, self.nodesize)?;
        let dag = WriteDependencyDag::from_cow_tree(&tree, generation)
            .map_err(|error| btrfs_mutation_to_ffs(&error))?;
        let order = dag.reverse_topological_order_with_levels();
        let mut changed = false;
        while self.pool.len() < order.len() {
            checkpoint(cx)?;
            let allocation = allocator
                .alloc_metadata_for_tree(
                    u64::from(self.nodesize),
                    BTRFS_FREE_SPACE_TREE_OBJECTID,
                    0,
                )
                .map_err(|error| btrfs_mutation_to_ffs(&error))?;
            self.pool.push(allocation.bytenr);
            changed = true;
        }
        while self.pool.len() > order.len() {
            checkpoint(cx)?;
            let address = self.pool.pop().expect("pool has a surplus address");
            allocator
                .free_extent(address, u64::from(self.nodesize), true)
                .map_err(|error| btrfs_mutation_to_ffs(&error))?;
            changed = true;
        }
        for (&address, &(_, level)) in self.pool.iter().zip(&order) {
            checkpoint(cx)?;
            changed |= allocator
                .ensure_self_metadata_item(
                    address,
                    level,
                    BTRFS_FREE_SPACE_TREE_OBJECTID,
                    generation,
                )
                .map_err(|error| btrfs_mutation_to_ffs(&error))?;
        }
        checkpoint(cx)?;
        self.tree = Some(tree);
        self.settled = !changed;
        Ok(changed)
    }

    /// Called only after the outer extent/root/free-space fixpoint converges.
    /// The caller must not allocate or retire another extent after this point.
    pub(super) fn finish(self, generation: u64) -> Result<PreparedFreeSpaceTree> {
        if !self.settled {
            return Err(FfsError::Format(
                "free-space tree reservations are not settled".into(),
            ));
        }
        let tree = self
            .tree
            .ok_or_else(|| FfsError::Format("missing free-space tree".into()))?;
        let order = WriteDependencyDag::from_cow_tree(&tree, generation)
            .map_err(|error| btrfs_mutation_to_ffs(&error))?
            .reverse_topological_order_with_levels();
        if order.len() != self.pool.len() || order.is_empty() {
            return Err(FfsError::Format(
                "free-space tree reservation count changed".into(),
            ));
        }
        let addresses = order
            .iter()
            .zip(self.pool)
            .map(|(&(block, _), address)| (block, address))
            .collect();
        Ok(PreparedFreeSpaceTree {
            tree,
            order,
            addresses,
            nodesize: self.nodesize,
        })
    }
}

pub(super) struct PreparedFreeSpaceTree {
    pub(super) tree: InMemoryCowBtrfsTree,
    pub(super) order: Vec<(u64, u8)>,
    pub(super) addresses: BTreeMap<u64, u64>,
    nodesize: u32,
}

impl PreparedFreeSpaceTree {
    pub(super) fn root_bytenr(&self) -> Result<u64> {
        self.addresses
            .get(&self.tree.root_block())
            .copied()
            .ok_or_else(|| FfsError::Format("free-space tree root has no reservation".into()))
    }

    pub(super) fn patch_root_item(&self, data: &mut [u8], generation: u64) -> Result<()> {
        BtrfsRootItem::patch_root_commit(
            data,
            self.root_bytenr()?,
            self.tree.root_level(),
            generation,
        )
        .map_err(|error| {
            FfsError::Parse(format!("FREE_SPACE_TREE ROOT_ITEM patch failed: {error}"))
        })?;
        let bytes_used = u64::try_from(self.order.len())
            .ok()
            .and_then(|count| count.checked_mul(u64::from(self.nodesize)))
            .ok_or_else(|| {
                FfsError::InvalidGeometry("free-space tree size overflow".into())
            })?;
        // Packed btrfs_root_item: 160-byte inode, then generation/root_dirid/
        // bytenr/byte_limit, followed by bytes_used at [192,200). Preserve all
        // other fields and the original legacy/extended root-item length.
        data.get_mut(192..200)
            .ok_or_else(|| FfsError::Parse("short FREE_SPACE_TREE ROOT_ITEM".into()))?
            .copy_from_slice(&bytes_used.to_le_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests;
