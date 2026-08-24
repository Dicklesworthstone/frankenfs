//! Read-only btrfs allocation diagnostics for integration tests.

use crate::OpenFs;
use ffs_error::FfsError;

/// Snapshot of the materialized btrfs extent-tree allocation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsExtentAllocationCount {
    /// Number of extent-tree items that currently describe allocated extents.
    pub extent_items: usize,
}

impl OpenFs {
    /// Return the current materialized btrfs extent-tree allocation count.
    ///
    /// This is intentionally read-only: it exposes no allocator mutation and
    /// exists so integration tests can prove that an ephemeral tree-log rotation
    /// returns superseded extents rather than merely hiding them from the log root.
    pub fn btrfs_extent_allocation_count(&self) -> Result<BtrfsExtentAllocationCount, FfsError> {
        let alloc = self.require_btrfs_alloc_state()?;
        let alloc = alloc.read();
        let extent_items = alloc
            .extent_alloc
            .allocated_extent_item_count()
            .map_err(|error| FfsError::Format(format!("btrfs extent allocation count: {error}")))?;
        Ok(BtrfsExtentAllocationCount { extent_items })
    }
}
