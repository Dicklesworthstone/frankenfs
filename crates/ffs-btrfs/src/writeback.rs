//! btrfs metadata writeback: write-dependency DAG and crash consistency.
//!
//! bd-xuo95.5 (A4): Implements write-dependency DAG construction, reverse-topological
//! flush ordering, and crash consistency oracles (WB-I1, WB-I2) for btrfs metadata.
#![allow(clippy::must_use_candidate)]
#![allow(clippy::uninlined_format_args)]
//!
//! # Write-Dependency DAG
//!
//! The DAG captures ordering constraints: a child node must be durable before any
//! parent that references it. Nodes are flushed in reverse topological order.
//!
//! # Crash Consistency Invariants
//!
//! - **WB-I1 (Prefix-Closed Durability):** At every crash point, the set of durable
//!   nodes is prefix-closed under references: no durable internal node points at a
//!   non-durable child.
//!
//! - **WB-I2 (Atomic Generation Transition):** A reader after crash observes
//!   generation `g` (pre-writeback) or `g+1` (post), never a torn mixture.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use tracing::{debug, trace};

use crate::{BtrfsCowNode, BtrfsMutationError, InMemoryCowBtrfsTree};

/// A node in the write-dependency DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNode {
    /// Block number of this node.
    pub block: u64,
    /// Tree level (0 = leaf).
    pub level: u8,
    /// Generation when this node was created/modified.
    pub generation: u64,
    /// Child block numbers (empty for leaves).
    pub children: Vec<u64>,
    /// Whether this node has been marked durable.
    pub durable: bool,
}

/// Write-dependency DAG for btrfs CoW tree nodes.
///
/// Captures the ordering constraint that children must be durable before parents.
#[derive(Debug, Clone)]
pub struct WriteDependencyDag {
    /// All nodes in the DAG, keyed by block number.
    nodes: BTreeMap<u64, DagNode>,
    /// Root block number.
    root: u64,
    /// Current generation.
    generation: u64,
}

impl WriteDependencyDag {
    /// Build a write-dependency DAG from an in-memory CoW tree.
    pub fn from_cow_tree(
        tree: &InMemoryCowBtrfsTree,
        generation: u64,
    ) -> Result<Self, BtrfsMutationError> {
        let mut nodes = BTreeMap::new();
        let root = tree.root_block();

        // Each node's on-disk header level MUST equal its true depth (leaf = 0,
        // each parent one greater), or btrfs readers reject the tree on the
        // `child.level == parent.level - 1` consistency check. Drive the level
        // top-down from the root rather than assigning every internal node the
        // root's level — the latter only happens to be correct for height <= 2
        // trees and corrupts deeper (height >= 3) commits (bd-iv5uy).
        let root_level = tree.root_level();
        Self::collect_nodes(tree, root, &mut nodes, generation, root_level)?;

        Ok(Self {
            nodes,
            root,
            generation,
        })
    }

    fn collect_nodes(
        tree: &InMemoryCowBtrfsTree,
        block: u64,
        nodes: &mut BTreeMap<u64, DagNode>,
        generation: u64,
        level: u8,
    ) -> Result<(), BtrfsMutationError> {
        if nodes.contains_key(&block) {
            return Ok(());
        }

        let node = tree.node_snapshot(block)?;
        // Leaves are always level 0; internal nodes carry the depth passed down
        // from the root (root = root_level, each child one less). Keep the
        // separate DAG and recursion child vectors; the moved-child variant was
        // measured slower in bd-xmh5g.400's gauntlet bench.
        let (node_level, children) = match &node {
            BtrfsCowNode::Leaf { .. } => (0, Vec::new()),
            BtrfsCowNode::Internal { children, .. } => (level, children.clone()),
        };

        nodes.insert(
            block,
            DagNode {
                block,
                level: node_level,
                generation,
                children: children.clone(),
                durable: false,
            },
        );

        // Recursively collect children one level shallower.
        let child_level = level.saturating_sub(1);
        for child in children {
            Self::collect_nodes(tree, child, nodes, generation, child_level)?;
        }

        Ok(())
    }

    /// Return blocks in reverse topological order (leaves first, root last).
    ///
    /// This is the order in which nodes must be flushed to maintain WB-I1.
    pub fn reverse_topological_order(&self) -> Vec<u64> {
        let mut result = Vec::with_capacity(self.nodes.len());
        let mut visited = HashSet::with_capacity(self.nodes.len());

        self.push_postorder(self.root, &mut visited, &mut result);

        // Robustness for malformed in-memory DAGs: include any nodes not
        // reachable from the recorded root, still preserving child-before-parent
        // order within each reachable component. A well-formed DAG has every
        // node reachable from the root, so the walk already emitted all of them
        // — skip the all-nodes sweep unless something was left out (each sweep
        // call is otherwise a redundant already-visited probe).
        if result.len() != self.nodes.len() {
            for block in self.nodes.keys().copied() {
                self.push_postorder(block, &mut visited, &mut result);
            }
        }

        trace!(
            order_len = result.len(),
            "writeback dag reverse_topological_order"
        );
        result
    }

    fn push_postorder(&self, block: u64, visited: &mut HashSet<u64>, result: &mut Vec<u64>) {
        if !visited.insert(block) {
            return;
        }

        let Some(node) = self.nodes.get(&block) else {
            return;
        };

        for child in &node.children {
            self.push_postorder(*child, visited, result);
        }

        result.push(block);
    }

    /// Reverse topological order paired with each node's tree level.
    ///
    /// Identical block order to `reverse_topological_order`, but the level is
    /// read from the same node visited during the postorder walk. This lets
    /// the writeback executor flush each node without a second per-node probe
    /// of the node map (`node_level`) — the block always has a node here (the
    /// postorder walk only pushes blocks it resolved), so the paired level is
    /// exactly what `node_level(block).unwrap_or(0)` would return.
    pub fn reverse_topological_order_with_levels(&self) -> Vec<(u64, u8)> {
        let mut result = Vec::with_capacity(self.nodes.len());
        let mut visited = HashSet::with_capacity(self.nodes.len());

        self.push_postorder_with_levels(self.root, &mut visited, &mut result);

        // Same well-formed-DAG fast path as reverse_topological_order: skip the
        // all-nodes sweep when the root walk already emitted every node.
        if result.len() != self.nodes.len() {
            for block in self.nodes.keys().copied() {
                self.push_postorder_with_levels(block, &mut visited, &mut result);
            }
        }

        result
    }

    /// Visit nodes in reverse topological order together with their levels.
    ///
    /// This is the streaming counterpart to
    /// [`Self::reverse_topological_order_with_levels`]. Production writeback
    /// consumes each pair exactly once, so it can avoid materializing the
    /// temporary vector while retaining the same malformed-DAG fallback and
    /// child-before-parent ordering.
    pub fn try_for_each_reverse_topological_with_levels<E, F>(&self, mut visit: F) -> Result<(), E>
    where
        F: FnMut(u64, u8) -> Result<(), E>,
    {
        let mut visited = HashSet::with_capacity(self.nodes.len());
        let mut emitted = 0usize;
        self.try_push_postorder_with_levels(self.root, &mut visited, &mut emitted, &mut visit)?;

        if emitted != self.nodes.len() {
            for block in self.nodes.keys().copied() {
                self.try_push_postorder_with_levels(block, &mut visited, &mut emitted, &mut visit)?;
            }
        }

        Ok(())
    }

    fn push_postorder_with_levels(
        &self,
        block: u64,
        visited: &mut HashSet<u64>,
        result: &mut Vec<(u64, u8)>,
    ) {
        if !visited.insert(block) {
            return;
        }

        let Some(node) = self.nodes.get(&block) else {
            return;
        };

        for child in &node.children {
            self.push_postorder_with_levels(*child, visited, result);
        }

        result.push((block, node.level));
    }

    fn try_push_postorder_with_levels<E, F>(
        &self,
        block: u64,
        visited: &mut HashSet<u64>,
        emitted: &mut usize,
        visit: &mut F,
    ) -> Result<(), E>
    where
        F: FnMut(u64, u8) -> Result<(), E>,
    {
        if !visited.insert(block) {
            return Ok(());
        }

        let Some(node) = self.nodes.get(&block) else {
            return Ok(());
        };

        for child in &node.children {
            self.try_push_postorder_with_levels(*child, visited, emitted, visit)?;
        }

        visit(block, node.level)?;
        *emitted = emitted.saturating_add(1);
        Ok(())
    }

    fn durable_block_set(&self) -> BTreeSet<u64> {
        self.nodes
            .iter()
            .filter(|(_, node)| node.durable)
            .map(|(block, _)| *block)
            .collect()
    }

    /// Mark a node as durable after it has been successfully flushed.
    pub fn mark_durable(&mut self, block: u64) -> Result<(), BtrfsMutationError> {
        let node = self
            .nodes
            .get_mut(&block)
            .ok_or(BtrfsMutationError::MissingNode(block))?;
        node.durable = true;
        trace!(block, "writeback dag mark_durable");
        Ok(())
    }

    /// Check if a node is durable.
    pub fn is_durable(&self, block: u64) -> bool {
        self.nodes.get(&block).is_some_and(|n| n.durable)
    }

    /// Return the root block number.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Return the current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the number of nodes in the DAG.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return all blocks in the DAG.
    pub fn blocks(&self) -> impl Iterator<Item = u64> + '_ {
        self.nodes.keys().copied()
    }

    /// Return block numbers and tree levels in ascending block-number order.
    pub fn blocks_with_levels(&self) -> impl Iterator<Item = (u64, u8)> + '_ {
        self.nodes.iter().map(|(block, node)| (*block, node.level))
    }

    /// Return all block numbers as a collected Vec.
    pub fn all_blocks(&self) -> Vec<u64> {
        self.nodes.keys().copied().collect()
    }

    /// Get a node by block number.
    pub fn get(&self, block: u64) -> Option<&DagNode> {
        self.nodes.get(&block)
    }

    /// Get the tree level of a node (0 = leaf).
    pub fn node_level(&self, block: u64) -> Option<u8> {
        self.nodes.get(&block).map(|n| n.level)
    }
}

/// WB-I1 oracle: verify prefix-closed durability.
///
/// At every crash point, the set of durable nodes must be prefix-closed:
/// no durable internal node may point at a non-durable child.
#[derive(Debug, Clone)]
pub struct WbI1Oracle {
    /// Blocks that are known durable.
    durable_blocks: BTreeSet<u64>,
}

impl WbI1Oracle {
    /// Create a new WB-I1 oracle with the given durable block set.
    pub fn new(durable_blocks: BTreeSet<u64>) -> Self {
        Self { durable_blocks }
    }

    /// Create from a DAG's current durability state.
    pub fn from_dag(dag: &WriteDependencyDag) -> Self {
        let durable_blocks = dag.durable_block_set();
        Self { durable_blocks }
    }

    /// Check WB-I1: every durable internal node's children must also be durable.
    ///
    /// Returns `Ok(())` if the invariant holds, or `Err` with the violating block.
    pub fn check(&self, dag: &WriteDependencyDag) -> Result<(), WbI1Violation> {
        for (block, node) in &dag.nodes {
            if !self.durable_blocks.contains(block) {
                continue;
            }
            // This node is durable; all its children must also be durable
            for child in &node.children {
                if !self.durable_blocks.contains(child) {
                    return Err(WbI1Violation {
                        durable_parent: *block,
                        non_durable_child: *child,
                    });
                }
            }
        }
        debug!(
            durable_count = self.durable_blocks.len(),
            "wb_i1 check passed"
        );
        Ok(())
    }

    /// Mark a block as durable.
    pub fn mark_durable(&mut self, block: u64) {
        self.durable_blocks.insert(block);
    }

    /// Check if a block is durable.
    pub fn is_durable(&self, block: u64) -> bool {
        self.durable_blocks.contains(&block)
    }
}

/// WB-I1 violation: a durable parent references a non-durable child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WbI1Violation {
    /// The durable internal node.
    pub durable_parent: u64,
    /// The non-durable child it references.
    pub non_durable_child: u64,
}

impl std::fmt::Display for WbI1Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WB-I1 violation: durable block {} references non-durable child {}",
            self.durable_parent, self.non_durable_child
        )
    }
}

impl std::error::Error for WbI1Violation {}

/// WB-I2 oracle: verify atomic generation transition.
///
/// After a crash, the observed generation must be exactly `g` or `g+1`,
/// never a torn mixture.
#[derive(Debug, Clone)]
pub struct WbI2Oracle {
    /// Pre-commit generation.
    pub pre_generation: u64,
    /// Post-commit generation (pre + 1).
    pub post_generation: u64,
}

impl WbI2Oracle {
    /// Create a new WB-I2 oracle for a commit from generation `g` to `g+1`.
    pub fn new(pre_generation: u64) -> Self {
        Self {
            pre_generation,
            post_generation: pre_generation.saturating_add(1),
        }
    }

    /// Check WB-I2: observed generation must be pre or post, not torn.
    pub fn check(&self, observed_generation: u64) -> Result<(), WbI2Violation> {
        if observed_generation == self.pre_generation || observed_generation == self.post_generation
        {
            debug!(
                observed = observed_generation,
                pre = self.pre_generation,
                post = self.post_generation,
                "wb_i2 check passed"
            );
            Ok(())
        } else {
            Err(WbI2Violation {
                expected_pre: self.pre_generation,
                expected_post: self.post_generation,
                observed: observed_generation,
            })
        }
    }
}

/// WB-I2 violation: observed generation is neither pre nor post commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WbI2Violation {
    /// Expected pre-commit generation.
    pub expected_pre: u64,
    /// Expected post-commit generation.
    pub expected_post: u64,
    /// Actually observed generation.
    pub observed: u64,
}

impl std::fmt::Display for WbI2Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WB-I2 violation: expected generation {} or {}, observed {}",
            self.expected_pre, self.expected_post, self.observed
        )
    }
}

impl std::error::Error for WbI2Violation {}

/// Crash point in a writeback sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashPoint {
    /// Unique identifier for this crash point.
    pub id: String,
    /// Blocks that were durable at this crash point.
    pub durable_blocks: BTreeSet<u64>,
    /// Whether the superblock was durable.
    pub superblock_durable: bool,
    /// Generation of the superblock if durable.
    pub superblock_generation: Option<u64>,
}

impl CrashPoint {
    /// Create a crash point from a DAG's current state.
    pub fn from_dag(
        dag: &WriteDependencyDag,
        id: impl Into<String>,
        superblock_durable: bool,
    ) -> Self {
        let durable_blocks = dag.durable_block_set();
        Self::from_durable_blocks(&durable_blocks, id, superblock_durable, dag.generation)
    }

    fn from_durable_blocks(
        durable_blocks: &BTreeSet<u64>,
        id: impl Into<String>,
        superblock_durable: bool,
        generation: u64,
    ) -> Self {
        Self {
            id: id.into(),
            durable_blocks: durable_blocks.clone(),
            superblock_durable,
            superblock_generation: if superblock_durable {
                Some(generation)
            } else {
                None
            },
        }
    }
}

/// Writeback executor that flushes nodes in correct order and tracks crash points.
#[derive(Debug)]
pub struct WritebackExecutor {
    dag: WriteDependencyDag,
    crash_points: Vec<CrashPoint>,
    fsync_barrier_issued: bool,
    record_crash_points: bool,
}

impl WritebackExecutor {
    /// Create a new writeback executor for the given DAG.
    ///
    /// Crash-point recording is enabled by default so the DPOR / WB-I1
    /// verification tests can inspect `crash_points()`.
    pub fn new(dag: WriteDependencyDag) -> Self {
        Self {
            dag,
            crash_points: Vec::new(),
            fsync_barrier_issued: false,
            record_crash_points: true,
        }
    }

    /// Disable per-flush crash-point recording for this executor.
    ///
    /// The production btrfs commit path drives writeback purely for its disk
    /// side effects (`flush_node`) and never reads `crash_points()` or calls
    /// `verify_wb_i1()`. Recording them there is pure waste: each `execute`
    /// otherwise clones the growing durable-block `BTreeSet` twice per node
    /// (O(N²) copies) and formats two per-node id strings. Turning it off is
    /// byte-identical on the disk output — the `flush_node` closure still sees
    /// the exact same `(block, level)` sequence — it only drops the unread
    /// telemetry. Test / verification callers keep the default (recording on).
    #[must_use]
    pub fn without_crash_tracking(mut self) -> Self {
        self.record_crash_points = false;
        self
    }

    /// Execute writeback in reverse topological order.
    ///
    /// The `flush_node` callback is called for each node in order. It should
    /// perform the actual I/O and return `Ok(())` on success.
    ///
    /// Crash points are recorded after each flush for DPOR enumeration.
    pub fn execute<F>(&mut self, mut flush_node: F) -> Result<(), BtrfsMutationError>
    where
        F: FnMut(u64, u8) -> Result<(), BtrfsMutationError>,
    {
        let total = self.dag.node_count();
        let generation = self.dag.generation;
        if !self.record_crash_points {
            let mut flushed = 0usize;
            self.dag
                .try_for_each_reverse_topological_with_levels(|block, level| {
                    flush_node(block, level)?;
                    trace!(
                        block,
                        progress = flushed + 1,
                        total,
                        "writeback executor flushed node"
                    );
                    flushed = flushed.saturating_add(1);
                    Ok(())
                })?;
            return Ok(());
        }

        // The running durable-block set and the per-node `mark_durable` exist
        // solely to build crash points and verify WB-I1 (both test/verification
        // only). Production writeback never reads DAG durability, so skip the
        // whole bookkeeping — including the O(N) `durable_block_set` seed and the
        // per-node node-map `get_mut` — when crash tracking is off. Byte-identical
        // on disk: `flush_node` still runs for every (block, level) and the
        // durable flag is never serialized.
        self.crash_points.reserve(total.saturating_mul(2));
        let mut durable_blocks = self.dag.durable_block_set();
        let order = self.dag.reverse_topological_order_with_levels();

        for (flushed, (block, level)) in order.into_iter().enumerate() {
            // Record crash point before this flush (test/verification only)
            let pre_crash_id = format!("pre_flush_{}", block);
            self.crash_points.push(CrashPoint::from_durable_blocks(
                &durable_blocks,
                pre_crash_id,
                false,
                generation,
            ));

            // Flush the node
            flush_node(block, level)?;

            // Durability bookkeeping + post-flush crash point (test/verification
            // only): mark_durable mutates only the in-memory durable flag.
            self.dag.mark_durable(block)?;
            durable_blocks.insert(block);
            let post_crash_id = format!("post_flush_{}", block);
            self.crash_points.push(CrashPoint::from_durable_blocks(
                &durable_blocks,
                post_crash_id,
                false,
                generation,
            ));

            trace!(
                block,
                progress = flushed + 1,
                total,
                "writeback executor flushed node"
            );
        }

        Ok(())
    }

    /// Issue fsync barrier before superblock write.
    pub fn fsync_barrier(&mut self) {
        self.fsync_barrier_issued = true;
        if self.record_crash_points {
            let durable_blocks = self.dag.durable_block_set();
            let generation = self.dag.generation;
            self.crash_points.push(CrashPoint::from_durable_blocks(
                &durable_blocks,
                "pre_fsync_barrier",
                false,
                generation,
            ));
            self.crash_points.push(CrashPoint::from_durable_blocks(
                &durable_blocks,
                "post_fsync_barrier",
                false,
                generation,
            ));
        }
        debug!("writeback executor fsync barrier issued");
    }

    /// Record superblock commit.
    pub fn commit_superblock(&mut self) {
        if self.record_crash_points {
            let durable_blocks = self.dag.durable_block_set();
            let generation = self.dag.generation;
            self.crash_points.push(CrashPoint::from_durable_blocks(
                &durable_blocks,
                "pre_superblock",
                false,
                generation,
            ));
            // After superblock write, the commit is durable
            self.crash_points.push(CrashPoint::from_durable_blocks(
                &durable_blocks,
                "post_superblock",
                true,
                generation,
            ));
        }
        debug!(
            generation = self.dag.generation,
            "writeback executor superblock committed"
        );
    }

    /// Return all crash points recorded during execution.
    pub fn crash_points(&self) -> &[CrashPoint] {
        &self.crash_points
    }

    /// Verify WB-I1 holds at all crash points.
    pub fn verify_wb_i1(&self) -> Result<(), WbI1Violation> {
        for crash_point in &self.crash_points {
            let oracle = WbI1Oracle::new(crash_point.durable_blocks.clone());
            oracle.check(&self.dag)?;
        }
        debug!(
            crash_points = self.crash_points.len(),
            "wb_i1 verified at all crash points"
        );
        Ok(())
    }

    /// Return the underlying DAG.
    pub fn dag(&self) -> &WriteDependencyDag {
        &self.dag
    }
}

/// Context for writing serialized CoW nodes to a real block device.
///
/// This bridges the in-memory `InMemoryCowBtrfsTree` to actual disk I/O,
/// preserving WB-I1 (prefix-closed durability) via reverse-topological flush.
#[derive(Debug)]
pub struct DiskWritebackContext {
    /// Filesystem UUID.
    pub fsid: [u8; 16],
    /// Chunk tree UUID.
    pub chunk_tree_uuid: [u8; 16],
    /// Current transaction generation.
    pub generation: u64,
    /// Tree ID that owns these nodes (e.g., FS_TREE = 5).
    pub owner: u64,
    /// Node size in bytes (from superblock).
    pub nodesize: u32,
    /// Checksum algorithm every serialized node is stamped with (from
    /// superblock `0xC4`).
    ///
    /// A constructor ARGUMENT, not a defaulted field, and deliberately so: a
    /// default here would be a crc32c stamp silently applied to an xxhash64
    /// filesystem, producing blocks the kernel refuses while our own reader
    /// agrees with them. Making it positional costs every caller one argument
    /// and buys a compiler error instead of a corrupt image.
    pub csum_type: u16,
    /// Block device sector size.
    pub sector_size: u32,
    /// Mapping from in-memory block numbers to allocated logical addresses.
    ///
    /// When `Some`, these are real chunk-covered addresses from the allocator.
    /// When `None`, falls back to the simulator-only synthetic
    /// `block * nodesize` mapping.
    allocated_addrs: Option<BTreeMap<u64, u64>>,
    /// bd-42gtq: per-block on-disk generation, for blocks this transaction is
    /// NOT rewriting.
    ///
    /// btrfs stores a generation in every parent key_ptr and a reader verifies it
    /// against the child block's own header — that check is what reports
    /// `parent transid verify failed ... wanted G found H` and refuses the whole
    /// filesystem with `open_ctree -5` (bd-73bi2, a P0). So a commit that reuses
    /// an unchanged child block MUST stamp that child's real generation into the
    /// COWed parent's pointer, not the transaction's.
    ///
    /// Absent (or missing an entry) means "this block is being written by this
    /// transaction", so it carries `generation` — which is exactly the previous
    /// behaviour for every caller that does not supply this map.
    block_generations: Option<BTreeMap<u64, u64>>,
}

impl DiskWritebackContext {
    /// Create a disk writeback context that uses the simulator-only synthetic mapping.
    pub fn new(
        fsid: [u8; 16],
        chunk_tree_uuid: [u8; 16],
        generation: u64,
        owner: u64,
        nodesize: u32,
        csum_type: u16,
        sector_size: u32,
    ) -> Self {
        Self {
            fsid,
            chunk_tree_uuid,
            generation,
            owner,
            nodesize,
            csum_type,
            sector_size,
            allocated_addrs: None,
            block_generations: None,
        }
    }

    /// Create a disk writeback context with pre-allocated logical addresses.
    ///
    /// The `allocated_addrs` map provides real chunk-covered logical addresses
    /// for each in-memory block number. These addresses must be obtained from
    /// `BtrfsAllocState::alloc_metadata_for_tree` before calling this.
    #[expect(
        clippy::too_many_arguments,
        reason = "a field-wise constructor: the arguments ARE the struct's fields, in \
                  declaration order, and this has callers in two crates."
    )]
    pub fn with_allocated_addresses(
        fsid: [u8; 16],
        chunk_tree_uuid: [u8; 16],
        generation: u64,
        owner: u64,
        nodesize: u32,
        csum_type: u16,
        sector_size: u32,
        allocated_addrs: BTreeMap<u64, u64>,
    ) -> Self {
        Self {
            fsid,
            chunk_tree_uuid,
            generation,
            owner,
            nodesize,
            csum_type,
            sector_size,
            allocated_addrs: Some(allocated_addrs),
            block_generations: None,
        }
    }

    /// Same as [`Self::with_allocated_addresses`], plus the on-disk generation of
    /// each block this transaction is NOT rewriting (bd-42gtq).
    ///
    /// Only blocks being reused need an entry; anything absent is treated as
    /// written-by-this-transaction and carries `generation`, so passing an empty
    /// map is byte-identical to [`Self::with_allocated_addresses`].
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "a field-wise constructor: the nine arguments ARE the struct's nine \
                  fields, in declaration order. Grouping them into a parameter struct \
                  would add a type whose only purpose is to be destructured immediately, \
                  and this has callers in two crates."
    )]
    pub fn with_allocated_addresses_and_generations(
        fsid: [u8; 16],
        chunk_tree_uuid: [u8; 16],
        generation: u64,
        owner: u64,
        nodesize: u32,
        csum_type: u16,
        sector_size: u32,
        allocated_addrs: BTreeMap<u64, u64>,
        block_generations: BTreeMap<u64, u64>,
    ) -> Self {
        Self {
            fsid,
            chunk_tree_uuid,
            generation,
            owner,
            nodesize,
            csum_type,
            sector_size,
            allocated_addrs: Some(allocated_addrs),
            block_generations: Some(block_generations),
        }
    }

    /// The generation a parent key_ptr must record for `block`.
    ///
    /// The child's own on-disk generation when this transaction is reusing it
    /// rather than rewriting it; otherwise this transaction's. Getting this wrong
    /// in the reuse direction is `open_ctree -5` (bd-73bi2).
    #[must_use]
    pub fn generation_of_block(&self, block: u64) -> u64 {
        self.block_generations
            .as_ref()
            .and_then(|gens| gens.get(&block).copied())
            .unwrap_or(self.generation)
    }

    /// Convert an in-memory block number to a disk byte offset.
    ///
    /// If allocated addresses are provided, returns the real logical address.
    /// Otherwise, falls back to the simulator-only synthetic
    /// `bytenr = block * nodesize` mapping.
    #[must_use]
    pub fn block_to_bytenr(&self, block: u64) -> u64 {
        let fallback = block.saturating_mul(u64::from(self.nodesize));
        self.allocated_addrs
            .as_ref()
            .and_then(|addrs| addrs.get(&block).copied())
            .unwrap_or(fallback)
    }

    /// Returns true if this context uses real allocated addresses.
    #[must_use]
    pub fn has_allocated_addresses(&self) -> bool {
        self.allocated_addrs.is_some()
    }

    /// Build serialization parameters for a node at the given block.
    ///
    /// `level` is the tree level (0 for leaves, 1+ for internal nodes).
    /// `child_bytenrs` should be the allocated on-disk addresses of each
    /// child (for internal nodes) when this context was constructed with a
    /// real allocation map. Pass an empty vector for leaves or when the
    /// caller wants the legacy "children are in-memory block numbers"
    /// behavior (simulator / standalone serializer tests).
    #[must_use]
    pub fn params_for_block(
        &self,
        block: u64,
        level: u8,
        child_generations: Vec<u64>,
        child_bytenrs: Vec<u64>,
        child_min_keys: Vec<crate::BtrfsKey>,
    ) -> crate::BtrfsNodeSerializeParams {
        crate::BtrfsNodeSerializeParams {
            fsid: self.fsid,
            chunk_tree_uuid: self.chunk_tree_uuid,
            bytenr: self.block_to_bytenr(block),
            // WRITTEN + MIXED backref revision, matching real btrfs. The backref
            // revision (high byte) is what makes `btrfs check` read the inline
            // TREE_BLOCK_REFs (bd-fdwuh); the old default of 0 made it ignore
            // them and report "extent item 0 / no backref" for every block.
            flags: crate::BTRFS_HEADER_FLAGS_COMMITTED,
            generation: self.generation,
            owner: self.owner,
            nodesize: self.nodesize,
            level,
            child_generations,
            child_bytenrs,
            child_min_keys,
            csum_type: self.csum_type,
        }
    }

    /// Serialize a node and return the bytes ready for disk write.
    ///
    /// `level` is the node's level in the tree (0 for leaf, 1+ for internal).
    ///
    /// For internal nodes, child blockptrs in the serialized bytes are
    /// resolved through the allocation map (when present) so that the
    /// on-disk node references its children by their allocated logical
    /// addresses — not by the in-memory block numbers the CoW tree uses
    /// internally. When the context has no allocation map (test mode),
    /// children fall back to the legacy `block * nodesize` mapping via
    /// `block_to_bytenr`, which is what the simulator expects.
    pub fn serialize_node(
        &self,
        tree: &InMemoryCowBtrfsTree,
        block: u64,
        level: u8,
    ) -> Result<Vec<u8>, BtrfsMutationError> {
        let node = tree.node_snapshot(block)?;

        let (child_generations, child_bytenrs, child_min_keys) = match &node {
            BtrfsCowNode::Leaf { .. } => (Vec::new(), Vec::new(), Vec::new()),
            BtrfsCowNode::Internal { children, .. } => {
                // bd-42gtq: each child's OWN on-disk generation, which is this
                // transaction's for a child it rewrites and the child's existing
                // one for a child it reuses. Stamping `self.generation`
                // unconditionally is only correct while every block is rewritten
                // every commit; once blocks are reused it is `parent transid
                // verify failed` and the kernel refuses the filesystem.
                let gens = children
                    .iter()
                    .map(|c| self.generation_of_block(*c))
                    .collect();
                let bytenrs = children.iter().map(|c| self.block_to_bytenr(*c)).collect();
                // Each key_ptr must carry the child's true subtree minimum key,
                // not the CoW separator (bd-6uyto).
                let mut mins = Vec::with_capacity(children.len());
                for child in children {
                    let min = tree.subtree_min_key(*child)?.ok_or(
                        BtrfsMutationError::BrokenInvariant("internal child subtree is empty"),
                    )?;
                    mins.push(min);
                }
                (gens, bytenrs, mins)
            }
        };

        let params = self.params_for_block(
            block,
            level,
            child_generations,
            child_bytenrs,
            child_min_keys,
        );
        node.serialize(&params)
    }
}

// ── Backup Root Ring (design §6.3) ───────────────────────────────────────────

/// Size of one btrfs_root_backup entry in bytes.
pub const BTRFS_ROOT_BACKUP_SIZE: usize = 168;

/// Number of backup root slots in the superblock.
pub const BTRFS_NUM_BACKUP_ROOTS: usize = 4;

/// Offset of the `super_roots[4]` array in the superblock.
pub const BTRFS_BACKUP_ROOTS_OFFSET: usize = 0x2A0;

/// One entry in the superblock's backup root ring (btrfs_root_backup).
///
/// Preserves the root tree location and generation for crash recovery.
/// The ring holds the last 4 committed states, enabling recovery from
/// a corrupted/torn superblock by falling back to an older root tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackupRootEntry {
    /// Root tree location.
    pub tree_root: u64,
    /// Root tree generation.
    pub tree_root_gen: u64,
    /// Chunk tree location.
    pub chunk_root: u64,
    /// Chunk tree generation.
    pub chunk_root_gen: u64,
    /// Extent tree location.
    pub extent_root: u64,
    /// Extent tree generation.
    pub extent_root_gen: u64,
    /// FS tree location.
    pub fs_root: u64,
    /// FS tree generation.
    pub fs_root_gen: u64,
    /// Device tree location.
    pub dev_root: u64,
    /// Device tree generation.
    pub dev_root_gen: u64,
    /// Checksum tree location.
    pub csum_root: u64,
    /// Csum tree generation.
    pub csum_root_gen: u64,
    /// Total bytes in filesystem.
    pub total_bytes: u64,
    /// Bytes used.
    pub bytes_used: u64,
    /// Number of devices.
    pub num_devices: u64,
    /// Root tree level.
    pub tree_root_level: u8,
    /// Chunk tree level.
    pub chunk_root_level: u8,
    /// Extent tree level.
    pub extent_root_level: u8,
    /// FS tree level.
    pub fs_root_level: u8,
    /// Device tree level.
    pub dev_root_level: u8,
    /// Checksum tree level.
    pub csum_root_level: u8,
}

impl BackupRootEntry {
    /// Parse a backup root entry from a 168-byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, BtrfsMutationError> {
        if data.len() < BTRFS_ROOT_BACKUP_SIZE {
            return Err(BtrfsMutationError::InvalidConfig(
                "backup root entry too short",
            ));
        }
        Ok(Self {
            tree_root: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_root_gen: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            chunk_root: u64::from_le_bytes(data[16..24].try_into().unwrap()),
            chunk_root_gen: u64::from_le_bytes(data[24..32].try_into().unwrap()),
            extent_root: u64::from_le_bytes(data[32..40].try_into().unwrap()),
            extent_root_gen: u64::from_le_bytes(data[40..48].try_into().unwrap()),
            fs_root: u64::from_le_bytes(data[48..56].try_into().unwrap()),
            fs_root_gen: u64::from_le_bytes(data[56..64].try_into().unwrap()),
            dev_root: u64::from_le_bytes(data[64..72].try_into().unwrap()),
            dev_root_gen: u64::from_le_bytes(data[72..80].try_into().unwrap()),
            csum_root: u64::from_le_bytes(data[80..88].try_into().unwrap()),
            csum_root_gen: u64::from_le_bytes(data[88..96].try_into().unwrap()),
            total_bytes: u64::from_le_bytes(data[96..104].try_into().unwrap()),
            bytes_used: u64::from_le_bytes(data[104..112].try_into().unwrap()),
            num_devices: u64::from_le_bytes(data[112..120].try_into().unwrap()),
            // unused_64[4] at 120..152
            tree_root_level: data[152],
            chunk_root_level: data[153],
            extent_root_level: data[154],
            fs_root_level: data[155],
            dev_root_level: data[156],
            csum_root_level: data[157],
            // unused_8[10] at 158..168
        })
    }

    /// Serialize this backup root entry to 168 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BTRFS_ROOT_BACKUP_SIZE] {
        let mut buf = [0u8; BTRFS_ROOT_BACKUP_SIZE];
        buf[0..8].copy_from_slice(&self.tree_root.to_le_bytes());
        buf[8..16].copy_from_slice(&self.tree_root_gen.to_le_bytes());
        buf[16..24].copy_from_slice(&self.chunk_root.to_le_bytes());
        buf[24..32].copy_from_slice(&self.chunk_root_gen.to_le_bytes());
        buf[32..40].copy_from_slice(&self.extent_root.to_le_bytes());
        buf[40..48].copy_from_slice(&self.extent_root_gen.to_le_bytes());
        buf[48..56].copy_from_slice(&self.fs_root.to_le_bytes());
        buf[56..64].copy_from_slice(&self.fs_root_gen.to_le_bytes());
        buf[64..72].copy_from_slice(&self.dev_root.to_le_bytes());
        buf[72..80].copy_from_slice(&self.dev_root_gen.to_le_bytes());
        buf[80..88].copy_from_slice(&self.csum_root.to_le_bytes());
        buf[88..96].copy_from_slice(&self.csum_root_gen.to_le_bytes());
        buf[96..104].copy_from_slice(&self.total_bytes.to_le_bytes());
        buf[104..112].copy_from_slice(&self.bytes_used.to_le_bytes());
        buf[112..120].copy_from_slice(&self.num_devices.to_le_bytes());
        // unused_64[4] at 120..152 stays zero
        buf[152] = self.tree_root_level;
        buf[153] = self.chunk_root_level;
        buf[154] = self.extent_root_level;
        buf[155] = self.fs_root_level;
        buf[156] = self.dev_root_level;
        buf[157] = self.csum_root_level;
        // unused_8[10] at 158..168 stays zero
        buf
    }
}

/// The backup root ring: `super_roots[4]` in the superblock.
///
/// On commit, the ring rotates: slot 3 ← slot 2 ← slot 1 ← slot 0 ← current.
/// This enables recovery from a corrupted superblock by falling back to
/// an older root tree state (generations g-3, g-2, g-1, g).
#[derive(Debug, Clone)]
pub struct BackupRootRing {
    entries: [BackupRootEntry; BTRFS_NUM_BACKUP_ROOTS],
}

impl Default for BackupRootRing {
    fn default() -> Self {
        Self {
            entries: [BackupRootEntry::default(); BTRFS_NUM_BACKUP_ROOTS],
        }
    }
}

impl BackupRootRing {
    /// Parse the backup root ring from a superblock region.
    pub fn parse(superblock: &[u8]) -> Result<Self, BtrfsMutationError> {
        let start = BTRFS_BACKUP_ROOTS_OFFSET;
        let end = start + BTRFS_NUM_BACKUP_ROOTS * BTRFS_ROOT_BACKUP_SIZE;
        if superblock.len() < end {
            return Err(BtrfsMutationError::InvalidConfig(
                "superblock too short for backup roots",
            ));
        }

        let mut entries = [BackupRootEntry::default(); BTRFS_NUM_BACKUP_ROOTS];
        for (i, entry) in entries.iter_mut().enumerate() {
            let offset = start + i * BTRFS_ROOT_BACKUP_SIZE;
            *entry = BackupRootEntry::parse(&superblock[offset..])?;
        }

        Ok(Self { entries })
    }

    /// Rotate the ring and insert a new entry at slot 0.
    ///
    /// Shifts: slot 3 ← slot 2 ← slot 1 ← slot 0 ← new_entry.
    pub fn rotate(&mut self, new_entry: BackupRootEntry) {
        self.entries[3] = self.entries[2];
        self.entries[2] = self.entries[1];
        self.entries[1] = self.entries[0];
        self.entries[0] = new_entry;
        trace!(
            tree_root = new_entry.tree_root,
            generation = new_entry.tree_root_gen,
            "backup root ring rotated"
        );
    }

    /// Get the entry at the given slot (0 = most recent).
    #[must_use]
    pub fn get(&self, slot: usize) -> Option<&BackupRootEntry> {
        self.entries.get(slot)
    }

    /// Get the most recent backup entry (slot 0).
    #[must_use]
    pub fn latest(&self) -> &BackupRootEntry {
        &self.entries[0]
    }

    /// Write the backup root ring to a superblock region.
    pub fn write_to(&self, superblock: &mut [u8]) -> Result<(), BtrfsMutationError> {
        let start = BTRFS_BACKUP_ROOTS_OFFSET;
        let end = start + BTRFS_NUM_BACKUP_ROOTS * BTRFS_ROOT_BACKUP_SIZE;
        if superblock.len() < end {
            return Err(BtrfsMutationError::InvalidConfig(
                "superblock too short for backup roots",
            ));
        }

        for (i, entry) in self.entries.iter().enumerate() {
            let offset = start + i * BTRFS_ROOT_BACKUP_SIZE;
            let bytes = entry.to_bytes();
            superblock[offset..offset + BTRFS_ROOT_BACKUP_SIZE].copy_from_slice(&bytes);
        }

        Ok(())
    }
}

// ── Atomic Root Commit Sequence (design §6.1-6.2) ────────────────────────────

/// Superblock mirror locations.
///
/// btrfs writes the superblock to multiple locations for redundancy:
/// - Primary: 64 KiB (0x10000)
/// - Mirror 1: 64 MiB (0x4000000)
/// - Mirror 2: 256 GiB (0x4000000000) — if device is large enough
pub const BTRFS_SUPERBLOCK_MIRRORS: [u64; 3] = [
    0x0001_0000,    // 64 KiB (primary)
    0x0400_0000,    // 64 MiB (mirror 1)
    0x40_0000_0000, // 256 GiB (mirror 2, optional)
];

/// Parameters for an atomic root commit.
#[derive(Debug, Clone)]
pub struct AtomicRootCommitParams {
    /// New root tree location (bytenr).
    pub root_tree_bytenr: u64,
    /// New root tree level.
    pub root_tree_level: u8,
    /// New generation (g+1).
    pub new_generation: u64,
    /// Chunk tree location (unchanged if None).
    pub chunk_root: Option<u64>,
    /// Chunk tree level (unchanged if None).
    pub chunk_root_level: Option<u8>,
    /// Extent tree location (for backup root entry).
    pub extent_root: u64,
    /// FS tree location (for backup root entry).
    pub fs_root: u64,
    /// Total bytes.
    pub total_bytes: u64,
    /// Bytes used.
    pub bytes_used: u64,
    /// Number of devices.
    pub num_devices: u64,
}

/// Result of an atomic root commit simulation.
#[derive(Debug, Clone)]
pub struct AtomicRootCommitResult {
    /// Whether the commit was successful (superblock durable).
    pub committed: bool,
    /// Generation observed after the commit (or crash).
    pub observed_generation: u64,
    /// Crash point ID if a crash occurred.
    pub crash_point_id: Option<String>,
    /// WB-I2 oracle result.
    pub wb_i2_passed: bool,
}

/// Atomic root commit executor.
///
/// Orchestrates the full commit sequence per design §6:
/// 1. ROOT_ITEM update per tree (via BtrfsRootItem::patch_root_commit)
/// 2. Flush root tree nodes
/// 3. fsync barrier
/// 4. Rotate backup root ring
/// 5. Superblock generation bump (the linearization point)
/// 6. Write superblock to all mirror locations
#[derive(Debug)]
pub struct AtomicRootCommit {
    /// Pre-commit generation.
    pre_generation: u64,
    /// Backup root ring state.
    backup_ring: BackupRootRing,
    /// Crash points for fault injection.
    crash_points: Vec<AtomicRootCrashPoint>,
    /// Whether the commit has completed.
    committed: bool,
}

/// A crash point in the atomic root commit sequence.
#[derive(Debug, Clone)]
pub struct AtomicRootCrashPoint {
    /// Unique identifier.
    pub id: String,
    /// Generation that would be observed if crash occurs here.
    pub observed_generation: u64,
    /// Whether the superblock has been committed.
    pub superblock_committed: bool,
    /// Phase of the commit sequence.
    pub phase: AtomicRootCommitPhase,
}

/// Phases of the atomic root commit sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicRootCommitPhase {
    /// Before any commit work begins.
    PreCommit,
    /// After ROOT_ITEM updates, before root tree flush.
    AfterRootItemUpdate,
    /// After root tree flush, before fsync barrier.
    AfterRootTreeFlush,
    /// After fsync barrier, before backup ring rotation.
    AfterFsyncBarrier,
    /// After backup ring rotation, before superblock write.
    AfterBackupRingRotation,
    /// After superblock write (the linearization point).
    AfterSuperblockWrite,
    /// After all mirror writes complete.
    AfterAllMirrorWrites,
}

impl AtomicRootCommit {
    /// Create a new atomic root commit executor.
    pub fn new(pre_generation: u64, backup_ring: BackupRootRing) -> Self {
        Self {
            pre_generation,
            backup_ring,
            crash_points: Vec::new(),
            committed: false,
        }
    }

    /// Create with a default (empty) backup ring.
    pub fn with_generation(pre_generation: u64) -> Self {
        Self::new(pre_generation, BackupRootRing::default())
    }

    /// Record a crash point at the current phase.
    fn record_crash_point(&mut self, id: impl Into<String>, phase: AtomicRootCommitPhase) {
        let observed_generation = if self.committed {
            self.pre_generation.saturating_add(1)
        } else {
            self.pre_generation
        };
        self.crash_points.push(AtomicRootCrashPoint {
            id: id.into(),
            observed_generation,
            superblock_committed: self.committed,
            phase,
        });
    }

    /// Execute the atomic root commit sequence (simulation).
    ///
    /// This simulates the commit, recording crash points at each phase.
    /// The actual I/O callbacks are provided for integration with real writeback.
    pub fn execute_simulation(&mut self, params: &AtomicRootCommitParams) {
        // Phase 0: Pre-commit
        self.record_crash_point("arc_pre_commit", AtomicRootCommitPhase::PreCommit);

        // Phase 1: ROOT_ITEM updates (simulated)
        self.record_crash_point(
            "arc_after_root_item_update",
            AtomicRootCommitPhase::AfterRootItemUpdate,
        );

        // Phase 2: Root tree flush (simulated)
        self.record_crash_point(
            "arc_after_root_tree_flush",
            AtomicRootCommitPhase::AfterRootTreeFlush,
        );

        // Phase 3: fsync barrier (simulated)
        self.record_crash_point(
            "arc_after_fsync_barrier",
            AtomicRootCommitPhase::AfterFsyncBarrier,
        );

        // Phase 4: Backup ring rotation
        let backup_entry = BackupRootEntry {
            tree_root: params.root_tree_bytenr,
            tree_root_gen: params.new_generation,
            chunk_root: params.chunk_root.unwrap_or(0),
            chunk_root_gen: params.new_generation,
            extent_root: params.extent_root,
            extent_root_gen: params.new_generation,
            fs_root: params.fs_root,
            fs_root_gen: params.new_generation,
            dev_root: 0,
            dev_root_gen: params.new_generation,
            csum_root: 0,
            csum_root_gen: params.new_generation,
            total_bytes: params.total_bytes,
            bytes_used: params.bytes_used,
            num_devices: params.num_devices,
            tree_root_level: params.root_tree_level,
            chunk_root_level: params.chunk_root_level.unwrap_or(0),
            extent_root_level: 0,
            fs_root_level: 0,
            dev_root_level: 0,
            csum_root_level: 0,
        };
        self.backup_ring.rotate(backup_entry);
        self.record_crash_point(
            "arc_after_backup_ring_rotation",
            AtomicRootCommitPhase::AfterBackupRingRotation,
        );

        // Phase 5: Superblock write — THE LINEARIZATION POINT
        // After this point, the commit is visible to readers.
        self.committed = true;
        self.record_crash_point(
            "arc_after_superblock_write",
            AtomicRootCommitPhase::AfterSuperblockWrite,
        );

        // Phase 6: Mirror writes (redundancy, not linearization)
        self.record_crash_point(
            "arc_after_all_mirror_writes",
            AtomicRootCommitPhase::AfterAllMirrorWrites,
        );

        debug!(
            pre_gen = self.pre_generation,
            new_gen = params.new_generation,
            root_bytenr = params.root_tree_bytenr,
            "atomic root commit simulation complete"
        );
    }

    /// Patch a superblock blob with new root and generation.
    ///
    /// Updates: root, root_level, generation, backup root ring, checksum.
    pub fn patch_superblock(
        &self,
        superblock: &mut [u8],
        params: &AtomicRootCommitParams,
    ) -> Result<(), BtrfsMutationError> {
        if superblock.len() < 4096 {
            return Err(BtrfsMutationError::InvalidConfig("superblock too short"));
        }

        // root at 0x50
        superblock[0x50..0x58].copy_from_slice(&params.root_tree_bytenr.to_le_bytes());
        // root_level at 0xC6
        superblock[0xC6] = params.root_tree_level;
        // generation at 0x48
        superblock[0x48..0x50].copy_from_slice(&params.new_generation.to_le_bytes());
        // chunk_root_generation at 0xA4
        superblock[0xA4..0xAC].copy_from_slice(&params.new_generation.to_le_bytes());

        // Write backup root ring
        self.backup_ring.write_to(superblock)?;

        // Recompute checksum (CRC32C over [0x20..])
        let csum = ffs_types::crc32c(&superblock[0x20..]);
        superblock[0..4].copy_from_slice(&csum.to_le_bytes());

        Ok(())
    }

    /// Return all recorded crash points.
    pub fn crash_points(&self) -> &[AtomicRootCrashPoint] {
        &self.crash_points
    }

    /// Verify WB-I2 at all crash points.
    ///
    /// WB-I2: A reader after crash observes generation g or g+1, never torn.
    pub fn verify_wb_i2(&self) -> Result<(), WbI2Violation> {
        let oracle = WbI2Oracle::new(self.pre_generation);
        for crash_point in &self.crash_points {
            oracle.check(crash_point.observed_generation)?;
        }
        debug!(
            crash_points = self.crash_points.len(),
            "atomic root commit WB-I2 verified"
        );
        Ok(())
    }

    /// Test WB-I2 at a specific crash point.
    pub fn test_wb_i2_at_crash_point(
        &self,
        crash_point_id: &str,
    ) -> Option<AtomicRootCommitResult> {
        let crash_point = self
            .crash_points
            .iter()
            .find(|cp| cp.id == crash_point_id)?;
        let oracle = WbI2Oracle::new(self.pre_generation);
        let wb_i2_result = oracle.check(crash_point.observed_generation);

        Some(AtomicRootCommitResult {
            committed: crash_point.superblock_committed,
            observed_generation: crash_point.observed_generation,
            crash_point_id: Some(crash_point.id.clone()),
            wb_i2_passed: wb_i2_result.is_ok(),
        })
    }

    /// Return the backup root ring.
    pub fn backup_ring(&self) -> &BackupRootRing {
        &self.backup_ring
    }

    /// Return whether the commit has completed.
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Return the pre-commit generation.
    pub fn pre_generation(&self) -> u64 {
        self.pre_generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree};

    fn make_test_tree() -> InMemoryCowBtrfsTree {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("create tree");
        // Insert some items to force tree structure
        for i in 0..10 {
            let key = BtrfsKey {
                objectid: i,
                item_type: 0x84, // INODE_ITEM
                offset: 0,
            };
            let data = vec![0u8; 100];
            tree.insert(key, &data).expect("insert");
        }
        tree
    }

    #[test]
    fn dag_from_cow_tree_captures_structure() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");

        assert!(dag.node_count() > 0, "dag should have nodes");
        assert_eq!(dag.generation(), 100);
        assert!(dag.get(dag.root()).is_some(), "root should be in dag");
    }

    #[test]
    fn reverse_topological_order_leaves_first() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let order = dag.reverse_topological_order();

        // All leaves (level 0) should come before internal nodes
        let mut seen_internal = false;
        for block in &order {
            let node = dag.get(*block).expect("node in dag");
            if node.level > 0 {
                seen_internal = true;
            } else if seen_internal {
                panic!(
                    "leaf {} appeared after internal node in reverse topo order",
                    block
                );
            }
        }
    }

    #[test]
    fn reverse_topological_order_preserves_internal_child_dependencies() {
        let generation = 100;
        let mut nodes = BTreeMap::new();
        nodes.insert(
            10,
            DagNode {
                block: 10,
                level: 2,
                generation,
                children: vec![20],
                durable: false,
            },
        );
        nodes.insert(
            20,
            DagNode {
                block: 20,
                level: 1,
                generation,
                children: vec![30],
                durable: false,
            },
        );
        nodes.insert(
            30,
            DagNode {
                block: 30,
                level: 0,
                generation,
                children: Vec::new(),
                durable: false,
            },
        );
        let dag = WriteDependencyDag {
            nodes,
            root: 10,
            generation,
        };

        let order = dag.reverse_topological_order();

        assert_eq!(
            order,
            vec![30, 20, 10],
            "every child must flush before the parent that references it"
        );
        for (parent, node) in &dag.nodes {
            let parent_pos = order
                .iter()
                .position(|block| block == parent)
                .expect("parent block appears in order");
            for child in &node.children {
                let child_pos = order
                    .iter()
                    .position(|block| block == child)
                    .expect("child block appears in order");
                assert!(
                    child_pos < parent_pos,
                    "child block {child} must precede parent block {parent}"
                );
            }
        }
    }

    #[test]
    fn streamed_reverse_topological_order_preserves_pairs_and_callback_errors() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let expected = dag.reverse_topological_order_with_levels();
        let mut streamed = Vec::new();

        dag.try_for_each_reverse_topological_with_levels(|block, level| {
            streamed.push((block, level));
            Ok::<(), ()>(())
        })
        .expect("streamed traversal succeeds");
        assert_eq!(streamed, expected);

        let error = dag.try_for_each_reverse_topological_with_levels(|_, _| Err("stop"));
        assert_eq!(error, Err("stop"));
    }

    fn reverse_topological_order_btree_model(dag: &WriteDependencyDag) -> Vec<u64> {
        fn push_postorder(
            dag: &WriteDependencyDag,
            block: u64,
            visited: &mut BTreeSet<u64>,
            result: &mut Vec<u64>,
        ) {
            if !visited.insert(block) {
                return;
            }

            let Some(node) = dag.get(block) else {
                return;
            };

            for child in &node.children {
                push_postorder(dag, *child, visited, result);
            }

            result.push(block);
        }

        let mut result = Vec::with_capacity(dag.node_count());
        let mut visited = BTreeSet::new();
        push_postorder(dag, dag.root(), &mut visited, &mut result);

        for block in dag.blocks() {
            push_postorder(dag, block, &mut visited, &mut result);
        }

        result
    }

    fn writeback_dag_double_clone_model(
        tree: &InMemoryCowBtrfsTree,
        generation: u64,
    ) -> Result<WriteDependencyDag, BtrfsMutationError> {
        fn collect_old(
            tree: &InMemoryCowBtrfsTree,
            block: u64,
            nodes: &mut BTreeMap<u64, DagNode>,
            generation: u64,
            level: u8,
        ) -> Result<(), BtrfsMutationError> {
            if nodes.contains_key(&block) {
                return Ok(());
            }

            let node = tree.node_snapshot(block)?;
            let (node_level, children) = match &node {
                BtrfsCowNode::Leaf { .. } => (0, Vec::new()),
                BtrfsCowNode::Internal { children, .. } => (level, children.clone()),
            };

            nodes.insert(
                block,
                DagNode {
                    block,
                    level: node_level,
                    generation,
                    children: children.clone(),
                    durable: false,
                },
            );

            let child_level = level.saturating_sub(1);
            for child in children {
                collect_old(tree, child, nodes, generation, child_level)?;
            }

            Ok(())
        }

        let mut nodes = BTreeMap::new();
        let root = tree.root_block();
        collect_old(tree, root, &mut nodes, generation, tree.root_level())?;
        Ok(WriteDependencyDag {
            nodes,
            root,
            generation,
        })
    }

    #[test]
    fn dag_build_single_clone_matches_double_clone_model() {
        let mut tree = InMemoryCowBtrfsTree::new(8).expect("create tree");
        for i in 0..512_u64 {
            let key = BtrfsKey {
                objectid: i,
                item_type: 0x84,
                offset: i * 4096,
            };
            tree.insert(key, &i.to_le_bytes()).expect("insert");
        }

        let old = writeback_dag_double_clone_model(&tree, 100).expect("old model");
        let new = WriteDependencyDag::from_cow_tree(&tree, 100).expect("production dag");

        assert_eq!(old.root(), new.root(), "root block changed");
        assert_eq!(old.generation(), new.generation(), "generation changed");
        assert_eq!(old.nodes, new.nodes, "DAG nodes changed");
        assert_eq!(
            reverse_topological_order_btree_model(&old),
            new.reverse_topological_order(),
            "child-vector move changed deterministic flush order"
        );

        let order = new.reverse_topological_order();
        for end in 0..=order.len() {
            let durable = order[..end].iter().copied().collect();
            WbI1Oracle::new(durable)
                .check(&new)
                .expect("every moved-child-vector flush prefix must satisfy WB-I1");
        }
    }

    #[test]
    fn reverse_topological_order_hashset_matches_btree_membership_model() {
        let mut tree = InMemoryCowBtrfsTree::new(8).expect("create tree");
        for i in 0..256_u64 {
            let key = BtrfsKey {
                objectid: i,
                item_type: 0x84,
                offset: i * 4096,
            };
            tree.insert(key, &i.to_le_bytes()).expect("insert");
        }
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");

        let order = dag.reverse_topological_order();
        let btree_model = reverse_topological_order_btree_model(&dag);
        assert_eq!(
            order, btree_model,
            "HashSet membership must not change deterministic flush order"
        );

        for end in 0..=order.len() {
            let durable = order[..end].iter().copied().collect();
            WbI1Oracle::new(durable)
                .check(&dag)
                .expect("every deterministic flush prefix must satisfy WB-I1");
        }
    }

    #[test]
    fn wb_i1_oracle_passes_for_empty_durable_set() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let oracle = WbI1Oracle::new(BTreeSet::new());

        // Empty durable set trivially satisfies WB-I1
        assert!(oracle.check(&dag).is_ok());
    }

    #[test]
    fn wb_i1_oracle_passes_for_leaves_only() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");

        // Mark only leaves as durable
        let leaves: BTreeSet<u64> = dag
            .nodes
            .iter()
            .filter(|(_, n)| n.level == 0)
            .map(|(b, _)| *b)
            .collect();

        let oracle = WbI1Oracle::new(leaves);
        assert!(
            oracle.check(&dag).is_ok(),
            "leaves-only should satisfy WB-I1"
        );
    }

    #[test]
    fn wb_i1_oracle_fails_for_parent_without_children() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");

        // Find an internal node
        let internal = dag
            .nodes
            .iter()
            .find(|(_, n)| !n.children.is_empty())
            .map(|(b, _)| *b);

        if let Some(block) = internal {
            // Mark only the internal node as durable (violates WB-I1)
            let mut durable = BTreeSet::new();
            durable.insert(block);
            let oracle = WbI1Oracle::new(durable);

            let result = oracle.check(&dag);
            assert!(
                result.is_err(),
                "parent without durable children should fail WB-I1"
            );
        }
    }

    #[test]
    fn wb_i2_oracle_accepts_valid_generations() {
        let oracle = WbI2Oracle::new(100);

        assert!(oracle.check(100).is_ok(), "pre-commit gen should pass");
        assert!(oracle.check(101).is_ok(), "post-commit gen should pass");
    }

    #[test]
    fn wb_i2_oracle_rejects_torn_generation() {
        let oracle = WbI2Oracle::new(100);

        assert!(oracle.check(99).is_err(), "old gen should fail");
        assert!(oracle.check(102).is_err(), "future gen should fail");
        assert!(oracle.check(50).is_err(), "random gen should fail");
    }

    #[test]
    fn writeback_executor_records_crash_points() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let mut executor = WritebackExecutor::new(dag);

        // Execute with no-op flush
        executor.execute(|_, _| Ok(())).expect("execute");
        executor.fsync_barrier();
        executor.commit_superblock();

        // Should have crash points: 2 per node + 2 for fsync + 2 for superblock
        let expected_min = executor.dag().node_count() * 2 + 4;
        assert!(
            executor.crash_points().len() >= expected_min,
            "should record crash points"
        );
    }

    #[test]
    fn writeback_executor_verifies_wb_i1() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let mut executor = WritebackExecutor::new(dag);

        executor.execute(|_, _| Ok(())).expect("execute");

        // WB-I1 should hold at all crash points after proper execution
        assert!(executor.verify_wb_i1().is_ok(), "WB-I1 should hold");
    }

    // ── Disk I/O round-trip tests (bd-jdo53 A4 wiring) ─────────────────────

    use ffs_ondisk::{BtrfsHeader, parse_leaf_items, verify_btrfs_tree_block_checksum};
    use std::cell::RefCell;

    const TEST_NODESIZE: u32 = 16384;
    const TEST_FSID: [u8; 16] = [0x11; 16];
    const TEST_CHUNK_UUID: [u8; 16] = [0x22; 16];

    fn make_disk_context(generation: u64) -> super::DiskWritebackContext {
        super::DiskWritebackContext::new(
            TEST_FSID,
            TEST_CHUNK_UUID,
            generation,
            5, // FS_TREE
            TEST_NODESIZE,
            ffs_types::BTRFS_CSUM_TYPE_CRC32C,
            4096,
        )
    }

    #[test]
    fn disk_writeback_context_block_to_bytenr() {
        let ctx = make_disk_context(100);
        assert!(!ctx.has_allocated_addresses());
        assert_eq!(ctx.block_to_bytenr(0), 0);
        assert_eq!(ctx.block_to_bytenr(1), 16_384);
        assert_eq!(ctx.block_to_bytenr(10), 163_840);
    }

    #[test]
    fn disk_writeback_context_allocated_addresses_override_synthetic_mapping() {
        let mut allocated_addrs = BTreeMap::new();
        allocated_addrs.insert(1, 0x4000_0000);
        allocated_addrs.insert(10, 0x4001_0000);

        let ctx = super::DiskWritebackContext::with_allocated_addresses(
            TEST_FSID,
            TEST_CHUNK_UUID,
            100,
            5,
            TEST_NODESIZE,
            ffs_types::BTRFS_CSUM_TYPE_CRC32C,
            4096,
            allocated_addrs,
        );

        assert!(ctx.has_allocated_addresses());
        assert_eq!(ctx.block_to_bytenr(1), 0x4000_0000);
        assert_eq!(ctx.block_to_bytenr(10), 0x4001_0000);
    }

    /// btrfs csum-type parity, write side: a node is stamped with the algorithm
    /// the context DECLARES, and a reader using the other one rejects it.
    ///
    /// PLANTED NEGATIVE. A `serialize` that hardcodes crc32c — which is what it
    /// did before this bead — passes the first assertion here and fails the
    /// second, because its stamp verifies as crc32c no matter what the context
    /// says. That is precisely the production defect: on an xxhash64 filesystem
    /// FrankenFS would write blocks only FrankenFS can read, and the kernel would
    /// refuse the filesystem at `open_ctree`.
    ///
    /// The cross-check in both directions is what makes this more than a
    /// round-trip: verifying a block only with the algorithm that wrote it is
    /// self-consistent for ANY implementation, correct or not.
    #[test]
    fn serialize_node_stamps_declared_csum_type_bd_csum_parity() {
        let tree = make_test_tree();
        let root = tree.root_block();
        // `make_test_tree` inserts enough items to force a real tree, so its root
        // is an INTERNAL node and serializing it at level 0 is rejected outright.
        // (`disk_writeback_context_serialize_leaf_roundtrip` guards this with an
        // `if let Leaf`, which is why it never noticed.)
        let level = match tree.node_snapshot(root).expect("root snapshot") {
            BtrfsCowNode::Leaf { .. } => 0,
            BtrfsCowNode::Internal { .. } => 1,
        };

        let xxh_ctx = super::DiskWritebackContext::new(
            TEST_FSID,
            TEST_CHUNK_UUID,
            100,
            5,
            TEST_NODESIZE,
            ffs_types::BTRFS_CSUM_TYPE_XXHASH64,
            4096,
        );
        let buf = xxh_ctx
            .serialize_node(&tree, root, level)
            .expect("serialize");
        verify_btrfs_tree_block_checksum(&buf, ffs_types::BTRFS_CSUM_TYPE_XXHASH64)
            .expect("a block stamped for an xxhash64 filesystem must verify as xxhash64");
        assert!(
            verify_btrfs_tree_block_checksum(&buf, ffs_types::BTRFS_CSUM_TYPE_CRC32C).is_err(),
            "an xxhash64-stamped block must NOT verify as crc32c — if it does, \
             serialize ignored csum_type and stamped crc32c"
        );

        // And the mirror image, so neither direction can pass by accident.
        let crc_ctx = make_disk_context(100);
        let crc_buf = crc_ctx
            .serialize_node(&tree, root, level)
            .expect("serialize");
        verify_btrfs_tree_block_checksum(&crc_buf, ffs_types::BTRFS_CSUM_TYPE_CRC32C)
            .expect("a crc32c filesystem's block must verify as crc32c");
        assert!(
            verify_btrfs_tree_block_checksum(&crc_buf, ffs_types::BTRFS_CSUM_TYPE_XXHASH64)
                .is_err(),
            "a crc32c-stamped block must not verify as xxhash64"
        );

        // The two stamps differ in the bytes, not merely in how they are read.
        assert_ne!(
            &buf[..8],
            &crc_buf[..8],
            "the same node under two algorithms must produce two different digests"
        );
        // Everything after the csum field is byte-identical: the algorithm
        // changes the checksum and nothing else about the block.
        assert_eq!(&buf[32..], &crc_buf[32..]);
    }

    #[test]
    fn disk_writeback_context_serialize_leaf_roundtrip() {
        let tree = make_test_tree();
        let ctx = make_disk_context(100);

        let root = tree.root_block();
        let node = tree.node_snapshot(root).expect("get root");

        if let BtrfsCowNode::Leaf { items } = &node {
            let buf = ctx.serialize_node(&tree, root, 0).expect("serialize");
            assert_eq!(buf.len(), TEST_NODESIZE as usize);

            verify_btrfs_tree_block_checksum(&buf, ffs_types::BTRFS_CSUM_TYPE_CRC32C)
                .expect("checksum valid");

            let hdr = BtrfsHeader::parse_from_block(&buf).expect("parse header");
            assert_eq!(hdr.generation, 100);
            assert_eq!(hdr.bytenr, ctx.block_to_bytenr(root));
            assert_eq!(hdr.nritems as usize, items.len());
            assert_eq!(hdr.level, 0);

            let (_, parsed) = parse_leaf_items(&buf).expect("parse items");
            assert_eq!(parsed.len(), items.len());
            for (orig, parsed) in items.iter().zip(parsed.iter()) {
                assert_eq!(orig.key.objectid, parsed.key.objectid);
                assert_eq!(orig.key.item_type, parsed.key.item_type);
                assert_eq!(orig.key.offset, parsed.key.offset);
            }
        }
    }

    #[test]
    #[expect(clippy::cast_possible_truncation)]
    fn disk_writeback_executor_writes_to_buffer() {
        let tree = make_test_tree();
        let ctx = make_disk_context(100);
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let mut executor = WritebackExecutor::new(dag);

        let disk: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 1024 * 1024]);

        executor
            .execute(|block, level| {
                let buf = ctx.serialize_node(&tree, block, level)?;
                let bytenr = ctx.block_to_bytenr(block) as usize;
                let end = bytenr + buf.len();
                disk.borrow_mut()[bytenr..end].copy_from_slice(&buf);
                Ok(())
            })
            .expect("execute");

        let order = executor.dag().reverse_topological_order();
        for block in &order {
            let bytenr = ctx.block_to_bytenr(*block) as usize;
            let end = bytenr + TEST_NODESIZE as usize;
            let node_bytes = &disk.borrow()[bytenr..end];

            verify_btrfs_tree_block_checksum(node_bytes, ffs_types::BTRFS_CSUM_TYPE_CRC32C)
                .expect("checksum valid after write");
        }

        assert!(executor.verify_wb_i1().is_ok(), "WB-I1 should hold");
    }

    #[test]
    fn disk_writeback_wb_i1_holds_at_every_crash_point() {
        let tree = make_test_tree();
        let ctx = make_disk_context(100);
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let mut executor = WritebackExecutor::new(dag);

        let writes: RefCell<Vec<(u64, Vec<u8>)>> = RefCell::new(Vec::new());

        executor
            .execute(|block, level| {
                let buf = ctx.serialize_node(&tree, block, level)?;
                writes.borrow_mut().push((block, buf));
                Ok(())
            })
            .expect("execute");

        for crash_point in executor.crash_points() {
            let oracle = WbI1Oracle::new(crash_point.durable_blocks.clone());
            oracle
                .check(executor.dag())
                .expect("WB-I1 must hold at every crash point");
        }
    }

    #[test]
    fn disk_writeback_partial_crash_leaves_prefix_closed() {
        let generation = 100_u64;
        let mut nodes = BTreeMap::new();
        nodes.insert(
            1,
            DagNode {
                block: 1,
                level: 1,
                generation,
                children: vec![2, 3],
                durable: false,
            },
        );
        nodes.insert(
            2,
            DagNode {
                block: 2,
                level: 0,
                generation,
                children: Vec::new(),
                durable: false,
            },
        );
        nodes.insert(
            3,
            DagNode {
                block: 3,
                level: 0,
                generation,
                children: Vec::new(),
                durable: false,
            },
        );
        let dag = WriteDependencyDag {
            nodes,
            root: 1,
            generation,
        };

        let order = dag.reverse_topological_order();
        assert_eq!(order.len(), 3);
        assert_eq!(order[2], 1, "root should be last");

        let prefixes = [
            vec![],
            vec![order[0]],
            vec![order[0], order[1]],
            vec![order[0], order[1], order[2]],
        ];

        for prefix in &prefixes {
            let durable: BTreeSet<u64> = prefix.iter().copied().collect();
            let oracle = WbI1Oracle::new(durable);
            oracle
                .check(&dag)
                .expect("every prefix of reverse-topo order must satisfy WB-I1");
        }
    }

    // ── Atomic Root Commit Tests (§6, WB-I2) ─────────────────────────────────

    fn make_commit_params(generation: u64) -> AtomicRootCommitParams {
        AtomicRootCommitParams {
            root_tree_bytenr: 0x1_0000,
            root_tree_level: 1,
            new_generation: generation,
            chunk_root: Some(0x2_0000),
            chunk_root_level: Some(0),
            extent_root: 0x3_0000,
            fs_root: 0x4_0000,
            total_bytes: 1024 * 1024 * 1024,
            bytes_used: 64 * 1024 * 1024,
            num_devices: 1,
        }
    }

    #[test]
    fn atomic_root_commit_records_all_crash_points() {
        let mut arc = AtomicRootCommit::with_generation(100);
        let params = make_commit_params(101);
        arc.execute_simulation(&params);

        assert_eq!(arc.crash_points().len(), 7, "should record 7 crash points");
        assert!(arc.is_committed(), "should be committed after simulation");
    }

    #[test]
    fn atomic_root_commit_wb_i2_pre_bump_sees_old_generation() {
        let mut arc = AtomicRootCommit::with_generation(100);
        let params = make_commit_params(101);
        arc.execute_simulation(&params);

        // All pre-superblock crash points should observe generation 100
        for crash_point in arc.crash_points() {
            if !crash_point.superblock_committed {
                assert_eq!(
                    crash_point.observed_generation, 100,
                    "pre-bump crash at {} should see generation 100",
                    crash_point.id
                );
            }
        }
    }

    #[test]
    fn atomic_root_commit_wb_i2_post_bump_sees_new_generation() {
        let mut arc = AtomicRootCommit::with_generation(100);
        let params = make_commit_params(101);
        arc.execute_simulation(&params);

        // Post-superblock crash points should observe generation 101
        for crash_point in arc.crash_points() {
            if crash_point.superblock_committed {
                assert_eq!(
                    crash_point.observed_generation, 101,
                    "post-bump crash at {} should see generation 101",
                    crash_point.id
                );
            }
        }
    }

    #[test]
    fn atomic_root_commit_wb_i2_holds_at_all_crash_points() {
        let mut arc = AtomicRootCommit::with_generation(100);
        let params = make_commit_params(101);
        arc.execute_simulation(&params);

        // WB-I2: observed generation is either 100 or 101, never torn
        arc.verify_wb_i2()
            .expect("WB-I2 must hold at all crash points");
    }

    #[test]
    fn atomic_root_commit_linearization_point_is_superblock_write() {
        let mut arc = AtomicRootCommit::with_generation(100);
        let params = make_commit_params(101);
        arc.execute_simulation(&params);

        // Find the superblock write crash point
        let before_sb = arc
            .crash_points()
            .iter()
            .find(|cp| cp.phase == AtomicRootCommitPhase::AfterBackupRingRotation)
            .expect("should have pre-superblock point");
        let after_sb = arc
            .crash_points()
            .iter()
            .find(|cp| cp.phase == AtomicRootCommitPhase::AfterSuperblockWrite)
            .expect("should have post-superblock point");

        assert!(
            !before_sb.superblock_committed,
            "pre-sb should not be committed"
        );
        assert!(after_sb.superblock_committed, "post-sb should be committed");
        assert_eq!(before_sb.observed_generation, 100);
        assert_eq!(after_sb.observed_generation, 101);
    }

    #[test]
    fn atomic_root_commit_backup_ring_rotates() {
        let mut arc = AtomicRootCommit::with_generation(100);
        let params = make_commit_params(101);
        arc.execute_simulation(&params);

        let latest = arc.backup_ring().latest();
        assert_eq!(latest.tree_root, params.root_tree_bytenr);
        assert_eq!(latest.tree_root_gen, params.new_generation);
        assert_eq!(latest.tree_root_level, params.root_tree_level);
    }

    #[test]
    fn backup_root_ring_rotation_preserves_history() {
        let mut ring = BackupRootRing::default();

        // Insert 5 generations (more than ring size of 4)
        for generation in 100..105 {
            let entry = BackupRootEntry {
                tree_root: generation * 0x1000,
                tree_root_gen: generation,
                ..Default::default()
            };
            ring.rotate(entry);
        }

        // Should have generations 104, 103, 102, 101 in slots 0-3
        assert_eq!(ring.get(0).unwrap().tree_root_gen, 104);
        assert_eq!(ring.get(1).unwrap().tree_root_gen, 103);
        assert_eq!(ring.get(2).unwrap().tree_root_gen, 102);
        assert_eq!(ring.get(3).unwrap().tree_root_gen, 101);
    }

    #[test]
    fn backup_root_entry_roundtrip() {
        let entry = BackupRootEntry {
            tree_root: 0x1000,
            tree_root_gen: 100,
            chunk_root: 0x2000,
            chunk_root_gen: 100,
            extent_root: 0x3000,
            extent_root_gen: 100,
            fs_root: 0x4000,
            fs_root_gen: 100,
            dev_root: 0x5000,
            dev_root_gen: 100,
            csum_root: 0x6000,
            csum_root_gen: 100,
            total_bytes: 1024 * 1024 * 1024,
            bytes_used: 64 * 1024 * 1024,
            num_devices: 1,
            tree_root_level: 2,
            chunk_root_level: 1,
            extent_root_level: 3,
            fs_root_level: 1,
            dev_root_level: 0,
            csum_root_level: 1,
        };

        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), BTRFS_ROOT_BACKUP_SIZE);

        let parsed = BackupRootEntry::parse(&bytes).expect("parse");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn atomic_root_commit_patches_superblock_correctly() {
        let mut arc = AtomicRootCommit::with_generation(100);
        let params = make_commit_params(101);
        arc.execute_simulation(&params);

        // Create a minimal valid superblock buffer
        let mut superblock = vec![0u8; 4096];
        // Set magic at 0x40
        superblock[0x40..0x48].copy_from_slice(&0x4D5F_5366_5248_425F_u64.to_le_bytes()); // btrfs magic

        arc.patch_superblock(&mut superblock, &params)
            .expect("patch");

        // Verify patched fields
        let root = u64::from_le_bytes(superblock[0x50..0x58].try_into().unwrap());
        let root_level = superblock[0xC6];
        let generation = u64::from_le_bytes(superblock[0x48..0x50].try_into().unwrap());

        assert_eq!(root, params.root_tree_bytenr);
        assert_eq!(root_level, params.root_tree_level);
        assert_eq!(generation, params.new_generation);

        // Verify checksum was recomputed
        let stored_csum = u32::from_le_bytes(superblock[0..4].try_into().unwrap());
        let computed_csum = ffs_types::crc32c(&superblock[0x20..]);
        assert_eq!(stored_csum, computed_csum, "checksum should be valid");
    }

    #[test]
    fn atomic_root_commit_wb_i2_fault_injection_all_phases() {
        // Fault-injection test: verify WB-I2 at every phase of commit
        let pre_gen = 100_u64;
        let post_gen = 101_u64;

        let mut arc = AtomicRootCommit::with_generation(pre_gen);
        let params = make_commit_params(post_gen);
        arc.execute_simulation(&params);

        // Test each crash point individually
        for crash_point in arc.crash_points() {
            let result = arc
                .test_wb_i2_at_crash_point(&crash_point.id)
                .expect("crash point should exist");

            assert!(
                result.wb_i2_passed,
                "WB-I2 failed at crash point {}: observed {} but expected {} or {}",
                crash_point.id, result.observed_generation, pre_gen, post_gen
            );

            // Verify the invariant: pre-bump sees g, post-bump sees g+1
            if result.committed {
                assert_eq!(
                    result.observed_generation, post_gen,
                    "committed crash point {} should see post-generation",
                    crash_point.id
                );
            } else {
                assert_eq!(
                    result.observed_generation, pre_gen,
                    "uncommitted crash point {} should see pre-generation",
                    crash_point.id
                );
            }
        }
    }

    #[test]
    fn atomic_root_commit_superblock_is_single_linearization_point() {
        // Prove: the superblock write is the SINGLE linearization point
        let mut arc = AtomicRootCommit::with_generation(100);
        let params = make_commit_params(101);
        arc.execute_simulation(&params);

        let mut saw_transition = false;
        let mut last_committed = false;

        for crash_point in arc.crash_points() {
            assert!(
                !last_committed || crash_point.superblock_committed,
                "commit state should never transition back to uncommitted"
            );
            if !last_committed && crash_point.superblock_committed {
                // This is the linearization point
                assert!(!saw_transition, "linearization should happen exactly once");
                assert_eq!(
                    crash_point.phase,
                    AtomicRootCommitPhase::AfterSuperblockWrite,
                    "linearization point must be AfterSuperblockWrite"
                );
                saw_transition = true;
            }
            last_committed = crash_point.superblock_committed;
        }

        assert!(saw_transition, "should have seen the linearization point");
    }

    /// bd-42gtq. btrfs stores a generation in every parent key_ptr and a reader
    /// verifies it against the child block's own header. Once a commit REUSES an
    /// unchanged child instead of rewriting it, that child still carries its old
    /// generation, so a COWed parent must record the CHILD's generation and not
    /// the transaction's. Getting this backwards is `parent transid verify failed
    /// ... wanted G found H` and the kernel refuses the whole filesystem with
    /// `open_ctree failed: -5` — the P0 shape of bd-73bi2, on an image our own
    /// reader opens perfectly well.
    #[test]
    fn generation_of_block_reports_the_childs_own_generation_bd_42gtq() {
        let mut addrs = BTreeMap::new();
        addrs.insert(7_u64, 0x10_0000_u64);
        addrs.insert(9_u64, 0x20_0000_u64);
        let mut gens = BTreeMap::new();
        // Block 9 is being REUSED: it is on disk at generation 4, and this
        // transaction is 10.
        gens.insert(9_u64, 4_u64);

        let ctx = DiskWritebackContext::with_allocated_addresses_and_generations(
            [0x5A; 16],
            [0x5A; 16],
            10,
            5,
            16384,
            ffs_types::BTRFS_CSUM_TYPE_CRC32C,
            4096,
            addrs,
            gens,
        );

        assert_eq!(
            ctx.generation_of_block(9),
            4,
            "a reused child must be recorded at the generation its BLOCK carries"
        );
        assert_eq!(
            ctx.generation_of_block(7),
            10,
            "a child this transaction rewrites carries the transaction generation"
        );
        assert_eq!(
            ctx.generation_of_block(12345),
            10,
            "an unknown block is being written, so it takes the transaction generation"
        );
    }

    /// bd-42gtq. The generation map is ADDITIVE: with no reused blocks, the new
    /// constructor must behave exactly like the old one, or landing it would have
    /// silently changed every existing caller (the ext4 commit path, the
    /// simulator, and three other btrfs trees).
    #[test]
    fn an_empty_generation_map_matches_the_old_constructor_bd_42gtq() {
        let mut addrs = BTreeMap::new();
        addrs.insert(3_u64, 0x30_0000_u64);

        let legacy = DiskWritebackContext::with_allocated_addresses(
            [0x11; 16],
            [0x11; 16],
            10,
            5,
            16384,
            ffs_types::BTRFS_CSUM_TYPE_CRC32C,
            4096,
            addrs.clone(),
        );
        let with_map = DiskWritebackContext::with_allocated_addresses_and_generations(
            [0x11; 16],
            [0x11; 16],
            10,
            5,
            16384,
            ffs_types::BTRFS_CSUM_TYPE_CRC32C,
            4096,
            addrs,
            BTreeMap::new(),
        );

        for block in [3_u64, 4, 99] {
            assert_eq!(
                legacy.generation_of_block(block),
                with_map.generation_of_block(block),
                "an empty generation map must not change block {block}"
            );
            assert_eq!(
                legacy.block_to_bytenr(block),
                with_map.block_to_bytenr(block),
                "an empty generation map must not change addressing for block {block}"
            );
        }
    }
}
