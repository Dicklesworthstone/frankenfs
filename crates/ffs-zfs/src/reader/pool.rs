//! Explicit immutable member sets for a leaf, ordinary mirror or RAIDZ group.
//!
//! Native child IDs come from verified labels, never argument positions.
//! Checksums decide whether replica or reconstructed bytes are usable.
//! This is read-only extraction, without degraded import, DTL recovery or healing.

pub(super) mod draid;
mod gang;
mod import;
pub mod indirect;
mod missing_mirror;
mod missing_raidz;
pub(super) mod raidz;
pub(super) mod stripe_mirrors;
pub mod vdev;

use super::{
    BlockPointer, BlockRead, Cx, DATA_OFFSET, FfsError, Label, Leaf, NvList, RaidzGroup,
    RaidzMember, Result, RootBlock, Uberblock, Value, VdevConfig, admit_vdev_state,
    admit_vdev_state_with_mode, checkpoint, corrupt, decode_or_verify, integer, parse, unsupported,
};
use ffs_ondisk::zfs::draid::DraidConfig;
use ffs_ondisk::zfs::raidz::expand::{RaidzReflowInfo, RaidzReflowScratchState};
use std::collections::BTreeSet;
use std::sync::Arc;

const MAX_MEMBERS: usize = 8;
const MAX_WIDE_MEMBERS: usize = 255;

#[derive(Clone)]
pub struct Pool {
    members: Vec<Leaf>,
    // An exact, operator-declared complement of exported mirrors' children.
    // Empty keeps complete-member admission; never infer missing devices.
    missing_mirror_guids: Vec<u64>,
    missing_raidz_guids: Vec<u64>,
    top_levels: Option<Arc<stripe_mirrors::Topology>>,
    draid_group: Option<Arc<draid::DraidGroup>>,
    expanded_raidz: Option<Arc<vdev::ExpandedRaidzMeta>>,
    indirect_maps: Option<Arc<indirect::IndirectVdevMap>>,
    topology: Option<Arc<vdev::PoolTopology>>,
}

impl From<Leaf> for Pool {
    fn from(leaf: Leaf) -> Self {
        Self {
            members: vec![leaf],
            missing_mirror_guids: Vec::new(),
            missing_raidz_guids: Vec::new(),
            top_levels: None,
            draid_group: None,
            expanded_raidz: None,
            indirect_maps: None,
            topology: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct GroupConfig {
    vdev: VdevConfig,
    // Preserve the complete native top-level tree when checking agreement.
    // Native path strings are compared as metadata, never opened as host paths.
    tree: NvList,
    member_guids: Vec<u64>,
    raidz_parity: usize,
    draid_config: Option<DraidConfig>,
    expanded_raidz: Option<vdev::ExpandedRaidzMeta>,
}

impl GroupConfig {
    fn mapped(self, supplied_guids: &[u64]) -> Result<VdevConfig> {
        let mut config = self.vdev;
        if self.raidz_parity != 0 && self.draid_config.is_none() {
            let mut members = Vec::with_capacity(self.member_guids.len());
            for guid in self.member_guids {
                let supplied_index = supplied_guids
                    .iter()
                    .position(|candidate| *candidate == guid)
                    .ok_or_else(|| corrupt("configured RAIDZ child has no supplied member"))?;
                members.push(RaidzMember {
                    supplied_index,
                    guid,
                    ashift: config.ashift,
                    allocated_bytes: config.allocated_bytes,
                });
            }
            config.raidz_members = Some(RaidzGroup {
                parity: self.raidz_parity,
                members,
            });
        }
        Ok(config)
    }

    fn build_draid_group(
        &self,
        supplied_guids: &[u64],
        missing_guids: &[u64],
    ) -> Result<Option<draid::DraidGroup>> {
        let Some(draid_cfg) = &self.draid_config else {
            return Ok(None);
        };
        let mut members = Vec::with_capacity(self.member_guids.len());
        for &guid in &self.member_guids {
            let supplied_index = match supplied_guids.iter().position(|&cand| cand == guid) {
                Some(idx) if !missing_guids.contains(&guid) => idx,
                None if missing_guids.contains(&guid) => missing_raidz::ABSENT_RAIDZ_INDEX,
                _ => {
                    return Err(corrupt(
                        "dRAID member partition disagrees with supplied and missing GUIDs",
                    ));
                }
            };
            members.push(RaidzMember {
                supplied_index,
                guid,
                ashift: self.vdev.ashift,
                allocated_bytes: self.vdev.allocated_bytes,
            });
        }
        Ok(Some(draid::DraidGroup {
            config: draid_cfg.clone(),
            members,
        }))
    }
}

impl Label {
    fn group_config_with_mode(
        &self,
        pool_guid: u64,
        allow_active_state: bool,
    ) -> Result<(GroupConfig, u64)> {
        let vdev = self.vdev_config_with_mode(pool_guid, allow_active_state, false)?;
        let tree = self
            .config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("missing redundant vdev tree"))?;
        let mut draid_config = None;
        let mut expanded_raidz = None;
        let raidz_parity = match tree.text("type") {
            Some("mirror") => 0,
            Some("raidz") => {
                let parity = integer(tree, "nparity")?;
                if !(1..=3).contains(&parity) {
                    return Err(unsupported(
                        "ordinary RAIDZ requires one through three parity columns",
                    ));
                }
                usize::try_from(parity).map_err(|_| corrupt("RAIDZ parity count overflow"))?
            }
            Some("draid") => {
                let cfg = vdev::parse_draid_tree_config(tree)?;
                let parity = cfg.nparity;
                draid_config = Some(cfg);
                parity
            }
            _ => {
                return Err(unsupported(
                    "multiple supplied images require one ordinary mirror, RAIDZ, or dRAID group",
                ));
            }
        };
        let Some(Value::Lists(children)) = tree.fields.get("children") else {
            return Err(corrupt(
                "redundant vdev has no native nvlist-array children",
            ));
        };
        if tree.text("type") == Some("raidz") {
            let has_expand_fields = tree.fields.contains_key("raidz_expand_txgs")
                || tree.fields.contains_key("raidz_expanding");
            if has_expand_fields
                && !vdev
                    .read_features
                    .iter()
                    .any(|f| f == "org.openzfs:raidz_expansion")
            {
                return Err(unsupported(
                    "expanded RAIDZ metadata requires org.openzfs:raidz_expansion feature",
                ));
            }
            expanded_raidz = vdev::ExpandedRaidzMeta::from_vdev_tree(tree, children.len())?;
        }
        let max_children = if draid_config.is_some() || expanded_raidz.is_some() {
            MAX_WIDE_MEMBERS
        } else {
            MAX_MEMBERS
        };
        if !(2..=max_children).contains(&children.len()) || children.len() <= raidz_parity {
            return Err(unsupported(
                "redundant read profile requires two through eight children (or up to 255 for dRAID/expanded RAIDZ) and a data column",
            ));
        }
        let allow_advanced = draid_config.is_some() || expanded_raidz.is_some();
        let mut seen = BTreeSet::from([vdev.pool_guid, vdev.top_guid]);
        let mut member_guids = Vec::with_capacity(children.len());
        for (index, child) in children.iter().enumerate() {
            if !matches!(child.text("type"), Some("file" | "disk" | "draid_spare"))
                || child.fields.contains_key("children")
            {
                return Err(unsupported(
                    "redundant vdev children must be ordinary file, disk, or draid_spare leaves",
                ));
            }
            admit_vdev_state_with_mode(child, allow_advanced)?;
            if integer(child, "id")? != index as u64 {
                return Err(corrupt("child IDs do not match the native child array"));
            }
            let guid = integer(child, "guid")?;
            if guid == 0 || !seen.insert(guid) {
                return Err(corrupt("duplicate or zero redundant member GUID"));
            }
            member_guids.push(guid);
        }
        let member_guid = integer(&self.config, "guid")?;
        if !member_guids.contains(&member_guid) {
            return Err(corrupt("label GUID is not a child of its declared group"));
        }
        Ok((
            GroupConfig {
                vdev,
                tree: tree.clone(),
                member_guids,
                raidz_parity,
                draid_config,
                expanded_raidz,
            },
            member_guid,
        ))
    }
}

fn same_candidate(left: &Uberblock, right: &Uberblock) -> bool {
    // Compare native values, allowing the containers themselves to be encoded
    // in either byte order. The complete root pointer includes payload order.
    left.version == right.version
        && left.txg == right.txg
        && left.guid_sum == right.guid_sum
        && left.timestamp == right.timestamp
        && left.root == right.root
}

impl Pool {
    /// Host paths have already been explicitly opened by the caller. Multiple
    /// images must supply the complete native mirror, RAIDZ, or striped top-level vdev set.
    pub fn from_leaves(members: Vec<Leaf>) -> Result<Self> {
        if !(1..=MAX_MEMBERS).contains(&members.len()) {
            return Err(unsupported(
                "supply one leaf or two through eight redundant or striped members",
            ));
        }
        Self::from_wide_leaves(members)
    }

    /// Construct a pool from `1..=255` leaves (for dRAID, wide/expanded RAIDZ,
    /// and multi-vdev/multi-class pools).
    pub fn from_wide_leaves(members: Vec<Leaf>) -> Result<Self> {
        if !(1..=MAX_WIDE_MEMBERS).contains(&members.len()) {
            return Err(unsupported(
                "supply between one and 255 physical ZFS member leaves",
            ));
        }
        Ok(Self {
            members,
            missing_mirror_guids: Vec::new(),
            missing_raidz_guids: Vec::new(),
            top_levels: None,
            draid_group: None,
            expanded_raidz: None,
            indirect_maps: None,
            topology: None,
        })
    }

    #[must_use]
    pub(crate) fn pool_topology(&self) -> Option<&vdev::PoolTopology> {
        self.topology.as_deref()
    }

    #[must_use]
    pub(crate) fn draid_group(&self) -> Option<&draid::DraidGroup> {
        self.draid_group.as_deref()
    }

    pub(crate) fn set_indirect_maps(&mut self, maps: indirect::IndirectVdevMap) {
        if !maps.is_empty() {
            self.indirect_maps = Some(Arc::new(maps));
        }
    }

    /// Re-bind dRAID or expanded-RAIDZ topology metadata onto a cloned `Pool`
    /// inside [`crate::reader::dmu::Objects::from_root`] when the member labels
    /// declare a dRAID or expanded-RAIDZ group.
    pub(in crate::reader) fn retain_advanced_topology(
        mut self,
        cx: &Cx,
        config: &VdevConfig,
        raidz_reflow_info: u64,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if config.version != 5000
            || !config
                .read_features
                .iter()
                .any(|f| f == "org.openzfs:draid" || f == "org.openzfs:raidz_expansion")
            || self.draid_group.is_some()
            || self.expanded_raidz.is_some()
            || self.members.is_empty()
        {
            return Ok(self);
        }
        let Ok(first_label) = self.members[0].label(cx, 0) else {
            return Ok(self);
        };
        let Some(tree) = first_label.config.list("vdev_tree") else {
            return Ok(self);
        };
        let ty = tree.text("type");
        if ty == Some("draid") {
            let (selected, _) = first_label.group_config_with_mode(config.pool_guid, true)?;
            let mut supplied_guids = Vec::with_capacity(self.members.len());
            for member in &self.members {
                let lbl = member.label(cx, 0)?;
                supplied_guids.push(integer(&lbl.config, "guid")?);
            }
            if let Some(dg) =
                selected.build_draid_group(&supplied_guids, &self.missing_raidz_guids)?
            {
                self.draid_group = Some(Arc::new(dg));
            }
        } else if ty == Some("raidz")
            && (tree.fields.contains_key("raidz_expand_txgs")
                || tree.fields.contains_key("raidz_expanding"))
            && let Some(Value::Lists(children)) = tree.fields.get("children")
            && let Some(mut exp) = vdev::ExpandedRaidzMeta::from_vdev_tree(tree, children.len())?
        {
            if raidz_reflow_info != 0
                && let Ok(info) = RaidzReflowInfo::decode(raidz_reflow_info)
            {
                if info.state == RaidzReflowScratchState::InvalidSyncedReflow {
                    exp.reflow_offset_synced = u64::MAX;
                    exp.reflow_offset_next = u64::MAX;
                    exp.use_scratch = false;
                } else {
                    exp.reflow_offset_synced = info.offset;
                    exp.reflow_offset_next = info.offset;
                    exp.use_scratch = info.use_scratch();
                }
            }
            self.expanded_raidz = Some(Arc::new(exp));
        }
        Ok(self)
    }

    pub(crate) fn has_missing_members(&self) -> bool {
        !self.missing_mirror_guids.is_empty() || !self.missing_raidz_guids.is_empty()
    }

    pub(super) fn standalone_leaf(&self) -> Option<&Leaf> {
        if self.has_missing_members() {
            return None;
        }
        match self.members.as_slice() {
            [leaf] => Some(leaf),
            _ => None,
        }
    }

    /// Immutable handles retained by the admitted native topology. Log blocks
    /// use their own checksum boundary rather than the ordinary DMU decoder.
    pub(crate) fn leaves(&self) -> &[Leaf] {
        &self.members
    }

    /// Pin protection on every admitted leaf before the first write. If a
    /// member refuses entry, the preceding guards abort without issuing I/O.
    pub(crate) fn defer_protection(
        &self,
        cx: &Cx,
    ) -> Result<Vec<ffs_block::DurabilityCommitDeferral<'_>>> {
        self.members
            .iter()
            .map(|leaf| ffs_block::DurabilityCommitDeferral::enter(cx, leaf.device.as_ref()))
            .collect()
    }

    pub fn root(
        &self,
        cx: &Cx,
        label_index: usize,
        slot: usize,
        pool_guid: u64,
    ) -> Result<RootBlock> {
        self.root_with_mode(cx, label_index, slot, pool_guid, false)
    }

    pub(super) fn root_with_mode(
        &self,
        cx: &Cx,
        label_index: usize,
        slot: usize,
        pool_guid: u64,
        allow_active_state: bool,
    ) -> Result<RootBlock> {
        checkpoint(cx)?;
        if self.has_missing_members() && allow_active_state {
            return Err(unsupported(
                "missing members require an explicit exported-pool candidate",
            ));
        }
        if let Some(leaf) = self.standalone_leaf() {
            return leaf.root(cx, label_index, slot, pool_guid);
        }
        let first_label = self.members[0].label(cx, label_index)?;
        if integer(&first_label.config, "vdev_children").unwrap_or(1) > 1 {
            if !self.missing_raidz_guids.is_empty() {
                return Err(unsupported(
                    "missing RAIDZ extraction requires one ordinary RAIDZ group",
                ));
            }
            return self.striped_root_with_mode(
                cx,
                label_index,
                slot,
                pool_guid,
                allow_active_state,
            );
        }
        let (selected, _) = first_label.group_config_with_mode(pool_guid, allow_active_state)?;
        if selected.member_guids.len()
            != self.members.len() + self.missing_mirror_guids.len() + self.missing_raidz_guids.len()
        {
            return Err(unsupported(
                "every configured redundant member must be explicitly supplied",
            ));
        }
        let expected_sum = selected.member_guids.iter().fold(
            selected.vdev.pool_guid.wrapping_add(selected.vdev.top_guid),
            |sum, guid| sum.wrapping_add(*guid),
        );
        let candidate = self.members[0].uberblock(cx, &first_label, slot)?;
        if candidate.version != selected.vdev.version
            || candidate.txg < selected.vdev.txg
            || candidate.guid_sum != expected_sum
        {
            return Err(corrupt(
                "candidate disagrees with the pool configuration or GUID sum",
            ));
        }
        let mut seen = BTreeSet::new();
        let mut member_guids = Vec::with_capacity(self.members.len());
        for member in &self.members {
            checkpoint(cx)?;
            let label = member.label(cx, label_index)?;
            let (config, guid) = label.group_config_with_mode(pool_guid, allow_active_state)?;
            if config != selected || !seen.insert(guid) {
                return Err(corrupt(
                    "supplied members disagree or repeat a physical GUID",
                ));
            }
            for index in 0..4 {
                let (other, other_guid) = member
                    .label(cx, index)?
                    .group_config_with_mode(pool_guid, allow_active_state)?;
                if other != selected || other_guid != guid {
                    return Err(corrupt(
                        "member labels disagree on identity or configuration",
                    ));
                }
            }
            let other = member.uberblock(cx, &label, slot)?;
            if !same_candidate(&candidate, &other) {
                return Err(corrupt(
                    "members disagree on the explicitly selected root candidate",
                ));
            }
            member_guids.push(guid);
        }
        self.validate_mirror_complement(&selected, &member_guids)?;
        if selected.draid_config.is_none() {
            self.validate_raidz_complement(&selected, &member_guids)?;
        }
        let draid_group = selected.build_draid_group(&member_guids, &self.missing_raidz_guids)?;
        let mut expanded_meta = selected.expanded_raidz.clone();
        if let Some(ref mut exp) = expanded_meta
            && candidate.raidz_reflow_info != 0
            && let Ok(info) = RaidzReflowInfo::decode(candidate.raidz_reflow_info)
        {
            if info.state == RaidzReflowScratchState::InvalidSyncedReflow {
                exp.reflow_offset_synced = u64::MAX;
                exp.reflow_offset_next = u64::MAX;
                exp.use_scratch = false;
            } else {
                exp.reflow_offset_synced = info.offset;
                exp.reflow_offset_next = info.offset;
                exp.use_scratch = info.use_scratch();
            }
        }
        // Preserve all configured children, including native RAIDZ width, and
        // every GUID in the candidate sum. Missing routes are never Leaf values.
        let config = if self.missing_raidz_guids.is_empty() || draid_group.is_some() {
            selected.mapped(&member_guids)?
        } else {
            selected.mapped_raidz_survivors(&member_guids, &self.missing_raidz_guids)?
        };
        let mut owner = self.clone();
        if let Some(dg) = draid_group {
            owner.draid_group = Some(Arc::new(dg));
        }
        if let Some(exp) = expanded_meta {
            owner.expanded_raidz = Some(Arc::new(exp));
        }
        let block = owner.read_block(cx, &config, &candidate.root)?;
        if block.bytes.len() < 1024
            || candidate
                .root
                .payload_order()
                .u64(&block.bytes, 704)
                .map_err(|error| parse(&error))?
                != 1
        {
            return Err(corrupt("selected group root is not a META object set"));
        }
        checkpoint(cx)?;
        Ok(RootBlock {
            uberblock: candidate,
            data: block.bytes,
            physical_offset: block.physical_offset,
            copy_index: block.copy_index,
            // RAIDZ identifies the first native data column, even when it
            // was reconstructed. Never index the survivor list with an absent
            // route, or mislabel a surviving parity disk as that native child.
            member_guid: block
                .raidz
                .as_ref()
                .and_then(|stripe| {
                    stripe
                        .columns
                        .iter()
                        .find(|column| !column.parity && column.bytes != 0)
                })
                .map_or(member_guids[block.member_index], |column| {
                    column.member_guid
                }),
            raidz: block.raidz,
            config,
        })
    }

    fn striped_root_with_mode(
        &self,
        cx: &Cx,
        label_index: usize,
        slot: usize,
        pool_guid: u64,
        allow_active_state: bool,
    ) -> Result<RootBlock> {
        let count = self.members.len();
        let first_label = self.members[0].label(cx, label_index)?;
        if !self.missing_mirror_guids.is_empty()
            || integer(&first_label.config, "vdev_children")? != count as u64
        {
            return self.mirror_stripe_root(cx, label_index, slot, pool_guid, allow_active_state);
        }
        let first_cfg = first_label.striped_leaf_config(pool_guid, count, allow_active_state)?;
        let candidate = self.members[0].uberblock(cx, &first_label, slot)?;
        let mut seen_guids = BTreeSet::from([pool_guid]);
        let mut by_vdev_id: Vec<Option<(usize, VdevConfig)>> = vec![None; count];
        let mut member_guids_by_supplied = Vec::with_capacity(count);
        for (supplied_index, member) in self.members.iter().enumerate() {
            checkpoint(cx)?;
            let label = member.label(cx, label_index)?;
            let cfg = label.striped_leaf_config(pool_guid, count, allow_active_state)?;
            if cfg.version != first_cfg.version || cfg.read_features != first_cfg.read_features {
                return Err(corrupt(
                    "striped top-level vdevs disagree on pool version or read features",
                ));
            }
            if !seen_guids.insert(cfg.top_guid) {
                return Err(corrupt("striped top-level vdevs repeat a GUID"));
            }
            for index in 0..4 {
                let other = member.label(cx, index)?.striped_leaf_config(
                    pool_guid,
                    count,
                    allow_active_state,
                )?;
                if other != cfg {
                    return Err(corrupt(
                        "striped member labels disagree on identity or configuration",
                    ));
                }
            }
            let ub = member.uberblock(cx, &label, slot)?;
            if ub.version != cfg.version || ub.txg < cfg.txg || !same_candidate(&candidate, &ub) {
                return Err(corrupt(
                    "striped top-level vdevs disagree on the selected uberblock candidate",
                ));
            }
            let vdev_slot = by_vdev_id
                .get_mut(cfg.id as usize)
                .ok_or_else(|| corrupt("striped top-level vdev ID out of bounds"))?;
            if vdev_slot.is_some() {
                return Err(corrupt("duplicate striped top-level vdev ID"));
            }
            member_guids_by_supplied.push(cfg.top_guid);
            *vdev_slot = Some((supplied_index, cfg));
        }
        let mut striped_members = Vec::with_capacity(count);
        let mut expected_sum = pool_guid;
        for entry in by_vdev_id {
            let (supplied_index, cfg) =
                entry.ok_or_else(|| corrupt("missing striped top-level vdev ID"))?;
            expected_sum = expected_sum.wrapping_add(cfg.top_guid);
            striped_members.push(RaidzMember {
                supplied_index,
                guid: cfg.top_guid,
                ashift: cfg.ashift,
                allocated_bytes: cfg.allocated_bytes,
            });
        }
        if candidate.guid_sum != expected_sum {
            return Err(corrupt(
                "candidate disagrees with the striped pool GUID sum",
            ));
        }
        let mut config = first_cfg;
        config.id = 0;
        config.top_guid = striped_members[0].guid;
        config.ashift = striped_members[0].ashift;
        config.allocated_bytes = striped_members[0].allocated_bytes;
        config.raidz_members = Some(RaidzGroup {
            parity: 0,
            members: striped_members,
        });
        let block = self.read_block(cx, &config, &candidate.root)?;
        if block.bytes.len() < 1024
            || candidate
                .root
                .payload_order()
                .u64(&block.bytes, 704)
                .map_err(|error| parse(&error))?
                != 1
        {
            return Err(corrupt(
                "selected striped pool root is not a META object set",
            ));
        }
        checkpoint(cx)?;
        Ok(RootBlock {
            uberblock: candidate,
            data: block.bytes,
            physical_offset: block.physical_offset,
            copy_index: block.copy_index,
            member_guid: member_guids_by_supplied[block.member_index],
            raidz: None,
            config,
        })
    }

    pub(super) fn read_block(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
    ) -> Result<BlockRead> {
        self.read_block_inner(cx, config, bp, false)
    }

    /// Read and physically checksum-verify a block without decompressing or
    /// requiring unprotected decoding. Used by the protected (encrypted /
    /// authenticated) DMU pipeline before MAC / AEAD verification.
    pub(super) fn read_raw_block(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
    ) -> Result<BlockRead> {
        self.read_block_inner(cx, config, bp, true)
    }

    fn read_block_inner(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
        raw_only: bool,
    ) -> Result<BlockRead> {
        checkpoint(cx)?;
        if let Some(indirect_maps) = &self.indirect_maps
            && !bp.gang()
            && bp
                .data_dvas()
                .is_ok_and(|dvas| dvas.iter().any(|d| indirect_maps.contains_vdev(d.vdev)))
        {
            return self.read_via_indirect(cx, config, bp, indirect_maps, raw_only);
        }
        if bp.gang() {
            return self.read_gang_block_inner(cx, config, bp, raw_only);
        }
        if let Some(draid) = &self.draid_group {
            return self.read_draid_block_inner(cx, config, bp, draid, raw_only);
        }
        if let Some(topo) = &self.topology
            && topo.top_vdevs.len() > 1
        {
            return self.read_from_pool_topology(cx, config, bp, topo, raw_only);
        }
        if let Some(group) = &config.raidz_members {
            if group.parity == 0 {
                return self.read_striped_block_inner(cx, bp, group, raw_only);
            }
            if let Some(expanded) = &self.expanded_raidz {
                return self
                    .read_expanded_raidz_block_inner(cx, config, bp, group, expanded, raw_only);
            }
            return self.read_raidz_block_inner(cx, config, bp, group, raw_only);
        }
        if self.members.len() == 1 {
            return self.members[0]
                .read_block_inner(cx, config, bp, raw_only)
                .map(|(bytes, physical_offset, copy_index)| BlockRead {
                    bytes,
                    physical_offset,
                    copy_index,
                    member_index: 0,
                    raidz: None,
                });
        }
        // OpenZFS zfs-2.3.0 vdev_default_asize rounds physical bytes to the
        // top-level ashift. Mirror width does not multiply the DVA asize.
        // Validate all declared DVAs against EVERY selected member before a
        // good first copy could conceal a foreign or out-of-range mapping.
        let dvas = self.members[0].block_dvas(config, bp)?;
        for member in &self.members[1..] {
            checkpoint(cx)?;
            member.block_dvas(config, bp)?;
        }
        let mut failures = Vec::new();
        for (copy_index, dva) in dvas.iter().enumerate() {
            let offset = DATA_OFFSET + dva.offset;
            for (member_index, member) in self.members.iter().enumerate() {
                checkpoint(cx)?;
                let result = member
                    .read(cx, offset, bp.physical_bytes())
                    .and_then(|raw| decode_or_verify(bp, raw, raw_only));
                match result {
                    Ok(bytes) => {
                        checkpoint(cx)?;
                        return Ok(BlockRead {
                            bytes,
                            physical_offset: offset,
                            copy_index,
                            member_index,
                            raidz: None,
                        });
                    }
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(error) => failures.push(format!(
                        "DVA {copy_index}, supplied member {member_index}: {error}"
                    )),
                }
            }
        }
        Err(corrupt(format!(
            "all ZFS mirror block copies failed: {}",
            failures.join("; ")
        )))
    }

    fn read_striped_block_inner(
        &self,
        cx: &Cx,
        bp: &BlockPointer,
        group: &RaidzGroup,
        raw_only: bool,
    ) -> Result<BlockRead> {
        let dvas = bp.data_dvas().map_err(|error| parse(&error))?;
        for dva in &dvas {
            checkpoint(cx)?;
            let vdev_idx = usize::try_from(dva.vdev).map_err(|_| corrupt("vdev ID overflow"))?;
            let vdev = group
                .members
                .get(vdev_idx)
                .ok_or_else(|| unsupported("DVA references an unconfigured top-level vdev"))?;
            for &index in self.striped_sources(dva.vdev, vdev)? {
                checkpoint(cx)?;
                let member = self
                    .members
                    .get(index)
                    .ok_or_else(|| corrupt("striped replica has no supplied image"))?;
                member.validate_dva_for_vdev(
                    vdev.ashift,
                    vdev.allocated_bytes,
                    dva.vdev,
                    bp,
                    dva,
                )?;
            }
        }
        let mut failures = Vec::new();
        for (copy_index, dva) in dvas.iter().enumerate() {
            checkpoint(cx)?;
            let vdev = &group.members[dva.vdev as usize];
            let offset = DATA_OFFSET + dva.offset;
            for &member_index in self.striped_sources(dva.vdev, vdev)? {
                checkpoint(cx)?;
                let result = self.members[member_index]
                    .read(cx, offset, bp.physical_bytes())
                    .and_then(|raw| decode_or_verify(bp, raw, raw_only));
                match result {
                    Ok(bytes) => {
                        checkpoint(cx)?;
                        return Ok(BlockRead {
                            bytes,
                            physical_offset: offset,
                            copy_index,
                            member_index,
                            raidz: None,
                        });
                    }
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(error) => {
                        failures.push(format!(
                            "DVA {copy_index} (vdev {}, supplied member {member_index}): {error}",
                            dva.vdev
                        ));
                    }
                }
            }
        }
        Err(corrupt(format!(
            "all ZFS striped block copies failed: {}",
            failures.join("; ")
        )))
    }

    /// Read a raw byte span `[offset, offset + len)` from a concrete (leaf or
    /// mirror) top-level vdev `vdev_id`, used after resolving an `indirect`
    /// vdev mapping span.
    pub(super) fn read_raw_span_from_concrete_vdev(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        vdev_id: u32,
        offset: u64,
        len: usize,
    ) -> Result<(Vec<u8>, u64, usize)> {
        checkpoint(cx)?;
        let phys_off = DATA_OFFSET
            .checked_add(offset)
            .ok_or_else(|| corrupt("indirect concrete offset overflow"))?;
        if let Some(topo) = &self.topology {
            let top = topo
                .top_vdev(vdev_id)
                .ok_or_else(|| unsupported("indirect target vdev ID not in pool topology"))?;
            let mut last_err = corrupt("indirect target vdev has no surviving member");
            for slot in &top.supplied_indices {
                let Some(m_idx) = *slot else {
                    continue;
                };
                match self.members[m_idx].read(cx, phys_off, len) {
                    Ok(bytes) => return Ok((bytes, phys_off, m_idx)),
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(err) => last_err = err,
                }
            }
            return Err(last_err);
        }
        if let Some(group) = &config.raidz_members
            && group.parity == 0
        {
            let vdev = group
                .members
                .get(vdev_id as usize)
                .ok_or_else(|| unsupported("indirect target vdev ID out of bounds"))?;
            let mut last_err = corrupt("indirect target vdev has no replica");
            for &m_idx in self.striped_sources(vdev_id, vdev)? {
                match self.members[m_idx].read(cx, phys_off, len) {
                    Ok(bytes) => return Ok((bytes, phys_off, m_idx)),
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(err) => last_err = err,
                }
            }
            return Err(last_err);
        }
        if vdev_id != config.id {
            return Err(unsupported("indirect target references unknown vdev ID"));
        }
        let mut last_err = corrupt("no member available for indirect read");
        for (m_idx, leaf) in self.members.iter().enumerate() {
            match leaf.read(cx, phys_off, len) {
                Ok(bytes) => return Ok((bytes, phys_off, m_idx)),
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(err) => last_err = err,
            }
        }
        Err(last_err)
    }

    /// Dispatch a block read across a heterogeneous multi-top-level
    /// [`vdev::PoolTopology`] (combining Leaf, Mirror, RAIDZ, expanded RAIDZ,
    /// dRAID, Special, Dedup, and Log vdevs).
    fn read_from_pool_topology(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
        topo: &vdev::PoolTopology,
        raw_only: bool,
    ) -> Result<BlockRead> {
        let dvas = bp.data_dvas().map_err(|error| parse(&error))?;
        let mut failures = Vec::new();
        for (copy_index, dva) in dvas.iter().enumerate() {
            checkpoint(cx)?;
            let Some(top) = topo.top_vdev(dva.vdev) else {
                failures.push(format!(
                    "DVA {copy_index}: unknown top-level vdev {}",
                    dva.vdev
                ));
                continue;
            };
            match &top.kind {
                vdev::TopVdevKind::Leaf | vdev::TopVdevKind::Mirror => {
                    let phys_off = DATA_OFFSET + dva.offset;
                    for slot in &top.supplied_indices {
                        let Some(m_idx) = *slot else {
                            continue;
                        };
                        match self.members[m_idx]
                            .read(cx, phys_off, bp.physical_bytes())
                            .and_then(|raw| decode_or_verify(bp, raw, raw_only))
                        {
                            Ok(bytes) => {
                                return Ok(BlockRead {
                                    bytes,
                                    physical_offset: phys_off,
                                    copy_index,
                                    member_index: m_idx,
                                    raidz: None,
                                });
                            }
                            Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                            Err(err) => failures.push(format!(
                                "DVA {copy_index} vdev {} member {m_idx}: {err}",
                                dva.vdev
                            )),
                        }
                    }
                }
                vdev::TopVdevKind::Raidz { parity, expanded } => {
                    let members: Vec<RaidzMember> = top
                        .children_guids
                        .iter()
                        .zip(&top.supplied_indices)
                        .map(|(&guid, &slot)| RaidzMember {
                            supplied_index: slot.unwrap_or(missing_raidz::ABSENT_RAIDZ_INDEX),
                            guid,
                            ashift: top.ashift,
                            allocated_bytes: top.asize,
                        })
                        .collect();
                    let group = RaidzGroup {
                        parity: *parity,
                        members,
                    };
                    let mut sub_cfg = config.clone();
                    sub_cfg.id = top.id;
                    sub_cfg.ashift = top.ashift;
                    sub_cfg.allocated_bytes = top.asize;
                    sub_cfg.raidz_members = Some(group.clone());
                    let res = expanded.as_ref().map_or_else(
                        || self.read_raidz_block_inner(cx, &sub_cfg, bp, &group, raw_only),
                        |exp| {
                            self.read_expanded_raidz_block_inner(
                                cx, &sub_cfg, bp, &group, exp, raw_only,
                            )
                        },
                    );
                    match res {
                        Ok(block) => return Ok(block),
                        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                        Err(err) => failures.push(format!("DVA {copy_index} raidz: {err}")),
                    }
                }
                vdev::TopVdevKind::Draid(draid_cfg) => {
                    let members: Vec<RaidzMember> = top
                        .children_guids
                        .iter()
                        .zip(&top.supplied_indices)
                        .map(|(&guid, &slot)| RaidzMember {
                            supplied_index: slot.unwrap_or(missing_raidz::ABSENT_RAIDZ_INDEX),
                            guid,
                            ashift: top.ashift,
                            allocated_bytes: top.asize,
                        })
                        .collect();
                    let group = draid::DraidGroup {
                        config: draid_cfg.clone(),
                        members,
                    };
                    let mut sub_cfg = config.clone();
                    sub_cfg.id = top.id;
                    sub_cfg.ashift = top.ashift;
                    sub_cfg.allocated_bytes = top.asize;
                    match self.read_draid_block_inner(cx, &sub_cfg, bp, &group, raw_only) {
                        Ok(block) => return Ok(block),
                        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                        Err(err) => failures.push(format!("DVA {copy_index} draid: {err}")),
                    }
                }
                vdev::TopVdevKind::Indirect(_) | vdev::TopVdevKind::Hole => {
                    failures.push(format!(
                        "DVA {copy_index}: unresolved indirect/hole vdev {}",
                        dva.vdev
                    ));
                }
            }
        }
        Err(corrupt(format!(
            "all ZFS multi-vdev block copies failed: {}",
            failures.join("; ")
        )))
    }
}
