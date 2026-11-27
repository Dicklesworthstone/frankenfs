//! Unified OpenZFS `zfs-2.4.0` pool topology, allocation classes, vdev health,
//! auxiliary vdev isolation (`l2cache` vs required storage), and `guid_sum`
//! computation.

use crate::reader::{NvList, Result, Value, corrupt, integer, parse, unsupported};
use ffs_ondisk::zfs::draid::DraidConfig;
use ffs_ondisk::zfs::indirect::VdevIndirectConfig;
use ffs_ondisk::zfs::raidz::expand::{
    ExpandedRaidzConfig, RaidzReflowInfo, RaidzReflowScratchState,
};
use serde::Serialize;
use std::collections::BTreeSet;

/// OpenZFS `zfs-2.4.0` allocation class / vdev role.
///
/// Required pool storage (`Normal`, `Special`, `Dedup`, `Log`) must never be
/// silently treated as optional cache: missing required classes fail closed.
/// Only `Cache` (`l2cache`) is optional and isolated from required storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum AllocClass {
    /// Ordinary data/metadata top-level vdev.
    Normal,
    /// Dedicated metadata & small-block allocation class (`allocation_bias="special"`).
    Special,
    /// Dedicated deduplication table allocation class (`allocation_bias="dedup"`).
    Dedup,
    /// Separate Intent Log / SLOG vdev (`is_log=1`).
    Log,
    /// Pool hot spare device (`spares` array in MOS config; excluded from `guid_sum`).
    Spare,
    /// Optional L2ARC read cache (`l2cache` array in MOS config; excluded from `guid_sum`).
    Cache,
}

impl AllocClass {
    /// Classify a top-level vdev tree from its OpenZFS nvlist fields.
    pub fn from_vdev_tree(tree: &NvList) -> Result<Self> {
        if tree.unsigned("is_log").unwrap_or(0) != 0 {
            if tree.fields.contains_key("allocation_bias") {
                return Err(corrupt(
                    "ZFS vdev cannot combine is_log with allocation_bias",
                ));
            }
            return Ok(Self::Log);
        }
        if tree.unsigned("is_spare").unwrap_or(0) != 0 {
            return Ok(Self::Spare);
        }
        if let Some(bias) = tree.text("allocation_bias") {
            return match bias {
                "special" => Ok(Self::Special),
                "dedup" => Ok(Self::Dedup),
                other => Err(unsupported(format!(
                    "unsupported ZFS vdev allocation_bias '{other}'"
                ))),
            };
        }
        if tree.fields.contains_key("allocation_bias") {
            return Err(corrupt("ZFS allocation_bias is not a string"));
        }
        Ok(Self::Normal)
    }

    /// True when missing this vdev class must fail closed rather than be ignored.
    #[must_use]
    pub const fn is_required_storage(self) -> bool {
        matches!(self, Self::Normal | Self::Special | Self::Dedup)
    }
}

/// Native vdev health state parsed from OpenZFS label/MOS vdev nvlist flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VdevHealth {
    Online,
    Degraded,
    Faulted,
    Offline,
    Removed,
    Unavail,
}

impl VdevHealth {
    #[must_use]
    pub fn from_vdev_tree(tree: &NvList) -> Self {
        if tree.unsigned("faulted").unwrap_or(0) != 0 {
            Self::Faulted
        } else if tree.unsigned("removed").unwrap_or(0) != 0 {
            Self::Removed
        } else if tree.unsigned("not_present").unwrap_or(0) != 0 {
            Self::Unavail
        } else if tree.unsigned("offline").unwrap_or(0) != 0 {
            Self::Offline
        } else if tree.unsigned("degraded").unwrap_or(0) != 0 {
            Self::Degraded
        } else {
            Self::Online
        }
    }

    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Online)
    }
}

/// Expanded RAIDZ metadata attached to a RAIDZ top-level vdev.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedRaidzMeta {
    pub original_width: usize,
    pub physical_width: usize,
    pub expand_txgs: Vec<u64>,
    pub expanding: bool,
    pub reflow_offset_synced: u64,
    pub reflow_offset_next: u64,
    pub use_scratch: bool,
}

impl ExpandedRaidzMeta {
    /// Bind physical read authority to the selected uberblock. State 4 also
    /// represents ordinary intermediate progress while expansion is active.
    pub fn apply_reflow_info(&mut self, raw: u64) -> Result<()> {
        let info = RaidzReflowInfo::decode(raw).map_err(|error| parse(&error))?;
        if self.expanding {
            if info.state == RaidzReflowScratchState::NotInUse && info.offset != 0 {
                return Err(corrupt("inactive RAIDZ scratch state has a reflow offset"));
            }
            self.reflow_offset_synced = info.offset;
            self.reflow_offset_next = info.offset;
            self.use_scratch = info.use_scratch();
        } else {
            if info.use_scratch() {
                return Err(corrupt(
                    "completed RAIDZ layout still names active scratch space",
                ));
            }
            self.reflow_offset_synced = u64::MAX;
            self.reflow_offset_next = u64::MAX;
            self.use_scratch = false;
        }
        Ok(())
    }

    /// Build an `ffs-ondisk` [`ExpandedRaidzConfig`] from this metadata and the
    /// vdev's `ashift` + `parity`.
    pub fn to_ondisk(&self, ashift: u8, parity: usize) -> Result<ExpandedRaidzConfig> {
        let cfg = ExpandedRaidzConfig {
            ashift,
            parity,
            original_width: self.original_width,
            physical_width: self.physical_width,
            expand_txgs: self.expand_txgs.clone(),
            reflow_offset_synced: self.reflow_offset_synced,
            reflow_offset_next: self.reflow_offset_next,
            use_scratch: self.use_scratch,
        };
        cfg.validate().map_err(|e| parse(&e))?;
        Ok(cfg)
    }

    /// Parse optional `raidz_expand_txgs` / `raidz_expanding` metadata from a
    /// RAIDZ `vdev_tree` nvlist.
    pub fn from_vdev_tree(tree: &NvList, physical_width: usize) -> Result<Option<Self>> {
        let expand_txgs = match tree.fields.get("raidz_expand_txgs") {
            None => Vec::new(),
            Some(Value::UnsignedArray(arr)) => arr.clone(),
            Some(_) => return Err(corrupt("raidz_expand_txgs is not a uint64 array")),
        };
        let expanding = match tree.fields.get("raidz_expanding") {
            None => false,
            Some(Value::Unsigned(1) | Value::Boolean(true)) => true,
            Some(_) => {
                return Err(unsupported(
                    "invalid or unsupported raidz_expanding metadata",
                ));
            }
        };
        if expand_txgs.is_empty() && !expanding {
            return Ok(None);
        }
        let added = expand_txgs.len() + usize::from(expanding);
        if added >= physical_width {
            return Err(corrupt(
                "raidz_expand_txgs count meets or exceeds physical width",
            ));
        }
        let original_width = physical_width - added;
        Ok(Some(Self {
            original_width,
            physical_width,
            expand_txgs,
            expanding,
            reflow_offset_synced: if expanding { 0 } else { u64::MAX },
            reflow_offset_next: if expanding { 0 } else { u64::MAX },
            use_scratch: false,
        }))
    }
}

/// Parse a dRAID `vdev_tree` into a validated [`DraidConfig`].
pub fn parse_draid_tree_config(tree: &NvList) -> Result<DraidConfig> {
    if tree.text("type") != Some("draid") {
        return Err(corrupt("expected draid vdev_tree type"));
    }
    let Some(Value::Lists(children)) = tree.fields.get("children") else {
        return Err(corrupt("dRAID vdev has no children array"));
    };
    let ndata = usize::try_from(integer(tree, "draid_ndata")?)
        .map_err(|_| corrupt("draid_ndata overflow"))?;
    let nparity = usize::try_from(integer(tree, "nparity")?)
        .map_err(|_| corrupt("dRAID nparity overflow"))?;
    let nspares = usize::try_from(tree.unsigned("draid_nspares").unwrap_or(0))
        .map_err(|_| corrupt("draid_nspares overflow"))?;
    let ngroups = usize::try_from(integer(tree, "draid_ngroups")?)
        .map_err(|_| corrupt("draid_ngroups overflow"))?;
    let ashift =
        u8::try_from(integer(tree, "ashift")?).map_err(|_| corrupt("dRAID ashift overflow"))?;
    DraidConfig::new(children.len(), ndata, nparity, nspares, ngroups, ashift)
        .map_err(|e| parse(&e))
}

/// Parse an `indirect` top-level vdev tree into [`VdevIndirectConfig`].
pub fn parse_indirect_tree_config(tree: &NvList) -> Result<VdevIndirectConfig> {
    if tree.text("type") != Some("indirect") {
        return Err(corrupt("expected indirect vdev_tree type"));
    }
    let vdev_id =
        u32::try_from(integer(tree, "id")?).map_err(|_| corrupt("indirect vdev ID overflow"))?;
    let mapping_object = integer(tree, "indirect_object")?;
    let births_object = integer(tree, "indirect_births")?;
    let prev_raw = tree.unsigned("prev_indirect_vdev").unwrap_or(u64::MAX);
    let prev_indirect_vdev = if prev_raw == u64::MAX {
        None
    } else {
        Some(u32::try_from(prev_raw).map_err(|_| corrupt("prev_indirect_vdev ID overflow"))?)
    };
    Ok(VdevIndirectConfig {
        vdev_id,
        mapping_object,
        births_object,
        prev_indirect_vdev,
    })
}

/// Top-level vdev implementation kind inside a [`PoolTopology`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopVdevKind {
    Leaf,
    Mirror,
    Raidz {
        parity: usize,
        expanded: Option<ExpandedRaidzMeta>,
    },
    Draid(DraidConfig),
    Indirect(VdevIndirectConfig),
    Hole,
}

/// Descriptor for one top-level vdev slot `0..vdev_children`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopVdevDescriptor {
    pub id: u32,
    pub guid: u64,
    pub ashift: u8,
    pub asize: u64,
    pub alloc_class: AllocClass,
    pub health: VdevHealth,
    pub kind: TopVdevKind,
    pub children_guids: Vec<u64>,
    pub supplied_indices: Vec<Option<usize>>,
    pub nonallocating: bool,
}

impl TopVdevDescriptor {
    /// True when this top-level vdev contributes to OpenZFS's `ub_guid_sum`.
    /// OpenZFS excludes `hole`, `indirect`, `spares`, and `l2cache` from `guid_sum`.
    #[must_use]
    pub const fn contributes_to_guid_sum(&self) -> bool {
        !matches!(self.kind, TopVdevKind::Hole | TopVdevKind::Indirect(_))
            && !matches!(self.alloc_class, AllocClass::Spare | AllocClass::Cache)
    }

    /// Recursive contribution of this top-level vdev to `ub_guid_sum`.
    #[must_use]
    pub fn guid_sum_contribution(&self) -> u64 {
        if !self.contributes_to_guid_sum() {
            return 0;
        }
        let mut sum = self.guid;
        for &child in &self.children_guids {
            if child != self.guid {
                sum = sum.wrapping_add(child);
            }
        }
        sum
    }

    /// True if every configured child has a supplied physical device handle.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        match self.kind {
            TopVdevKind::Hole | TopVdevKind::Indirect(_) => true,
            _ => {
                !self.supplied_indices.is_empty()
                    && self.supplied_indices.iter().all(Option::is_some)
            }
        }
    }
}

/// Unified pool-wide vdev topology parsed from MOS `config` + member labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolTopology {
    pub pool_guid: u64,
    pub version: u64,
    pub top_vdevs: Vec<TopVdevDescriptor>,
    /// Auxiliary hot spare leaf GUIDs (never included in `guid_sum`).
    pub spares: Vec<u64>,
    /// Optional L2ARC cache leaf GUIDs (isolated; never required or in `guid_sum`).
    pub l2cache: Vec<u64>,
    /// Expected OpenZFS `ub_guid_sum` across `pool_guid` and active data/log vdevs.
    pub guid_sum: u64,
}

impl PoolTopology {
    /// Compute canonical OpenZFS `vdev_guid_sum` over `pool_guid` and all
    /// participating top-level vdevs (excluding `hole`, `indirect`, `spares`,
    /// and `l2cache`).
    #[must_use]
    pub fn compute_guid_sum(pool_guid: u64, top_vdevs: &[TopVdevDescriptor]) -> u64 {
        top_vdevs.iter().fold(pool_guid, |acc, top| {
            acc.wrapping_add(top.guid_sum_contribution())
        })
    }

    /// Parse pool-wide topology from a MOS `config` packed nvlist and bind
    /// each concrete physical child GUID to its supplied index in `supplied_guids`.
    ///
    /// Enforces fail-closed checks:
    /// - Required storage classes (`Normal`, `Special`, `Dedup`) with zero
    ///   surviving members fail closed immediately.
    /// - `l2cache` entries are recorded in `l2cache` and completely isolated
    ///   from required storage and `guid_sum`.
    #[allow(clippy::too_many_lines)]
    pub fn from_mos_config(mos_config: &NvList, supplied_guids: &[u64]) -> Result<Self> {
        let pool_guid = integer(mos_config, "pool_guid")?;
        if pool_guid == 0 {
            return Err(corrupt("MOS config has zero pool_guid"));
        }
        let version = integer(mos_config, "version")?;
        let root = mos_config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("MOS config missing vdev_tree"))?;
        if root.text("type") != Some("root") || integer(root, "guid")? != pool_guid {
            return Err(corrupt("MOS vdev_tree root GUID disagrees with pool_guid"));
        }
        let Some(Value::Lists(children)) = root.fields.get("children") else {
            return Err(corrupt("MOS root vdev_tree has no children"));
        };
        if children.is_empty() || children.len() > 255 {
            return Err(unsupported(
                "MOS root vdev_tree child count outside supported 1..=255 range",
            ));
        }

        let mut spares = Vec::new();
        if let Some(Value::Lists(spare_list)) = root.fields.get("spares") {
            for sp in spare_list {
                if let Some(g) = sp.unsigned("guid")
                    && g != 0
                {
                    spares.push(g);
                }
            }
        }
        let mut l2cache = Vec::new();
        if let Some(Value::Lists(cache_list)) = root.fields.get("l2cache") {
            for c in cache_list {
                if let Some(g) = c.unsigned("guid")
                    && g != 0
                {
                    l2cache.push(g);
                }
            }
        }

        let mut seen_guids = BTreeSet::from([pool_guid]);
        let mut top_vdevs = Vec::with_capacity(children.len());
        for (idx, child) in children.iter().enumerate() {
            let id = u32::try_from(integer(child, "id")?)
                .map_err(|_| corrupt("top-level vdev ID overflow"))?;
            if id as usize != idx {
                return Err(corrupt("MOS top-level vdev IDs are not contiguous"));
            }
            let ty = child
                .text("type")
                .ok_or_else(|| corrupt("top-level vdev missing type"))?;
            let is_hole = ty == "hole" || child.unsigned("is_hole").unwrap_or(0) != 0;
            if is_hole {
                top_vdevs.push(TopVdevDescriptor {
                    id,
                    guid: 0,
                    ashift: 0,
                    asize: 0,
                    alloc_class: AllocClass::Normal,
                    health: VdevHealth::Online,
                    kind: TopVdevKind::Hole,
                    children_guids: Vec::new(),
                    supplied_indices: Vec::new(),
                    nonallocating: true,
                });
                continue;
            }
            if ty == "indirect" {
                let ind = parse_indirect_tree_config(child)?;
                let guid = child.unsigned("guid").unwrap_or(0);
                let ashift = u8::try_from(child.unsigned("ashift").unwrap_or(9))
                    .map_err(|_| corrupt("indirect vdev ashift overflow"))?;
                let asize = child.unsigned("asize").unwrap_or(0);
                top_vdevs.push(TopVdevDescriptor {
                    id,
                    guid,
                    ashift,
                    asize,
                    alloc_class: AllocClass::Normal,
                    health: VdevHealth::Online,
                    kind: TopVdevKind::Indirect(ind),
                    children_guids: Vec::new(),
                    supplied_indices: Vec::new(),
                    nonallocating: true,
                });
                continue;
            }

            let alloc_class = AllocClass::from_vdev_tree(child)?;
            let health = VdevHealth::from_vdev_tree(child);
            let guid = integer(child, "guid")?;
            if guid == 0 || !seen_guids.insert(guid) {
                return Err(corrupt("duplicate or zero top-level vdev GUID"));
            }
            let ashift =
                u8::try_from(integer(child, "ashift")?).map_err(|_| corrupt("ashift overflow"))?;
            let asize = integer(child, "asize")?;
            let nonallocating = child.unsigned("nonallocating").unwrap_or(0) != 0;

            let (kind, children_guids, supplied_indices) = match ty {
                "file" | "disk" => {
                    let supplied = supplied_guids.iter().position(|&g| g == guid);
                    (TopVdevKind::Leaf, vec![guid], vec![supplied])
                }
                "mirror" => {
                    let (guids, indices) =
                        collect_physical_children(child, &mut seen_guids, supplied_guids)?;
                    (TopVdevKind::Mirror, guids, indices)
                }
                "raidz" => {
                    let parity = usize::try_from(integer(child, "nparity")?)
                        .map_err(|_| corrupt("RAIDZ nparity overflow"))?;
                    if !(1..=3).contains(&parity) {
                        return Err(unsupported("RAIDZ requires 1..=3 parity columns"));
                    }
                    let (guids, indices) =
                        collect_physical_children(child, &mut seen_guids, supplied_guids)?;
                    if guids.len() <= parity || guids.len() > 255 {
                        return Err(unsupported("RAIDZ width outside parity+1..=255"));
                    }
                    let expanded = ExpandedRaidzMeta::from_vdev_tree(child, guids.len())?;
                    (TopVdevKind::Raidz { parity, expanded }, guids, indices)
                }
                "draid" => {
                    let draid_cfg = parse_draid_tree_config(child)?;
                    let (guids, indices) =
                        collect_physical_children(child, &mut seen_guids, supplied_guids)?;
                    if guids.len() != draid_cfg.children {
                        return Err(corrupt("dRAID child count disagrees with config"));
                    }
                    (TopVdevKind::Draid(draid_cfg), guids, indices)
                }
                other => {
                    return Err(unsupported(format!(
                        "unsupported top-level ZFS vdev type '{other}'"
                    )));
                }
            };

            top_vdevs.push(TopVdevDescriptor {
                id,
                guid,
                ashift,
                asize,
                alloc_class,
                health,
                kind,
                children_guids,
                supplied_indices,
                nonallocating,
            });
        }

        let guid_sum = Self::compute_guid_sum(pool_guid, &top_vdevs);
        let topology = Self {
            pool_guid,
            version,
            top_vdevs,
            spares,
            l2cache,
            guid_sum,
        };
        topology.validate_required_classes_present()?;
        Ok(topology)
    }

    /// Verify every required storage class (`Normal`, `Special`, `Dedup`) has
    /// sufficient surviving members to be readable. Missing required classes
    /// fail closed — they are NEVER silently treated as optional cache.
    pub fn validate_required_classes_present(&self) -> Result<()> {
        for top in &self.top_vdevs {
            if !top.alloc_class.is_required_storage() {
                continue;
            }
            if matches!(top.kind, TopVdevKind::Hole | TopVdevKind::Indirect(_)) {
                continue;
            }
            let present = top
                .supplied_indices
                .iter()
                .filter(|idx| idx.is_some())
                .count();
            let missing = top.supplied_indices.len().saturating_sub(present);
            let readable = match &top.kind {
                TopVdevKind::Leaf => present == 1,
                TopVdevKind::Mirror => present >= 1,
                TopVdevKind::Raidz { parity, .. } => present >= 1 && missing <= *parity,
                TopVdevKind::Draid(cfg) => present >= 1 && missing <= cfg.nparity,
                TopVdevKind::Hole | TopVdevKind::Indirect(_) => true,
            };
            if !readable {
                return Err(unsupported(format!(
                    "required ZFS {:?} top-level vdev {} (guid {}) lacks surviving members ({} missing)",
                    top.alloc_class, top.id, top.guid, missing
                )));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn top_vdev(&self, vdev_id: u32) -> Option<&TopVdevDescriptor> {
        self.top_vdevs.get(vdev_id as usize)
    }

    #[must_use]
    pub fn has_degraded_vdev(&self) -> bool {
        self.top_vdevs
            .iter()
            .any(|top| !top.is_complete() || !top.health.is_healthy())
    }
}

fn collect_physical_children(
    parent: &NvList,
    seen_guids: &mut BTreeSet<u64>,
    supplied_guids: &[u64],
) -> Result<(Vec<u64>, Vec<Option<usize>>)> {
    let Some(Value::Lists(children)) = parent.fields.get("children") else {
        return Err(corrupt("compound vdev missing children array"));
    };
    if children.is_empty() || children.len() > 255 {
        return Err(unsupported("compound vdev child count outside 1..=255"));
    }
    let mut guids = Vec::with_capacity(children.len());
    let mut indices = Vec::with_capacity(children.len());
    for (idx, child) in children.iter().enumerate() {
        if integer(child, "id")? != idx as u64 {
            return Err(corrupt("compound vdev child IDs are not contiguous"));
        }
        let child_ty = child.text("type");
        if matches!(child_ty, Some("replacing" | "spare")) {
            // Virtual wrapper over [old_child, new_or_spare_child]: take the
            // first supplied leaf or fall back to child[0]'s GUID.
            let Some(Value::Lists(sub)) = child.fields.get("children") else {
                return Err(corrupt("replacing/spare vdev missing children"));
            };
            let mut chosen_guid = None;
            let mut chosen_idx = None;
            for leaf in sub {
                if let Some(g) = leaf.unsigned("guid")
                    && g != 0
                {
                    let _ = seen_guids.insert(g);
                    if chosen_guid.is_none() {
                        chosen_guid = Some(g);
                    }
                    if chosen_idx.is_none()
                        && let Some(pos) = supplied_guids.iter().position(|&s| s == g)
                    {
                        chosen_guid = Some(g);
                        chosen_idx = Some(pos);
                    }
                }
            }
            let g = chosen_guid.ok_or_else(|| corrupt("replacing/spare vdev has no leaf GUID"))?;
            guids.push(g);
            indices.push(chosen_idx);
            continue;
        }
        if !matches!(child_ty, Some("file" | "disk" | "draid_spare")) {
            return Err(unsupported(
                "compound vdev child must be file, disk, draid_spare, replacing, or spare",
            ));
        }
        let g = integer(child, "guid")?;
        if g == 0 || !seen_guids.insert(g) {
            return Err(corrupt("duplicate or zero physical child GUID"));
        }
        let pos = supplied_guids.iter().position(|&s| s == g);
        guids.push(g);
        indices.push(pos);
    }
    Ok((guids, indices))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn first_active_raidz_expansion_has_no_completed_history() {
        let tree = NvList {
            fields: BTreeMap::from([("raidz_expanding".into(), Value::Boolean(true))]),
        };
        let mut meta = ExpandedRaidzMeta::from_vdev_tree(&tree, 4)
            .unwrap()
            .unwrap();
        assert!(meta.expanding);
        assert_eq!(meta.original_width, 3);
        assert_eq!(
            meta.to_ondisk(12, 1).unwrap().logical_width_for_birth(900),
            3
        );
        meta.apply_reflow_info(0).unwrap();
        assert_eq!(meta.reflow_offset_synced, 0);
        for state in [
            RaidzReflowScratchState::Valid,
            RaidzReflowScratchState::InvalidSynced,
            RaidzReflowScratchState::InvalidSyncedOnImport,
            RaidzReflowScratchState::InvalidSyncedReflow,
        ] {
            meta.apply_reflow_info(
                RaidzReflowInfo {
                    offset: 65_536,
                    state,
                }
                .encode()
                .unwrap(),
            )
            .unwrap();
            assert_eq!(meta.reflow_offset_synced, 65_536);
            assert_eq!(meta.reflow_offset_next, 65_536);
            assert_eq!(meta.use_scratch, state == RaidzReflowScratchState::Valid);
        }
        assert!(meta.apply_reflow_info(5_u64 << 55).is_err());
    }

    #[test]
    fn active_and_completed_expansion_history_have_distinct_widths() {
        let mut tree = NvList {
            fields: BTreeMap::from([
                ("raidz_expanding".into(), Value::Unsigned(1)),
                ("raidz_expand_txgs".into(), Value::UnsignedArray(vec![20])),
            ]),
        };
        let active = ExpandedRaidzMeta::from_vdev_tree(&tree, 5)
            .unwrap()
            .unwrap();
        let config = active.to_ondisk(12, 1).unwrap();
        assert_eq!(config.logical_width_for_birth(19), 3);
        assert_eq!(config.logical_width_for_birth(20), 4);
        assert_eq!(config.logical_width_for_birth(100), 4);

        tree.fields.remove("raidz_expanding");
        tree.fields.insert(
            "raidz_expand_txgs".into(),
            Value::UnsignedArray(vec![20, 40]),
        );
        let mut finished = ExpandedRaidzMeta::from_vdev_tree(&tree, 5)
            .unwrap()
            .unwrap();
        assert!(!finished.expanding);
        assert_eq!(
            finished
                .to_ondisk(12, 1)
                .unwrap()
                .logical_width_for_birth(40),
            5
        );
        finished.apply_reflow_info(0).unwrap();
        assert_eq!(finished.reflow_offset_synced, u64::MAX);
        assert!(
            finished
                .apply_reflow_info(
                    RaidzReflowInfo {
                        offset: 65_536,
                        state: RaidzReflowScratchState::Valid,
                    }
                    .encode()
                    .unwrap()
                )
                .is_err()
        );
    }

    fn leaf_nv(id: u64, guid: u64, alloc_bias: Option<&str>, is_log: bool) -> NvList {
        let mut fields = BTreeMap::new();
        fields.insert("type".into(), Value::String("file".into()));
        fields.insert("id".into(), Value::Unsigned(id));
        fields.insert("guid".into(), Value::Unsigned(guid));
        fields.insert("ashift".into(), Value::Unsigned(12));
        fields.insert("asize".into(), Value::Unsigned(64 * 1024 * 1024));
        if let Some(b) = alloc_bias {
            fields.insert("allocation_bias".into(), Value::String(b.into()));
        }
        if is_log {
            fields.insert("is_log".into(), Value::Unsigned(1));
        }
        NvList { fields }
    }

    #[test]
    fn topology_excludes_hole_indirect_spares_l2cache_from_guid_sum_and_refuses_missing_special() {
        let normal = leaf_nv(0, 100, None, false);
        let special = leaf_nv(1, 200, Some("special"), false);
        let slog = leaf_nv(2, 300, None, true);
        let mut hole_fields = BTreeMap::new();
        hole_fields.insert("type".into(), Value::String("hole".into()));
        hole_fields.insert("id".into(), Value::Unsigned(3));
        hole_fields.insert("is_hole".into(), Value::Unsigned(1));
        let hole = NvList {
            fields: hole_fields,
        };
        let mut ind_fields = BTreeMap::new();
        ind_fields.insert("type".into(), Value::String("indirect".into()));
        ind_fields.insert("id".into(), Value::Unsigned(4));
        ind_fields.insert("guid".into(), Value::Unsigned(999));
        ind_fields.insert("indirect_object".into(), Value::Unsigned(55));
        ind_fields.insert("indirect_births".into(), Value::Unsigned(56));
        let indirect = NvList { fields: ind_fields };

        let spare = leaf_nv(0, 777, None, false);
        let cache = leaf_nv(0, 888, None, false);

        let mut root_fields = BTreeMap::new();
        root_fields.insert("type".into(), Value::String("root".into()));
        root_fields.insert("id".into(), Value::Unsigned(0));
        root_fields.insert("guid".into(), Value::Unsigned(42));
        root_fields.insert(
            "children".into(),
            Value::Lists(vec![normal, special, slog, hole, indirect]),
        );
        root_fields.insert("spares".into(), Value::Lists(vec![spare]));
        root_fields.insert("l2cache".into(), Value::Lists(vec![cache]));

        let mut cfg_fields = BTreeMap::new();
        cfg_fields.insert("pool_guid".into(), Value::Unsigned(42));
        cfg_fields.insert("version".into(), Value::Unsigned(5000));
        cfg_fields.insert(
            "vdev_tree".into(),
            Value::List(NvList {
                fields: root_fields,
            }),
        );
        let mos_cfg = NvList { fields: cfg_fields };

        // Supplying Normal + Special + SLOG succeeds even without l2cache or spare!
        let topo = PoolTopology::from_mos_config(&mos_cfg, &[100, 200, 300]).unwrap();
        assert_eq!(topo.guid_sum, 42 + 100 + 200 + 300);
        assert_eq!(topo.spares, vec![777]);
        assert_eq!(topo.l2cache, vec![888]);
        assert_eq!(topo.top_vdev(1).unwrap().alloc_class, AllocClass::Special);
        assert_eq!(topo.top_vdev(2).unwrap().alloc_class, AllocClass::Log);
        assert!(matches!(topo.top_vdev(3).unwrap().kind, TopVdevKind::Hole));
        assert!(matches!(
            topo.top_vdev(4).unwrap().kind,
            TopVdevKind::Indirect(_)
        ));

        // Omitting required Special vdev MUST fail closed!
        assert!(PoolTopology::from_mos_config(&mos_cfg, &[100, 300]).is_err());
        // Omitting optional SLOG (when clean) is not blocked by required_storage check,
        // while supplying Normal + Special passes.
        assert!(PoolTopology::from_mos_config(&mos_cfg, &[100, 200]).is_ok());
    }
}
