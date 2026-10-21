//! Complete, immutable stripes of ordinary mirrors and/or standalone leaves.
//!
//! Labels describe their own top-level subtree, not every disk in the pool.
//! Join those subtrees by native ID/GUID before admitting a payload address.
//! Reference: OpenZFS zfs-2.3.0 vdev_label.c's configuration contract. No native
//! implementation code is reused; this grants neither write nor import authority.

use super::{
    BTreeSet, Cx, Label, MAX_MEMBERS, NvList, Pool, RaidzGroup, RaidzMember, Result, RootBlock,
    Value, VdevConfig, admit_vdev_state, checkpoint, corrupt, integer, parse, same_candidate,
    unsupported,
};
use crate::reader::{DATA_OFFSET, LABEL_BYTES};
use std::sync::Arc;

#[derive(Clone, PartialEq, Eq)]
struct Top {
    config: VdevConfig,
    tree: NvList,
    guids: Vec<u64>,
    state: u64,
}

/// The config still counts top-level capacity once. Sources retain every real
/// child in native mirror order; indices always address the owning Pool's leaves.
#[derive(Clone)]
pub(super) struct Topology {
    pub(super) config: VdevConfig,
    sources: Vec<Vec<usize>>,
    pub(super) supplied_guids: Vec<u64>,
    pub(super) guid_sum: u64,
}

fn top(label: &Label, pool_guid: u64, count: usize, active: bool) -> Result<(Top, u64)> {
    let config = label.vdev_config_with_mode(pool_guid, active, true)?;
    if integer(&label.config, "vdev_children")? != count as u64 {
        return Err(corrupt("top-level labels disagree on vdev_children"));
    }
    let tree = label
        .config
        .list("vdev_tree")
        .ok_or_else(|| corrupt("missing top-level subtree"))?;
    let guid = integer(&label.config, "guid")?;
    let mut guids = Vec::new();
    match tree.text("type") {
        Some("file" | "disk") if !tree.fields.contains_key("children") => {
            if guid != config.top_guid {
                return Err(corrupt("standalone top-level and leaf GUIDs disagree"));
            }
            guids.push(guid);
        }
        Some("mirror") => {
            let Some(Value::Lists(children)) = tree.fields.get("children") else {
                return Err(corrupt("mirror has no native child array"));
            };
            if !(2..=MAX_MEMBERS).contains(&children.len()) {
                return Err(unsupported(
                    "ordinary mirror requires two through eight children",
                ));
            }
            let mut seen = BTreeSet::from([pool_guid, config.top_guid]);
            for (id, child) in children.iter().enumerate() {
                if !matches!(child.text("type"), Some("file" | "disk"))
                    || child.fields.contains_key("children")
                {
                    return Err(unsupported(
                        "striped mirror children must be ordinary disk or file leaves",
                    ));
                }
                admit_vdev_state(child)?;
                let child_guid = integer(child, "guid")?;
                if integer(child, "id")? != id as u64 || child_guid == 0 || !seen.insert(child_guid)
                {
                    return Err(corrupt("mirror child IDs or GUIDs are invalid"));
                }
                guids.push(child_guid);
            }
            if !guids.contains(&guid) {
                return Err(corrupt("physical label GUID is not in its mirror subtree"));
            }
        }
        _ => {
            return Err(unsupported(
                "multi-vdev extraction admits ordinary mirrors and standalone leaves only",
            ));
        }
    }
    Ok((
        Top {
            config,
            tree: tree.clone(),
            guids,
            state: integer(&label.config, "state")?,
        },
        guid,
    ))
}

impl Pool {
    fn admit_striped_mirrors(&self, cx: &Cx, pool_guid: u64, active: bool) -> Result<Topology> {
        checkpoint(cx)?;
        if self.has_missing_members() {
            return Err(unsupported(
                "multi-vdev extraction requires every configured physical child",
            ));
        }
        // Explicit candidate selection retains its strict four-label contract.
        // Only automatic selection may discard an unreadable/bad-checksum copy.
        let labels = self
            .members
            .iter()
            .map(|member| {
                (0..4)
                    .map(|index| {
                        checkpoint(cx)?;
                        Ok((index, member.label(cx, index)?))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        self.admit_striped_labels(cx, &labels, pool_guid, active)
    }

    /// Join already checksum-verified label sets by native top-level identity.
    /// Both explicit and automatic selection use these identical topology rules.
    /// The sets must retain every valid copy, not just a preferred configuration.
    pub(super) fn admit_striped_labels(
        &self,
        cx: &Cx,
        labels: &[Vec<(usize, Label)>],
        pool_guid: u64,
        active: bool,
    ) -> Result<Topology> {
        checkpoint(cx)?;
        if self.has_missing_members() {
            return Err(unsupported(
                "multi-vdev extraction requires every configured physical child",
            ));
        }
        if labels.len() != self.members.len()
            || labels
                .iter()
                .any(|copies| copies.is_empty() || copies.len() > 4)
        {
            return Err(corrupt("each supplied member needs its verified label set"));
        }
        let first = labels
            .first()
            .and_then(|copies| copies.first())
            .ok_or_else(|| corrupt("no supplied top-level labels"))?;
        let count = usize::try_from(integer(&first.1.config, "vdev_children")?)
            .map_err(|_| corrupt("top-level vdev count overflows"))?;
        if !(2..=MAX_MEMBERS).contains(&count) || count > self.members.len() {
            return Err(unsupported(
                "supply every top-level vdev and all of its mirror children",
            ));
        }
        let mut tops: Vec<Option<Top>> = vec![None; count];
        let mut supplied_guids = Vec::with_capacity(self.members.len());
        let mut seen_leaves = BTreeSet::new();
        for (member, copies) in self.members.iter().zip(labels) {
            checkpoint(cx)?;
            let (selected, guid) = top(&copies[0].1, pool_guid, count, active)?;
            if !seen_leaves.insert(guid) {
                return Err(corrupt("supplied images repeat a physical leaf GUID"));
            }
            for (_, label) in &copies[1..] {
                checkpoint(cx)?;
                let (other, other_guid) = top(label, pool_guid, count, active)?;
                if other != selected || other_guid != guid {
                    return Err(corrupt(
                        "physical member labels disagree on their complete top-level subtree",
                    ));
                }
            }
            // Check EVERY member's capacity, including vdevs not used by the
            // selected MOS DVA. A good first replica must not conceal a short disk.
            let cfg = &selected.config;
            if !(9..=16).contains(&cfg.ashift) {
                return Err(corrupt("invalid top-level sector geometry"));
            }
            let sector = 1_u64 << cfg.ashift;
            let end = member.length / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
            if cfg.allocated_bytes == 0
                || !cfg.allocated_bytes.is_multiple_of(sector)
                || cfg.allocated_bytes > end - DATA_OFFSET
            {
                return Err(corrupt(
                    "top-level allocation exceeds a supplied physical child",
                ));
            }
            let slot = tops
                .get_mut(cfg.id as usize)
                .ok_or_else(|| corrupt("top-level ID exceeds the native slot count"))?;
            if let Some(previous) = slot {
                if *previous != selected {
                    return Err(corrupt(
                        "members disagree on their shared top-level subtree",
                    ));
                }
            } else {
                *slot = Some(selected);
            }
            supplied_guids.push(guid);
        }
        let tops: Vec<Top> = tops
            .into_iter()
            .map(|entry| {
                entry.ok_or_else(|| corrupt("a configured top-level vdev is not supplied"))
            })
            .collect::<Result<_>>()?;
        let first = &tops[0];
        let mut config = first.config.clone();
        let mut identities = BTreeSet::from([pool_guid]);
        let mut assigned = BTreeSet::new();
        let mut guid_sum = pool_guid;
        let mut sources = Vec::with_capacity(count);
        let mut routes = Vec::with_capacity(count);
        for selected in &tops {
            checkpoint(cx)?;
            let cfg = &selected.config;
            if cfg.version != first.config.version
                || cfg.read_features != first.config.read_features
                || selected.state != first.state
            {
                return Err(corrupt(
                    "top-level vdevs disagree on pool version, state or read features",
                ));
            }
            if !identities.insert(cfg.top_guid) {
                return Err(corrupt("top-level GUID aliases another native identity"));
            }
            guid_sum = guid_sum.wrapping_add(cfg.top_guid);
            config.txg = config.txg.max(cfg.txg);
            let mut indices = Vec::with_capacity(selected.guids.len());
            for &guid in &selected.guids {
                if guid != cfg.top_guid {
                    if !identities.insert(guid) {
                        return Err(corrupt("mirror leaf aliases another native identity"));
                    }
                    guid_sum = guid_sum.wrapping_add(guid);
                }
                let index = supplied_guids
                    .iter()
                    .position(|supplied| *supplied == guid)
                    .ok_or_else(|| {
                        unsupported("every configured mirror child must be explicitly supplied")
                    })?;
                if !assigned.insert(index) {
                    return Err(corrupt(
                        "one physical member belongs to multiple top-level vdevs",
                    ));
                }
                indices.push(index);
            }
            routes.push(RaidzMember {
                supplied_index: indices[0],
                guid: cfg.top_guid,
                ashift: cfg.ashift,
                allocated_bytes: cfg.allocated_bytes,
            });
            sources.push(indices);
        }
        if assigned.len() != self.members.len() {
            return Err(corrupt("a supplied member has no unique configured owner"));
        }
        config.raidz_members = Some(RaidzGroup {
            parity: 0,
            members: routes,
        });
        checkpoint(cx)?;
        Ok(Topology {
            config,
            sources,
            supplied_guids,
            guid_sum,
        })
    }

    pub(super) fn mirror_stripe_root(
        &self,
        cx: &Cx,
        label_index: usize,
        slot: usize,
        pool_guid: u64,
        active: bool,
    ) -> Result<RootBlock> {
        let topology = Arc::new(self.admit_striped_mirrors(cx, pool_guid, active)?);
        let mut candidate = None;
        for member in &self.members {
            checkpoint(cx)?;
            let label = member.label(cx, label_index)?;
            let ub = member.uberblock(cx, &label, slot)?;
            if ub.version != topology.config.version
                || ub.txg < topology.config.txg
                || ub.guid_sum != topology.guid_sum
                || candidate
                    .as_ref()
                    .is_some_and(|previous| !same_candidate(previous, &ub))
            {
                return Err(corrupt(
                    "striped mirror members disagree on the selected root or full GUID sum",
                ));
            }
            candidate = Some(ub);
        }
        let candidate = candidate.ok_or_else(|| corrupt("no selected striped-mirror candidate"))?;
        let mut owner = self.clone();
        owner.top_levels = Some(Arc::clone(&topology));
        let block = owner.read_block(cx, &topology.config, &candidate.root)?;
        if block.bytes.len() < 1024
            || candidate
                .root
                .payload_order()
                .u64(&block.bytes, 704)
                .map_err(|error| parse(&error))?
                != 1
        {
            return Err(corrupt(
                "selected striped-mirror root is not a META object set",
            ));
        }
        checkpoint(cx)?;
        Ok(RootBlock {
            uberblock: candidate,
            data: block.bytes,
            physical_offset: block.physical_offset,
            copy_index: block.copy_index,
            member_guid: topology.supplied_guids[block.member_index],
            raidz: None,
            config: topology.config.clone(),
        })
    }

    /// Bind a selected RootBlock to a retained owner before MOS feature reads.
    /// Ordinary leaf stripes need no extra map. Composite roots are re-admitted
    /// and must reproduce their complete selected config and supplied indices.
    pub(in crate::reader) fn retain_striped_topology(
        mut self,
        cx: &Cx,
        config: &VdevConfig,
    ) -> Result<Self> {
        if config
            .raidz_members
            .as_ref()
            .is_some_and(|group| group.parity == 0 && group.members.len() != self.members.len())
        {
            // Automatic import may have selected a healthy ring beside a bad
            // config copy. Reopening that view must not revert to label zero or
            // lose mirror children before MOS feature and dataset reads.
            // Explicit selection already checked all four copies at its entry.
            let labels = self
                .members
                .iter()
                .map(|member| super::import::verified_labels(cx, member))
                .collect::<Result<Vec<_>>>()?;
            let topology = self.admit_striped_labels(cx, &labels, config.pool_guid, true)?;
            if topology.config != *config {
                return Err(corrupt(
                    "selected root lost its native striped-mirror mapping",
                ));
            }
            self.top_levels = Some(Arc::new(topology));
        }
        checkpoint(cx)?;
        Ok(self)
    }

    pub(in crate::reader) fn striped_sources<'a>(
        &'a self,
        id: u32,
        route: &'a RaidzMember,
    ) -> Result<&'a [usize]> {
        if let Some(topology) = &self.top_levels {
            let group = topology
                .config
                .raidz_members
                .as_ref()
                .ok_or_else(|| corrupt("retained striped topology has no native routes"))?;
            if group.members.get(id as usize) != Some(route) {
                return Err(corrupt("striped route differs from its retained topology"));
            }
            return topology
                .sources
                .get(id as usize)
                .map(Vec::as_slice)
                .ok_or_else(|| corrupt("striped route has no retained physical members"));
        }
        Ok(std::slice::from_ref(&route.supplied_index))
    }

    /// Conservative multiplicity for whole-tree gang read/audit work admission.
    pub(in crate::reader) fn replica_factor(&self, config: &VdevConfig) -> u64 {
        match &config.raidz_members {
            Some(group) if group.parity == 0 => self
                .top_levels
                .as_ref()
                .and_then(|topology| topology.sources.iter().map(Vec::len).max())
                .unwrap_or(1) as u64,
            Some(_) => 1,
            None => self.members.len() as u64,
        }
    }
}

#[cfg(test)]
pub(in crate::reader) mod tests;
