//! Explicit immutable member sets for a leaf, ordinary mirror or RAIDZ group.
//!
//! Native child IDs come from verified labels, never argument positions.
//! Checksums decide whether replica or reconstructed bytes are usable.
//! This is read-only extraction, without degraded import, DTL recovery or healing.

pub(in crate::reader) mod raidz;

use super::{
    BlockPointer, BlockRead, Cx, DATA_OFFSET, FfsError, Label, Leaf, NvList, RaidzGroup,
    RaidzMember, Result, RootBlock, Uberblock, Value, VdevConfig, admit_vdev_state,
    checkpoint, corrupt, integer, parse, unsupported,
};
use std::collections::BTreeSet;

const MAX_MEMBERS: usize = 8;

#[derive(Clone)]
pub struct Pool {
    members: Vec<Leaf>,
}

impl From<Leaf> for Pool {
    fn from(leaf: Leaf) -> Self {
        Self {
            members: vec![leaf],
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
}

impl GroupConfig {
    fn mapped(self, supplied_guids: &[u64]) -> Result<VdevConfig> {
        let mut config = self.vdev;
        if self.raidz_parity != 0 {
            let mut members = Vec::with_capacity(self.member_guids.len());
            for guid in self.member_guids {
                let supplied_index = supplied_guids
                    .iter()
                    .position(|candidate| *candidate == guid)
                    .ok_or_else(|| corrupt("configured RAIDZ child has no supplied member"))?;
                members.push(RaidzMember {
                    supplied_index,
                    guid,
                });
            }
            config.raidz_members = Some(RaidzGroup {
                parity: self.raidz_parity,
                members,
            });
        }
        Ok(config)
    }
}

impl Label {
    fn group_config(&self, pool_guid: u64) -> Result<(GroupConfig, u64)> {
        let vdev = self.vdev_config(pool_guid)?;
        let tree = self
            .config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("missing redundant vdev tree"))?;
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
            _ => {
                return Err(unsupported(
                    "multiple supplied images require one ordinary mirror or RAIDZ group",
                ));
            }
        };
        let Some(Value::Lists(children)) = tree.fields.get("children") else {
            return Err(corrupt(
                "redundant vdev has no native nvlist-array children",
            ));
        };
        if !(2..=MAX_MEMBERS).contains(&children.len()) || children.len() <= raidz_parity {
            return Err(unsupported(
                "redundant read profile requires two through eight children and a data column",
            ));
        }
        let mut seen = BTreeSet::from([vdev.pool_guid, vdev.top_guid]);
        let mut member_guids = Vec::with_capacity(children.len());
        for (index, child) in children.iter().enumerate() {
            if !matches!(child.text("type"), Some("file" | "disk"))
                || child.fields.contains_key("children")
            {
                return Err(unsupported(
                    "redundant vdev children must be ordinary file or disk leaves",
                ));
            }
            admit_vdev_state(child)?;
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
    /// images must supply the complete native mirror or RAIDZ member set.
    pub fn from_leaves(members: Vec<Leaf>) -> Result<Self> {
        if !(1..=MAX_MEMBERS).contains(&members.len()) {
            return Err(unsupported(
                "supply one leaf or two through eight redundant members",
            ));
        }
        Ok(Self { members })
    }

    pub(super) fn standalone_leaf(&self) -> Option<&Leaf> {
        match self.members.as_slice() {
            [leaf] => Some(leaf),
            _ => None,
        }
    }

    pub fn root(
        &self,
        cx: &Cx,
        label_index: usize,
        slot: usize,
        pool_guid: u64,
    ) -> Result<RootBlock> {
        checkpoint(cx)?;
        if self.members.len() == 1 {
            return self.members[0].root(cx, label_index, slot, pool_guid);
        }
        let first_label = self.members[0].label(cx, label_index)?;
        let (selected, _) = first_label.group_config(pool_guid)?;
        if selected.member_guids.len() != self.members.len() {
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
            let (config, guid) = label.group_config(pool_guid)?;
            if config != selected || !seen.insert(guid) {
                return Err(corrupt(
                    "supplied members disagree or repeat a physical GUID",
                ));
            }
            for index in 0..4 {
                let (other, other_guid) = member.label(cx, index)?.group_config(pool_guid)?;
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
        // Membership, uniqueness and counts prove this is the complete group.
        // Bind native child IDs and parity only after all labels have agreed.
        let config = selected.mapped(&member_guids)?;
        let block = self.read_block(cx, &config, &candidate.root)?;
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
            member_guid: member_guids[block.member_index],
            raidz: block.raidz,
            config,
        })
    }

    pub(super) fn read_block(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
    ) -> Result<BlockRead> {
        checkpoint(cx)?;
        if let Some(group) = &config.raidz_members {
            return self.read_raidz_block(cx, config, bp, group);
        }
        if self.members.len() == 1 {
            return self.members[0].read_block(cx, config, bp).map(
                |(bytes, physical_offset, copy_index)| BlockRead {
                    bytes,
                    physical_offset,
                    copy_index,
                    member_index: 0,
                    raidz: None,
                },
            );
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
                    .and_then(|raw| bp.decode(&raw).map_err(|error| parse(&error)));
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
}
