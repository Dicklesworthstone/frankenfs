//! Explicit immutable member sets for one ordinary leaf or one native mirror.
//!
//! Mirrors use the same data offset on every physical child. Checksums decide
//! whether a copy is usable; successful physical I/O alone never does. This is
//! read-only extraction, without degraded import, DTL recovery or healing.

use super::{
    BlockPointer, Cx, DATA_OFFSET, FfsError, Label, Leaf, NvList, Result, RootBlock, Uberblock,
    Value, VdevConfig, admit_vdev_state, checkpoint, corrupt, integer, parse, unsupported,
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
struct MirrorConfig {
    vdev: VdevConfig,
    // Preserve the complete native top-level tree when checking agreement.
    // Native path strings are compared as metadata, never opened as host paths.
    tree: NvList,
    member_guids: Vec<u64>,
}

impl Label {
    fn mirror_config(&self, pool_guid: u64) -> Result<(MirrorConfig, u64)> {
        let vdev = self.vdev_config(pool_guid)?;
        let tree = self
            .config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("missing mirror vdev tree"))?;
        if tree.text("type") != Some("mirror") {
            return Err(unsupported(
                "multiple supplied images require one ordinary top-level mirror",
            ));
        }
        let Some(Value::Lists(children)) = tree.fields.get("children") else {
            return Err(corrupt("mirror has no native nvlist-array children"));
        };
        if !(2..=MAX_MEMBERS).contains(&children.len()) {
            return Err(unsupported(
                "mirror profile requires two through eight children",
            ));
        }
        let mut seen = BTreeSet::from([vdev.pool_guid, vdev.top_guid]);
        let mut member_guids = Vec::with_capacity(children.len());
        for (index, child) in children.iter().enumerate() {
            if !matches!(child.text("type"), Some("file" | "disk"))
                || child.fields.contains_key("children")
            {
                return Err(unsupported(
                    "mirror children must be ordinary file or disk leaves",
                ));
            }
            admit_vdev_state(child)?;
            if integer(child, "id")? != index as u64 {
                return Err(corrupt(
                    "mirror child IDs do not match the native child array",
                ));
            }
            let guid = integer(child, "guid")?;
            if guid == 0 || !seen.insert(guid) {
                return Err(corrupt("duplicate or zero mirror member GUID"));
            }
            member_guids.push(guid);
        }
        let member_guid = integer(&self.config, "guid")?;
        if !member_guids.contains(&member_guid) {
            return Err(corrupt("label GUID is not a child of its declared mirror"));
        }
        Ok((
            MirrorConfig {
                vdev,
                tree: tree.clone(),
                member_guids,
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
    /// Host paths have already been explicitly opened by the caller. A single
    /// image retains the standalone-leaf profile; two or more require a mirror.
    pub fn from_leaves(members: Vec<Leaf>) -> Result<Self> {
        if !(1..=MAX_MEMBERS).contains(&members.len()) {
            return Err(unsupported(
                "supply one leaf or two through eight mirror members",
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
        let (selected, _) = first_label.mirror_config(pool_guid)?;
        if selected.member_guids.len() != self.members.len() {
            return Err(unsupported(
                "every configured mirror member must be explicitly supplied",
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
                "mirror candidate disagrees with the pool configuration or GUID sum",
            ));
        }
        let mut seen = BTreeSet::new();
        let mut member_guids = Vec::with_capacity(self.members.len());
        for member in &self.members {
            checkpoint(cx)?;
            let label = member.label(cx, label_index)?;
            let (config, guid) = label.mirror_config(pool_guid)?;
            if config != selected || !seen.insert(guid) {
                return Err(corrupt(
                    "supplied mirror members disagree or repeat a physical GUID",
                ));
            }
            for index in 0..4 {
                let (other, other_guid) = member.label(cx, index)?.mirror_config(pool_guid)?;
                if other != selected || other_guid != guid {
                    return Err(corrupt(
                        "mirror member labels disagree on identity or configuration",
                    ));
                }
            }
            let other = member.uberblock(cx, &label, slot)?;
            if !same_candidate(&candidate, &other) {
                return Err(corrupt(
                    "mirror members disagree on the explicitly selected root candidate",
                ));
            }
            member_guids.push(guid);
        }
        // Each member was checked for membership and uniqueness, and the counts
        // match the complete configuration. Argument position never supplies an ID.
        let (data, physical_offset, copy_index, member_index) =
            self.read_block(cx, &selected.vdev, &candidate.root)?;
        if data.len() < 1024
            || candidate
                .root
                .payload_order()
                .u64(&data, 704)
                .map_err(|error| parse(&error))?
                != 1
        {
            return Err(corrupt("selected mirror root is not a META object set"));
        }
        checkpoint(cx)?;
        Ok(RootBlock {
            uberblock: candidate,
            data,
            physical_offset,
            copy_index,
            member_guid: member_guids[member_index],
            config: selected.vdev,
        })
    }

    pub(super) fn read_block(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
    ) -> Result<(Vec<u8>, u64, usize, usize)> {
        checkpoint(cx)?;
        if self.members.len() == 1 {
            return self.members[0]
                .read_block(cx, config, bp)
                .map(|(bytes, offset, copy)| (bytes, offset, copy, 0));
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
                        return Ok((bytes, offset, copy_index, member_index));
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
