//! Redundant native root selection, including interrupted RAIDZ label waves.
//!
//! Physical identities, configuration generations, and uberblock authority are
//! verified independently. Same-generation forks and missing committed members
//! remain errors; automatic read selection never modifies a physical device.

mod configuration;

use super::{
    Cx, FfsError, GroupConfig, Label, Leaf, NvList, Pool, RaidzGroup, RaidzMember, Result,
    RootBlock, Uberblock, VdevConfig, checkpoint, corrupt, integer, parse, same_candidate,
    unsupported,
};
use ffs_ondisk::zfs::{
    LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET, UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET,
    label_offsets, uberblock_bytes, verify_label_checksum,
};
use std::collections::BTreeSet;
use std::sync::Arc;

struct Admission {
    config: VdevConfig,
    supplied_guids: Vec<u64>,
    guid_sum: u64,
    draid_group: Option<super::draid::DraidGroup>,
    expanded_raidz: Option<super::vdev::ExpandedRaidzMeta>,
}

struct Candidate {
    member_guid: u64,
    label_index: usize,
    slot: usize,
    uberblock: Uberblock,
}

/// Only I/O failures and invalid checksums make a redundant label disposable.
/// Once its checksum verifies, malformed metadata or unsupported features must
/// be reported, not hidden by a healthy copy. Cancellation is never a bad copy.
pub(super) fn verified_labels(cx: &Cx, leaf: &Leaf) -> Result<Vec<(usize, Label)>> {
    let mut labels = Vec::with_capacity(4);
    for (index, offset) in label_offsets(leaf.length)
        .map_err(|error| parse(&error))?
        .into_iter()
        .enumerate()
    {
        checkpoint(cx)?;
        let config_offset = offset + LABEL_CONFIG_OFFSET;
        let raw = match leaf.read(cx, config_offset, LABEL_CONFIG_BYTES) {
            Ok(raw) => raw,
            Err(FfsError::Io(_)) => continue,
            Err(error) => return Err(error),
        };
        let Ok(order) = verify_label_checksum(&raw, config_offset) else {
            continue;
        };
        let config = NvList::parse(&raw[..raw.len() - 40]).map_err(|error| parse(&error))?;
        let tree = config
            .list("vdev_tree")
            .ok_or_else(|| unsupported("label has no normal data-vdev tree"))?;
        let ashift =
            u8::try_from(integer(tree, "ashift")?).map_err(|_| corrupt("ashift overflow"))?;
        let slot_bytes = uberblock_bytes(ashift).map_err(|error| parse(&error))?;
        labels.push((
            index,
            Label {
                offset,
                order,
                config,
                slot_bytes,
            },
        ));
    }
    checkpoint(cx)?;
    if labels.is_empty() {
        return Err(corrupt("supplied ZFS member has no checksum-valid label"));
    }
    Ok(labels)
}

fn admit_single(labels: &[(usize, Label)], pool_guid: u64) -> Result<Admission> {
    let selected = labels[0].1.single_leaf_with_mode(pool_guid, true)?;
    for (_, label) in &labels[1..] {
        if label.single_leaf_with_mode(pool_guid, true)? != selected {
            return Err(corrupt("ZFS label identities or configurations disagree"));
        }
    }
    Ok(Admission {
        supplied_guids: vec![selected.top_guid],
        guid_sum: pool_guid.wrapping_add(selected.top_guid),
        config: selected,
        draid_group: None,
        expanded_raidz: None,
    })
}

fn admit_group(labels: &[Vec<(usize, Label)>], pool_guid: u64) -> Result<Admission> {
    let (selected, _) = labels[0][0].1.group_config_with_mode(pool_guid, true)?;
    if selected.member_guids.len() != labels.len() {
        return Err(unsupported(
            "every configured redundant member must be explicitly supplied",
        ));
    }
    let guid_sum = selected.member_guids.iter().fold(
        pool_guid.wrapping_add(selected.vdev.top_guid),
        |sum, guid| sum.wrapping_add(*guid),
    );
    let mut supplied_guids = Vec::with_capacity(labels.len());
    let mut seen = BTreeSet::new();
    for member_labels in labels {
        let (config, guid): (GroupConfig, u64) =
            member_labels[0].1.group_config_with_mode(pool_guid, true)?;
        if config != selected || !seen.insert(guid) {
            return Err(corrupt(
                "supplied members disagree or repeat a physical GUID",
            ));
        }
        for (_, label) in &member_labels[1..] {
            let (other, other_guid) = label.group_config_with_mode(pool_guid, true)?;
            if other != selected || other_guid != guid {
                return Err(corrupt(
                    "member labels disagree on identity or configuration",
                ));
            }
        }
        supplied_guids.push(guid);
    }
    let draid_group = selected.build_draid_group(&supplied_guids, &[])?;
    let expanded_raidz = selected.expanded_raidz.clone();
    Ok(Admission {
        config: selected.mapped(&supplied_guids)?,
        supplied_guids,
        guid_sum,
        draid_group,
        expanded_raidz,
    })
}

fn admit_stripe(labels: &[Vec<(usize, Label)>], pool_guid: u64) -> Result<Admission> {
    let count = labels.len();
    let first = labels[0][0].1.striped_leaf_config(pool_guid, count, true)?;
    let mut by_id: Vec<Option<(usize, VdevConfig)>> = vec![None; count];
    let mut supplied_guids = Vec::with_capacity(count);
    let mut seen = BTreeSet::from([pool_guid]);
    let mut config_txg = first.txg;
    for (supplied_index, member_labels) in labels.iter().enumerate() {
        let config = member_labels[0]
            .1
            .striped_leaf_config(pool_guid, count, true)?;
        if config.version != first.version || config.read_features != first.read_features {
            return Err(corrupt(
                "striped vdevs disagree on pool version or read features",
            ));
        }
        if !seen.insert(config.top_guid) {
            return Err(corrupt("striped top-level vdevs repeat a GUID"));
        }
        for (_, label) in &member_labels[1..] {
            if label.striped_leaf_config(pool_guid, count, true)? != config {
                return Err(corrupt("striped member labels disagree on configuration"));
            }
        }
        config_txg = config_txg.max(config.txg);
        let entry = by_id
            .get_mut(config.id as usize)
            .ok_or_else(|| corrupt("striped top-level vdev ID out of bounds"))?;
        if entry.is_some() {
            return Err(corrupt("duplicate striped top-level vdev ID"));
        }
        supplied_guids.push(config.top_guid);
        *entry = Some((supplied_index, config));
    }
    let mut members = Vec::with_capacity(count);
    let mut guid_sum = pool_guid;
    for entry in by_id {
        let (supplied_index, config) =
            entry.ok_or_else(|| corrupt("missing striped top-level vdev ID"))?;
        guid_sum = guid_sum.wrapping_add(config.top_guid);
        members.push(RaidzMember {
            supplied_index,
            guid: config.top_guid,
            ashift: config.ashift,
            allocated_bytes: config.allocated_bytes,
        });
    }
    let mut config = first;
    config.id = 0;
    config.top_guid = members[0].guid;
    config.ashift = members[0].ashift;
    config.allocated_bytes = members[0].allocated_bytes;
    // The candidate must not predate ANY member's admitted configuration.
    config.txg = config_txg;
    config.raidz_members = Some(RaidzGroup { parity: 0, members });
    Ok(Admission {
        config,
        supplied_guids,
        guid_sum,
        draid_group: None,
        expanded_raidz: None,
    })
}

impl Pool {
    fn import_candidates(
        &self,
        cx: &Cx,
        labels: &[Vec<(usize, Label)>],
        admission: &Admission,
        strict_authority: bool,
    ) -> Result<Vec<Candidate>> {
        let mut candidates = Vec::new();
        for (member_index, member_labels) in labels.iter().enumerate() {
            let member = &self.members[member_index];
            let slot_bytes = member_labels[0].1.slot_bytes;
            // Configuration and uberblock rings have independent checksums.
            // All surviving configurations already agreed on ashift. Use that
            // geometry to scan every ring, even beside a damaged config copy.
            for (label_index, label_offset) in label_offsets(member.length)
                .map_err(|error| parse(&error))?
                .into_iter()
                .enumerate()
            {
                for slot in 0..UBERBLOCK_RING_BYTES / slot_bytes {
                    checkpoint(cx)?;
                    let offset = label_offset + UBERBLOCK_RING_OFFSET + (slot * slot_bytes) as u64;
                    let result = member.read(cx, offset, slot_bytes).and_then(|raw| {
                        Uberblock::parse(&raw, offset).map_err(|error| parse(&error))
                    });
                    let ub = match result {
                        Ok(ub) => ub,
                        Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                        Err(error @ FfsError::Io(_)) if strict_authority => return Err(error),
                        Err(_) => continue,
                    };
                    if ub.version == admission.config.version
                        && ub.txg >= admission.config.txg
                        && ub.guid_sum == admission.guid_sum
                    {
                        if strict_authority
                            && ub.raidz_reflow_info != 0
                            && admission.expanded_raidz.is_none()
                        {
                            return Err(corrupt(
                                "RAIDZ reflow authority has no admitted expansion layout",
                            ));
                        }
                        candidates.push(Candidate {
                            member_guid: admission.supplied_guids[member_index],
                            label_index,
                            slot,
                            uberblock: ub,
                        });
                    }
                }
            }
        }
        candidates.sort_unstable_by(|left, right| {
            right
                .uberblock
                .txg
                .cmp(&left.uberblock.txg)
                .then_with(|| right.uberblock.timestamp.cmp(&left.uberblock.timestamp))
                .then_with(|| left.member_guid.cmp(&right.member_guid))
                .then_with(|| left.label_index.cmp(&right.label_index))
                .then_with(|| left.slot.cmp(&right.slot))
        });
        for pair in candidates.windows(2) {
            let left = &pair[0].uberblock;
            let right = &pair[1].uberblock;
            if left.txg == right.txg
                && (left.root != right.root
                    || (left.timestamp == right.timestamp
                        && (left.checkpoint_txg != right.checkpoint_txg
                            || left.raidz_reflow_info != right.raidz_reflow_info)))
            {
                return Err(corrupt(
                    "checksum-valid ZFS uberblocks conflict within one TXG",
                ));
            }
        }
        // Identical roots would retry precisely the same DVAs on the same
        // immutable devices. Deduplicate only AFTER checking for forks.
        candidates.dedup_by(|left, right| left.uberblock.txg == right.uberblock.txg);
        checkpoint(cx)?;
        Ok(candidates)
    }

    /// An explicit historical root remains readable only under the same
    /// physical layout. Reflow progress cannot be rolled back with its slot.
    pub(super) fn verify_explicit_raidz_candidate(
        &self,
        cx: &Cx,
        selected: &GroupConfig,
        supplied_guids: &[u64],
        candidate: &Uberblock,
    ) -> Result<Option<Self>> {
        let labels = self
            .members
            .iter()
            .map(|member| verified_labels(cx, member))
            .collect::<Result<Vec<_>>>()?;
        let pool_guid = selected.vdev.pool_guid;
        if self.has_missing_members() {
            // Preserve the existing explicitly degraded ordinary-RAIDZ
            // profile, but never infer a missing successor configuration.
            if selected.expanded_raidz.is_some() {
                return Err(unsupported(
                    "expanded RAIDZ authority requires its complete physical member set",
                ));
            }
            let guid_sum = selected.member_guids.iter().fold(
                pool_guid.wrapping_add(selected.vdev.top_guid),
                |sum, guid| sum.wrapping_add(*guid),
            );
            self.reject_unmatched_configuration_authority(
                cx,
                &labels,
                &BTreeSet::from([guid_sum]),
                selected.vdev.version,
                selected.vdev.txg,
            )?;
            let admission = Admission {
                config: selected.vdev.clone(),
                supplied_guids: supplied_guids.to_vec(),
                guid_sum,
                draid_group: None,
                expanded_raidz: None,
            };
            self.import_candidates(cx, &labels, &admission, true)?;
            return Ok(None);
        }

        let mut cohorts = self
            .raidz_configuration_cohorts(cx, &labels, pool_guid)?
            .ok_or_else(|| corrupt("explicit RAIDZ root has no native configuration cohort"))?;
        let cohort = cohorts
            .pop()
            .ok_or_else(|| corrupt("explicit RAIDZ root has no committed configuration"))?;
        if cohort.admission.config != selected.clone().mapped(supplied_guids)? {
            return Err(corrupt(
                "explicit RAIDZ root predates the authoritative native configuration",
            ));
        }
        if cohort
            .admission
            .expanded_raidz
            .as_ref()
            .is_some_and(|meta| meta.expanding)
        {
            let newest = cohort
                .candidates
                .first()
                .ok_or_else(|| corrupt("active RAIDZ expansion has no native root authority"))?;
            if !same_candidate(candidate, &newest.uberblock) {
                return Err(corrupt(
                    "explicit RAIDZ root predates the authoritative reflow progress",
                ));
            }
        }
        // Expanded layouts must carry the selected cohort through MOS loading
        // so its allocation geometry is checked before it can replace label
        // routing. Ordinary strict historical reads keep their existing profile.
        Ok(cohort
            .admission
            .expanded_raidz
            .is_some()
            .then_some(cohort.owner))
    }

    fn read_import_candidates(
        cx: &Cx,
        mut owner: Self,
        admission: Admission,
        candidates: Vec<Candidate>,
    ) -> Result<(usize, usize, RootBlock)> {
        let expanding = admission
            .expanded_raidz
            .as_ref()
            .is_some_and(|meta| meta.expanding);
        let mut last_error = corrupt("no valid active ZFS uberblock candidates in ring");
        for candidate in candidates {
            checkpoint(cx)?;
            let ub = candidate.uberblock;
            if let Some(meta) = &admission.expanded_raidz {
                let mut updated = meta.clone();
                updated.apply_reflow_info(ub.raidz_reflow_info)?;
                owner.expanded_raidz = Some(Arc::new(updated));
            }
            match owner.read_block(cx, &admission.config, &ub.root) {
                Ok(block) => {
                    if block.bytes.len() < 1024
                        || ub
                            .root
                            .payload_order()
                            .u64(&block.bytes, 704)
                            .map_err(|error| parse(&error))?
                            != 1
                    {
                        last_error = corrupt("selected root is not a META object set");
                        if expanding {
                            break;
                        }
                        continue;
                    }
                    let member_guid = admission.supplied_guids[block.member_index];
                    checkpoint(cx)?;
                    return Ok((
                        candidate.label_index,
                        candidate.slot,
                        RootBlock {
                            uberblock: ub,
                            data: block.bytes,
                            physical_offset: block.physical_offset,
                            copy_index: block.copy_index,
                            member_guid,
                            raidz: block.raidz,
                            config: admission.config,
                            imported_pool: Some(owner),
                        },
                    ));
                }
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => last_error = error,
            }
            // Old root bytes can survive even when some old-width descendants
            // have already been overwritten. Active reflow authority cannot be
            // rolled back merely because the newest root is unreadable.
            if expanding {
                break;
            }
        }
        Err(last_error)
    }

    /// Select the highest readable, checksum-verified TXG from supplied member
    /// rings, retaining the exact native topology that authenticated its root.
    ///
    /// RAIDZ label generations may span an interrupted expansion publication.
    /// Physical identities and all native configuration transitions are checked
    /// before selecting that generation. Other topologies retain strict
    /// configuration agreement. No device is modified by this reader.
    pub fn import_active(
        &self,
        cx: &Cx,
        expected_pool_guid: Option<u64>,
    ) -> Result<(usize, usize, RootBlock)> {
        checkpoint(cx)?;
        if self.has_missing_members() {
            return Err(unsupported(
                "automatic root selection requires every configured physical member",
            ));
        }
        let labels = self
            .members
            .iter()
            .map(|member| verified_labels(cx, member))
            .collect::<Result<Vec<_>>>()?;
        let first = labels
            .first()
            .and_then(|member| member.first())
            .ok_or_else(|| corrupt("no supplied ZFS member labels"))?;
        let pool_guid = integer(&first.1.config, "pool_guid")?;
        if expected_pool_guid.is_some_and(|expected| expected != pool_guid) {
            return Err(corrupt("label belongs to another pool GUID"));
        }
        if let Some(mut cohorts) = self.raidz_configuration_cohorts(cx, &labels, pool_guid)? {
            let cohort = cohorts
                .pop()
                .ok_or_else(|| corrupt("no selected RAIDZ configuration cohort"))?;
            return Self::read_import_candidates(
                cx,
                cohort.owner,
                cohort.admission,
                cohort.candidates,
            );
        }
        let mut owner = self.clone();
        let admission = if labels.len() == 1 {
            admit_single(&labels[0], pool_guid)?
        } else if integer(&first.1.config, "vdev_children")? > 1 {
            if labels.iter().any(|copies| {
                copies[0]
                    .1
                    .config
                    .list("vdev_tree")
                    .is_some_and(|tree| tree.text("type") == Some("mirror"))
            }) {
                let topology = Arc::new(self.admit_striped_labels(cx, &labels, pool_guid, true)?);
                let admission = Admission {
                    config: topology.config.clone(),
                    supplied_guids: topology.supplied_guids.clone(),
                    guid_sum: topology.guid_sum,
                    draid_group: None,
                    expanded_raidz: None,
                };
                owner.top_levels = Some(topology);
                admission
            } else {
                admit_stripe(&labels, pool_guid)?
            }
        } else {
            let admission = admit_group(&labels, pool_guid)?;
            if let Some(group) = &admission.draid_group {
                owner.draid_group = Some(Arc::new(group.clone()));
            }
            if let Some(meta) = &admission.expanded_raidz {
                owner.expanded_raidz = Some(Arc::new(meta.clone()));
            }
            admission
        };
        let candidates = self.import_candidates(cx, &labels, &admission, false)?;
        Self::read_import_candidates(cx, owner, admission, candidates)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::reader::tests::mirror::{
            Fault, MIRROR_GUID, install_labels, native_config, open_bytes,
        };
        use ffs_ondisk::zfs::{DATA_OFFSET, Endian, LABEL_BYTES, UBERBLOCK_RING_OFFSET, checksum};
        use sha2::{Digest, Sha256};
        use std::sync::{Arc, Mutex};

        const BASE: usize = 1024;
        const LENGTH: usize = 8 * 1024 * 1024;
        const GUIDS: [u64; 2] = [1001, 1002];
        const FIRST: u64 = DATA_OFFSET + 4096;
        const SECOND: u64 = DATA_OFFSET + 8192;
        type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

        fn stamp(bytes: &mut [u8], offset: u64, order: Endian) {
            let at = bytes.len() - 40;
            bytes[at..at + 8].copy_from_slice(&order.encode(0x0210_da7a_b10c_7a11));
            bytes[at + 8..].fill(0);
            bytes[at + 8..at + 16].copy_from_slice(&order.encode(offset));
            let digest = Sha256::digest(&*bytes);
            for i in 0..4 {
                let word = u64::from_be_bytes(std::array::from_fn(|n| digest[i * 8 + n]));
                bytes[at + 8 + i * 8..at + 16 + i * 8].copy_from_slice(&order.encode(word));
            }
        }

        struct Fixture {
            images: Vec<Vec<u8>>,
            root: Vec<u8>,
            ub: Vec<u8>,
            order: Endian,
        }

        impl Fixture {
            fn new(order: Endian) -> Self {
                let mut root = vec![0; 1024];
                root[704..712].copy_from_slice(&order.encode(1));
                let mut bp = [0_u64; 16];
                bp[0] = 2;
                bp[1] = 8;
                bp[2] = 2;
                bp[3] = 16;
                bp[6] = 1 | (1 << 16) | (2 << 32) | (7 << 40) | (11 << 48)
                    | (u64::from(order == Endian::Little) << 63);
                bp[10] = 42;
                bp[12..].copy_from_slice(&checksum(&root, 7, order).unwrap());
                let mut ub = vec![0; 1024];
                for (at, value) in [
                    (0, 0x00ba_b10c), (8, 5000), (16, 43),
                    (24, 123 + MIRROR_GUID + GUIDS[0] + GUIDS[1]),
                    (32, 1_700_000_000),
                ] {
                    ub[at..at + 8].copy_from_slice(&order.encode(value));
                }
                for (i, word) in bp.into_iter().enumerate() {
                    ub[40 + i * 8..48 + i * 8].copy_from_slice(&order.encode(word));
                }
                let images = GUIDS.iter().map(|guid| {
                    let mut bytes = vec![0; BASE + LENGTH + 512];
                    bytes[..BASE].fill(0xA1);
                    bytes[BASE + LENGTH..].fill(0xB2);
                    let config = native_config(*guid, &GUIDS, 9,
                        LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES, 42);
                    install_labels(&mut bytes, BASE, LENGTH as u64, order, &config, &ub);
                    for offset in [FIRST, SECOND] {
                        let at = BASE + offset as usize;
                        bytes[at..at + root.len()].copy_from_slice(&root);
                    }
                    bytes
                }).collect();
                Self { images, root, ub, order }
            }

            fn clear_rings(&mut self) {
                for image in &mut self.images {
                    for label in label_offsets(LENGTH as u64).unwrap() {
                        let at = BASE + (label + UBERBLOCK_RING_OFFSET) as usize;
                        image[at..at + UBERBLOCK_RING_BYTES].fill(0);
                    }
                }
            }

            fn candidate(&mut self, member: usize, label: usize, slot: usize, ub: &[u8]) {
                let offset = label_offsets(LENGTH as u64).unwrap()[label]
                    + UBERBLOCK_RING_OFFSET + (slot * 1024) as u64;
                let mut bytes = ub.to_vec();
                stamp(&mut bytes, offset, self.order);
                let at = BASE + offset as usize;
                self.images[member][at..at + bytes.len()].copy_from_slice(&bytes);
            }

            fn damage_label(&mut self, member: usize, label: usize) {
                let offset = label_offsets(LENGTH as u64).unwrap()[label] + LABEL_CONFIG_OFFSET;
                self.images[member][BASE + offset as usize] ^= 1;
            }

            fn pool(self, faults: [Fault; 2], reverse: bool, reads: &Reads) -> Pool {
                let mut leaves: Vec<_> = self.images.into_iter().zip(faults).map(|(bytes, fault)| {
                    open_bytes(bytes, BASE, LENGTH as u64, Arc::clone(reads), fault)
                }).collect();
                if reverse { leaves.reverse(); }
                Pool::from_leaves(leaves).unwrap()
            }
        }

        fn data_reads(reads: &Reads) -> usize {
            reads.lock().unwrap().iter().filter(|(offset, _)| {
                *offset >= BASE as u64 + DATA_OFFSET
                    && *offset < BASE as u64 + LENGTH as u64 - 2 * LABEL_BYTES
            }).count()
        }

        #[test]
        fn auto_import_scans_other_members_and_independent_ring_locations() {
            for order in [Endian::Little, Endian::Big] {
                for reverse in [false, true] {
                    let mut fixture = Fixture::new(order);
                    fixture.clear_rings();
                    let ub = fixture.ub.clone();
                    fixture.candidate(1, 3, 7, &ub);
                    let expected = fixture.root.clone();
                    let pool = fixture.pool([Fault::None; 2], reverse, &Arc::default());
                    let (label, slot, root) = pool.import_active(&Cx::for_testing(), Some(123)).unwrap();
                    assert_eq!((label, slot), (3, 7));
                    assert_eq!(root.uberblock.txg, 43);
                    assert_eq!(root.data, expected);
                }
            }
        }

        #[test]
        fn auto_import_reads_a_healthy_ring_beside_a_damaged_configuration() {
            for order in [Endian::Little, Endian::Big] {
                let mut fixture = Fixture::new(order);
                fixture.clear_rings();
                let ub = fixture.ub.clone();
                fixture.candidate(1, 3, 7, &ub);
                fixture.damage_label(1, 3);
                let expected = fixture.root.clone();
                let pool = fixture.pool([Fault::None; 2], false, &Arc::default());
                let (label, slot, root) = pool.import_active(&Cx::for_testing(), None).unwrap();
                assert_eq!((label, slot), (3, 7));
                assert_eq!(root.data, expected);
            }
        }

        #[test]
        fn auto_import_recovers_bad_labels_but_explicit_selection_stays_strict() {
            for order in [Endian::Little, Endian::Big] {
                let mut fixture = Fixture::new(order);
                fixture.damage_label(0, 0);
                fixture.damage_label(1, 1);
                let expected = fixture.root.clone();
                let pool = fixture.pool([Fault::None; 2], false, &Arc::default());
                assert!(pool.root(&Cx::for_testing(), 2, 2, 123).is_err());
                assert_eq!(pool.import_active(&Cx::for_testing(), None).unwrap().2.data, expected);
            }
        }

        #[test]
        fn auto_import_requires_a_verified_label_on_every_member() {
            let mut fixture = Fixture::new(Endian::Little);
            for label in 0..4 { fixture.damage_label(1, label); }
            let reads = Arc::default();
            let pool = fixture.pool([Fault::None; 2], false, &reads);
            assert!(pool.import_active(&Cx::for_testing(), None).is_err());
            assert_eq!(data_reads(&reads), 0);
        }

        #[test]
        fn auto_import_does_not_hide_checksum_valid_foreign_labels() {
            let mut fixture = Fixture::new(Endian::Little);
            let config = native_config(GUIDS[0], &GUIDS, 9,
                LENGTH as u64 - DATA_OFFSET - 2 * LABEL_BYTES, 42);
            // All labels on member 1 now repeat member 0's physical identity.
            install_labels(&mut fixture.images[1], BASE, LENGTH as u64,
                fixture.order, &config, &fixture.ub);
            let reads = Arc::default();
            let pool = fixture.pool([Fault::None; 2], false, &reads);
            assert!(pool.import_active(&Cx::for_testing(), None).is_err());
            assert_eq!(data_reads(&reads), 0);
        }

        #[test]
        fn auto_import_label_and_ring_cancellation_are_terminal() {
            for offset in [LABEL_CONFIG_OFFSET, UBERBLOCK_RING_OFFSET + 1024] {
                for member in 0..2 {
                    let fixture = Fixture::new(Endian::Little);
                    let mut faults = [Fault::None; 2];
                    faults[member] = Fault::Cancel(BASE as u64 + offset);
                    let reads = Arc::default();
                    let pool = fixture.pool(faults, false, &reads);
                    assert!(matches!(pool.import_active(&Cx::for_testing(), None), Err(FfsError::Cancelled)));
                    assert_eq!(data_reads(&reads), 0);
                }
            }
        }

        #[test]
        fn auto_import_label_io_failure_uses_other_copies() {
            let fixture = Fixture::new(Endian::Big);
            let expected = fixture.root.clone();
            let faults = [Fault::Io(BASE as u64 + LABEL_CONFIG_OFFSET), Fault::None];
            let pool = fixture.pool(faults, false, &Arc::default());
            assert_eq!(pool.import_active(&Cx::for_testing(), None).unwrap().2.data, expected);
        }

        #[test]
        fn auto_import_still_verifies_and_falls_back_between_data_replicas() {
            let mut fixture = Fixture::new(Endian::Little);
            for offset in [FIRST, SECOND] {
                let at = BASE + offset as usize;
                fixture.images[0][at..at + 1024].fill(0);
            }
            let expected = fixture.root.clone();
            let pool = fixture.pool([Fault::None; 2], false, &Arc::default());
            let root = pool.import_active(&Cx::for_testing(), None).unwrap().2;
            assert_eq!(root.member_guid, GUIDS[1]);
            assert_eq!(root.data, expected);
        }

        #[test]
        fn auto_import_rejects_conflicting_roots_in_the_same_txg_before_data_io() {
            let mut fixture = Fixture::new(Endian::Little);
            let mut fork = fixture.ub.clone();
            fork[48..56].copy_from_slice(&fixture.order.encode(24));
            fixture.candidate(1, 3, 7, &fork);
            let reads = Arc::default();
            let pool = fixture.pool([Fault::None; 2], false, &reads);
            assert!(pool.import_active(&Cx::for_testing(), None).is_err());
            assert_eq!(data_reads(&reads), 0);
        }

        #[test]
        fn auto_import_timestamp_tie_break_does_not_confuse_identical_roots_with_forks() {
            let mut fixture = Fixture::new(Endian::Big);
            let mut newer = fixture.ub.clone();
            newer[32..40].copy_from_slice(&fixture.order.encode(1_700_000_001));
            fixture.candidate(1, 3, 7, &newer);
            let pool = fixture.pool([Fault::None; 2], false, &Arc::default());
            let (label, slot, root) = pool.import_active(&Cx::for_testing(), None).unwrap();
            assert_eq!((label, slot), (3, 7));
            assert_eq!(root.uberblock.timestamp, 1_700_000_001);
        }

        #[test]
        fn auto_import_uses_older_readable_txg_when_newer_root_copies_fail() {
            let mut fixture = Fixture::new(Endian::Little);
            let mut newer = fixture.ub.clone();
            newer[16..24].copy_from_slice(&fixture.order.encode(50));
            newer[48..56].copy_from_slice(&fixture.order.encode(24));
            newer[64..72].copy_from_slice(&fixture.order.encode(32));
            fixture.candidate(1, 3, 7, &newer);
            let expected = fixture.root.clone();
            let pool = fixture.pool([Fault::None; 2], false, &Arc::default());
            let root = pool.import_active(&Cx::for_testing(), None).unwrap().2;
            assert_eq!(root.uberblock.txg, 43);
            assert_eq!(root.data, expected);
        }

        #[test]
        fn auto_import_does_not_repeat_failed_data_reads_for_identical_ring_copies() {
            let mut fixture = Fixture::new(Endian::Little);
            for image in &mut fixture.images {
                for offset in [FIRST, SECOND] {
                    let at = BASE + offset as usize;
                    image[at..at + 1024].fill(0);
                }
            }
            let reads = Arc::default();
            let pool = fixture.pool([Fault::None; 2], false, &reads);
            assert!(pool.import_active(&Cx::for_testing(), None).is_err());
            // Two DVAs on two mirrors, not eight ring copies times four reads.
            assert_eq!(data_reads(&reads), 4);
        }

        #[test]
        fn auto_import_rejects_same_epoch_reflow_and_checkpoint_forks_before_payload() {
            for order in [Endian::Little, Endian::Big] {
                for reflow in [false, true] {
                    let mut fixture = Fixture::new(order);
                    let offset = label_offsets(LENGTH as u64).unwrap()[0]
                        + UBERBLOCK_RING_OFFSET + 2 * 1024;
                    let mut raw = fixture.ub.clone();
                    stamp(&mut raw, offset, order);
                    let mut ub = Uberblock::parse(&raw, offset).unwrap();
                    if reflow {
                        ub.raidz_reflow_info = 1_u64 << 55;
                    } else {
                        ub.checkpoint_txg = 42;
                    }
                    let fork = ub.encode_with_meta(1024, offset, 5000, 0, 0).unwrap();
                    fixture.candidate(1, 0, 2, &fork);
                    let reads = Arc::default();
                    let pool = fixture.pool([Fault::None; 2], false, &reads);
                    assert!(pool.root(&Cx::for_testing(), 0, 2, 123).is_err());
                    assert!(pool.import_active(&Cx::for_testing(), None).is_err());
                    assert_eq!(data_reads(&reads), 0);
                }
            }
        }

        #[test]
        fn strict_authority_scan_does_not_turn_ring_io_failure_into_an_older_root() {
            let cx = Cx::for_testing();
            for order in [Endian::Little, Endian::Big] {
                let mut fixture = Fixture::new(order);
                let mut newer = fixture.ub.clone();
                newer[16..24].copy_from_slice(&order.encode(44));
                fixture.candidate(1, 3, 7, &newer);
                let expected = fixture.root.clone();
                let offset = label_offsets(LENGTH as u64).unwrap()[3]
                    + UBERBLOCK_RING_OFFSET
                    + 7 * 1024;
                let reads = Arc::default();
                let pool = fixture.pool(
                    [Fault::None, Fault::Io(BASE as u64 + offset)],
                    false,
                    &reads,
                );
                let labels = pool
                    .members
                    .iter()
                    .map(|member| verified_labels(&cx, member))
                    .collect::<Result<Vec<_>>>()
                    .unwrap();
                let admission = admit_group(&labels, 123).unwrap();
                let ordinary = pool
                    .import_candidates(&cx, &labels, &admission, false)
                    .unwrap();
                assert_eq!(ordinary[0].uberblock.txg, 43);
                assert!(matches!(
                    pool.import_candidates(&cx, &labels, &admission, true),
                    Err(FfsError::Io(_))
                ));
                assert_eq!(data_reads(&reads), 0);
                // Ordinary mirror import still recovers from another readable
                // copy; the stricter contract belongs to mutable RAIDZ layout.
                assert_eq!(pool.import_active(&cx, None).unwrap().2.data, expected);
            }
        }

        #[test]
        fn explicit_raidz_history_refuses_unknown_successor_but_keeps_unchanged_layout() {
            use crate::reader::tests::raidz::fixture::StripedImage;

            let cx = Cx::for_testing();
            for order in [Endian::Little, Endian::Big] {
                for successor in [false, true] {
                    for degraded in [false, true] {
                        let source = Fixture::new(order);
                        let expected = source.root.clone();
                        let image = StripedImage::graph(
                            &source.images[0],
                            source.root.clone(),
                            order,
                            3,
                            43,
                            42,
                        );
                        let seed = image.open(&[Fault::None; 3], false);
                        let mut images: Vec<_> = seed
                            .members
                            .iter()
                            .map(|member| {
                                member
                                    .read_raw(&cx, 0, member.length_bytes() as usize)
                                    .unwrap()
                            })
                            .collect();
                        let selected_offset = UBERBLOCK_RING_OFFSET + 2 * 1024;
                        let selected_start = selected_offset as usize;
                        let mut newer = Uberblock::parse(
                            &images[0][selected_start..selected_start + 1024],
                            selected_offset,
                        )
                        .unwrap();
                        newer.txg += 1;
                        newer.timestamp += 1;
                        if successor {
                            // A bootstrap UB has raw reflow state zero. The
                            // absent appended child may own its only config.
                            newer.guid_sum = newer.guid_sum.wrapping_add(9001);
                        }
                        let future_offset = label_offsets(LENGTH as u64).unwrap()[3]
                            + UBERBLOCK_RING_OFFSET
                            + 7 * 1024;
                        let bytes = newer
                            .encode_with_meta(1024, future_offset, 5000, 0, 0)
                            .unwrap();
                        let start = future_offset as usize;
                        images[0][start..start + bytes.len()].copy_from_slice(&bytes);
                        if degraded {
                            images.truncate(2);
                        }
                        let reads = Arc::default();
                        let leaves = images
                            .into_iter()
                            .map(|bytes| {
                                open_bytes(
                                    bytes,
                                    0,
                                    LENGTH as u64,
                                    Arc::clone(&reads),
                                    Fault::None,
                                )
                            })
                            .collect();
                        let pool = if degraded {
                            Pool::from_raidz_survivors(&cx, leaves, vec![1003]).unwrap()
                        } else {
                            Pool::from_leaves(leaves).unwrap()
                        };
                        let result = pool.root(&cx, 0, 2, 123);
                        if successor {
                            assert!(result.is_err());
                            assert_eq!(data_reads(&reads), 0);
                        } else {
                            let root = result.unwrap();
                            assert_eq!(root.uberblock.txg, 43);
                            assert_eq!(root.data, expected);
                        }
                    }
                }
            }
        }
    }
}
