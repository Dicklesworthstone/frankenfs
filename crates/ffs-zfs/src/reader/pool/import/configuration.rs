//! Recover native RAIDZ configuration generations across interrupted label waves.
//!
//! Physical ownership is established from every checksum-valid label before a
//! configuration is selected. Only a stable RAIDZ group and a single appended
//! expansion child may span generations; unrelated pools, identity changes,
//! same-generation forks, and missing committed members remain errors.

use super::{
    Admission, Candidate, Cx, GroupConfig, Label, Pool, Result, checkpoint, corrupt, integer,
    unsupported,
};
use crate::reader::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(super) struct ConfigurationCohort {
    pub(super) owner: Pool,
    pub(super) admission: Admission,
    pub(super) candidates: Vec<Candidate>,
}

fn required_member_bytes(group: &GroupConfig) -> Result<u64> {
    let sector = 1_u64
        .checked_shl(u32::from(group.vdev.ashift))
        .ok_or_else(|| corrupt("RAIDZ configuration sector size overflows"))?;
    let asize = group.vdev.allocated_bytes;
    if asize == 0 || !asize.is_multiple_of(sector) {
        return Err(corrupt(
            "RAIDZ configuration has an invalid allocation size",
        ));
    }
    let mut width = group.member_guids.len();
    if let Some(meta) = &group.expanded_raidz {
        meta.to_ondisk(group.vdev.ashift, group.raidz_parity)?;
        if meta
            .expand_txgs
            .last()
            .is_some_and(|txg| *txg > group.vdev.txg)
        {
            return Err(corrupt(
                "RAIDZ expansion history is newer than its configuration",
            ));
        }
        if meta.expanding {
            // Until reflow finishes, the old asize still addresses rows on the
            // previous physical width. The appended member cannot shorten the
            // capacity required to read those unreflowed rows.
            width = width
                .checked_sub(1)
                .ok_or_else(|| corrupt("active RAIDZ configuration has no previous width"))?;
        }
    }
    if width <= group.raidz_parity {
        return Err(corrupt("RAIDZ configuration has no data column"));
    }
    let row_bytes = u64::try_from(width)
        .ok()
        .and_then(|width| width.checked_mul(sector))
        .ok_or_else(|| corrupt("RAIDZ configuration row size overflows"))?;
    asize
        .div_ceil(row_bytes)
        .checked_mul(sector)
        .ok_or_else(|| corrupt("RAIDZ configuration member size overflows"))
}

fn validate_successor(previous: &GroupConfig, next: &GroupConfig) -> Result<()> {
    let old = &previous.vdev;
    let new = &next.vdev;
    if old.pool_guid != new.pool_guid
        || old.top_guid != new.top_guid
        || old.version != new.version
        || old.id != new.id
        || old.ashift != new.ashift
        || previous.raidz_parity != next.raidz_parity
        || old.txg >= new.txg
        || new.allocated_bytes < old.allocated_bytes
        || !next.member_guids.starts_with(&previous.member_guids)
        || next.member_guids.len() > previous.member_guids.len() + 1
    {
        return Err(unsupported(
            "conflicting native RAIDZ configuration generations",
        ));
    }
    let old_original = previous
        .expanded_raidz
        .as_ref()
        .map_or(previous.member_guids.len(), |meta| meta.original_width);
    let new_original = next
        .expanded_raidz
        .as_ref()
        .map_or(next.member_guids.len(), |meta| meta.original_width);
    let old_history = previous
        .expanded_raidz
        .as_ref()
        .map_or(&[][..], |meta| meta.expand_txgs.as_slice());
    let new_history = next
        .expanded_raidz
        .as_ref()
        .map_or(&[][..], |meta| meta.expand_txgs.as_slice());
    let old_active = previous
        .expanded_raidz
        .as_ref()
        .is_some_and(|meta| meta.expanding);
    let new_active = next
        .expanded_raidz
        .as_ref()
        .is_some_and(|meta| meta.expanding);
    if old_original != new_original
        || !new_history.starts_with(old_history)
        || new_history.len() > old_history.len() + 1
        || (new_active && new.allocated_bytes != old.allocated_bytes)
        || (next.member_guids.len() > previous.member_guids.len()
            && (old_active || !new_active || new_history != old_history))
        || (new_history.len() > old_history.len()
            && (!old_active || new_active || new_history.last().is_some_and(|txg| *txg <= old.txg)))
        || old
            .read_features
            .iter()
            .any(|feature| !new.read_features.contains(feature))
        || new.read_features.iter().any(|feature| {
            !old.read_features.contains(feature) && feature != "org.openzfs:raidz_expansion"
        })
    {
        return Err(unsupported(
            "RAIDZ configuration history is not a native expansion transition",
        ));
    }
    Ok(())
}

impl Pool {
    /// Preserve complete native configuration generations rather than requiring
    /// all four independently written labels to change atomically.
    pub(super) fn raidz_configuration_cohorts(
        &self,
        cx: &Cx,
        labels: &[Vec<(usize, Label)>],
        pool_guid: u64,
    ) -> Result<Option<Vec<ConfigurationCohort>>> {
        let is_raidz = labels.iter().flatten().any(|(_, label)| {
            label
                .config
                .list("vdev_tree")
                .and_then(|tree| tree.text("type"))
                == Some("raidz")
        });
        if !is_raidz {
            return Ok(None);
        }
        let mut identities = Vec::with_capacity(labels.len());
        let mut seen = BTreeSet::new();
        let mut generations = BTreeMap::<u64, (GroupConfig, Label)>::new();
        for copies in labels {
            checkpoint(cx)?;
            let mut identity = None;
            for (_, label) in copies {
                let (group, guid) = label.group_config_with_mode(pool_guid, true)?;
                if group.raidz_parity == 0 || group.draid_config.is_some() {
                    return Err(unsupported(
                        "RAIDZ configuration recovery requires one RAIDZ group",
                    ));
                }
                required_member_bytes(&group)?;
                if identity.replace(guid).is_some_and(|old| old != guid) {
                    return Err(corrupt("physical member GUID changed between valid labels"));
                }
                match generations.get(&group.vdev.txg) {
                    Some((previous, _)) if previous != &group => {
                        return Err(corrupt("RAIDZ labels fork within one configuration TXG"));
                    }
                    Some(_) => {}
                    None => {
                        // Bound retained configuration clones before accepting
                        // another generation, not after walking every label.
                        if generations.len() == 4 {
                            return Err(unsupported(
                                "too many concurrent RAIDZ configuration generations",
                            ));
                        }
                        generations.insert(group.vdev.txg, (group, label.clone()));
                    }
                }
            }
            let guid = identity.ok_or_else(|| corrupt("member has no verified native identity"))?;
            if guid == 0 || !seen.insert(guid) {
                return Err(corrupt("supplied RAIDZ members repeat a physical GUID"));
            }
            identities.push(guid);
        }
        let ordered: Vec<_> = generations.values().collect();
        for pair in ordered.windows(2) {
            validate_successor(&pair[0].0, &pair[1].0)?;
        }
        let newest = ordered
            .last()
            .ok_or_else(|| corrupt("no RAIDZ configuration generation"))?;
        if identities
            .iter()
            .any(|guid| !newest.0.member_guids.contains(guid))
        {
            return Err(corrupt(
                "supplied member is absent from every admitted RAIDZ generation",
            ));
        }

        let known_sums: BTreeSet<_> = generations
            .values()
            .map(|(group, _)| {
                group
                    .member_guids
                    .iter()
                    .fold(pool_guid.wrapping_add(group.vdev.top_guid), |sum, guid| {
                        sum.wrapping_add(*guid)
                    })
            })
            .collect();
        let oldest = ordered
            .first()
            .ok_or_else(|| corrupt("no RAIDZ configuration generation"))?;
        self.reject_unmatched_configuration_authority(
            cx,
            labels,
            &known_sums,
            newest.0.vdev.version,
            oldest.0.vdev.txg,
        )?;
        let mut result = Vec::new();
        let mut upper_txg = None;
        for (group, canonical) in generations.values().rev() {
            checkpoint(cx)?;
            let guid_sum = group
                .member_guids
                .iter()
                .fold(pool_guid.wrapping_add(group.vdev.top_guid), |sum, guid| {
                    sum.wrapping_add(*guid)
                });
            // Ring checksums and label checksums are independent. Observe newer
            // native authority even if one of its configured children is absent;
            // it must never authorize a writable rollback to the old width.
            let probe = Admission {
                config: group.vdev.clone(),
                supplied_guids: identities.clone(),
                guid_sum,
                draid_group: None,
                expanded_raidz: group.expanded_raidz.clone(),
            };
            let mut candidates = self.import_candidates(cx, labels, &probe, true)?;
            if let Some(upper) = upper_txg {
                candidates.retain(|candidate| candidate.uberblock.txg < upper);
            }
            upper_txg = Some(group.vdev.txg);
            let complete = group.member_guids.iter().all(|guid| seen.contains(guid));
            if !complete {
                if !candidates.is_empty() {
                    return Err(unsupported(
                        "newer committed RAIDZ configuration requires an absent physical member",
                    ));
                }
                continue;
            }
            if candidates.is_empty() {
                continue;
            }
            let indices: Vec<_> = identities
                .iter()
                .enumerate()
                .filter_map(|(index, guid)| group.member_guids.contains(guid).then_some(index))
                .collect();
            let supplied_guids: Vec<_> = indices.iter().map(|&index| identities[index]).collect();
            let mut owner = Pool::from_wide_leaves(
                indices
                    .iter()
                    .map(|&index| self.members[index].clone())
                    .collect(),
            )?;
            let mut selected_labels = Vec::with_capacity(indices.len());
            let needed = required_member_bytes(group)?;
            for &index in &indices {
                let physical = &labels[index][0].1;
                let data_end = ffs_ondisk::zfs::label_offsets(self.members[index].length)
                    .map_err(|error| super::parse(&error))?[2];
                if data_end
                    .checked_sub(ffs_ondisk::zfs::DATA_OFFSET)
                    .is_none_or(|available| needed > available)
                {
                    return Err(corrupt("RAIDZ configuration exceeds a supplied member"));
                }
                let mut config = canonical.config.clone();
                config
                    .fields
                    .insert("guid".into(), Value::Unsigned(identities[index]));
                let selected = Label {
                    offset: physical.offset,
                    order: physical.order,
                    config,
                    slot_bytes: canonical.slot_bytes,
                };
                selected_labels.push(selected);
            }
            let admission = Admission {
                config: group.clone().mapped(&supplied_guids)?,
                supplied_guids,
                guid_sum,
                draid_group: None,
                expanded_raidz: group.expanded_raidz.clone(),
            };
            if let Some(meta) = &admission.expanded_raidz {
                owner.expanded_raidz = Some(Arc::new(meta.clone()));
            }
            owner.imported_configuration = Some(Arc::new(super::super::ImportedConfiguration {
                labels: selected_labels,
                source_indices: indices,
            }));
            result.push(ConfigurationCohort {
                owner,
                admission,
                candidates,
            });
            // A checksum-valid successor root establishes its configuration
            // authority. Data corruption must not silently rewind a topology
            // transition after reflow may already have overwritten old locations.
            break;
        }
        if result.is_empty() {
            return Err(corrupt("no committed native RAIDZ configuration cohort"));
        }
        Ok(Some(result))
    }

    pub(super) fn reject_unmatched_configuration_authority(
        &self,
        cx: &Cx,
        labels: &[Vec<(usize, Label)>],
        guid_sums: &BTreeSet<u64>,
        version: u64,
        earliest_config_txg: u64,
    ) -> Result<()> {
        for (member, copies) in self.members.iter().zip(labels) {
            let template = &copies[0].1;
            for offset in ffs_ondisk::zfs::label_offsets(member.length)
                .map_err(|error| super::parse(&error))?
            {
                let label = Label {
                    offset,
                    order: template.order,
                    config: template.config.clone(),
                    slot_bytes: template.slot_bytes,
                };
                for slot in 0..ffs_ondisk::zfs::UBERBLOCK_RING_BYTES / label.slot_bytes {
                    checkpoint(cx)?;
                    let ub = match member.uberblock(cx, &label, slot) {
                        Ok(ub) => ub,
                        Err(super::FfsError::Cancelled) => return Err(super::FfsError::Cancelled),
                        // An unreadable ring cannot prove that a newer native
                        // configuration never committed on this member.
                        Err(error @ super::FfsError::Io(_)) => return Err(error),
                        Err(_) => continue,
                    };
                    if ub.version == version
                        && ub.txg >= earliest_config_txg
                        && !guid_sums.contains(&ub.guid_sum)
                    {
                        return Err(unsupported(
                            "native RAIDZ authority has no supplied configuration generation",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub(in crate::reader) fn verify_imported_mos(
        &mut self,
        config: &super::NvList,
        reflow_info: u64,
    ) -> Result<()> {
        let Some(selection) = &self.imported_configuration else {
            return Ok(());
        };
        let first = selection
            .labels
            .first()
            .ok_or_else(|| corrupt("empty imported label cohort"))?;
        let pool_guid = integer(&first.config, "pool_guid")?;
        let (selected, _) = first.group_config_with_mode(pool_guid, true)?;
        let supplied_guids = selection
            .labels
            .iter()
            .map(|label| integer(&label.config, "guid"))
            .collect::<Result<Vec<_>>>()?;
        let mut topology =
            super::super::vdev::PoolTopology::from_mos_config(config, &supplied_guids)?;
        let expected_sum = selected.member_guids.iter().fold(
            pool_guid.wrapping_add(selected.vdev.top_guid),
            |sum, guid| sum.wrapping_add(*guid),
        );
        if topology.pool_guid != pool_guid
            || topology.version != selected.vdev.version
            || topology.guid_sum != expected_sum
            || topology.top_vdevs.len() != 1
        {
            return Err(corrupt(
                "selected MOS identity disagrees with its native label cohort",
            ));
        }
        let top = &mut topology.top_vdevs[0];
        let super::super::vdev::TopVdevKind::Raidz { parity, expanded } = &mut top.kind else {
            return Err(corrupt(
                "selected MOS no longer describes its admitted RAIDZ group",
            ));
        };
        if top.id != selected.vdev.id
            || top.guid != selected.vdev.top_guid
            || top.ashift != selected.vdev.ashift
            || top.asize != selected.vdev.allocated_bytes
            || top.children_guids != selected.member_guids
            || *parity != selected.raidz_parity
            || *expanded != selected.expanded_raidz
        {
            return Err(corrupt(
                "selected MOS allocation geometry disagrees with its label cohort",
            ));
        }
        if let Some(meta) = expanded {
            meta.apply_reflow_info(reflow_info)?;
        }
        self.topology = Some(Arc::new(topology));
        Ok(())
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::reader::pool::vdev::ExpandedRaidzMeta;
        use crate::reader::tests::mirror::{Fault, open_bytes};
        use crate::reader::{NvList, VdevConfig};
        use ffs_ondisk::zfs::{
            BlockPointer, Dva, Endian, RegularBlockSpec, UBERBLOCK_RING_OFFSET, Uberblock,
        };

        fn group(width: usize, txg: u64, history: &[u64], expanding: bool) -> GroupConfig {
            let expanded_raidz = (!history.is_empty() || expanding).then(|| ExpandedRaidzMeta {
                original_width: width - history.len() - usize::from(expanding),
                physical_width: width,
                expand_txgs: history.to_vec(),
                expanding,
                reflow_offset_synced: if expanding { 0 } else { u64::MAX },
                reflow_offset_next: if expanding { 0 } else { u64::MAX },
                use_scratch: false,
            });
            GroupConfig {
                vdev: VdevConfig {
                    pool_guid: 123,
                    top_guid: 777,
                    version: 5000,
                    txg,
                    ashift: 12,
                    id: 0,
                    allocated_bytes: 25 * 4096,
                    read_features: vec!["org.openzfs:raidz_expansion".into()],
                    raidz_members: None,
                },
                tree: NvList { fields: BTreeMap::new() },
                member_guids: (0..width).map(|index| 1001 + index as u64).collect(),
                raidz_parity: 1,
                draid_config: None,
                expanded_raidz,
            }
        }

        #[test]
        fn active_generation_keeps_old_width_and_rounds_complete_sectors() {
            let ordinary = group(3, 10, &[], false);
            let active = group(4, 20, &[], true);
            // Twenty-five allocation sectors still occupy nine physical rows
            // on the three old children, even after the fourth is appended.
            assert_eq!(required_member_bytes(&ordinary).unwrap(), 9 * 4096);
            assert_eq!(required_member_bytes(&active).unwrap(), 9 * 4096);
            let mut completed = group(4, 30, &[30], false);
            completed.vdev.allocated_bytes = 32 * 4096;
            assert_eq!(required_member_bytes(&completed).unwrap(), 8 * 4096);
            completed.vdev.allocated_bytes += 1;
            assert!(required_member_bytes(&completed).is_err());
        }

        #[test]
        fn configuration_history_cannot_predate_active_or_exceed_committed_generation() {
            let active = group(4, 20, &[], true);
            assert!(validate_successor(&active, &group(4, 30, &[30], false)).is_ok());
            assert!(validate_successor(&active, &group(4, 30, &[20], false)).is_err());
            for invalid in [
                group(4, 30, &[31], false),
                group(4, 30, &[0], false),
                group(5, 30, &[20, 10], false),
                group(3, 30, &[20], true),
            ] {
                assert!(required_member_bytes(&invalid).is_err());
            }
        }

        #[test]
        fn active_generation_retains_asize_until_completion() {
            let ordinary = group(3, 10, &[], false);
            let active = group(4, 20, &[], true);
            assert!(validate_successor(&ordinary, &active).is_ok());
            let mut grown = active.clone();
            grown.vdev.txg = 21;
            grown.vdev.allocated_bytes += 4096;
            assert!(validate_successor(&ordinary, &grown).is_err());
            assert!(validate_successor(&active, &grown).is_err());
            let mut completed = group(4, 30, &[30], false);
            completed.vdev.allocated_bytes = 32 * 4096;
            assert!(validate_successor(&active, &completed).is_ok());
            let mut ordinary_grown = ordinary.clone();
            ordinary_grown.vdev.txg = 11;
            ordinary_grown.vdev.allocated_bytes += 4096;
            assert!(validate_successor(&ordinary, &ordinary_grown).is_ok());
        }

        fn ring_member(txg: u64, guid_sum: u64, order: Endian, fault: Fault) -> (Pool, Label) {
            let payload = [0; 1024];
            let root = BlockPointer::new_regular(&RegularBlockSpec {
                dvas: &[Dva { vdev: 0, offset: 4096, allocated_bytes: 1024, gang: false }],
                logical_bytes: payload.len(),
                physical: &payload,
                compression: 2,
                checksum_type: 7,
                object_type: 11,
                level: 0,
                payload_order: order,
                birth: 1,
                fill: 1,
            }).unwrap();
            let ub = Uberblock {
                order,
                version: 5000,
                txg,
                guid_sum,
                timestamp: 1_700_000_000,
                root,
                checkpoint_txg: 0,
                raidz_reflow_info: 0,
            };
            const LENGTH: usize = 8 * 1024 * 1024;
            let offset = UBERBLOCK_RING_OFFSET + 3 * 1024;
            let raw = ub.encode(1024, offset).unwrap();
            let mut bytes = vec![0; LENGTH];
            let start = usize::try_from(offset).unwrap();
            bytes[start..start + raw.len()].copy_from_slice(&raw);
            let leaf = open_bytes(bytes, 0, LENGTH as u64, Arc::default(), fault);
            let label = Label {
                offset: 0,
                order,
                config: NvList { fields: BTreeMap::new() },
                slot_bytes: 1024,
            };
            (Pool::from(leaf), label)
        }

        #[test]
        fn raw_zero_successor_authority_cannot_fall_back_to_older_configuration() {
            let cx = Cx::for_testing();
            let known = BTreeSet::from([3906]);
            for order in [Endian::Little, Endian::Big] {
                for (txg, sum, refused) in [(41, 4906, false), (43, 3906, false), (43, 4906, true)] {
                    let (pool, label) = ring_member(txg, sum, order, Fault::None);
                    let result = pool.reject_unmatched_configuration_authority(
                        &cx, &[vec![(0, label)]], &known, 5000, 42,
                    );
                    if refused {
                        assert!(result.unwrap_err().to_string().contains("authority"));
                    } else {
                        result.unwrap();
                    }
                }
            }
        }

        #[test]
        fn unreadable_authority_ring_is_not_evidence_that_successor_is_absent() {
            let cx = Cx::for_testing();
            let (pool, label) = ring_member(
                43, 3906, Endian::Little, Fault::Io(UBERBLOCK_RING_OFFSET),
            );
            assert!(matches!(
                pool.reject_unmatched_configuration_authority(
                    &cx, &[vec![(0, label)]], &BTreeSet::from([3906]), 5000, 42,
                ),
                Err(super::super::FfsError::Io(_))
            ));
        }
    }
}
