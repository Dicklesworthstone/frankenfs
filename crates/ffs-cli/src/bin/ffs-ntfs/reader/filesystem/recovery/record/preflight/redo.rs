//! Repeat-history redo candidates through a selected, validated LFS boundary.
//!
//! Native reference: Linux v6.17 fs/ntfs3/fslog.c Redo, including dirty-page
//! oldest_lsn and deleted-cluster handling. This profile refuses mixed live/
//! retired spans rather than guessing a safe partial metadata update. It resolves
//! journal claims, NOT physical ownership, page LSNs, or volume geometry.
//! A candidate plan is never permission to write or to mount a dirty image.

mod replay;

use super::{
    Cx, LFS_CLIENT_RECORD, LogRecord, NtfsVolume, Result, checkpoint, corrupt,
    targets::{self, Attribute, State},
    u16_at, u64_at, unsupported,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_RECORDS: usize = 4096;
const MAX_CLAIMS: usize = 65_536;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct Candidate<'a> {
    record: &'a LogRecord,
    attribute: &'a Attribute,
    // Current surviving mappings, including HotFix relocation. Never blindly
    // replay to the older physical LCNs recorded in the original update.
    lcns: Vec<u64>,
    payload: &'a [u8],
}

pub(super) struct Plan<'a> {
    candidates: Vec<Candidate<'a>>,
    obsolete: usize,
    relocated: usize,
}

pub(super) struct Summary {
    pub(super) records: usize,
    pub(super) obsolete: usize,
    pub(super) bytes: usize,
    pub(super) clusters: usize,
    pub(super) files: usize,
    pub(super) relocated: usize,
    pub(super) first_lsn: Option<u64>,
}

#[derive(Clone, Copy)]
pub(super) struct ReplayInput<'a> {
    pub(super) volume: &'a NtfsVolume,
    pub(super) restart: &'a super::Restart,
    pub(super) targets: &'a State,
    pub(super) history: &'a [LogRecord],
    pub(super) undo: &'a super::analysis::Report,
}

pub(super) struct ReplaySummary {
    pub(super) records: usize,
    pub(super) redo: usize,
    pub(super) undo: usize,
    pub(super) skipped: usize,
}

impl Plan<'_> {
    pub(super) fn stage(
        &self,
        cx: &Cx,
        input: ReplayInput<'_>,
        read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<ReplaySummary> {
        replay::stage(cx, self, input, read)
    }

    pub(super) fn summary(&self) -> Summary {
        Summary {
            records: self.candidates.len(),
            obsolete: self.obsolete,
            bytes: self
                .candidates
                .iter()
                .map(|entry| entry.payload.len())
                .sum(),
            clusters: self.candidates.iter().map(|entry| entry.lcns.len()).sum(),
            files: self
                .candidates
                .iter()
                .map(|entry| entry.attribute.reference)
                .collect::<BTreeSet<_>>()
                .len(),
            relocated: self.relocated,
            first_lsn: self.candidates.first().map(|entry| entry.record.lsn),
        }
    }
}

fn same_stream(a: &Attribute, b: &Attribute) -> bool {
    a.reference == b.reference
        && a.kind == b.kind
        && a.name == b.name
        && a.index_bytes == b.index_bytes
}

/// Refuse contradictory surviving claims before constructing any candidates.
/// Two native slots may identify the same exact stream/VCN; different streams
/// or different VCNs cannot own the same physical dirty cluster in this profile.
fn ownership(cx: &Cx, targets: &State) -> Result<()> {
    checkpoint(cx)?;
    if targets.clusters.len() > MAX_CLAIMS {
        return Err(unsupported("$LogFile redo ownership exceeds 65536 claims"));
    }
    let mut owners: BTreeMap<u64, (u32, u64)> = BTreeMap::new();
    for (&(slot, vcn), cluster) in &targets.clusters {
        checkpoint(cx)?;
        let Some(lcn) = cluster.lcn else { continue };
        if lcn == 0 || lcn > i64::MAX as u64 {
            return Err(corrupt(0, "invalid physical LCN in $LogFile redo claims"));
        }
        let attribute = targets
            .attributes
            .get(&slot)
            .ok_or_else(|| corrupt(0, "dirty redo claim has no native stream identity"))?;
        if let Some(&(other, other_vcn)) = owners.get(&lcn) {
            let previous = targets
                .attributes
                .get(&other)
                .ok_or_else(|| corrupt(0, "redo ownership lost a stream identity"))?;
            if vcn != other_vcn || !same_stream(attribute, previous) {
                return Err(corrupt(
                    0,
                    "different NTFS streams or VCNs claim the same dirty LCN",
                ));
            }
        } else {
            owners.insert(lcn, (slot, vcn));
        }
    }
    checkpoint(cx)
}

/// Build all candidates privately before returning any of them. Call with the
/// full chronological interval beginning at the oldest surviving dirty LSN,
/// even when that record precedes the checkpoint's Analysis start.
/// No winner/loser filter belongs here: Redo repeats both, including CLRs.
pub(super) fn build<'a>(cx: &Cx, targets: &'a State, history: &'a [LogRecord]) -> Result<Plan<'a>> {
    checkpoint(cx)?;
    if history.len() > MAX_RECORDS {
        return Err(unsupported("$LogFile redo exceeds 4096 records"));
    }
    ownership(cx, targets)?;
    if let Some(oldest) = targets.finish(cx)?.2
        && history.first().is_none_or(|record| record.lsn > oldest)
    {
        return Err(unsupported(
            "$LogFile redo window omits surviving pre-checkpoint dirty work",
        ));
    }
    let mut plan = Plan {
        candidates: Vec::new(),
        obsolete: 0,
        relocated: 0,
    };
    let mut previous = 0;
    let mut claims = 0_usize;
    let mut payload_bytes = 0_usize;
    for record in history {
        checkpoint(cx)?;
        if record.lsn == 0 || record.lsn <= previous {
            return Err(corrupt(0, "$LogFile redo input is not chronological"));
        }
        previous = record.lsn;
        if record.kind != LFS_CLIENT_RECORD || !targets::changes_pages(record.summary.redo_op) {
            continue;
        }
        let count = usize::from(u16_at(&record.data, 14)?);
        if count == 0 {
            continue;
        }
        claims = claims
            .checked_add(count)
            .filter(|claims| *claims <= MAX_CLAIMS)
            .ok_or_else(|| unsupported("$LogFile redo exceeds 65536 inspected mapping claims"))?;
        let payload = targets::payload(record, false)?;
        let slot = u32::from(u16_at(&record.data, 12)?);
        let vcn = u64_at(&record.data, 24)?;
        if vcn.checked_add(count as u64).is_none() {
            return Err(corrupt(0, "$LogFile redo VCN span overflows"));
        }
        let attribute = targets.attributes.get(&slot);
        if attribute.is_some_and(|attribute| record.lsn < attribute.opened) {
            plan.obsolete += 1;
            continue;
        }
        let mut lcns = Vec::with_capacity(count);
        let mut relocated = 0;
        for index in 0..count {
            checkpoint(cx)?;
            if let Some(cluster) = targets.clusters.get(&(slot, vcn + index as u64))
                && record.lsn >= cluster.oldest
                && let Some(lcn) = cluster.lcn
            {
                if lcn != u64_at(&record.data, 32 + index * 8)? {
                    relocated += 1;
                }
                lcns.push(lcn);
            }
        }
        if lcns.is_empty() {
            plan.obsolete += 1;
            continue;
        }
        if lcns.len() != count {
            return Err(unsupported(
                "$LogFile redo spans live and retired or superseded clusters; partial-page replay is required",
            ));
        }
        let attribute = attribute
            .ok_or_else(|| corrupt(0, "$LogFile redo target has no current stream identity"))?;
        payload_bytes = payload_bytes
            .checked_add(payload.len())
            .filter(|bytes| *bytes <= MAX_PAYLOAD)
            .ok_or_else(|| unsupported("$LogFile redo payloads exceed 16 MiB"))?;
        plan.relocated += relocated;
        plan.candidates.push(Candidate {
            record,
            attribute,
            lcns,
            payload,
        });
    }
    checkpoint(cx)?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::super::super::TailRecord;
    use super::super::targets::Cluster;
    use super::*;

    fn state() -> State {
        let mut state = State::default();
        state.attributes.insert(
            24,
            Attribute {
                reference: (7 << 48) | 0x002a,
                kind: 0x80,
                index_bytes: 0,
                opened: 10,
                name: vec![0xD800, 97],
            },
        );
        state.clusters.insert(
            (24, 5),
            Cluster {
                oldest: 20,
                lcn: Some(100),
            },
        );
        state
    }

    fn record(lsn: u64, id: u32, undo: u16, vcn: u64, lcns: &[u64], bytes: &[u8]) -> LogRecord {
        let start = 32 + lcns.len().max(1) * 8;
        let mut data = vec![0; start + bytes.len()];
        data[..2].copy_from_slice(&8_u16.to_le_bytes());
        data[2..4].copy_from_slice(&undo.to_le_bytes());
        data[4..6].copy_from_slice(&(start as u16).to_le_bytes());
        data[6..8].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        data[12..14].copy_from_slice(&24_u16.to_le_bytes());
        data[14..16].copy_from_slice(&(lcns.len() as u16).to_le_bytes());
        data[24..32].copy_from_slice(&vcn.to_le_bytes());
        for (i, lcn) in lcns.iter().enumerate() {
            data[32 + i * 8..40 + i * 8].copy_from_slice(&lcn.to_le_bytes());
        }
        data[start..].copy_from_slice(bytes);
        LogRecord {
            lsn,
            previous: 0,
            undo_next: 0,
            kind: LFS_CLIENT_RECORD,
            summary: TailRecord {
                transaction_id: id,
                redo_op: 8,
                undo_op: undo,
            },
            data,
        }
    }

    #[test]
    fn repeat_history_keeps_interleaved_transactions_and_compensation_redo() {
        let cx = Cx::for_testing();
        let state = state();
        let history = [
            record(20, 24, 8, 5, &[100], b"old"),
            record(30, 64, 8, 5, &[100], b"new"),
            record(40, 24, 1, 5, &[100], b"undo"),
        ];
        let plan = build(&cx, &state, &history).unwrap();
        assert_eq!(
            plan.candidates
                .iter()
                .map(|entry| entry.record.lsn)
                .collect::<Vec<_>>(),
            vec![20, 30, 40]
        );
        assert_eq!(plan.candidates[2].payload, b"undo");
        let summary = plan.summary();
        assert_eq!((summary.records, summary.bytes, summary.files), (3, 10, 1));
        assert_eq!(summary.first_lsn, Some(20));
    }

    #[test]
    fn redo_uses_hotfixed_mapping_without_rewriting_the_original_journal() {
        let state = state();
        let history = [record(20, 24, 8, 5, &[99], b"data")];
        let before = history[0].data.clone();
        let plan = build(&Cx::for_testing(), &state, &history).unwrap();
        assert_eq!(plan.candidates[0].lcns, vec![100]);
        assert_eq!(plan.summary().relocated, 1);
        assert_eq!(history[0].data, before);
        assert_eq!(plan.candidates[0].attribute.name, vec![0xD800, 97]);
    }

    #[test]
    fn dirty_low_water_and_slot_lifetimes_exclude_obsolete_records() {
        let state = state();
        let history = [
            record(9, 24, 8, 5, &[100], b"a"),
            record(19, 24, 8, 5, &[100], b"b"),
            record(20, 24, 8, 5, &[100], b"c"),
        ];
        let plan = build(&Cx::for_testing(), &state, &history).unwrap();
        assert_eq!(plan.summary().obsolete, 2);
        assert_eq!(plan.candidates[0].payload, b"c");
    }

    #[test]
    fn fully_retired_ranges_are_excluded_but_mixed_metadata_updates_are_refused() {
        let cx = Cx::for_testing();
        let mut state = state();
        state.clusters.insert(
            (24, 6),
            Cluster {
                oldest: 20,
                lcn: None,
            },
        );
        let history = [record(20, 24, 8, 6, &[200], b"gone")];
        let plan = build(&cx, &state, &history).unwrap();
        assert!(plan.candidates.is_empty());
        assert_eq!(plan.summary().obsolete, 1);
        let mixed = [record(20, 24, 8, 5, &[100, 200], b"cross-page")];
        assert!(build(&cx, &state, &mixed).is_err());
        state.clusters.insert(
            (24, 6),
            Cluster {
                oldest: 30,
                lcn: Some(200),
            },
        );
        assert!(build(&cx, &state, &mixed).is_err());
    }

    #[test]
    fn self_alias_and_cross_file_cross_stream_dirty_ownership_are_refused() {
        let cx = Cx::for_testing();
        for mutation in 0..4 {
            let mut state = state();
            if mutation == 0 {
                state.clusters.insert(
                    (24, 6),
                    Cluster {
                        oldest: 20,
                        lcn: Some(100),
                    },
                );
            } else {
                let mut alias = state.attributes[&24].clone();
                match mutation {
                    1 => alias.reference += 1,
                    2 => alias.name.push(98),
                    _ => alias.kind = 0xB0,
                }
                state.attributes.insert(64, alias);
                state.clusters.insert(
                    (64, 5),
                    Cluster {
                        oldest: 20,
                        lcn: Some(100),
                    },
                );
            }
            assert!(build(&cx, &state, &[]).is_err());
        }
    }

    #[test]
    fn exact_duplicate_native_stream_slots_are_not_false_crosslinks() {
        let mut state = state();
        state.attributes.insert(64, state.attributes[&24].clone());
        state.clusters.insert(
            (64, 5),
            Cluster {
                oldest: 20,
                lcn: Some(100),
            },
        );
        let history = [record(20, 24, 8, 5, &[100], b"data")];
        assert_eq!(
            build(&Cx::for_testing(), &state, &history)
                .unwrap()
                .summary()
                .records,
            1
        );
    }

    #[test]
    fn malformed_later_records_never_return_an_earlier_partial_plan() {
        let cx = Cx::for_testing();
        for mutation in 0..3 {
            let state = state();
            let first = record(20, 24, 8, 5, &[100], b"good");
            let mut later = record(30, 24, 8, 5, &[100], b"bad");
            match mutation {
                0 => later.data[6..8].copy_from_slice(&u16::MAX.to_le_bytes()),
                1 => later.data[24..32].copy_from_slice(&u64::MAX.to_le_bytes()),
                _ => later.lsn = 19,
            }
            assert!(build(&cx, &state, &[first, later]).is_err());
        }
    }

    #[test]
    fn candidate_mapping_work_is_bounded_even_when_every_record_is_obsolete() {
        let state = State::default();
        let lcns = vec![100; 4096];
        let history: Vec<_> = (1..=17)
            .map(|lsn| record(lsn, 24, 8, 0, &lcns, &[]))
            .collect();
        assert!(build(&Cx::for_testing(), &state, &history).is_err());
    }

    #[test]
    fn dirty_lsn_before_analysis_start_is_the_required_redo_scan_boundary() {
        let state = state();
        assert_eq!(state.finish(&Cx::for_testing()).unwrap().2, Some(20));
        // A checkpoint-start-only history would omit the required byte update.
        let history = [
            record(20, 24, 8, 5, &[100], b"before-checkpoint"),
            record(50, 64, 8, 5, &[100], b"after-checkpoint"),
        ];
        let plan = build(&Cx::for_testing(), &state, &history).unwrap();
        assert_eq!(plan.summary().first_lsn, Some(20));
        assert_eq!(plan.summary().records, 2);
        assert!(build(&Cx::for_testing(), &state, &history[1..]).is_err());
        assert!(build(&Cx::for_testing(), &state, &[]).is_err());
    }
}
