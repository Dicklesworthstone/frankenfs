//! Native NTFS 3.1 transactional operations (`create_file`, `mkdir`, `write_file_data`,
//! `rename_entry`, `unlink_file`, `grow_mft`) with strict WAL barrier ordering,
//! `$Bitmap` & `$MFT::$BITMAP` reservation, `$MFTMirr` sync, and `NtfsTxOutcome`
//! classification (`Committed`, `NotCommitted`, `Uncertain`).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::logfile_writer::{
    LFS_RECORD_CLIENT, NtfsClientUpdateSpec, NtfsLogRingWriter, encode_client_update_payload,
    encode_open_attribute_entry, next_usa_token,
};
use ffs_ondisk::ntfs::recovery::{
    FileEdit, FileEditResult, FileOperation, RecoveryPass, apply_file_edit,
    deallocate_file_record_slot, initialize_file_record_slot,
};
use ffs_ondisk::ntfs::{
    DATA, EA, EA_INFORMATION, NtfsFileRecord, NtfsLogOp, NtfsNonResident, NtfsReference, NtfsRun,
    NtfsValue, decode_mapping_pairs, encode_mapping_pairs, restore_record,
};

use super::dir_index::{
    DirPrePayloadWrite, I30_NAME, build_empty_small_index_root, directory_has_external_indx,
    encode_nonresident_attribute, encode_resident_attribute, find_attr_offset_in_restored,
    split_parent_and_leaf, utf8_component_to_utf16,
};
use super::{
    NtfsPersistenceStage, NtfsTransactionEngine, NtfsTxOutcome, OpenAttrRuntime, SECTOR_BYTES,
    checkpoint, corrupt, extract_plain_nonresident_runs, extract_plain_nonresident_stream,
    extract_resident_attr, map_logical_offset, map_ring_err, parse_err, read_mapped_runs,
    read_mft_record_raw_via_runs, read_mft_record_via_runs, unsupported, write_mapped_runs,
};

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_SECURITY_DESCRIPTOR: u32 = 0x50;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const ATTR_BITMAP: u32 = 0xB0;

const DEFAULT_NTFS_FILETIME: u64 = 133_500_000_000_000_000; // 2024-01-19 UTC in 100ns intervals
const FILE_ATTR_DIRECTORY: u32 = 0x1000_0000; // DUP_FILE_NAME_INDEX_PRESENT
const FILE_ATTR_ARCHIVE: u32 = 0x0000_0020;
const MAX_RESIDENT_DATA_PAYLOAD: usize = 512;

#[derive(Debug)]
enum TargetWriteKind {
    MftRecord {
        runs: Vec<NtfsRun>,
        record_no: u32,
        raw_protected: Vec<u8>,
    },
    IndxBlock {
        runs: Vec<NtfsRun>,
        byte_offset: u64,
        raw_protected: Vec<u8>,
    },
    BitmapStream {
        runs: Vec<NtfsRun>,
        byte_offset: u64,
        bytes: Vec<u8>,
    },
}

#[derive(Debug)]
struct PreparedTxPlan<T> {
    operation: &'static str,
    operation_digest: [u8; 32],
    result_value: T,
    pre_payload_writes: Vec<DirPrePayloadWrite>,
    mft_zero_writes: Vec<DirPrePayloadWrite>,
    open_attr_registrations: Vec<(u32, OpenAttrRuntime, NtfsClientUpdateSpec)>,
    mutation_specs: Vec<NtfsClientUpdateSpec>,
    target_writes: Vec<TargetWriteKind>,
}

#[derive(Clone, Copy)]
enum FileDataEdit<'a> {
    Write { offset: u64, data: &'a [u8] },
    Truncate { size: u64 },
}

#[derive(Debug, Clone)]
enum InheritedSecurity {
    SharedId(u32),
    Descriptor(Vec<u8>),
}

fn minimal_self_relative_sd() -> Vec<u8> {
    // Valid 52-byte self-relative SECURITY_DESCRIPTOR:
    // Header (20B): revision=1, sbz1=0, control=0x8004 (SE_SELF_RELATIVE | SE_DACL_PRESENT),
    // owner=20, group=32, sacl=0, dacl=44.
    // Owner SID S-1-5-18 (12B): [1, 1, 0,0,0,0,0,5, 18,0,0,0]
    // Group SID S-1-5-18 (12B): [1, 1, 0,0,0,0,0,5, 18,0,0,0]
    // DACL (8B): revision=2, sbz1=0, acl_size=8, ace_count=0, sbz2=0.
    let mut sd = vec![0_u8; 52];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
    sd[4..8].copy_from_slice(&20_u32.to_le_bytes());
    sd[8..12].copy_from_slice(&32_u32.to_le_bytes());
    sd[16..20].copy_from_slice(&44_u32.to_le_bytes());
    let sid_local_system = [1_u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    sd[20..32].copy_from_slice(&sid_local_system);
    sd[32..44].copy_from_slice(&sid_local_system);
    sd[44] = 2;
    sd[46..48].copy_from_slice(&8_u16.to_le_bytes());
    sd
}

fn extract_parent_security(parent_rec: &NtfsFileRecord) -> InheritedSecurity {
    if let Ok(std_info) = extract_resident_attr(parent_rec, ATTR_STANDARD_INFORMATION, &[])
        && std_info.len() == 72
    {
        let sec_id = u32::from_le_bytes([std_info[52], std_info[53], std_info[54], std_info[55]]);
        if sec_id != 0 {
            return InheritedSecurity::SharedId(sec_id);
        }
    }
    if let Ok(sd) = extract_resident_attr(parent_rec, ATTR_SECURITY_DESCRIPTOR, &[])
        && (20..=65_536).contains(&sd.len())
    {
        return InheritedSecurity::Descriptor(sd);
    }
    InheritedSecurity::Descriptor(minimal_self_relative_sd())
}

fn encode_standard_information(is_dir: bool, security: &InheritedSecurity) -> Vec<u8> {
    let flags: u32 = if is_dir { 0 } else { FILE_ATTR_ARCHIVE };
    match security {
        InheritedSecurity::SharedId(sec_id) => {
            let mut buf = vec![0_u8; 72];
            for off in [0_usize, 8, 16, 24] {
                buf[off..off + 8].copy_from_slice(&DEFAULT_NTFS_FILETIME.to_le_bytes());
            }
            buf[32..36].copy_from_slice(&flags.to_le_bytes());
            buf[52..56].copy_from_slice(&sec_id.to_le_bytes());
            buf
        }
        InheritedSecurity::Descriptor(_) => {
            let mut buf = vec![0_u8; 48];
            for off in [0_usize, 8, 16, 24] {
                buf[off..off + 8].copy_from_slice(&DEFAULT_NTFS_FILETIME.to_le_bytes());
            }
            buf[32..36].copy_from_slice(&flags.to_le_bytes());
            buf
        }
    }
}

fn stamp_protected_lsn(raw: &[u8], signature: [u8; 4], lsn: u64) -> Result<Vec<u8>> {
    let mut restored = restore_record(raw, &signature).map_err(|err| parse_err(&err))?;
    let usa = usize::from(u16::from_le_bytes([restored[4], restored[5]]));
    let old_tok = u16::from_le_bytes([raw[usa], raw[usa + 1]]);
    restored[8..16].copy_from_slice(&lsn.to_le_bytes());
    protect_indx_block_or_file(restored, next_usa_token(old_tok))
}

fn protect_indx_block_or_file(mut restored: Vec<u8>, usa_token: u16) -> Result<Vec<u8>> {
    let usa = usize::from(u16::from_le_bytes([restored[4], restored[5]]));
    let count = usize::from(u16::from_le_bytes([restored[6], restored[7]]));
    if count != restored.len() / SECTOR_BYTES + 1 || usa + count * 2 > 510 {
        return Err(corrupt(0, "invalid multi-sector USA bounds"));
    }
    restored[usa..usa + 2].copy_from_slice(&usa_token.to_le_bytes());
    for sector in 1..count {
        let end = sector * SECTOR_BYTES;
        let saved = [restored[end - 2], restored[end - 1]];
        restored[usa + sector * 2..usa + sector * 2 + 2].copy_from_slice(&saved);
        restored[end - 2..end].copy_from_slice(&usa_token.to_le_bytes());
    }
    Ok(restored)
}

fn build_restored_file_template(
    record_bytes: u32,
    record_no: u32,
    sequence: u16,
    is_dir: bool,
    sorted_attrs: &[(u32, Vec<u8>)],
    next_attr_id: u16,
) -> Result<Vec<u8>> {
    let len = record_bytes as usize;
    let usa_offset: u16 = 48;
    let usa_count = u16::try_from(len / SECTOR_BYTES + 1).map_err(|_| corrupt(0, "usa_count"))?;
    let first_attr = (usize::from(usa_offset) + usize::from(usa_count) * 2 + 7) & !7;
    let attrs_bytes: usize = sorted_attrs.iter().map(|(_, b)| b.len()).sum();
    let used = first_attr + attrs_bytes + 8;
    if used > len {
        return Err(FfsError::NoSpace);
    }
    let mut buf = vec![0_u8; len];
    buf[0..4].copy_from_slice(b"FILE");
    buf[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    buf[6..8].copy_from_slice(&usa_count.to_le_bytes());
    buf[16..18].copy_from_slice(&sequence.to_le_bytes());
    buf[18..20].copy_from_slice(&1_u16.to_le_bytes()); // hard_links = 1
    buf[20..22].copy_from_slice(&(first_attr as u16).to_le_bytes());
    let flags: u16 = if is_dir { 0x0003 } else { 0x0001 };
    buf[22..24].copy_from_slice(&flags.to_le_bytes());
    buf[24..28].copy_from_slice(&(used as u32).to_le_bytes());
    buf[28..32].copy_from_slice(&record_bytes.to_le_bytes());
    buf[40..42].copy_from_slice(&next_attr_id.to_le_bytes());
    buf[44..48].copy_from_slice(&record_no.to_le_bytes());
    let mut pos = first_attr;
    for (_, attr_raw) in sorted_attrs {
        buf[pos..pos + attr_raw.len()].copy_from_slice(attr_raw);
        pos += attr_raw.len();
    }
    buf[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    Ok(buf)
}

fn find_contiguous_zero_bits(
    bitmap: &[u8],
    limit_bits: u64,
    count: u64,
    min_start: u64,
) -> Option<u64> {
    if count == 0 {
        return Some(min_start);
    }
    let max_bit = limit_bits.min((bitmap.len() as u64) * 8);
    let mut run_start = min_start;
    let mut run_len = 0_u64;
    for bit_idx in min_start..max_bit {
        let is_set = (bitmap[(bit_idx / 8) as usize] & (1_u8 << (bit_idx % 8))) != 0;
        if is_set {
            run_start = bit_idx + 1;
            run_len = 0;
        } else {
            run_len += 1;
            if run_len == count {
                return Some(run_start);
            }
        }
    }
    None
}

fn set_or_clear_bits(bitmap: &mut [u8], start: u64, count: u64, set: bool) {
    for b in start..start + count {
        let idx = (b / 8) as usize;
        let mask = 1_u8 << (b % 8);
        if set {
            bitmap[idx] |= mask;
        } else {
            bitmap[idx] &= !mask;
        }
    }
}

/// Prefer the earliest contiguous allocation, otherwise use the largest free
/// runs to minimize mapping pairs. One cancellable scan retains at most
/// `max_runs` candidates and never reuses an allocated COW source cluster.
fn find_free_data_runs(
    cx: &Cx,
    bitmap: &[u8],
    volume_clusters: u64,
    clusters: u64,
    max_runs: usize,
) -> Result<Vec<NtfsRun>> {
    checkpoint(cx)?;
    if clusters == 0 {
        return Ok(Vec::new());
    }
    if max_runs == 0 {
        return Err(unsupported("DATA allocation has no mapping-pair capacity"));
    }

    let limit = volume_clusters.min((bitmap.len() as u64).saturating_mul(8));
    // The heap root is the shortest retained run; equal lengths discard the
    // latest physical run first. Its size depends on FILE capacity, not on
    // volume size or the number of holes encountered during the scan.
    let mut candidates: BinaryHeap<(Reverse<u64>, u64)> = BinaryHeap::new();
    let mut retain_run = |start: u64, length: u64| {
        let candidate = (Reverse(length), start);
        if candidates.len() < max_runs {
            candidates.push(candidate);
        } else if let Some(mut worst) = candidates.peek_mut()
            && candidate < *worst
        {
            *worst = candidate;
        }
    };
    let mut free_clusters = 0_u64;
    let mut run_start = 1;
    let mut run_length = 0;
    for cluster in 1..limit {
        if cluster.is_multiple_of(4096) {
            checkpoint(cx)?;
        }
        if bitmap[(cluster / 8) as usize] & (1 << (cluster % 8)) != 0 {
            if run_length != 0 {
                retain_run(run_start, run_length);
                run_length = 0;
            }
            continue;
        }
        if run_length == 0 {
            run_start = cluster;
        }
        run_length += 1;
        free_clusters += 1;
        if run_length == clusters {
            return Ok(vec![NtfsRun {
                vcn: 0,
                clusters,
                lcn: Some(run_start),
            }]);
        }
    }
    if run_length != 0 {
        retain_run(run_start, run_length);
    }
    if free_clusters < clusters {
        return Err(FfsError::NoSpace);
    }

    // Ascending heap keys put the largest extents first. Take only as many
    // runs as needed before sorting physically, so early tiny holes cannot
    // consume the mapping budget when larger later holes suffice.
    let mut runs = Vec::new();
    let mut remaining = clusters;
    for (Reverse(length), start) in candidates.into_sorted_vec() {
        let allocated = length.min(remaining);
        runs.push(NtfsRun {
            vcn: 0,
            clusters: allocated,
            lcn: Some(start),
        });
        remaining -= allocated;
        if remaining == 0 {
            break;
        }
    }
    if remaining != 0 {
        return Err(unsupported(
            "fragmented DATA mapping requires an attribute-list extension",
        ));
    }
    runs.sort_unstable_by_key(|run| run.lcn);
    let mut vcn = 0;
    for run in &mut runs {
        run.vcn = vcn;
        vcn += run.clusters;
    }
    Ok(runs)
}

impl NtfsTransactionEngine {
    fn reserve_data_payload(
        &self,
        cx: &Cx,
        bitmap: &mut [u8],
        payload: &[u8],
        pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
    ) -> Result<Vec<NtfsRun>> {
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());
        let clusters = (payload.len() as u64).div_ceil(cluster_bytes);
        // Each non-sparse mapping pair needs at least a header, length and LCN
        // delta. The complete encoded attribute must still fit its FILE record;
        // this upper bound prevents building an unbounded run/log plan first.
        let max_runs = self.geometry.record_bytes() as usize / 3;
        let runs = find_free_data_runs(
            cx,
            bitmap,
            self.geometry.cluster_count(),
            clusters,
            max_runs,
        )?;
        for run in &runs {
            checkpoint(cx)?;
            let lcn = run
                .lcn
                .ok_or_else(|| corrupt(0, "sparse DATA reservation"))?;
            let allocated_bytes =
                usize::try_from(run.clusters * cluster_bytes).map_err(|_| FfsError::NoSpace)?;
            let payload_start =
                usize::try_from(run.vcn * cluster_bytes).map_err(|_| FfsError::NoSpace)?;
            let copied = allocated_bytes.min(payload.len() - payload_start);
            let mut initialized = vec![0; allocated_bytes];
            initialized[..copied].copy_from_slice(&payload[payload_start..payload_start + copied]);
            pre_payload_writes.push(DirPrePayloadWrite {
                phys_offset: self
                    .geometry
                    .cluster_offset(lcn)
                    .map_err(|err| parse_err(&err))?,
                bytes: initialized,
            });
            set_or_clear_bits(bitmap, lcn, run.clusters, true);
        }
        Ok(runs)
    }

    fn map_mft_record_transfer(
        &self,
        mft_runs: &[NtfsRun],
        record_no: u32,
    ) -> Result<(u64, u16, Vec<u64>)> {
        let rec_bytes = u64::from(self.geometry.record_bytes());
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());
        let logical = u64::from(record_no) * rec_bytes;
        let target_vcn = logical / cluster_bytes;
        let within = (logical % cluster_bytes) as usize;
        let cbo = u16::try_from(within / SECTOR_BYTES).map_err(|_| corrupt(0, "cbo"))?;
        let n_clusters = (within as u64 + rec_bytes).div_ceil(cluster_bytes);
        let mut lcns = Vec::with_capacity(n_clusters as usize);
        for i in 0..n_clusters {
            let (_, _, lcn) =
                map_logical_offset(&self.geometry, mft_runs, (target_vcn + i) * cluster_bytes)?;
            lcns.push(lcn);
        }
        Ok((target_vcn, cbo, lcns))
    }

    #[allow(clippy::unused_self)]
    fn plan_open_attr(
        &self,
        staged_open: &mut BTreeMap<u32, OpenAttrRuntime>,
        new_registrations: &mut Vec<(u32, OpenAttrRuntime, NtfsClientUpdateSpec)>,
        reference: NtfsReference,
        kind: u32,
        name: &[u16],
        index_bytes: u32,
    ) -> Result<u16> {
        let ref_raw = reference.encode().map_err(|err| parse_err(&err))?;
        for (&slot, info) in staged_open.iter() {
            if info.reference_raw == ref_raw
                && info.kind == kind
                && info.name.as_slice() == name
                && info.index_bytes == index_bytes
            {
                return u16::try_from(slot).map_err(|_| corrupt(0, "slot u16"));
            }
        }
        let mut k = 0_u32;
        let slot = loop {
            let candidate = 24 + k * 40;
            if candidate > u32::from(u16::MAX) {
                return Err(FfsError::NoSpace);
            }
            if !staged_open.contains_key(&candidate) {
                break candidate;
            }
            k += 1;
        };
        let slot_u16 = u16::try_from(slot).map_err(|_| corrupt(0, "slot u16"))?;
        let entry_bytes = encode_open_attribute_entry(kind, index_bytes, ref_raw, 0);
        let mut name_le = Vec::with_capacity(name.len() * 2);
        for &u in name {
            name_le.extend_from_slice(&u.to_le_bytes());
        }
        let runtime = OpenAttrRuntime {
            reference_raw: ref_raw,
            kind,
            name: name.to_vec(),
            index_bytes,
            opened_lsn: 0,
        };
        let spec = NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::OpenNonresidentAttribute,
            undo_op: NtfsLogOp::Noop,
            target_attribute: slot_u16,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: 0,
            target_vcn: 0,
            target_lcns: Vec::new(),
            redo_data: entry_bytes.to_vec(),
            undo_data: name_le,
        };
        staged_open.insert(slot, runtime.clone());
        new_registrations.push((slot, runtime, spec));
        Ok(slot_u16)
    }

    fn build_bitmap_range_specs(
        &self,
        bitmap_attr_slot: u16,
        bitmap_runs: &[NtfsRun],
        start_bit: u64,
        bit_count: u64,
        set_bits: bool,
    ) -> Result<Vec<NtfsClientUpdateSpec>> {
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());
        let bits_per_cluster = cluster_bytes * 8;
        let mut specs = Vec::new();
        let mut cur = start_bit;
        let end = start_bit + bit_count;
        while cur < end {
            let vcn = cur / bits_per_cluster;
            let bit_in_cluster = cur % bits_per_cluster;
            let chunk = (end - cur).min(bits_per_cluster - bit_in_cluster);
            let (_, _, bm_lcn) =
                map_logical_offset(&self.geometry, bitmap_runs, vcn * cluster_bytes)?;
            let mut payload = Vec::with_capacity(8);
            payload.extend_from_slice(&(bit_in_cluster as u32).to_le_bytes());
            payload.extend_from_slice(&(chunk as u32).to_le_bytes());
            let (redo_op, undo_op) = if set_bits {
                (
                    NtfsLogOp::SetBitsInNonresidentBitMap,
                    NtfsLogOp::ClearBitsInNonresidentBitMap,
                )
            } else {
                (
                    NtfsLogOp::ClearBitsInNonresidentBitMap,
                    NtfsLogOp::SetBitsInNonresidentBitMap,
                )
            };
            specs.push(NtfsClientUpdateSpec {
                redo_op,
                undo_op,
                target_attribute: bitmap_attr_slot,
                record_offset: 0,
                attribute_offset: 0,
                cluster_block_offset: 0,
                target_vcn: vcn,
                target_lcns: vec![bm_lcn],
                redo_data: payload.clone(),
                undo_data: payload,
            });
            cur += chunk;
        }
        Ok(specs)
    }

    #[allow(clippy::too_many_lines)]
    fn execute_logged_tx<T>(&mut self, cx: &Cx, plan: PreparedTxPlan<T>) -> NtfsTxOutcome<T> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = self.ensure_ring_initialized(cx, plan.operation) {
            return NtfsTxOutcome::NotCommitted(err);
        }

        // Encode all client payloads up front and verify $LogFile ring space BEFORE any disk write!
        let mut pre_commit_payloads =
            Vec::with_capacity(plan.open_attr_registrations.len() + plan.mutation_specs.len());
        for (_, _, spec) in &plan.open_attr_registrations {
            match encode_client_update_payload(spec) {
                Ok(b) => pre_commit_payloads.push((b, false)),
                Err(e) => return NtfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        }
        for spec in &plan.mutation_specs {
            match encode_client_update_payload(spec) {
                Ok(b) => pre_commit_payloads.push((b, true)),
                Err(e) => return NtfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        }
        let commit_payload = match encode_client_update_payload(&NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::CommitTransaction,
            undo_op: NtfsLogOp::Noop,
            target_attribute: 0,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: 0,
            target_vcn: 0,
            target_lcns: Vec::new(),
            redo_data: Vec::new(),
            undo_data: Vec::new(),
        }) {
            Ok(b) => b,
            Err(e) => return NtfsTxOutcome::NotCommitted(parse_err(&e)),
        };
        let forget_payload = match encode_client_update_payload(&NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::ForgetTransaction,
            undo_op: NtfsLogOp::Noop,
            target_attribute: 0,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: 0,
            target_vcn: 0,
            target_lcns: Vec::new(),
            redo_data: Vec::new(),
            undo_data: Vec::new(),
        }) {
            Ok(b) => b,
            Err(e) => return NtfsTxOutcome::NotCommitted(parse_err(&e)),
        };

        // Reserve space for pre-commit records + Commit + Forget + Checkpoint slack (4 extra records).
        let mut sizes_for_check: Vec<usize> =
            pre_commit_payloads.iter().map(|(b, _)| b.len()).collect();
        sizes_for_check.push(commit_payload.len());
        sizes_for_check.push(forget_payload.len());
        sizes_for_check.extend_from_slice(&[512, 512, 128]);
        if let Some(ring) = self.ring.as_ref()
            && let Err(e) = ring.check_space_for_payloads(&sizes_for_check)
        {
            return NtfsTxOutcome::NotCommitted(map_ring_err(&e));
        }

        let tx_id = self.allocate_tx_id();

        // Stage 1: Flush payload data clusters BEFORE publishing mappings/sizes!
        if !plan.pre_payload_writes.is_empty() {
            for pw in &plan.pre_payload_writes {
                if let Err(err) = self.write_volume(
                    cx,
                    plan.operation,
                    NtfsPersistenceStage::PayloadDataWrite,
                    tx_id,
                    0,
                    pw.phys_offset,
                    &pw.bytes,
                ) {
                    return NtfsTxOutcome::NotCommitted(err);
                }
            }
            if let Err(err) = self.barrier(
                cx,
                plan.operation,
                NtfsPersistenceStage::PayloadBarrier,
                tx_id,
                0,
            ) {
                return NtfsTxOutcome::NotCommitted(err);
            }
        }

        // Stage 2: Flush zeroed MFT slots BEFORE advancing $MFT initialized_bytes!
        if !plan.mft_zero_writes.is_empty() {
            for zw in &plan.mft_zero_writes {
                if let Err(err) = self.write_volume(
                    cx,
                    plan.operation,
                    NtfsPersistenceStage::MftSlotZeroWrite,
                    tx_id,
                    0,
                    zw.phys_offset,
                    &zw.bytes,
                ) {
                    return NtfsTxOutcome::NotCommitted(err);
                }
            }
            if let Err(err) = self.barrier(
                cx,
                plan.operation,
                NtfsPersistenceStage::MftSlotZeroBarrier,
                tx_id,
                0,
            ) {
                return NtfsTxOutcome::NotCommitted(err);
            }
        }

        // Clone ring + open_attrs so pre-commit failures leave in-memory engine state untouched!
        let Some(mut working_ring) = self.ring.clone() else {
            return NtfsTxOutcome::NotCommitted(corrupt(0, "missing initialized ring"));
        };
        let mut working_open = self.open_attrs.clone();

        // Stage 3: Mark both $LogFile RSTR slots dirty + barrier BEFORE appending client records
        // so both RSTR copies agree (`first == second`, `clean = false`) across tail discovery!
        let dirty_rstr_a = match working_ring.build_next_rstr_page(false) {
            Ok(p) => p,
            Err(e) => return NtfsTxOutcome::NotCommitted(parse_err(&e)),
        };
        let dirty_rstr_b = match working_ring.build_next_rstr_page(false) {
            Ok(p) => p,
            Err(e) => return NtfsTxOutcome::NotCommitted(parse_err(&e)),
        };
        for dirty_rstr in [&dirty_rstr_a, &dirty_rstr_b] {
            if let Err(err) = self.write_logfile_page(
                cx,
                plan.operation,
                NtfsPersistenceStage::DirtyRestartWrite,
                tx_id,
                working_ring.current_lsn(),
                dirty_rstr.page_vbo,
                &dirty_rstr.bytes,
            ) {
                self.ring = None;
                return NtfsTxOutcome::NotCommitted(err);
            }
        }
        if let Err(err) = self.barrier(
            cx,
            plan.operation,
            NtfsPersistenceStage::DirtyRestartBarrier,
            tx_id,
            working_ring.current_lsn(),
        ) {
            // Dirty RSTR may be on disk without any new client records; invalidate ring cache
            // so a future open recovers cleanly, while this tx is strictly NotCommitted!
            self.ring = None;
            return NtfsTxOutcome::NotCommitted(err);
        }

        // Stage 4a: Append and write pre-commit LFS records (Active transaction window).
        let mut prev_lsn = 0_u64;
        let mut undo_next_lsn = 0_u64;
        let mut pre_pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut open_reg_iter = plan.open_attr_registrations.iter();
        for (payload, undoable) in &pre_commit_payloads {
            let rec = match working_ring.append_raw_record(
                LFS_RECORD_CLIENT,
                tx_id,
                prev_lsn,
                undo_next_lsn,
                payload,
            ) {
                Ok(r) => r,
                Err(e) => {
                    self.ring = None;
                    return NtfsTxOutcome::NotCommitted(map_ring_err(&e));
                }
            };
            prev_lsn = rec.lsn;
            if *undoable {
                undo_next_lsn = rec.lsn;
            } else if let Some((slot, runtime, _)) = open_reg_iter.next() {
                let mut rt = runtime.clone();
                rt.opened_lsn = rec.lsn;
                working_open.insert(*slot, rt);
            }
            pre_pages.insert(rec.page_vbo, rec.protected_page);
        }
        for (vbo, page_bytes) in &pre_pages {
            if let Err(err) = self.write_logfile_page(
                cx,
                plan.operation,
                NtfsPersistenceStage::LogRecordWrite,
                tx_id,
                prev_lsn,
                *vbo,
                page_bytes,
            ) {
                self.ring = None;
                return NtfsTxOutcome::NotCommitted(err);
            }
        }

        // Stage 4b: COMMIT POINT — append CommitTransaction (0x1A) + ForgetTransaction (0x1B)
        // and flush LogCommitBarrier! Once this write starts, any failure is Uncertain!
        let commit_rec = match working_ring.append_raw_record(
            LFS_RECORD_CLIENT,
            tx_id,
            prev_lsn,
            undo_next_lsn,
            &commit_payload,
        ) {
            Ok(r) => r,
            Err(e) => {
                self.ring = None;
                return NtfsTxOutcome::NotCommitted(map_ring_err(&e));
            }
        };
        let commit_lsn = commit_rec.lsn;
        let mut commit_pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        commit_pages.insert(commit_rec.page_vbo, commit_rec.protected_page);

        let forget_rec = match working_ring.append_raw_record(
            LFS_RECORD_CLIENT,
            tx_id,
            commit_lsn,
            0,
            &forget_payload,
        ) {
            Ok(r) => r,
            Err(e) => {
                self.ring = None;
                return NtfsTxOutcome::NotCommitted(map_ring_err(&e));
            }
        };
        commit_pages.insert(forget_rec.page_vbo, forget_rec.protected_page);

        for (vbo, page_bytes) in &commit_pages {
            if let Err(err) = self.write_logfile_page(
                cx,
                plan.operation,
                NtfsPersistenceStage::LogRecordWrite,
                tx_id,
                commit_lsn,
                *vbo,
                page_bytes,
            ) {
                self.ring = None;
                return NtfsTxOutcome::Uncertain {
                    reason: err,
                    transaction_id: tx_id,
                    commit_lsn,
                };
            }
        }
        if let Err(err) = self.barrier(
            cx,
            plan.operation,
            NtfsPersistenceStage::LogCommitBarrier,
            tx_id,
            commit_lsn,
        ) {
            self.ring = None;
            return NtfsTxOutcome::Uncertain {
                reason: err,
                transaction_id: tx_id,
                commit_lsn,
            };
        }

        // Stage 5: Write target metadata (stamping FILE/INDX pages with commit_lsn and syncing $MFTMirr)!
        let post_commit_step = (|| -> Result<u64> {
            let mft0_for_mirr = self.read_mft_record_zero(cx)?;
            let mft0_runs_init =
                extract_plain_nonresident_runs(&self.geometry, &mft0_for_mirr, DATA, &[])?;
            let mirr_rec =
                read_mft_record_via_runs(&self.device, cx, &self.geometry, &mft0_runs_init, 1)?;
            let (mirr_runs, mirr_size, _) =
                extract_plain_nonresident_stream(&self.geometry, &mirr_rec, DATA, &[])?;
            let rec_bytes = u64::from(self.geometry.record_bytes());
            let mirr_count = mirr_size / rec_bytes;

            for tw in &plan.target_writes {
                match tw {
                    TargetWriteKind::MftRecord {
                        runs,
                        record_no,
                        raw_protected,
                    } => {
                        let stamped = stamp_protected_lsn(raw_protected, *b"FILE", commit_lsn)?;
                        let logical = u64::from(*record_no) * rec_bytes;
                        self.write_mapped_target(
                            cx,
                            plan.operation,
                            tx_id,
                            commit_lsn,
                            runs,
                            logical,
                            &stamped,
                        )?;
                        if u64::from(*record_no) < mirr_count {
                            self.write_mapped_target(
                                cx,
                                plan.operation,
                                tx_id,
                                commit_lsn,
                                &mirr_runs,
                                logical,
                                &stamped,
                            )?;
                        }
                    }
                    TargetWriteKind::IndxBlock {
                        runs,
                        byte_offset,
                        raw_protected,
                    } => {
                        let stamped = stamp_protected_lsn(raw_protected, *b"INDX", commit_lsn)?;
                        self.write_mapped_target(
                            cx,
                            plan.operation,
                            tx_id,
                            commit_lsn,
                            runs,
                            *byte_offset,
                            &stamped,
                        )?;
                    }
                    TargetWriteKind::BitmapStream {
                        runs,
                        byte_offset,
                        bytes,
                    } => {
                        self.write_mapped_target(
                            cx,
                            plan.operation,
                            tx_id,
                            commit_lsn,
                            runs,
                            *byte_offset,
                            bytes,
                        )?;
                    }
                }
            }
            self.barrier(
                cx,
                plan.operation,
                NtfsPersistenceStage::TargetMetadataBarrier,
                tx_id,
                commit_lsn,
            )?;

            self.open_attrs = working_open;
            self.ring = Some(working_ring);
            let ckpt_lsn = self.publish_clean_checkpoint_and_rstr(cx, plan.operation, tx_id)?;
            self.record_event_checked(
                plan.operation,
                NtfsPersistenceStage::AckPublished,
                tx_id,
                commit_lsn,
                0,
                0,
            )?;
            Ok(ckpt_lsn)
        })();

        match post_commit_step {
            Ok(ckpt_lsn) => {
                let token =
                    self.make_token(tx_id, commit_lsn, Some(ckpt_lsn), plan.operation_digest);
                NtfsTxOutcome::Committed {
                    value: plan.result_value,
                    token,
                }
            }
            Err(err) => {
                self.ring = None;
                NtfsTxOutcome::Uncertain {
                    reason: err,
                    transaction_id: tx_id,
                    commit_lsn,
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_mapped_target(
        &mut self,
        cx: &Cx,
        operation: &str,
        tx_id: u32,
        lsn: u64,
        runs: &[NtfsRun],
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        let mut done = 0_usize;
        while done < data.len() {
            let (phys, avail, _) = map_logical_offset(&self.geometry, runs, offset + done as u64)?;
            let chunk = (data.len() - done).min(avail as usize);
            self.write_volume(
                cx,
                operation,
                NtfsPersistenceStage::TargetMetadataWrite,
                tx_id,
                lsn,
                phys,
                &data[done..done + chunk],
            )?;
            done += chunk;
        }
        let _ = write_mapped_runs;
        Ok(())
    }

    /// Create a regular file inside `parent_path` with initial resident or cluster-backed `DATA`.
    pub fn create_file(
        &mut self,
        cx: &Cx,
        parent_path: &str,
        name: &str,
        initial_data: &[u8],
    ) -> NtfsTxOutcome<NtfsReference> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.create_file:");
        hasher.update(parent_path.as_bytes());
        hasher.update(b"/");
        hasher.update(name.as_bytes());
        hasher.update(&(initial_data.len() as u64).to_le_bytes());
        hasher.update(blake3::hash(initial_data).as_bytes());
        let digest = *hasher.finalize().as_bytes();

        match self.plan_create_node(
            cx,
            "create_file",
            digest,
            parent_path,
            name,
            Some(initial_data),
        ) {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Create an empty directory with `$I30` `INDEX_ROOT` inside `parent_path`.
    pub fn mkdir(
        &mut self,
        cx: &Cx,
        parent_path: &str,
        name: &str,
    ) -> NtfsTxOutcome<NtfsReference> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.mkdir:");
        hasher.update(parent_path.as_bytes());
        hasher.update(b"/");
        hasher.update(name.as_bytes());
        let digest = *hasher.finalize().as_bytes();

        match self.plan_create_node(cx, "mkdir", digest, parent_path, name, None) {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn plan_create_node(
        &mut self,
        cx: &Cx,
        operation: &'static str,
        operation_digest: [u8; 32],
        parent_path: &str,
        name: &str,
        file_payload: Option<&[u8]>,
    ) -> Result<PreparedTxPlan<NtfsReference>> {
        checkpoint(cx)?;
        let leaf_utf16 = utf8_component_to_utf16(name)?;

        // Check MFT slot availability first; if all initialized/logical slots >= 24 are full,
        // grow $MFT cleanly before planning the child creation!
        {
            let mft0 = self.read_mft_record_zero(cx)?;
            let (_, mft_size, _) =
                extract_plain_nonresident_stream(&self.geometry, &mft0, DATA, &[])?;
            let logical_records = mft_size / u64::from(self.geometry.record_bytes());
            let mft_bm = self.read_mft_bitmap_bytes(cx, &mft0, logical_records)?;
            if find_contiguous_zero_bits(&mft_bm, logical_records, 1, 24).is_none() {
                let (_, _tok) = self.grow_mft(cx, 16).into_result()?;
            }
        }

        let mft0_raw = read_mft_record_raw_via_runs(
            &self.device,
            cx,
            &self.geometry,
            &[NtfsRun {
                vcn: 0,
                clusters: u64::from(self.geometry.record_bytes())
                    .div_ceil(u64::from(self.geometry.cluster_bytes())),
                lcn: Some(self.geometry.mft_cluster()),
            }],
            0,
        )?;
        let mft0 = NtfsFileRecord::parse(&mft0_raw).map_err(|err| parse_err(&err))?;
        let (mft_runs, mft_data_bytes, mft_init_bytes) =
            extract_plain_nonresident_stream(&self.geometry, &mft0, DATA, &[])?;
        let rec_bytes = u64::from(self.geometry.record_bytes());
        let logical_records = mft_data_bytes / rec_bytes;
        let init_records = mft_init_bytes / rec_bytes;

        let (parent_no, parent_rec) = self.resolve_path_raw(cx, &mft_runs, parent_path)?;
        if !parent_rec.is_directory() {
            return Err(FfsError::NotDirectory);
        }
        let parent_raw =
            read_mft_record_raw_via_runs(&self.device, cx, &self.geometry, &mft_runs, parent_no)?;
        let parent_ref = NtfsReference {
            record: u64::from(parent_no),
            sequence: parent_rec.sequence,
        };

        let mut mft_bm_bytes = self.read_mft_bitmap_bytes(cx, &mft0, logical_records)?;
        let new_slot_u64 = find_contiguous_zero_bits(&mft_bm_bytes, logical_records, 1, 24)
            .ok_or(FfsError::NoSpace)?;
        let new_slot = u32::try_from(new_slot_u64).map_err(|_| corrupt(0, "MFT slot overflow"))?;

        // Load volume $Bitmap (record 6) for cluster reservations.
        let bm_rec = read_mft_record_via_runs(&self.device, cx, &self.geometry, &mft_runs, 6)?;
        let (bm_runs, bm_size, _) =
            extract_plain_nonresident_stream(&self.geometry, &bm_rec, DATA, &[])?;
        let mut vol_bm = read_mapped_runs(
            &self.device,
            cx,
            &self.geometry,
            &bm_runs,
            0,
            bm_size as usize,
        )?;
        let vol_clusters = self.geometry.cluster_count();

        let mut staged_open = self.open_attrs.clone();
        let mut open_regs = Vec::new();
        let mft_attr_slot = self.plan_open_attr(
            &mut staged_open,
            &mut open_regs,
            NtfsReference {
                record: 0,
                sequence: mft0.sequence,
            },
            DATA,
            &[],
            0,
        )?;
        let bm_attr_slot = self.plan_open_attr(
            &mut staged_open,
            &mut open_regs,
            NtfsReference {
                record: 6,
                sequence: bm_rec.sequence,
            },
            DATA,
            &[],
            0,
        )?;

        let mut pre_payload_writes = Vec::new();
        let mut mutation_specs = Vec::new();
        let mut allocated_data_runs = Vec::new();
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());

        let is_dir = file_payload.is_none();
        let security = extract_parent_security(&parent_rec);
        let std_info = encode_standard_information(is_dir, &security);

        let (alloc_size_for_fn, data_size_for_fn) = if let Some(payload) = file_payload {
            if payload.len() <= MAX_RESIDENT_DATA_PAYLOAD {
                let aligned = ((payload.len() + 7) & !7) as u64;
                (aligned, payload.len() as u64)
            } else {
                let n_clusters = (payload.len() as u64).div_ceil(cluster_bytes);
                allocated_data_runs =
                    self.reserve_data_payload(cx, &mut vol_bm, payload, &mut pre_payload_writes)?;
                let alloc_b = n_clusters * cluster_bytes;
                (alloc_b, payload.len() as u64)
            }
        } else {
            (0_u64, 0_u64)
        };

        // Determine sequence number for new_slot.
        let mut mft_zero_writes = Vec::new();
        let mut cur_mft0_raw = mft0_raw;
        let mut mft0_modified = if new_slot_u64 >= init_records {
            let new_init_records = (new_slot_u64 + 1).min(logical_records);
            for slot_to_zero in init_records..new_init_records {
                let (phys, avail, _) =
                    map_logical_offset(&self.geometry, &mft_runs, slot_to_zero * rec_bytes)?;
                if avail < rec_bytes {
                    return Err(unsupported("sub-record fragmented MFT cluster"));
                }
                mft_zero_writes.push(DirPrePayloadWrite {
                    phys_offset: phys,
                    bytes: vec![0_u8; rec_bytes as usize],
                });
            }
            let new_init_bytes = new_init_records * rec_bytes;
            let rest0 = restore_record(&cur_mft0_raw, b"FILE").map_err(|err| parse_err(&err))?;
            let (d_at, _) = find_attr_offset_in_restored(&rest0, DATA, &[])?
                .ok_or_else(|| corrupt(0, "$MFT missing DATA"))?;
            let alloc0 = u64::from_le_bytes(
                rest0[d_at + 40..d_at + 48]
                    .try_into()
                    .map_err(|_| corrupt(0, "alloc0"))?,
            );
            let mut redo_sz = Vec::with_capacity(24);
            redo_sz.extend_from_slice(&alloc0.to_le_bytes());
            redo_sz.extend_from_slice(&new_init_bytes.to_le_bytes());
            redo_sz.extend_from_slice(&mft_data_bytes.to_le_bytes());
            let mut undo_sz = Vec::with_capacity(24);
            undo_sz.extend_from_slice(&alloc0.to_le_bytes());
            undo_sz.extend_from_slice(&mft_init_bytes.to_le_bytes());
            undo_sz.extend_from_slice(&mft_data_bytes.to_le_bytes());

            let (m0_vcn, m0_cbo, m0_lcns) = self.map_mft_record_transfer(&mft_runs, 0)?;
            let FileEditResult::Applied(upd0) = apply_file_edit(
                &cur_mft0_raw,
                0,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::SetSizes,
                    record_offset: u16::try_from(d_at).map_err(|_| corrupt(0, "d_at"))?,
                    attribute_offset: 0,
                    data: &redo_sz,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            mutation_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::SetNewAttributeSizes,
                undo_op: NtfsLogOp::SetNewAttributeSizes,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(d_at).map_err(|_| corrupt(0, "d_at"))?,
                attribute_offset: 0,
                cluster_block_offset: m0_cbo,
                target_vcn: m0_vcn,
                target_lcns: m0_lcns,
                redo_data: redo_sz,
                undo_data: undo_sz,
            });
            cur_mft0_raw = upd0;
            true
        } else {
            false
        };

        let existing_slot_raw = if new_slot_u64 < init_records {
            read_mft_record_raw_via_runs(&self.device, cx, &self.geometry, &mft_runs, new_slot)?
        } else {
            vec![0_u8; rec_bytes as usize]
        };
        // DeallocateFileRecordSegment already increments `sequence` when clearing `in_use`,
        // so an inactive initialized FILE slot already carries its next valid sequence number.
        let next_seq = if let Ok(prev_rec) = NtfsFileRecord::parse(&existing_slot_raw) {
            if prev_rec.in_use() {
                prev_rec.sequence.wrapping_add(1).max(1)
            } else {
                prev_rec.sequence.max(1)
            }
        } else {
            1_u16
        };
        let child_ref = NtfsReference {
            record: u64::from(new_slot),
            sequence: next_seq,
        };

        let fn_attr_flags = if is_dir {
            FILE_ATTR_DIRECTORY
        } else {
            FILE_ATTR_ARCHIVE
        };
        let fn_struct = NtfsFileName {
            parent: parent_ref,
            namespace: 1, // FILE_NAME_WIN32_AND_DOS (POSIX/Win32 single-entry compatible)
            name: leaf_utf16,
        };
        let fn_value = fn_struct
            .encode(
                DEFAULT_NTFS_FILETIME,
                DEFAULT_NTFS_FILETIME,
                DEFAULT_NTFS_FILETIME,
                DEFAULT_NTFS_FILETIME,
                alloc_size_for_fn,
                data_size_for_fn,
                fn_attr_flags,
                0,
            )
            .map_err(|err| parse_err(&err))?;

        // Build child attributes in ascending kind order.
        let mut child_attrs: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut attr_id = 0_u16;
        child_attrs.push((
            ATTR_STANDARD_INFORMATION,
            encode_resident_attribute(ATTR_STANDARD_INFORMATION, attr_id, &[], false, &std_info)?,
        ));
        attr_id += 1;
        child_attrs.push((
            ATTR_FILE_NAME,
            encode_resident_attribute(ATTR_FILE_NAME, attr_id, &[], true, &fn_value)?,
        ));
        attr_id += 1;
        if let InheritedSecurity::Descriptor(ref sd_bytes) = security {
            child_attrs.push((
                ATTR_SECURITY_DESCRIPTOR,
                encode_resident_attribute(ATTR_SECURITY_DESCRIPTOR, attr_id, &[], false, sd_bytes)?,
            ));
            attr_id += 1;
        }
        if let Some(payload) = file_payload {
            if !allocated_data_runs.is_empty() {
                child_attrs.push((
                    DATA,
                    encode_nonresident_attribute(
                        DATA,
                        attr_id,
                        &[],
                        &allocated_data_runs,
                        alloc_size_for_fn,
                        payload.len() as u64,
                        payload.len() as u64,
                    )?,
                ));
            } else {
                child_attrs.push((
                    DATA,
                    encode_resident_attribute(DATA, attr_id, &[], false, payload)?,
                ));
            }
            attr_id += 1;
        } else {
            let empty_root = build_empty_small_index_root(
                self.geometry.index_bytes(),
                self.geometry.cluster_bytes(),
            )?;
            child_attrs.push((
                0x90,
                encode_resident_attribute(0x90, attr_id, &I30_NAME, false, &empty_root)?,
            ));
            attr_id += 1;
        }

        let restored_child = build_restored_file_template(
            self.geometry.record_bytes(),
            new_slot,
            next_seq,
            is_dir,
            &child_attrs,
            attr_id,
        )?;
        let FileEditResult::Applied(protected_child) = initialize_file_record_slot(
            &existing_slot_raw,
            new_slot,
            RecoveryPass::Undo,
            &restored_child,
        )
        .map_err(|err| parse_err(&err))?
        else {
            return Err(corrupt(0, "AlreadyApplied on InitializeFileRecordSegment"));
        };

        let (child_vcn, child_cbo, child_lcns) =
            self.map_mft_record_transfer(&mft_runs, new_slot)?;
        mutation_specs.push(NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::InitializeFileRecordSegment,
            undo_op: NtfsLogOp::DeallocateFileRecordSegment,
            target_attribute: mft_attr_slot,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: child_cbo,
            target_vcn: child_vcn,
            target_lcns: child_lcns,
            redo_data: restored_child,
            undo_data: Vec::new(),
        });

        // Mark new_slot allocated in $MFT::$BITMAP!
        set_or_clear_bits(&mut mft_bm_bytes, new_slot_u64, 1, true);
        let mut target_writes = Vec::new();
        self.append_mft_bitmap_mutation(
            &mut staged_open,
            &mut open_regs,
            &mut mutation_specs,
            &mut target_writes,
            &mut cur_mft0_raw,
            &mut mft0_modified,
            mft_attr_slot,
            &mft_runs,
            new_slot_u64,
            true,
            &mft_bm_bytes,
        )?;

        // Plan parent directory $I30 insertion!
        let indx_slot_opt = if let Some(block_bytes) = directory_has_external_indx(&parent_rec)? {
            Some(self.plan_open_attr(
                &mut staged_open,
                &mut open_regs,
                parent_ref,
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
                block_bytes,
            )?)
        } else {
            None
        };
        let (p_vcn, p_cbo, p_lcns) = self.map_mft_record_transfer(&mft_runs, parent_no)?;
        let mut dir_alloc_run: Option<(u64, u64)> = None;
        let dir_plan = self.plan_directory_insert(
            cx,
            parent_no,
            &parent_raw,
            &parent_rec,
            mft_attr_slot,
            p_vcn,
            p_cbo,
            &p_lcns,
            indx_slot_opt,
            child_ref,
            &fn_value,
            &mut |need_clusters| {
                let lcn = find_contiguous_zero_bits(&vol_bm, vol_clusters, need_clusters, 1)
                    .ok_or(FfsError::NoSpace)?;
                set_or_clear_bits(&mut vol_bm, lcn, need_clusters, true);
                dir_alloc_run = Some((lcn, need_clusters));
                Ok(lcn)
            },
        )?;
        pre_payload_writes.extend(dir_plan.pre_payload_writes);
        mutation_specs.extend(dir_plan.log_specs);

        // Emit $Bitmap log specs + TargetWriteKind::BitmapStream for any allocated clusters!
        for run in &allocated_data_runs {
            mutation_specs.extend(
                self.build_bitmap_range_specs(
                    bm_attr_slot,
                    &bm_runs,
                    run.lcn
                        .ok_or_else(|| corrupt(0, "sparse DATA reservation"))?,
                    run.clusters,
                    true,
                )?,
            );
        }
        if let Some((lcn, count)) = dir_plan.allocated_clusters.or(dir_alloc_run) {
            mutation_specs.extend(self.build_bitmap_range_specs(
                bm_attr_slot,
                &bm_runs,
                lcn,
                count,
                true,
            )?);
        }
        if !allocated_data_runs.is_empty() || dir_plan.allocated_clusters.is_some() {
            target_writes.push(TargetWriteKind::BitmapStream {
                runs: bm_runs,
                byte_offset: 0,
                bytes: vol_bm,
            });
        }

        if mft0_modified {
            target_writes.push(TargetWriteKind::MftRecord {
                runs: mft_runs.clone(),
                record_no: 0,
                raw_protected: cur_mft0_raw,
            });
        }
        target_writes.push(TargetWriteKind::MftRecord {
            runs: mft_runs.clone(),
            record_no: new_slot,
            raw_protected: protected_child,
        });
        if !dir_plan.updated_indx_blocks.is_empty() {
            let upd_parent =
                NtfsFileRecord::parse(&dir_plan.updated_dir_raw).map_err(|err| parse_err(&err))?;
            let (a0_runs, _, _) = extract_plain_nonresident_stream(
                &self.geometry,
                &upd_parent,
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
            )?;
            for (boff, raw_blk) in dir_plan.updated_indx_blocks {
                target_writes.push(TargetWriteKind::IndxBlock {
                    runs: a0_runs.clone(),
                    byte_offset: boff,
                    raw_protected: raw_blk,
                });
            }
        }
        if dir_plan.updated_dir_raw != parent_raw {
            target_writes.push(TargetWriteKind::MftRecord {
                runs: mft_runs,
                record_no: parent_no,
                raw_protected: dir_plan.updated_dir_raw,
            });
        }

        Ok(PreparedTxPlan {
            operation,
            operation_digest,
            result_value: child_ref,
            pre_payload_writes,
            mft_zero_writes,
            open_attr_registrations: open_regs,
            mutation_specs,
            target_writes,
        })
    }

    /// Write at a byte offset without truncating the existing suffix. Gaps beyond
    /// EOF are initialized to zero before the new stream becomes reachable.
    ///
    /// A nonempty write's resulting stream must fit [`super::MAX_FILE_EDIT_BYTES`].
    /// The current implementation stages a bounded complete replacement, then
    /// uses the same native WAL and disjoint-cluster publication as
    /// [`Self::write_file_data`]. An empty write validates the native target and
    /// commits without staging data, preserving even a larger stream at any offset.
    pub fn write_file_range(
        &mut self,
        cx: &Cx,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> NtfsTxOutcome<NtfsReference> {
        self.edit_file_data(cx, path, FileDataEdit::Write { offset, data })
    }

    /// Set a regular file's unnamed stream length through a native logged
    /// transaction. Growth initializes every newly exposed byte to zero; shrink
    /// retires old allocation only with the recoverable metadata transaction.
    ///
    /// The requested size must fit [`super::MAX_FILE_EDIT_BYTES`]. A larger
    /// existing stream can be shrunk without reading its discarded suffix.
    pub fn truncate_file(
        &mut self,
        cx: &Cx,
        path: &str,
        size: u64,
    ) -> NtfsTxOutcome<NtfsReference> {
        self.edit_file_data(cx, path, FileDataEdit::Truncate { size })
    }

    fn edit_file_data(
        &mut self,
        cx: &Cx,
        path: &str,
        edit: FileDataEdit<'_>,
    ) -> NtfsTxOutcome<NtfsReference> {
        match self.plan_file_data_edit(cx, path, edit) {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    fn plan_file_data_edit(
        &self,
        cx: &Cx,
        path: &str,
        edit: FileDataEdit<'_>,
    ) -> Result<PreparedTxPlan<NtfsReference>> {
        checkpoint(cx)?;
        let too_large = || FfsError::RequestRejected {
            errno: libc::EFBIG,
            detail: "NTFS positioned write/truncate exceeds the 16 MiB staging limit".into(),
        };
        let requested_end = match edit {
            FileDataEdit::Write { offset, data } if !data.is_empty() => offset
                .checked_add(u64::try_from(data.len()).map_err(|_| too_large())?)
                .ok_or_else(too_large)?,
            FileDataEdit::Write { .. } => 0,
            FileDataEdit::Truncate { size } => size,
        };
        if requested_end > super::MAX_FILE_EDIT_BYTES {
            return Err(too_large());
        }

        let mft0 = self.read_mft_record_zero(cx)?;
        let mft_runs = extract_plain_nonresident_runs(&self.geometry, &mft0, DATA, &[])?;
        let (file_no, file_rec) = self.resolve_path_raw(cx, &mft_runs, path)?;
        if file_rec.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        if file_no < 24 {
            return Err(FfsError::PermissionDenied);
        }
        let (parent_path, leaf_utf16) = split_parent_and_leaf(path)?;
        let (parent_no, parent_rec) = self.resolve_path_raw(cx, &mft_runs, &parent_path)?;
        self.admit_plain_data_target(
            &file_rec,
            NtfsReference {
                record: u64::from(parent_no),
                sequence: parent_rec.sequence,
            },
            &leaf_utf16,
        )?;
        let volume = self.volume_view(cx)?;
        let stream = volume.data_stream(cx, &file_rec, &[])?;

        let mut hasher = blake3::Hasher::new();
        let (operation, unchanged) = match edit {
            FileDataEdit::Write { offset, data } => {
                hasher.update(b"ntfs.write_file_range:");
                hasher.update(&offset.to_le_bytes());
                hasher.update(&(data.len() as u64).to_le_bytes());
                hasher.update(blake3::hash(data).as_bytes());
                ("write_file_range", data.is_empty())
            }
            FileDataEdit::Truncate { size } => {
                hasher.update(b"ntfs.truncate_file:");
                hasher.update(&size.to_le_bytes());
                ("truncate_file", size == stream.size)
            }
        };
        hasher.update(path.as_bytes());
        let digest = *hasher.finalize().as_bytes();
        if unchanged {
            // Commit the ordinary WAL barrier/token transaction without reading
            // or relocating an unchanged stream, even when no free clusters remain.
            return Ok(PreparedTxPlan {
                operation,
                operation_digest: digest,
                result_value: NtfsReference {
                    record: u64::from(file_no),
                    sequence: file_rec.sequence,
                },
                pre_payload_writes: Vec::new(),
                mft_zero_writes: Vec::new(),
                open_attr_registrations: Vec::new(),
                mutation_specs: Vec::new(),
                target_writes: Vec::new(),
            });
        }
        let new_size = match edit {
            FileDataEdit::Write { .. } => stream.size.max(requested_end),
            FileDataEdit::Truncate { size } => size,
        };
        if new_size > super::MAX_FILE_EDIT_BYTES {
            return Err(too_large());
        }
        let new_len = usize::try_from(new_size).map_err(|_| too_large())?;
        let retained = usize::try_from(stream.size.min(new_size)).map_err(|_| too_large())?;
        // The reader also enforces initialized length: old allocation beyond
        // ValidDataLength must remain zeros in the replacement, never stale data.
        let mut replacement = volume.read(cx, &stream, 0, retained)?;
        if replacement.len() != retained {
            return Err(corrupt(0, "short NTFS stream read while staging an edit"));
        }
        replacement
            .try_reserve_exact(new_len - replacement.len())
            .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
        replacement.resize(new_len, 0);

        if let FileDataEdit::Write { offset, data } = edit {
            let start = usize::try_from(offset).map_err(|_| too_large())?;
            replacement[start..start + data.len()].copy_from_slice(data);
        }
        checkpoint(cx)?;
        let mut plan = self.plan_write_file_data(cx, digest, path, &replacement)?;
        plan.operation = operation;
        Ok(plan)
    }

    /// Overwrite a regular file's unnamed `DATA` stream (resident, resident->nonresident,
    /// or nonresident copy-on-write cluster replacement with pre-commit payload flush).
    pub fn write_file_data(
        &mut self,
        cx: &Cx,
        path: &str,
        new_data: &[u8],
    ) -> NtfsTxOutcome<NtfsReference> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.write_file_data:");
        hasher.update(path.as_bytes());
        hasher.update(&(new_data.len() as u64).to_le_bytes());
        hasher.update(blake3::hash(new_data).as_bytes());
        let digest = *hasher.finalize().as_bytes();

        match self.plan_write_file_data(cx, digest, path, new_data) {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// The current replacement transaction owns one base-record unnamed stream
    /// and one FILE_NAME/$I30 pair. Preserve ordinary security, EA and same-record
    /// plain ADS values, but do not turn an unsupported native provider or an
    /// incomplete extent/link catalog into an apparently successful overwrite.
    fn admit_plain_data_write(&self, record: &NtfsFileRecord) -> Result<NtfsFileName> {
        if record.base.record != 0 || record.base.sequence != 0 || record.flags != 1 {
            return Err(unsupported(
                "NTFS data writes require an ordinary in-use base FILE record",
            ));
        }
        if record.hard_links != 1 {
            return Err(unsupported(
                "NTFS data writes require maintenance of every hard-link FILE_NAME",
            ));
        }
        let mut file_name = None;
        let mut standard_information = false;
        let mut stream_names = BTreeSet::new();
        for attribute in record.attributes().map_err(|err| parse_err(&err))? {
            if attribute.flags != 0 {
                return Err(unsupported(
                    "NTFS data writes do not yet maintain transformed attributes",
                ));
            }
            match attribute.kind {
                ATTR_STANDARD_INFORMATION => {
                    let NtfsValue::Resident(value) = attribute.value else {
                        return Err(corrupt(0, "nonresident NTFS STANDARD_INFORMATION"));
                    };
                    if standard_information
                        || !attribute.name.is_empty()
                        || !matches!(value.len(), 48 | 72)
                    {
                        return Err(corrupt(0, "ambiguous NTFS STANDARD_INFORMATION"));
                    }
                    let flags = u32::from_le_bytes(
                        value[32..36]
                            .try_into()
                            .map_err(|_| corrupt(0, "file flags"))?,
                    );
                    // Native sparse/compressed/reparse/encrypted FILE attributes
                    // carry obligations even if a DATA header omits its flag.
                    if flags & 0x4E00 != 0 {
                        return Err(unsupported(
                            "NTFS data writes require a plain file without native transforms or reparse semantics",
                        ));
                    }
                    standard_information = true;
                }
                ATTR_FILE_NAME => {
                    if file_name.is_some() || !attribute.name.is_empty() {
                        return Err(unsupported(
                            "NTFS data writes require maintenance of every native name or alias",
                        ));
                    }
                    let NtfsValue::Resident(value) = attribute.value else {
                        return Err(corrupt(0, "nonresident NTFS FILE_NAME"));
                    };
                    file_name = Some(NtfsFileName::parse(value).map_err(|err| parse_err(&err))?);
                }
                DATA => {
                    if !stream_names.insert(attribute.name) {
                        return Err(unsupported(
                            "NTFS data writes require a complete unambiguous stream extent catalog",
                        ));
                    }
                    if let NtfsValue::NonResident(extent) = attribute.value {
                        self.admit_plain_data_extent(&extent)?;
                    }
                }
                ATTR_SECURITY_DESCRIPTOR | EA_INFORMATION | EA => {}
                kind => {
                    return Err(unsupported(format!(
                        "NTFS data writes cannot yet maintain native attribute {kind:#x}"
                    )));
                }
            }
        }
        if !standard_information || !stream_names.contains(&Vec::<u16>::new()) {
            return Err(corrupt(
                0,
                "NTFS file lacks standard information or unnamed DATA",
            ));
        }
        file_name.ok_or_else(|| corrupt(0, "NTFS file lacks its native FILE_NAME"))
    }

    fn admit_plain_data_extent(&self, extent: &NtfsNonResident<'_>) -> Result<()> {
        if extent.first_vcn != 0 || extent.compression_unit != 0 {
            return Err(unsupported(
                "NTFS data writes require an untransformed complete base-record extent",
            ));
        }
        let runs = decode_mapping_pairs(
            extent.mapping_pairs,
            extent.first_vcn,
            extent.last_vcn,
            self.geometry.cluster_count(),
        )
        .map_err(|err| parse_err(&err))?;
        let coverage = runs
            .last()
            .map_or(0, |run| run.vcn + run.clusters)
            .checked_mul(u64::from(self.geometry.cluster_bytes()))
            .ok_or_else(|| corrupt(0, "NTFS data mapping size overflow"))?;
        if runs.iter().any(|run| run.lcn.is_none()) {
            return Err(unsupported(
                "NTFS data writes do not yet maintain sparse extents",
            ));
        }
        if extent.allocated_bytes != coverage
            || extent.data_bytes > coverage
            || extent.data_bytes > i64::MAX as u64
            || extent.initialized_bytes > extent.data_bytes
        {
            return Err(corrupt(
                0,
                "NTFS data mapping does not cover its declared allocation",
            ));
        }
        let mut physical: Vec<_> = runs
            .iter()
            .filter_map(|run| run.lcn.map(|lcn| (lcn, lcn + run.clusters)))
            .collect();
        physical.sort_unstable();
        if physical.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(corrupt(
                0,
                "NTFS data stream aliases its own physical clusters",
            ));
        }
        Ok(())
    }

    fn admit_plain_data_target(
        &self,
        record: &NtfsFileRecord,
        parent: NtfsReference,
        leaf: &[u16],
    ) -> Result<Vec<u16>> {
        let native_name = self.admit_plain_data_write(record)?;
        if native_name.namespace == 2 {
            return Err(unsupported(
                "NTFS DOS alias data writes require coupled long-name maintenance",
            ));
        }
        if native_name.parent != parent
            || (native_name.name.as_slice() != leaf
                && (native_name.namespace == 0
                    || self.fold_upcase(&native_name.name) != self.fold_upcase(leaf)))
        {
            return Err(corrupt(
                0,
                "NTFS write target FILE_NAME disagrees with its parent index",
            ));
        }
        Ok(native_name.name)
    }

    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn plan_write_file_data(
        &self,
        cx: &Cx,
        operation_digest: [u8; 32],
        path: &str,
        new_data: &[u8],
    ) -> Result<PreparedTxPlan<NtfsReference>> {
        checkpoint(cx)?;
        let (parent_path, leaf_utf16) = split_parent_and_leaf(path)?;
        let mft0 = self.read_mft_record_zero(cx)?;
        let mft_runs = extract_plain_nonresident_runs(&self.geometry, &mft0, DATA, &[])?;

        let (parent_no, parent_rec) = self.resolve_path_raw(cx, &mft_runs, &parent_path)?;
        let (file_no, file_rec) = self.resolve_path_raw(cx, &mft_runs, path)?;
        if file_rec.is_directory() {
            return Err(FfsError::IsDirectory);
        }
        if file_no < 24 {
            return Err(FfsError::PermissionDenied);
        }
        let leaf_utf16 = self.admit_plain_data_target(
            &file_rec,
            NtfsReference {
                record: u64::from(parent_no),
                sequence: parent_rec.sequence,
            },
            &leaf_utf16,
        )?;
        let file_ref = NtfsReference {
            record: u64::from(file_no),
            sequence: file_rec.sequence,
        };

        let parent_raw =
            read_mft_record_raw_via_runs(&self.device, cx, &self.geometry, &mft_runs, parent_no)?;
        let file_raw =
            read_mft_record_raw_via_runs(&self.device, cx, &self.geometry, &mft_runs, file_no)?;
        let file_rest = restore_record(&file_raw, b"FILE").map_err(|err| parse_err(&err))?;

        let (data_at, data_sz) = find_attr_offset_in_restored(&file_rest, DATA, &[])?
            .ok_or_else(|| corrupt(0, "file lacks unnamed DATA attribute"))?;
        let was_nonresident = file_rest[data_at + 8] == 1;

        let mut staged_open = self.open_attrs.clone();
        let mut open_regs = Vec::new();
        let mft_attr_slot = self.plan_open_attr(
            &mut staged_open,
            &mut open_regs,
            NtfsReference {
                record: 0,
                sequence: mft0.sequence,
            },
            DATA,
            &[],
            0,
        )?;
        let (f_vcn, f_cbo, f_lcns) = self.map_mft_record_transfer(&mft_runs, file_no)?;

        let mut pre_payload_writes = Vec::new();
        let mut mutation_specs = Vec::new();
        let mut target_writes = Vec::new();
        let mut cur_file_raw = file_raw;
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());

        let new_alloc_for_fn: u64;
        if !was_nonresident && new_data.len() <= MAX_RESIDENT_DATA_PAYLOAD {
            // Fast allocation-preserving resident DATA update (also compatible with NtfsVolume --recover-logfile)!
            let val_off = usize::from(u16::from_le_bytes([
                file_rest[data_at + 20],
                file_rest[data_at + 21],
            ]));
            let val_len = u32::from_le_bytes([
                file_rest[data_at + 16],
                file_rest[data_at + 17],
                file_rest[data_at + 18],
                file_rest[data_at + 19],
            ]) as usize;
            let old_val = file_rest[data_at + val_off..data_at + val_off + val_len].to_vec();
            let resize = old_val.len() != new_data.len();
            let FileEditResult::Applied(upd) = apply_file_edit(
                &cur_file_raw,
                file_no,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::UpdateResident { resize },
                    record_offset: u16::try_from(data_at).map_err(|_| corrupt(0, "data_at"))?,
                    attribute_offset: u16::try_from(val_off).map_err(|_| corrupt(0, "val_off"))?,
                    data: new_data,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            mutation_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::UpdateResidentValue,
                undo_op: NtfsLogOp::UpdateResidentValue,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(data_at).map_err(|_| corrupt(0, "data_at"))?,
                attribute_offset: u16::try_from(val_off).map_err(|_| corrupt(0, "val_off"))?,
                cluster_block_offset: f_cbo,
                target_vcn: f_vcn,
                target_lcns: f_lcns.clone(),
                redo_data: new_data.to_vec(),
                undo_data: old_val,
            });
            cur_file_raw = upd;
            new_alloc_for_fn = ((new_data.len() + 7) & !7) as u64;
        } else {
            // Nonresident COW cluster replacement (or resident -> nonresident promotion):
            // NEVER overwrite old clusters in-place before commit so Loser Undo keeps old data intact!
            let bm_rec = read_mft_record_via_runs(&self.device, cx, &self.geometry, &mft_runs, 6)?;
            let (bm_runs, bm_size, _) =
                extract_plain_nonresident_stream(&self.geometry, &bm_rec, DATA, &[])?;
            let mut vol_bm = read_mapped_runs(
                &self.device,
                cx,
                &self.geometry,
                &bm_runs,
                0,
                bm_size as usize,
            )?;
            let bm_attr_slot = self.plan_open_attr(
                &mut staged_open,
                &mut open_regs,
                NtfsReference {
                    record: 6,
                    sequence: bm_rec.sequence,
                },
                DATA,
                &[],
                0,
            )?;

            let old_runs_to_free = if was_nonresident {
                let map_off = usize::from(u16::from_le_bytes([
                    file_rest[data_at + 32],
                    file_rest[data_at + 33],
                ]));
                let first_vcn = u64::from_le_bytes(
                    file_rest[data_at + 16..data_at + 24]
                        .try_into()
                        .map_err(|_| corrupt(0, "fvcn"))?,
                );
                let last_vcn = u64::from_le_bytes(
                    file_rest[data_at + 24..data_at + 32]
                        .try_into()
                        .map_err(|_| corrupt(0, "lvcn"))?,
                );
                decode_mapping_pairs(
                    &file_rest[data_at + map_off..data_at + data_sz],
                    first_vcn,
                    last_vcn,
                    self.geometry.cluster_count(),
                )
                .map_err(|err| parse_err(&err))?
            } else {
                Vec::new()
            };

            let new_clusters = (new_data.len() as u64).div_ceil(cluster_bytes);
            // Reserve currently-free runs before freeing the old mapping so
            // COW payload writes remain strictly disjoint from the old file.
            let new_runs =
                self.reserve_data_payload(cx, &mut vol_bm, new_data, &mut pre_payload_writes)?;
            for run in &new_runs {
                mutation_specs.extend(
                    self.build_bitmap_range_specs(
                        bm_attr_slot,
                        &bm_runs,
                        run.lcn
                            .ok_or_else(|| corrupt(0, "sparse DATA reservation"))?,
                        run.clusters,
                        true,
                    )?,
                );
            }

            for old_r in &old_runs_to_free {
                if let Some(old_lcn) = old_r.lcn
                    && old_r.clusters > 0
                {
                    set_or_clear_bits(&mut vol_bm, old_lcn, old_r.clusters, false);
                    mutation_specs.extend(self.build_bitmap_range_specs(
                        bm_attr_slot,
                        &bm_runs,
                        old_lcn,
                        old_r.clusters,
                        false,
                    )?);
                }
            }

            new_alloc_for_fn = new_clusters * cluster_bytes;
            let data_id = u16::from_le_bytes([file_rest[data_at + 14], file_rest[data_at + 15]]);
            let old_attr_bytes = file_rest[data_at..data_at + data_sz].to_vec();
            let new_attr_bytes = if new_clusters == 0 {
                encode_resident_attribute(DATA, data_id, &[], false, &[])?
            } else {
                encode_nonresident_attribute(
                    DATA,
                    data_id,
                    &[],
                    &new_runs,
                    new_alloc_for_fn,
                    new_data.len() as u64,
                    new_data.len() as u64,
                )?
            };

            let FileEditResult::Applied(del_f) = apply_file_edit(
                &cur_file_raw,
                file_no,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::DeleteAttribute,
                    record_offset: u16::try_from(data_at).map_err(|_| corrupt(0, "at"))?,
                    attribute_offset: 0,
                    data: &[],
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            mutation_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::DeleteAttribute,
                undo_op: NtfsLogOp::CreateAttribute,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(data_at).map_err(|_| corrupt(0, "at"))?,
                attribute_offset: 0,
                cluster_block_offset: f_cbo,
                target_vcn: f_vcn,
                target_lcns: f_lcns.clone(),
                redo_data: Vec::new(),
                undo_data: old_attr_bytes,
            });
            let FileEditResult::Applied(ins_f) = apply_file_edit(
                &del_f,
                file_no,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::CreateAttribute,
                    record_offset: u16::try_from(data_at).map_err(|_| corrupt(0, "at"))?,
                    attribute_offset: 0,
                    data: &new_attr_bytes,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            mutation_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::CreateAttribute,
                undo_op: NtfsLogOp::DeleteAttribute,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(data_at).map_err(|_| corrupt(0, "at"))?,
                attribute_offset: 0,
                cluster_block_offset: f_cbo,
                target_vcn: f_vcn,
                target_lcns: f_lcns.clone(),
                redo_data: new_attr_bytes,
                undo_data: Vec::new(),
            });
            cur_file_raw = ins_f;
            target_writes.push(TargetWriteKind::BitmapStream {
                runs: bm_runs,
                byte_offset: 0,
                bytes: vol_bm,
            });
        }

        // Update 0x30 FILE_NAME duplicated sizes on the file's FILE record + parent $I30!
        let cur_rest = restore_record(&cur_file_raw, b"FILE").map_err(|err| parse_err(&err))?;
        if let Some((fn_at, _)) = find_attr_offset_in_restored(&cur_rest, ATTR_FILE_NAME, &[])? {
            let fn_voff = usize::from(u16::from_le_bytes([
                cur_rest[fn_at + 20],
                cur_rest[fn_at + 21],
            ]));
            let old_dup = cur_rest[fn_at + fn_voff + 8..fn_at + fn_voff + 64].to_vec();
            let mut new_dup = old_dup.clone();
            new_dup[32..40].copy_from_slice(&new_alloc_for_fn.to_le_bytes());
            new_dup[40..48].copy_from_slice(&(new_data.len() as u64).to_le_bytes());

            let FileEditResult::Applied(upd_fn) = apply_file_edit(
                &cur_file_raw,
                file_no,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::UpdateResident { resize: false },
                    record_offset: u16::try_from(fn_at).map_err(|_| corrupt(0, "fn_at"))?,
                    attribute_offset: u16::try_from(fn_voff + 8).map_err(|_| corrupt(0, "off"))?,
                    data: &new_dup,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            mutation_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::UpdateResidentValue,
                undo_op: NtfsLogOp::UpdateResidentValue,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(fn_at).map_err(|_| corrupt(0, "fn_at"))?,
                attribute_offset: u16::try_from(fn_voff + 8).map_err(|_| corrupt(0, "off"))?,
                cluster_block_offset: f_cbo,
                target_vcn: f_vcn,
                target_lcns: f_lcns,
                redo_data: new_dup.clone(),
                undo_data: old_dup,
            });
            cur_file_raw = upd_fn;

            // Update parent directory $I30 dup info if parent_no >= 24 (keeping system root record 5
            // untouched on user file writes so NtfsVolume --recover-logfile also admits user writes!).
            let indx_slot_opt = if let Some(bb) = directory_has_external_indx(&parent_rec)? {
                Some(self.plan_open_attr(
                    &mut staged_open,
                    &mut open_regs,
                    NtfsReference {
                        record: u64::from(parent_no),
                        sequence: parent_rec.sequence,
                    },
                    ATTR_INDEX_ALLOCATION,
                    &I30_NAME,
                    bb,
                )?)
            } else {
                None
            };
            let (p_vcn, p_cbo, p_lcns) = self.map_mft_record_transfer(&mft_runs, parent_no)?;
            let dir_upd = self.plan_directory_update_dup(
                cx,
                parent_no,
                &parent_raw,
                &parent_rec,
                mft_attr_slot,
                p_vcn,
                p_cbo,
                &p_lcns,
                indx_slot_opt,
                &leaf_utf16,
                &new_dup,
            )?;
            mutation_specs.extend(dir_upd.log_specs);
            if dir_upd.updated_dir_raw != parent_raw {
                target_writes.push(TargetWriteKind::MftRecord {
                    runs: mft_runs.clone(),
                    record_no: parent_no,
                    raw_protected: dir_upd.updated_dir_raw,
                });
            }
            if !dir_upd.updated_indx_blocks.is_empty() {
                let (a0_runs, _, _) = extract_plain_nonresident_stream(
                    &self.geometry,
                    &parent_rec,
                    ATTR_INDEX_ALLOCATION,
                    &I30_NAME,
                )?;
                for (boff, raw_blk) in dir_upd.updated_indx_blocks {
                    target_writes.push(TargetWriteKind::IndxBlock {
                        runs: a0_runs.clone(),
                        byte_offset: boff,
                        raw_protected: raw_blk,
                    });
                }
            }
        }

        target_writes.push(TargetWriteKind::MftRecord {
            runs: mft_runs,
            record_no: file_no,
            raw_protected: cur_file_raw,
        });

        Ok(PreparedTxPlan {
            operation: "write_file_data",
            operation_digest,
            result_value: file_ref,
            pre_payload_writes,
            mft_zero_writes: Vec::new(),
            open_attr_registrations: open_regs,
            mutation_specs,
            target_writes,
        })
    }

    /// Atomically rename a file or directory across same or different directories,
    /// supporting post-commit pre-reply retry idempotency via `expected_source_ref`.
    pub fn rename_entry(
        &mut self,
        cx: &Cx,
        src_path: &str,
        dst_path: &str,
        expected_source_ref: Option<NtfsReference>,
    ) -> NtfsTxOutcome<NtfsReference> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.rename_entry:");
        hasher.update(src_path.as_bytes());
        hasher.update(b"->");
        hasher.update(dst_path.as_bytes());
        let digest = *hasher.finalize().as_bytes();

        // Check post-commit pre-reply idempotent retry BEFORE mutating!
        if let Some(expected_ref) = expected_source_ref
            && let Ok(mft0) = self.read_mft_record_zero(cx)
            && let Ok(mft_runs) = extract_plain_nonresident_runs(&self.geometry, &mft0, DATA, &[])
            && matches!(
                self.resolve_path_raw(cx, &mft_runs, src_path),
                Err(FfsError::NotFound(_))
            )
            && let Ok((dst_no, dst_rec)) = self.resolve_path_raw(cx, &mft_runs, dst_path)
            && u64::from(dst_no) == expected_ref.record
            && dst_rec.sequence == expected_ref.sequence
        {
            if let Err(err) = self.check_clean_consistency(cx) {
                return NtfsTxOutcome::NotCommitted(err);
            }
            let cur_lsn = self.ring.as_ref().map_or(1, |r| r.current_lsn().max(1));
            let ckpt_lsn = self
                .ring
                .as_ref()
                .map(NtfsLogRingWriter::client_restart_lsn);
            let token = self.make_token(0, cur_lsn, ckpt_lsn, digest);
            return NtfsTxOutcome::Committed {
                value: expected_ref,
                token,
            };
        }

        match self.plan_rename_entry(cx, digest, src_path, dst_path, expected_source_ref) {
            Ok(plan) => {
                let target_ref = plan.result_value;
                let out = self.execute_logged_tx(cx, plan);
                if out.is_committed() {
                    self.committed_renames
                        .insert((src_path.to_owned(), dst_path.to_owned()), target_ref);
                }
                out
            }
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn plan_rename_entry(
        &self,
        cx: &Cx,
        operation_digest: [u8; 32],
        src_path: &str,
        dst_path: &str,
        expected_source_ref: Option<NtfsReference>,
    ) -> Result<PreparedTxPlan<NtfsReference>> {
        checkpoint(cx)?;
        let (src_parent_path, src_leaf) = split_parent_and_leaf(src_path)?;
        let (dst_parent_path, dst_leaf) = split_parent_and_leaf(dst_path)?;

        let mft0 = self.read_mft_record_zero(cx)?;
        let mft_runs = extract_plain_nonresident_runs(&self.geometry, &mft0, DATA, &[])?;

        let (src_no, src_rec) = self.resolve_path_raw(cx, &mft_runs, src_path)?;
        if src_no < 24 {
            return Err(FfsError::PermissionDenied);
        }
        let src_ref = NtfsReference {
            record: u64::from(src_no),
            sequence: src_rec.sequence,
        };
        if let Some(exp) = expected_source_ref
            && exp != src_ref
        {
            return Err(corrupt(0, "rename_entry expected_source_ref mismatch"));
        }

        let (src_dir_no, src_dir_rec) = self.resolve_path_raw(cx, &mft_runs, &src_parent_path)?;
        let (dst_dir_no, dst_dir_rec) = self.resolve_path_raw_avoiding(
            cx,
            &mft_runs,
            &dst_parent_path,
            src_rec.is_directory().then_some(src_ref),
        )?;
        if !src_dir_rec.is_directory() || !dst_dir_rec.is_directory() {
            return Err(FfsError::NotDirectory);
        }

        // The native name, its parent sequence and the selected source must
        // identify the same link. Until coupled DOS aliases and extension
        // records are maintained, do not rename an arbitrary first FILE_NAME.
        let source_attributes = src_rec.attributes().map_err(|err| parse_err(&err))?;
        if source_attributes.iter().any(|attr| attr.kind == 0x20) {
            return Err(unsupported(
                "NTFS rename with ATTRIBUTE_LIST requires complete name-catalog mutation",
            ));
        }
        let mut source_names = source_attributes
            .iter()
            .filter(|attr| attr.kind == ATTR_FILE_NAME);
        let source_name_attr = source_names
            .next()
            .ok_or_else(|| corrupt(0, "rename source lacks FILE_NAME"))?;
        if source_names.next().is_some() || src_rec.hard_links != 1 {
            return Err(unsupported(
                "multi-link or aliased NTFS rename requires selective FILE_NAME maintenance",
            ));
        }
        let NtfsValue::Resident(source_name_value) = &source_name_attr.value else {
            return Err(corrupt(0, "rename source FILE_NAME must be resident"));
        };
        let source_name = NtfsFileName::parse(source_name_value).map_err(|err| parse_err(&err))?;
        if source_name.namespace == 2 {
            return Err(unsupported(
                "NTFS DOS alias rename requires coupled long-name maintenance",
            ));
        }
        let source_parent_ref = NtfsReference {
            record: u64::from(src_dir_no),
            sequence: src_dir_rec.sequence,
        };
        if source_name.parent != source_parent_ref
            || (source_name.name != src_leaf
                && (source_name.namespace == 0
                    || self.fold_upcase(&source_name.name) != self.fold_upcase(&src_leaf)))
        {
            return Err(corrupt(0, "rename source FILE_NAME identity mismatch"));
        }

        if let Some(destination_ref) =
            self.lookup_in_directory_raw(cx, &mft_runs, &dst_dir_rec, &self.fold_upcase(&dst_leaf))?
            && (src_dir_no != dst_dir_no || destination_ref != src_ref)
        {
            return Err(FfsError::Exists);
        }

        let mut staged_open = self.open_attrs.clone();
        let mut open_regs = Vec::new();
        let mft_attr_slot = self.plan_open_attr(
            &mut staged_open,
            &mut open_regs,
            NtfsReference {
                record: 0,
                sequence: mft0.sequence,
            },
            DATA,
            &[],
            0,
        )?;

        let bm_rec = read_mft_record_via_runs(&self.device, cx, &self.geometry, &mft_runs, 6)?;
        let (bm_runs, bm_size, _) =
            extract_plain_nonresident_stream(&self.geometry, &bm_rec, DATA, &[])?;
        let mut vol_bm = read_mapped_runs(
            &self.device,
            cx,
            &self.geometry,
            &bm_runs,
            0,
            bm_size as usize,
        )?;
        let mut bm_dirty = false;

        // 1. Update 0x30 FILE_NAME on src_no (DeleteAttribute + CreateAttribute)!
        let src_raw =
            read_mft_record_raw_via_runs(&self.device, cx, &self.geometry, &mft_runs, src_no)?;
        let src_rest = restore_record(&src_raw, b"FILE").map_err(|err| parse_err(&err))?;
        let (fn_at, fn_sz) = find_attr_offset_in_restored(&src_rest, ATTR_FILE_NAME, &[])?
            .ok_or_else(|| corrupt(0, "source lacks FILE_NAME"))?;
        let fn_id = u16::from_le_bytes([src_rest[fn_at + 14], src_rest[fn_at + 15]]);
        let fn_voff = usize::from(u16::from_le_bytes([
            src_rest[fn_at + 20],
            src_rest[fn_at + 21],
        ]));
        let fn_vlen = u32::from_le_bytes([
            src_rest[fn_at + 16],
            src_rest[fn_at + 17],
            src_rest[fn_at + 18],
            src_rest[fn_at + 19],
        ]) as usize;
        let old_fn_val = &src_rest[fn_at + fn_voff..fn_at + fn_voff + fn_vlen];
        let old_fn_parsed = NtfsFileName::parse(old_fn_val).map_err(|err| parse_err(&err))?;
        let dst_parent_ref = NtfsReference {
            record: u64::from(dst_dir_no),
            sequence: dst_dir_rec.sequence,
        };
        let new_fn_struct = NtfsFileName {
            parent: dst_parent_ref,
            namespace: old_fn_parsed.namespace,
            name: dst_leaf,
        };
        let mut new_fn_val = new_fn_struct
            .encode(0, 0, 0, 0, 0, 0, 0, 0)
            .map_err(|err| parse_err(&err))?;
        // Preserve exact 56-byte duplicated timestamps/sizes/flags from old_fn_val[8..64]!
        new_fn_val[8..64].copy_from_slice(&old_fn_val[8..64]);
        let old_fn_attr = src_rest[fn_at..fn_at + fn_sz].to_vec();
        let new_fn_attr = encode_resident_attribute(ATTR_FILE_NAME, fn_id, &[], true, &new_fn_val)?;

        let (s_vcn, s_cbo, s_lcns) = self.map_mft_record_transfer(&mft_runs, src_no)?;
        let FileEditResult::Applied(s_del) = apply_file_edit(
            &src_raw,
            src_no,
            RecoveryPass::Undo,
            &FileEdit {
                operation: FileOperation::DeleteAttribute,
                record_offset: u16::try_from(fn_at).map_err(|_| corrupt(0, "fn_at"))?,
                attribute_offset: 0,
                data: &[],
            },
        )
        .map_err(|err| parse_err(&err))?
        else {
            return Err(corrupt(0, "AlreadyApplied"));
        };
        let FileEditResult::Applied(s_ins) = apply_file_edit(
            &s_del,
            src_no,
            RecoveryPass::Undo,
            &FileEdit {
                operation: FileOperation::CreateAttribute,
                record_offset: u16::try_from(fn_at).map_err(|_| corrupt(0, "fn_at"))?,
                attribute_offset: 0,
                data: &new_fn_attr,
            },
        )
        .map_err(|err| parse_err(&err))?
        else {
            return Err(corrupt(0, "AlreadyApplied"));
        };

        let mut mutation_specs = vec![
            NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::DeleteAttribute,
                undo_op: NtfsLogOp::CreateAttribute,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(fn_at).map_err(|_| corrupt(0, "fn_at"))?,
                attribute_offset: 0,
                cluster_block_offset: s_cbo,
                target_vcn: s_vcn,
                target_lcns: s_lcns.clone(),
                redo_data: Vec::new(),
                undo_data: old_fn_attr,
            },
            NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::CreateAttribute,
                undo_op: NtfsLogOp::DeleteAttribute,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(fn_at).map_err(|_| corrupt(0, "fn_at"))?,
                attribute_offset: 0,
                cluster_block_offset: s_cbo,
                target_vcn: s_vcn,
                target_lcns: s_lcns,
                redo_data: new_fn_attr,
                undo_data: Vec::new(),
            },
        ];

        // 2. Delete from src_dir $I30, then insert into dst_dir $I30!
        let src_dir_raw =
            read_mft_record_raw_via_runs(&self.device, cx, &self.geometry, &mft_runs, src_dir_no)?;
        let src_indx_slot = if let Some(bb) = directory_has_external_indx(&src_dir_rec)? {
            Some(self.plan_open_attr(
                &mut staged_open,
                &mut open_regs,
                NtfsReference {
                    record: u64::from(src_dir_no),
                    sequence: src_dir_rec.sequence,
                },
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
                bb,
            )?)
        } else {
            None
        };
        let (sd_vcn, sd_cbo, sd_lcns) = self.map_mft_record_transfer(&mft_runs, src_dir_no)?;
        let del_plan = self.plan_directory_delete(
            cx,
            src_dir_no,
            &src_dir_raw,
            &src_dir_rec,
            mft_attr_slot,
            sd_vcn,
            sd_cbo,
            &sd_lcns,
            src_indx_slot,
            &source_name.name,
        )?;
        mutation_specs.extend(del_plan.log_specs);

        let mut pre_payload_writes = del_plan.pre_payload_writes;
        let mut target_writes = vec![TargetWriteKind::MftRecord {
            runs: mft_runs.clone(),
            record_no: src_no,
            raw_protected: s_ins,
        }];

        if src_dir_no == dst_dir_no {
            // Same-directory rename! If external INDX was modified by del_plan, we must apply
            // insert against a temporary PreviewDevice or resident-updated record!
            if del_plan.updated_indx_blocks.is_empty() {
                let upd_dir_rec = NtfsFileRecord::parse(&del_plan.updated_dir_raw)
                    .map_err(|err| parse_err(&err))?;
                let ins_plan = self.plan_directory_insert(
                    cx,
                    src_dir_no,
                    &del_plan.updated_dir_raw,
                    &upd_dir_rec,
                    mft_attr_slot,
                    sd_vcn,
                    sd_cbo,
                    &sd_lcns,
                    src_indx_slot,
                    src_ref,
                    &new_fn_val,
                    &mut |need| {
                        let lcn = find_contiguous_zero_bits(
                            &vol_bm,
                            self.geometry.cluster_count(),
                            need,
                            1,
                        )
                        .ok_or(FfsError::NoSpace)?;
                        set_or_clear_bits(&mut vol_bm, lcn, need, true);
                        bm_dirty = true;
                        Ok(lcn)
                    },
                )?;
                pre_payload_writes.extend(ins_plan.pre_payload_writes);
                mutation_specs.extend(ins_plan.log_specs);
                if let Some((lcn, cnt)) = ins_plan.allocated_clusters {
                    let bm_slot = self.plan_open_attr(
                        &mut staged_open,
                        &mut open_regs,
                        NtfsReference {
                            record: 6,
                            sequence: bm_rec.sequence,
                        },
                        DATA,
                        &[],
                        0,
                    )?;
                    mutation_specs
                        .extend(self.build_bitmap_range_specs(bm_slot, &bm_runs, lcn, cnt, true)?);
                }
                target_writes.push(TargetWriteKind::MftRecord {
                    runs: mft_runs,
                    record_no: src_dir_no,
                    raw_protected: ins_plan.updated_dir_raw,
                });
            } else {
                // External INDX same-dir rename: delete + insert on external INDX with
                // del_plan's updated INDX blocks overlaid so same-leaf renames compose cleanly!
                let upd_dir_rec = NtfsFileRecord::parse(&del_plan.updated_dir_raw)
                    .map_err(|err| parse_err(&err))?;
                let ins_plan = self.plan_directory_insert_with_overrides(
                    cx,
                    dst_dir_no,
                    &del_plan.updated_dir_raw,
                    &upd_dir_rec,
                    mft_attr_slot,
                    sd_vcn,
                    sd_cbo,
                    &sd_lcns,
                    src_indx_slot,
                    src_ref,
                    &new_fn_val,
                    &del_plan.updated_indx_blocks,
                    &mut |need| {
                        let lcn = find_contiguous_zero_bits(
                            &vol_bm,
                            self.geometry.cluster_count(),
                            need,
                            1,
                        )
                        .ok_or(FfsError::NoSpace)?;
                        set_or_clear_bits(&mut vol_bm, lcn, need, true);
                        bm_dirty = true;
                        Ok(lcn)
                    },
                )?;
                pre_payload_writes.extend(ins_plan.pre_payload_writes);
                mutation_specs.extend(ins_plan.log_specs);
                if let Some((lcn, cnt)) = ins_plan.allocated_clusters {
                    let bm_slot = self.plan_open_attr(
                        &mut staged_open,
                        &mut open_regs,
                        NtfsReference {
                            record: 6,
                            sequence: bm_rec.sequence,
                        },
                        DATA,
                        &[],
                        0,
                    )?;
                    mutation_specs
                        .extend(self.build_bitmap_range_specs(bm_slot, &bm_runs, lcn, cnt, true)?);
                }
                let final_dir_rec = NtfsFileRecord::parse(&ins_plan.updated_dir_raw)
                    .map_err(|err| parse_err(&err))?;
                let (a0_runs, _, _) = extract_plain_nonresident_stream(
                    &self.geometry,
                    &final_dir_rec,
                    ATTR_INDEX_ALLOCATION,
                    &I30_NAME,
                )?;
                let mut merged_indx: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
                for (boff, raw_blk) in del_plan.updated_indx_blocks {
                    merged_indx.insert(boff, raw_blk);
                }
                for (boff, raw_blk) in ins_plan.updated_indx_blocks {
                    merged_indx.insert(boff, raw_blk);
                }
                for (boff, raw_blk) in merged_indx {
                    target_writes.push(TargetWriteKind::IndxBlock {
                        runs: a0_runs.clone(),
                        byte_offset: boff,
                        raw_protected: raw_blk,
                    });
                }
                if ins_plan.updated_dir_raw != src_dir_raw {
                    target_writes.push(TargetWriteKind::MftRecord {
                        runs: mft_runs,
                        record_no: src_dir_no,
                        raw_protected: ins_plan.updated_dir_raw,
                    });
                }
            }
        } else {
            // Cross-directory rename!
            if !del_plan.updated_indx_blocks.is_empty() {
                let upd_src_dir = NtfsFileRecord::parse(&del_plan.updated_dir_raw)
                    .map_err(|err| parse_err(&err))?;
                let (s_a0, _, _) = extract_plain_nonresident_stream(
                    &self.geometry,
                    &upd_src_dir,
                    ATTR_INDEX_ALLOCATION,
                    &I30_NAME,
                )?;
                for (boff, raw_blk) in del_plan.updated_indx_blocks {
                    target_writes.push(TargetWriteKind::IndxBlock {
                        runs: s_a0.clone(),
                        byte_offset: boff,
                        raw_protected: raw_blk,
                    });
                }
            }
            if del_plan.updated_dir_raw != src_dir_raw {
                target_writes.push(TargetWriteKind::MftRecord {
                    runs: mft_runs.clone(),
                    record_no: src_dir_no,
                    raw_protected: del_plan.updated_dir_raw,
                });
            }

            let dst_dir_raw = read_mft_record_raw_via_runs(
                &self.device,
                cx,
                &self.geometry,
                &mft_runs,
                dst_dir_no,
            )?;
            let dst_indx_slot = if let Some(bb) = directory_has_external_indx(&dst_dir_rec)? {
                Some(self.plan_open_attr(
                    &mut staged_open,
                    &mut open_regs,
                    dst_parent_ref,
                    ATTR_INDEX_ALLOCATION,
                    &I30_NAME,
                    bb,
                )?)
            } else {
                None
            };
            let (dd_vcn, dd_cbo, dd_lcns) = self.map_mft_record_transfer(&mft_runs, dst_dir_no)?;
            let ins_plan = self.plan_directory_insert(
                cx,
                dst_dir_no,
                &dst_dir_raw,
                &dst_dir_rec,
                mft_attr_slot,
                dd_vcn,
                dd_cbo,
                &dd_lcns,
                dst_indx_slot,
                src_ref,
                &new_fn_val,
                &mut |need| {
                    let lcn =
                        find_contiguous_zero_bits(&vol_bm, self.geometry.cluster_count(), need, 1)
                            .ok_or(FfsError::NoSpace)?;
                    set_or_clear_bits(&mut vol_bm, lcn, need, true);
                    bm_dirty = true;
                    Ok(lcn)
                },
            )?;
            pre_payload_writes.extend(ins_plan.pre_payload_writes);
            mutation_specs.extend(ins_plan.log_specs);
            if let Some((lcn, cnt)) = ins_plan.allocated_clusters {
                let bm_slot = self.plan_open_attr(
                    &mut staged_open,
                    &mut open_regs,
                    NtfsReference {
                        record: 6,
                        sequence: bm_rec.sequence,
                    },
                    DATA,
                    &[],
                    0,
                )?;
                mutation_specs
                    .extend(self.build_bitmap_range_specs(bm_slot, &bm_runs, lcn, cnt, true)?);
            }
            if !ins_plan.updated_indx_blocks.is_empty() {
                let upd_dst_dir = NtfsFileRecord::parse(&ins_plan.updated_dir_raw)
                    .map_err(|err| parse_err(&err))?;
                let (d_a0, _, _) = extract_plain_nonresident_stream(
                    &self.geometry,
                    &upd_dst_dir,
                    ATTR_INDEX_ALLOCATION,
                    &I30_NAME,
                )?;
                for (boff, raw_blk) in ins_plan.updated_indx_blocks {
                    target_writes.push(TargetWriteKind::IndxBlock {
                        runs: d_a0.clone(),
                        byte_offset: boff,
                        raw_protected: raw_blk,
                    });
                }
            }
            if ins_plan.updated_dir_raw != dst_dir_raw {
                target_writes.push(TargetWriteKind::MftRecord {
                    runs: mft_runs,
                    record_no: dst_dir_no,
                    raw_protected: ins_plan.updated_dir_raw,
                });
            }
        }

        if bm_dirty {
            target_writes.push(TargetWriteKind::BitmapStream {
                runs: bm_runs,
                byte_offset: 0,
                bytes: vol_bm,
            });
        }

        Ok(PreparedTxPlan {
            operation: "rename_entry",
            operation_digest,
            result_value: src_ref,
            pre_payload_writes,
            mft_zero_writes: Vec::new(),
            open_attr_registrations: open_regs,
            mutation_specs,
            target_writes,
        })
    }

    /// Unlink a regular file or an empty directory, freeing its `$I30` entry,
    /// deallocating its MFT slot (incrementing sequence number), and releasing
    /// `$MFT::$BITMAP` and `$Bitmap` clusters.
    ///
    /// Reclamation covers complete ordinary base-record streams, including
    /// named DATA and directory index allocation. Extension records, aliases,
    /// transformed streams and provider-maintained metadata are refused before
    /// any persistent mutation because their complete teardown is not supported.
    pub fn unlink_file(&mut self, cx: &Cx, path: &str) -> NtfsTxOutcome<NtfsReference> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.unlink_file:");
        hasher.update(path.as_bytes());
        let digest = *hasher.finalize().as_bytes();

        match self.plan_unlink_file(cx, digest, path) {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Directory unlink owns the complete ordinary $I30 catalog in this record.
    /// Every other native index or extension catalog requires its own teardown.
    fn admit_directory_unlink(record: &NtfsFileRecord) -> Result<NtfsFileName> {
        if record.base.record != 0
            || record.base.sequence != 0
            || record.flags != 3
            || record.hard_links != 1
        {
            return Err(unsupported(
                "NTFS directory removal requires one ordinary base-record link",
            ));
        }
        let mut identities = BTreeSet::new();
        let mut standard_information = false;
        let mut index_root = false;
        let mut file_name = None;
        for attribute in record.attributes().map_err(|err| parse_err(&err))? {
            if attribute.flags != 0 || !identities.insert((attribute.kind, attribute.name.clone()))
            {
                return Err(unsupported(
                    "NTFS directory removal requires complete untransformed attribute catalogs",
                ));
            }
            match attribute.kind {
                ATTR_STANDARD_INFORMATION => {
                    let NtfsValue::Resident(value) = attribute.value else {
                        return Err(corrupt(0, "nonresident NTFS STANDARD_INFORMATION"));
                    };
                    if !attribute.name.is_empty() || !matches!(value.len(), 48 | 72) {
                        return Err(corrupt(0, "invalid NTFS STANDARD_INFORMATION"));
                    }
                    let flags = u32::from_le_bytes(
                        value[32..36]
                            .try_into()
                            .map_err(|_| corrupt(0, "short NTFS STANDARD_INFORMATION flags"))?,
                    );
                    if flags & 0x4E00 != 0 {
                        return Err(unsupported(
                            "NTFS directory removal cannot maintain transformed or reparse metadata",
                        ));
                    }
                    standard_information = true;
                }
                ATTR_FILE_NAME => {
                    if file_name.is_some() || !attribute.name.is_empty() {
                        return Err(unsupported(
                            "NTFS directory removal requires a single native name",
                        ));
                    }
                    let NtfsValue::Resident(value) = attribute.value else {
                        return Err(corrupt(0, "nonresident NTFS FILE_NAME"));
                    };
                    file_name = Some(NtfsFileName::parse(value).map_err(|err| parse_err(&err))?);
                }
                0x90 if attribute.name == I30_NAME => {
                    if !matches!(attribute.value, NtfsValue::Resident(_)) {
                        return Err(corrupt(0, "nonresident NTFS INDEX_ROOT"));
                    }
                    index_root = true;
                }
                ATTR_INDEX_ALLOCATION if attribute.name == I30_NAME => {
                    if !matches!(attribute.value, NtfsValue::NonResident(_)) {
                        return Err(corrupt(0, "resident NTFS INDEX_ALLOCATION"));
                    }
                }
                ATTR_BITMAP if attribute.name == I30_NAME => {}
                DATA if !attribute.name.is_empty() => {}
                ATTR_SECURITY_DESCRIPTOR | EA_INFORMATION | EA if attribute.name.is_empty() => {}
                kind => {
                    return Err(unsupported(format!(
                        "NTFS directory removal cannot yet maintain native attribute {kind:#x}"
                    )));
                }
            }
        }
        if !standard_information || !index_root {
            return Err(corrupt(
                0,
                "NTFS directory lacks standard information or $I30",
            ));
        }
        file_name.ok_or_else(|| corrupt(0, "NTFS directory lacks its native FILE_NAME"))
    }

    fn unlink_owned_runs(&self, record: &NtfsFileRecord) -> Result<Vec<NtfsRun>> {
        let mut runs = Vec::new();
        for attribute in record.attributes().map_err(|err| parse_err(&err))? {
            if let NtfsValue::NonResident(extent) = attribute.value {
                self.admit_plain_data_extent(&extent)?;
                runs.extend(
                    decode_mapping_pairs(
                        extent.mapping_pairs,
                        extent.first_vcn,
                        extent.last_vcn,
                        self.geometry.cluster_count(),
                    )
                    .map_err(|err| parse_err(&err))?,
                );
            }
        }
        let mut physical: Vec<_> = runs
            .iter()
            .filter_map(|run| run.lcn.map(|lcn| (lcn, lcn + run.clusters)))
            .collect();
        physical.sort_unstable();
        if physical.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(corrupt(0, "NTFS unlink streams share physical clusters"));
        }
        Ok(runs)
    }

    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn plan_unlink_file(
        &self,
        cx: &Cx,
        operation_digest: [u8; 32],
        path: &str,
    ) -> Result<PreparedTxPlan<NtfsReference>> {
        checkpoint(cx)?;
        let (parent_path, leaf_utf16) = split_parent_and_leaf(path)?;
        let mft0_raw = read_mft_record_raw_via_runs(
            &self.device,
            cx,
            &self.geometry,
            &[NtfsRun {
                vcn: 0,
                clusters: u64::from(self.geometry.record_bytes())
                    .div_ceil(u64::from(self.geometry.cluster_bytes())),
                lcn: Some(self.geometry.mft_cluster()),
            }],
            0,
        )?;
        let mft0 = NtfsFileRecord::parse(&mft0_raw).map_err(|err| parse_err(&err))?;
        let (mft_runs, mft_size, _) =
            extract_plain_nonresident_stream(&self.geometry, &mft0, DATA, &[])?;
        let logical_records = mft_size / u64::from(self.geometry.record_bytes());

        let (parent_no, parent_rec) = self.resolve_path_raw(cx, &mft_runs, &parent_path)?;
        let (target_no, target_rec) = self.resolve_path_raw(cx, &mft_runs, path)?;
        if target_no < 24 {
            return Err(FfsError::PermissionDenied);
        }
        if !parent_rec.is_directory() {
            return Err(FfsError::NotDirectory);
        }
        let native_name = if target_rec.is_directory() {
            Self::admit_directory_unlink(&target_rec)?
        } else {
            self.admit_plain_data_write(&target_rec)?
        };
        if native_name.namespace == 2 {
            return Err(unsupported(
                "NTFS DOS alias unlink requires coupled long-name maintenance",
            ));
        }
        if native_name.parent
            != (NtfsReference {
                record: u64::from(parent_no),
                sequence: parent_rec.sequence,
            })
            || (native_name.name != leaf_utf16
                && (native_name.namespace == 0
                    || self.fold_upcase(&native_name.name) != self.fold_upcase(&leaf_utf16)))
        {
            return Err(corrupt(
                0,
                "NTFS unlink FILE_NAME disagrees with its parent index",
            ));
        }
        let runs_to_free = self.unlink_owned_runs(&target_rec)?;
        if target_rec.is_directory() && !self.directory_is_empty(cx, &target_rec)? {
            return Err(FfsError::NotEmpty);
        }
        let leaf_utf16 = native_name.name;

        let target_ref = NtfsReference {
            record: u64::from(target_no),
            sequence: target_rec.sequence,
        };
        let parent_raw =
            read_mft_record_raw_via_runs(&self.device, cx, &self.geometry, &mft_runs, parent_no)?;
        let target_raw =
            read_mft_record_raw_via_runs(&self.device, cx, &self.geometry, &mft_runs, target_no)?;
        let target_rest = restore_record(&target_raw, b"FILE").map_err(|err| parse_err(&err))?;

        let mut staged_open = self.open_attrs.clone();
        let mut open_regs = Vec::new();
        let mft_attr_slot = self.plan_open_attr(
            &mut staged_open,
            &mut open_regs,
            NtfsReference {
                record: 0,
                sequence: mft0.sequence,
            },
            DATA,
            &[],
            0,
        )?;

        let mut mutation_specs = Vec::new();
        let mut target_writes = Vec::new();

        // 1. Delete from parent directory $I30!
        let p_indx_slot = if let Some(bb) = directory_has_external_indx(&parent_rec)? {
            Some(self.plan_open_attr(
                &mut staged_open,
                &mut open_regs,
                NtfsReference {
                    record: u64::from(parent_no),
                    sequence: parent_rec.sequence,
                },
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
                bb,
            )?)
        } else {
            None
        };
        let (p_vcn, p_cbo, p_lcns) = self.map_mft_record_transfer(&mft_runs, parent_no)?;
        let del_plan = self.plan_directory_delete(
            cx,
            parent_no,
            &parent_raw,
            &parent_rec,
            mft_attr_slot,
            p_vcn,
            p_cbo,
            &p_lcns,
            p_indx_slot,
            &leaf_utf16,
        )?;
        mutation_specs.extend(del_plan.log_specs);
        if del_plan.updated_dir_raw != parent_raw {
            target_writes.push(TargetWriteKind::MftRecord {
                runs: mft_runs.clone(),
                record_no: parent_no,
                raw_protected: del_plan.updated_dir_raw,
            });
        }
        if !del_plan.updated_indx_blocks.is_empty() {
            let (a0_runs, _, _) = extract_plain_nonresident_stream(
                &self.geometry,
                &parent_rec,
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
            )?;
            for (boff, raw_blk) in del_plan.updated_indx_blocks {
                target_writes.push(TargetWriteKind::IndxBlock {
                    runs: a0_runs.clone(),
                    byte_offset: boff,
                    raw_protected: raw_blk,
                });
            }
        }

        // 2. Free the complete, validated owned cluster set in $Bitmap!
        if !runs_to_free.is_empty() {
            let bm_rec = read_mft_record_via_runs(&self.device, cx, &self.geometry, &mft_runs, 6)?;
            let (bm_runs, bm_size, _) =
                extract_plain_nonresident_stream(&self.geometry, &bm_rec, DATA, &[])?;
            let mut vol_bm = read_mapped_runs(
                &self.device,
                cx,
                &self.geometry,
                &bm_runs,
                0,
                bm_size as usize,
            )?;
            let bm_attr_slot = self.plan_open_attr(
                &mut staged_open,
                &mut open_regs,
                NtfsReference {
                    record: 6,
                    sequence: bm_rec.sequence,
                },
                DATA,
                &[],
                0,
            )?;
            for r in &runs_to_free {
                if let Some(lcn) = r.lcn
                    && r.clusters > 0
                {
                    set_or_clear_bits(&mut vol_bm, lcn, r.clusters, false);
                    mutation_specs.extend(self.build_bitmap_range_specs(
                        bm_attr_slot,
                        &bm_runs,
                        lcn,
                        r.clusters,
                        false,
                    )?);
                }
            }
            target_writes.push(TargetWriteKind::BitmapStream {
                runs: bm_runs,
                byte_offset: 0,
                bytes: vol_bm,
            });
        }

        // 3. Clear target_no bit in $MFT::$BITMAP!
        let mut mft_bm = self.read_mft_bitmap_bytes(cx, &mft0, logical_records)?;
        set_or_clear_bits(&mut mft_bm, u64::from(target_no), 1, false);
        let mut cur_mft0_raw = mft0_raw;
        let mut mft0_modified = false;
        self.append_mft_bitmap_mutation(
            &mut staged_open,
            &mut open_regs,
            &mut mutation_specs,
            &mut target_writes,
            &mut cur_mft0_raw,
            &mut mft0_modified,
            mft_attr_slot,
            &mft_runs,
            u64::from(target_no),
            false,
            &mft_bm,
        )?;
        if mft0_modified {
            target_writes.push(TargetWriteKind::MftRecord {
                runs: mft_runs.clone(),
                record_no: 0,
                raw_protected: cur_mft0_raw,
            });
        }

        // 4. DeallocateFileRecordSegment (0x03) on target_no (undo = InitializeFileRecordSegment 0x02)!
        let FileEditResult::Applied(dealloc_raw) =
            deallocate_file_record_slot(&target_raw, target_no, RecoveryPass::Undo)
                .map_err(|err| parse_err(&err))?
        else {
            return Err(corrupt(0, "AlreadyApplied on DeallocateFileRecordSegment"));
        };
        let (t_vcn, t_cbo, t_lcns) = self.map_mft_record_transfer(&mft_runs, target_no)?;
        mutation_specs.push(NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::DeallocateFileRecordSegment,
            undo_op: NtfsLogOp::InitializeFileRecordSegment,
            target_attribute: mft_attr_slot,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: t_cbo,
            target_vcn: t_vcn,
            target_lcns: t_lcns,
            redo_data: Vec::new(),
            undo_data: target_rest,
        });
        target_writes.push(TargetWriteKind::MftRecord {
            runs: mft_runs,
            record_no: target_no,
            raw_protected: dealloc_raw,
        });

        Ok(PreparedTxPlan {
            operation: "unlink_file",
            operation_digest,
            result_value: target_ref,
            pre_payload_writes: Vec::new(),
            mft_zero_writes: Vec::new(),
            open_attr_registrations: open_regs,
            mutation_specs,
            target_writes,
        })
    }

    /// Grow `$MFT::$DATA` and `$MFT::$BITMAP` by at least `additional_records` slots,
    /// zero-filling + flushing the newly allocated clusters before publishing sizes,
    /// and syncing `$MFTMirr` record 0. Returns the new total logical MFT record count.
    pub fn grow_mft(&mut self, cx: &Cx, additional_records: u32) -> NtfsTxOutcome<u64> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.grow_mft:");
        hasher.update(&additional_records.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        match self.plan_grow_mft(cx, digest, additional_records) {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn plan_grow_mft(
        &self,
        cx: &Cx,
        operation_digest: [u8; 32],
        additional_records: u32,
    ) -> Result<PreparedTxPlan<u64>> {
        checkpoint(cx)?;
        if additional_records == 0 {
            return Err(FfsError::Format(
                "grow_mft requires additional_records >= 1".into(),
            ));
        }
        let mft0_raw = read_mft_record_raw_via_runs(
            &self.device,
            cx,
            &self.geometry,
            &[NtfsRun {
                vcn: 0,
                clusters: u64::from(self.geometry.record_bytes())
                    .div_ceil(u64::from(self.geometry.cluster_bytes())),
                lcn: Some(self.geometry.mft_cluster()),
            }],
            0,
        )?;
        let mft0 = NtfsFileRecord::parse(&mft0_raw).map_err(|err| parse_err(&err))?;
        let (mut mft_runs, old_mft_data, old_mft_init) =
            extract_plain_nonresident_stream(&self.geometry, &mft0, DATA, &[])?;

        let rec_bytes = u64::from(self.geometry.record_bytes());
        let cluster_bytes = u64::from(self.geometry.cluster_bytes());
        let add_bytes =
            (u64::from(additional_records) * rec_bytes).div_ceil(cluster_bytes) * cluster_bytes;
        let add_clusters = add_bytes / cluster_bytes;

        let bm_rec = read_mft_record_via_runs(&self.device, cx, &self.geometry, &mft_runs, 6)?;
        let (bm_runs, bm_size, _) =
            extract_plain_nonresident_stream(&self.geometry, &bm_rec, DATA, &[])?;
        let mut vol_bm = read_mapped_runs(
            &self.device,
            cx,
            &self.geometry,
            &bm_runs,
            0,
            bm_size as usize,
        )?;
        let new_lcn =
            find_contiguous_zero_bits(&vol_bm, self.geometry.cluster_count(), add_clusters, 1)
                .ok_or(FfsError::NoSpace)?;
        set_or_clear_bits(&mut vol_bm, new_lcn, add_clusters, true);

        let zero_phys = self
            .geometry
            .cluster_offset(new_lcn)
            .map_err(|err| parse_err(&err))?;
        let mft_zero_writes = vec![DirPrePayloadWrite {
            phys_offset: zero_phys,
            bytes: vec![0_u8; add_bytes as usize],
        }];

        let old_total_clusters: u64 = mft_runs.iter().map(|r| r.clusters).sum();
        mft_runs.push(NtfsRun {
            vcn: old_total_clusters,
            clusters: add_clusters,
            lcn: Some(new_lcn),
        });
        let new_mft_alloc = (old_total_clusters + add_clusters) * cluster_bytes;
        let new_mft_data = old_mft_data + add_bytes;
        let new_logical_records = new_mft_data / rec_bytes;

        let mut staged_open = self.open_attrs.clone();
        let mut open_regs = Vec::new();
        let mft_attr_slot = self.plan_open_attr(
            &mut staged_open,
            &mut open_regs,
            NtfsReference {
                record: 0,
                sequence: mft0.sequence,
            },
            DATA,
            &[],
            0,
        )?;
        let bm_attr_slot = self.plan_open_attr(
            &mut staged_open,
            &mut open_regs,
            NtfsReference {
                record: 6,
                sequence: bm_rec.sequence,
            },
            DATA,
            &[],
            0,
        )?;

        let mut mutation_specs =
            self.build_bitmap_range_specs(bm_attr_slot, &bm_runs, new_lcn, add_clusters, true)?;
        let (m0_vcn, m0_cbo, m0_lcns) = self.map_mft_record_transfer(&mft_runs, 0)?;

        // Update $MFT::$DATA mapping pairs + sizes!
        let mut cur_mft0_raw = mft0_raw;
        {
            let rest0 = restore_record(&cur_mft0_raw, b"FILE").map_err(|err| parse_err(&err))?;
            let (d_at, d_sz) = find_attr_offset_in_restored(&rest0, DATA, &[])?
                .ok_or_else(|| corrupt(0, "$MFT missing DATA"))?;
            let map_off = usize::from(u16::from_le_bytes([rest0[d_at + 32], rest0[d_at + 33]]));
            let old_pairs = rest0[d_at + map_off..d_at + d_sz].to_vec();
            let (new_pairs, _) = encode_mapping_pairs(&mft_runs, 0, self.geometry.cluster_count())
                .map_err(|err| parse_err(&err))?;
            let FileEditResult::Applied(upd1) = apply_file_edit(
                &cur_mft0_raw,
                0,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::UpdateMappingPairs {
                        volume_clusters: self.geometry.cluster_count(),
                    },
                    record_offset: u16::try_from(d_at).map_err(|_| corrupt(0, "d_at"))?,
                    attribute_offset: u16::try_from(map_off).map_err(|_| corrupt(0, "map"))?,
                    data: &new_pairs,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            mutation_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::UpdateMappingPairs,
                undo_op: NtfsLogOp::UpdateMappingPairs,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(d_at).map_err(|_| corrupt(0, "d_at"))?,
                attribute_offset: u16::try_from(map_off).map_err(|_| corrupt(0, "map"))?,
                cluster_block_offset: m0_cbo,
                target_vcn: m0_vcn,
                target_lcns: m0_lcns.clone(),
                redo_data: new_pairs,
                undo_data: old_pairs,
            });
            cur_mft0_raw = upd1;
        }
        {
            let rest0 = restore_record(&cur_mft0_raw, b"FILE").map_err(|err| parse_err(&err))?;
            let (d_at, _) = find_attr_offset_in_restored(&rest0, DATA, &[])?
                .ok_or_else(|| corrupt(0, "$MFT missing DATA"))?;
            let old_alloc = u64::from_le_bytes(
                rest0[d_at + 40..d_at + 48]
                    .try_into()
                    .map_err(|_| corrupt(0, "alloc"))?,
            );
            let mut redo_sz = Vec::with_capacity(24);
            redo_sz.extend_from_slice(&new_mft_alloc.to_le_bytes());
            redo_sz.extend_from_slice(&new_mft_data.to_le_bytes());
            redo_sz.extend_from_slice(&new_mft_data.to_le_bytes());
            let mut undo_sz = Vec::with_capacity(24);
            undo_sz.extend_from_slice(&old_alloc.to_le_bytes());
            undo_sz.extend_from_slice(&old_mft_init.to_le_bytes());
            undo_sz.extend_from_slice(&old_mft_data.to_le_bytes());

            let FileEditResult::Applied(upd2) = apply_file_edit(
                &cur_mft0_raw,
                0,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::SetSizes,
                    record_offset: u16::try_from(d_at).map_err(|_| corrupt(0, "d_at"))?,
                    attribute_offset: 0,
                    data: &redo_sz,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            mutation_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::SetNewAttributeSizes,
                undo_op: NtfsLogOp::SetNewAttributeSizes,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(d_at).map_err(|_| corrupt(0, "d_at"))?,
                attribute_offset: 0,
                cluster_block_offset: m0_cbo,
                target_vcn: m0_vcn,
                target_lcns: m0_lcns.clone(),
                redo_data: redo_sz,
                undo_data: undo_sz,
            });
            cur_mft0_raw = upd2;
        }

        // Grow $MFT::$BITMAP (0xB0) if new_logical_records.div_ceil(8) exceeds current $MFT::$BITMAP size!
        let req_bm_bytes = new_logical_records.div_ceil(8).div_ceil(8) * 8;
        let rest_b = restore_record(&cur_mft0_raw, b"FILE").map_err(|err| parse_err(&err))?;
        let (b0_at, _) = find_attr_offset_in_restored(&rest_b, ATTR_BITMAP, &[])?
            .ok_or_else(|| corrupt(0, "$MFT missing 0xB0 BITMAP"))?;
        if rest_b[b0_at + 8] == 0 {
            let voff = usize::from(u16::from_le_bytes([rest_b[b0_at + 20], rest_b[b0_at + 21]]));
            let vlen = u32::from_le_bytes([
                rest_b[b0_at + 16],
                rest_b[b0_at + 17],
                rest_b[b0_at + 18],
                rest_b[b0_at + 19],
            ]) as usize;
            if (vlen as u64) < req_bm_bytes {
                let old_val = rest_b[b0_at + voff..b0_at + voff + vlen].to_vec();
                let mut new_val = old_val.clone();
                new_val.resize(req_bm_bytes as usize, 0);
                let FileEditResult::Applied(upd3) = apply_file_edit(
                    &cur_mft0_raw,
                    0,
                    RecoveryPass::Undo,
                    &FileEdit {
                        operation: FileOperation::UpdateResident { resize: true },
                        record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0"))?,
                        attribute_offset: u16::try_from(voff).map_err(|_| corrupt(0, "voff"))?,
                        data: &new_val,
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "AlreadyApplied"));
                };
                mutation_specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::UpdateResidentValue,
                    undo_op: NtfsLogOp::UpdateResidentValue,
                    target_attribute: mft_attr_slot,
                    record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0"))?,
                    attribute_offset: u16::try_from(voff).map_err(|_| corrupt(0, "voff"))?,
                    cluster_block_offset: m0_cbo,
                    target_vcn: m0_vcn,
                    target_lcns: m0_lcns,
                    redo_data: new_val,
                    undo_data: old_val,
                });
                cur_mft0_raw = upd3;
            }
        } else {
            let (_, bm0_size, bm0_init) =
                extract_plain_nonresident_stream(&self.geometry, &mft0, ATTR_BITMAP, &[])?;
            if bm0_size < req_bm_bytes || bm0_init < req_bm_bytes {
                let bm0_alloc = u64::from_le_bytes(
                    rest_b[b0_at + 40..b0_at + 48]
                        .try_into()
                        .map_err(|_| corrupt(0, "bm0_alloc"))?,
                );
                if req_bm_bytes > bm0_alloc {
                    return Err(unsupported(
                        "nonresident $MFT::$BITMAP cluster reallocation exceeds current capacity",
                    ));
                }
                let mut redo_sz = Vec::with_capacity(24);
                redo_sz.extend_from_slice(&bm0_alloc.to_le_bytes());
                redo_sz.extend_from_slice(&req_bm_bytes.to_le_bytes());
                redo_sz.extend_from_slice(&req_bm_bytes.to_le_bytes());
                let mut undo_sz = Vec::with_capacity(24);
                undo_sz.extend_from_slice(&bm0_alloc.to_le_bytes());
                undo_sz.extend_from_slice(&bm0_init.to_le_bytes());
                undo_sz.extend_from_slice(&bm0_size.to_le_bytes());
                let FileEditResult::Applied(upd3) = apply_file_edit(
                    &cur_mft0_raw,
                    0,
                    RecoveryPass::Undo,
                    &FileEdit {
                        operation: FileOperation::SetSizes,
                        record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0"))?,
                        attribute_offset: 0,
                        data: &redo_sz,
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "AlreadyApplied"));
                };
                mutation_specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::SetNewAttributeSizes,
                    undo_op: NtfsLogOp::SetNewAttributeSizes,
                    target_attribute: mft_attr_slot,
                    record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0"))?,
                    attribute_offset: 0,
                    cluster_block_offset: m0_cbo,
                    target_vcn: m0_vcn,
                    target_lcns: m0_lcns,
                    redo_data: redo_sz,
                    undo_data: undo_sz,
                });
                cur_mft0_raw = upd3;
            }
        }

        let target_writes = vec![
            TargetWriteKind::BitmapStream {
                runs: bm_runs,
                byte_offset: 0,
                bytes: vol_bm,
            },
            TargetWriteKind::MftRecord {
                runs: mft_runs,
                record_no: 0,
                raw_protected: cur_mft0_raw,
            },
        ];

        Ok(PreparedTxPlan {
            operation: "grow_mft",
            operation_digest,
            result_value: new_logical_records,
            pre_payload_writes: Vec::new(),
            mft_zero_writes,
            open_attr_registrations: open_regs,
            mutation_specs,
            target_writes,
        })
    }

    fn read_mft_bitmap_bytes(
        &self,
        cx: &Cx,
        mft0: &NtfsFileRecord,
        logical_records: u64,
    ) -> Result<Vec<u8>> {
        for attr in mft0.attributes().map_err(|err| parse_err(&err))? {
            if attr.kind == ATTR_BITMAP && attr.name.is_empty() {
                return match attr.value {
                    NtfsValue::Resident(b) => {
                        if (b.len() as u64) * 8 < logical_records {
                            return Err(corrupt(0, "short resident $MFT::$BITMAP"));
                        }
                        Ok(b.to_vec())
                    }
                    NtfsValue::NonResident(_) => {
                        let (runs, sz, _) = extract_plain_nonresident_stream(
                            &self.geometry,
                            mft0,
                            ATTR_BITMAP,
                            &[],
                        )?;
                        read_mapped_runs(&self.device, cx, &self.geometry, &runs, 0, sz as usize)
                    }
                };
            }
        }
        Err(corrupt(0, "$MFT missing 0xB0 BITMAP"))
    }

    #[allow(clippy::too_many_arguments)]
    fn append_mft_bitmap_mutation(
        &self,
        staged_open: &mut BTreeMap<u32, OpenAttrRuntime>,
        open_regs: &mut Vec<(u32, OpenAttrRuntime, NtfsClientUpdateSpec)>,
        mutation_specs: &mut Vec<NtfsClientUpdateSpec>,
        target_writes: &mut Vec<TargetWriteKind>,
        cur_mft0_raw: &mut Vec<u8>,
        mft0_modified: &mut bool,
        mft_attr_slot: u16,
        mft_runs: &[NtfsRun],
        bit_index: u64,
        set_bit: bool,
        updated_bm_bytes: &[u8],
    ) -> Result<()> {
        let rest0 = restore_record(cur_mft0_raw, b"FILE").map_err(|err| parse_err(&err))?;
        let (b0_at, _) = find_attr_offset_in_restored(&rest0, ATTR_BITMAP, &[])?
            .ok_or_else(|| corrupt(0, "$MFT missing 0xB0 BITMAP"))?;
        if rest0[b0_at + 8] == 0 {
            let voff = usize::from(u16::from_le_bytes([rest0[b0_at + 20], rest0[b0_at + 21]]));
            let byte_pos = (bit_index / 8) as usize;
            let old_b = rest0[b0_at + voff + byte_pos];
            let new_b = updated_bm_bytes[byte_pos];
            let (m0_vcn, m0_cbo, m0_lcns) = self.map_mft_record_transfer(mft_runs, 0)?;
            let FileEditResult::Applied(upd0) = apply_file_edit(
                cur_mft0_raw,
                0,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::UpdateResident { resize: false },
                    record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0"))?,
                    attribute_offset: u16::try_from(voff + byte_pos)
                        .map_err(|_| corrupt(0, "off"))?,
                    data: &[new_b],
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            mutation_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::UpdateResidentValue,
                undo_op: NtfsLogOp::UpdateResidentValue,
                target_attribute: mft_attr_slot,
                record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0"))?,
                attribute_offset: u16::try_from(voff + byte_pos).map_err(|_| corrupt(0, "off"))?,
                cluster_block_offset: m0_cbo,
                target_vcn: m0_vcn,
                target_lcns: m0_lcns,
                redo_data: vec![new_b],
                undo_data: vec![old_b],
            });
            *cur_mft0_raw = upd0;
            *mft0_modified = true;
            Ok(())
        } else {
            let mft0_parsed = NtfsFileRecord::parse(cur_mft0_raw).map_err(|err| parse_err(&err))?;
            let (bm0_runs, _, _) =
                extract_plain_nonresident_stream(&self.geometry, &mft0_parsed, ATTR_BITMAP, &[])?;
            let bm0_slot = self.plan_open_attr(
                staged_open,
                open_regs,
                NtfsReference {
                    record: 0,
                    sequence: mft0_parsed.sequence,
                },
                ATTR_BITMAP,
                &[],
                0,
            )?;
            mutation_specs
                .extend(self.build_bitmap_range_specs(bm0_slot, &bm0_runs, bit_index, 1, set_bit)?);
            target_writes.push(TargetWriteKind::BitmapStream {
                runs: bm0_runs,
                byte_offset: 0,
                bytes: updated_bm_bytes.to_vec(),
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod data_run_tests {
    use super::{Cx, FfsError, find_free_data_runs, set_or_clear_bits};

    #[test]
    fn fragmented_data_uses_later_large_holes_within_mapping_budget() {
        let cx = Cx::for_testing();
        let mut bitmap = [u8::MAX; 4];
        for (start, count) in [(1, 1), (3, 1), (5, 1), (8, 3), (16, 4)] {
            set_or_clear_bits(&mut bitmap, start, count, false);
        }
        let runs = find_free_data_runs(&cx, &bitmap, 32, 6, 2).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(
            (runs[0].vcn, runs[0].clusters, runs[0].lcn),
            (0, 2, Some(8))
        );
        assert_eq!(
            (runs[1].vcn, runs[1].clusters, runs[1].lcn),
            (2, 4, Some(16))
        );
    }

    #[test]
    fn fragmented_data_preserves_earliest_contiguous_allocation() {
        let cx = Cx::for_testing();
        let mut bitmap = [u8::MAX; 4];
        for (start, count) in [(1, 2), (5, 4), (12, 6)] {
            set_or_clear_bits(&mut bitmap, start, count, false);
        }
        let runs = find_free_data_runs(&cx, &bitmap, 32, 4, 1).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(
            (runs[0].vcn, runs[0].clusters, runs[0].lcn),
            (0, 4, Some(5))
        );
    }

    #[test]
    fn fragmented_data_distinguishes_capacity_and_space_exhaustion() {
        let cx = Cx::for_testing();
        let bitmap = [0b0101_0101_u8];
        assert!(matches!(
            find_free_data_runs(&cx, &bitmap, 8, 3, 2),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            find_free_data_runs(&cx, &bitmap, 8, 5, 2),
            Err(FfsError::NoSpace)
        ));
        // Bit zero and bits beyond the declared volume are never usable.
        assert!(matches!(
            find_free_data_runs(&cx, &[0], 4, 4, 4),
            Err(FfsError::NoSpace)
        ));
        assert!(find_free_data_runs(&cx, &[], 0, 0, 0).unwrap().is_empty());
    }
}
