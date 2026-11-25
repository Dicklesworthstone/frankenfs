//! Transactional secondary metadata maintenance for `$Extend/$Reparse::$R`,
//! `$Extend/$ObjId::$O`, `$OBJECT_ID (0x40)`, and `$Extend/$UsnJrnl` (`$Max` + `$J`).

use asupersync::Cx;
use ffs_error::Result;
use ffs_ondisk::ntfs::usn::{USN_PAGE_BYTES, UsnMaxData, UsnRecordV2, align_usn_offset};
use ffs_ondisk::ntfs::view_index::ViewCollation;
use ffs_ondisk::ntfs::{NtfsGeometry, NtfsReference, NtfsRun};
use serde::Serialize;

use super::catalog::{
    EditableCatalog, EditableStreamStorage, coalesce_physical_spans, normalize_ntfs_runs,
    physical_spans_of_runs, stage_runs_writes,
};
use super::dir_index::DirPrePayloadWrite;
use super::view_index::{ViewRawEntry, rebalance_view_index_tree};
use super::{NtfsTransactionEngine, checkpoint, corrupt, parse_err, unsupported};

pub(super) const REPARSE_R_NAME: [u16; 2] = [b'$' as u16, b'R' as u16];
pub(super) const OBJID_O_NAME: [u16; 2] = [b'$' as u16, b'O' as u16];
pub(super) const USN_MAX_NAME: [u16; 4] = [b'$' as u16, b'M' as u16, b'a' as u16, b'x' as u16];
pub(super) const USN_J_NAME: [u16; 2] = [b'$' as u16, b'J' as u16];

pub(super) const EXTEND_REPARSE_UPPER: [u16; 8] = [
    b'$' as u16,
    b'R' as u16,
    b'E' as u16,
    b'P' as u16,
    b'A' as u16,
    b'R' as u16,
    b'S' as u16,
    b'E' as u16,
];
pub(super) const EXTEND_OBJID_UPPER: [u16; 6] = [
    b'$' as u16,
    b'O' as u16,
    b'B' as u16,
    b'J' as u16,
    b'I' as u16,
    b'D' as u16,
];
pub(super) const EXTEND_USNJRNL_UPPER: [u16; 8] = [
    b'$' as u16,
    b'U' as u16,
    b'S' as u16,
    b'N' as u16,
    b'J' as u16,
    b'R' as u16,
    b'N' as u16,
    b'L' as u16,
];

/// Parsed `$OBJECT_ID` (`0x40`) attribute payload (16 or 64 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NtfsObjectIdData {
    pub object_id: [u8; 16],
    pub birth_volume_id: [u8; 16],
    pub birth_object_id: [u8; 16],
    pub domain_id: [u8; 16],
}

impl NtfsObjectIdData {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() != 16 && raw.len() != 64 {
            return Err(corrupt(
                0,
                "$OBJECT_ID attribute must be exactly 16 or 64 bytes",
            ));
        }
        let mut object_id = [0_u8; 16];
        object_id.copy_from_slice(&raw[0..16]);
        let mut birth_volume_id = [0_u8; 16];
        let mut birth_object_id = [0_u8; 16];
        let mut domain_id = [0_u8; 16];
        if raw.len() == 64 {
            birth_volume_id.copy_from_slice(&raw[16..32]);
            birth_object_id.copy_from_slice(&raw[32..48]);
            domain_id.copy_from_slice(&raw[48..64]);
        }
        Ok(Self {
            object_id,
            birth_volume_id,
            birth_object_id,
            domain_id,
        })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        if self.birth_volume_id == [0; 16]
            && self.birth_object_id == [0; 16]
            && self.domain_id == [0; 16]
        {
            return self.object_id.to_vec();
        }
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.object_id);
        out.extend_from_slice(&self.birth_volume_id);
        out.extend_from_slice(&self.birth_object_id);
        out.extend_from_slice(&self.domain_id);
        out
    }
}

/// Summary of an active `$Extend/$UsnJrnl` change journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NtfsUsnSummary {
    pub record: u32,
    pub maximum_size: u64,
    pub allocation_delta: u64,
    pub usn_id: u64,
    pub lowest_valid_usn: u64,
    pub next_usn: u64,
    pub records_inspected: usize,
}

/// Encode the 12-byte `$Extend/$Reparse::$R` key (`[tag: u32, file_ref: u64]` LE).
pub(super) fn encode_reparse_r_key(tag: u32, file_ref: NtfsReference) -> Result<Vec<u8>> {
    let raw_ref = file_ref.encode().map_err(|err| parse_err(&err))?;
    let mut key = Vec::with_capacity(12);
    key.extend_from_slice(&tag.to_le_bytes());
    key.extend_from_slice(&raw_ref.to_le_bytes());
    Ok(key)
}

/// Encode the 56-byte `$Extend/$ObjId::$O` value (`file_ref(8) + birth_vol(16) + birth_obj(16) + domain(16)`).
pub(super) fn encode_objid_o_data(
    file_ref: NtfsReference,
    data: &NtfsObjectIdData,
) -> Result<Vec<u8>> {
    let raw_ref = file_ref.encode().map_err(|err| parse_err(&err))?;
    let mut out = Vec::with_capacity(56);
    out.extend_from_slice(&raw_ref.to_le_bytes());
    out.extend_from_slice(&data.birth_volume_id);
    out.extend_from_slice(&data.birth_object_id);
    out.extend_from_slice(&data.domain_id);
    Ok(out)
}

/// Upsert `(key, data)` in a view-index entry vector while maintaining uniqueness.
pub(super) fn upsert_view_entry(
    entries: &mut Vec<ViewRawEntry>,
    key: Vec<u8>,
    data: Vec<u8>,
    collation: ViewCollation,
) {
    if let Some(existing) = entries
        .iter_mut()
        .find(|e| collation.compare_keys(&e.key, &key) == std::cmp::Ordering::Equal)
    {
        existing.key = key;
        existing.data = data;
        return;
    }
    entries.push(ViewRawEntry { key, data });
}

/// Remove all entries matching `pred` from a view-index entry vector.
pub(super) fn remove_view_entries_matching(
    entries: &mut Vec<ViewRawEntry>,
    mut pred: impl FnMut(&ViewRawEntry) -> bool,
) -> bool {
    let before = entries.len();
    entries.retain(|e| !pred(e));
    entries.len() != before
}

/// Flush an updated view-index back into its owning `$Extend` record catalog.
#[allow(clippy::too_many_arguments)]
pub(super) fn flush_view_index_into_catalog<FAlloc>(
    geometry: &NtfsGeometry,
    cat: &mut EditableCatalog,
    index_name: &[u16],
    collation: ViewCollation,
    entries: Vec<ViewRawEntry>,
    max_root_value_bytes: usize,
    pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
    freed_clusters: &mut Vec<(u64, u64)>,
    mut alloc_clusters: FAlloc,
) -> Result<()>
where
    FAlloc: FnMut(u64, u64) -> Result<Vec<(u64, u64)>>,
{
    for view in &cat.view_indexes {
        if view.index_name == index_name
            && let Some((ref a0_runs, _, _)) = view.external
        {
            freed_clusters.extend(physical_spans_of_runs(a0_runs));
        }
    }
    let reb = rebalance_view_index_tree(
        geometry,
        index_name,
        collation,
        entries,
        max_root_value_bytes,
        &mut alloc_clusters,
    )?;
    pre_payload_writes.extend(reb.pre_payload_writes);
    if let Some(slot) = cat
        .view_indexes
        .iter_mut()
        .find(|v| v.index_name == index_name)
    {
        *slot = reb.view_index;
    } else {
        cat.view_indexes.push(reb.view_index);
    }
    Ok(())
}

/// COW-append a batch of `USN_RECORD_V2` entries to `$Extend/$UsnJrnl` (`$Max` + `$J`)
/// in one single COW allocation, respecting 4 KiB page-boundary zero-padding and trimming
/// the sparse head when live bytes exceed `$Max.maximum_size`. Returns assigned `usn` offsets.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn append_usn_records_to_catalog<FAlloc>(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    usn_cat: &mut EditableCatalog,
    records: &mut [UsnRecordV2],
    pre_payload_writes: &mut Vec<DirPrePayloadWrite>,
    freed_clusters: &mut Vec<(u64, u64)>,
    mut alloc_clusters: FAlloc,
) -> Result<Vec<u64>>
where
    FAlloc: FnMut(u64) -> Result<Vec<(u64, u64)>>,
{
    checkpoint(cx)?;
    if records.is_empty() {
        return Ok(Vec::new());
    }
    let max_idx = usn_cat
        .data_streams
        .iter()
        .position(|s| s.name == USN_MAX_NAME)
        .ok_or_else(|| corrupt(0, "$UsnJrnl missing $Max stream"))?;
    let j_idx = usn_cat
        .data_streams
        .iter()
        .position(|s| s.name == USN_J_NAME)
        .ok_or_else(|| corrupt(0, "$UsnJrnl missing $J stream"))?;

    let mut max_data = match &usn_cat.data_streams[max_idx].storage {
        EditableStreamStorage::Resident(bytes) => {
            UsnMaxData::parse(bytes).map_err(|err| parse_err(&err))?
        }
        EditableStreamStorage::NonResident { .. } => {
            return Err(corrupt(0, "$UsnJrnl:$Max must be resident"));
        }
    };

    let (mut j_runs, j_size, j_init) = match &usn_cat.data_streams[j_idx].storage {
        EditableStreamStorage::NonResident {
            runs,
            sparse,
            compressed,
            encrypted,
            data_bytes,
            initialized_bytes,
            ..
        } => {
            if !*sparse || *compressed || *encrypted {
                return Err(unsupported(
                    "$UsnJrnl:$J must be a non-resident SPARSE data stream",
                ));
            }
            (runs.clone(), *data_bytes, *initialized_bytes)
        }
        EditableStreamStorage::Resident(_) => {
            return Err(corrupt(0, "$UsnJrnl:$J must be non-resident SPARSE"));
        }
    };

    // Advancing ValidDataLength to the new EOF must not expose an existing
    // uninitialized tail. Supporting it requires zeroing that interval first.
    if j_init != j_size {
        return Err(unsupported(
            "$UsnJrnl:$J append requires a fully initialized existing journal",
        ));
    }

    let mut cursor = j_size;
    let mut assigned = Vec::with_capacity(records.len());
    let mut staged_encoded = Vec::with_capacity(records.len());
    for record in records.iter_mut() {
        let rec_len = record.encoded_len();
        let usn_offset = align_usn_offset(cursor, rec_len);
        record.usn = usn_offset;
        let encoded = record.encode().map_err(|err| parse_err(&err))?;
        cursor = usn_offset + encoded.len() as u64;
        assigned.push(usn_offset);
        staged_encoded.push((usn_offset, encoded));
    }
    let new_end = cursor;

    let cb = u64::from(engine.geometry.cluster_bytes());
    // The new record can start on the next USN page. Include the old EOF's
    // cluster so its previously invisible tail is zeroed before the new
    // initialized length makes that page padding visible.
    let start_vcn = j_size / cb;
    let end_vcn = new_end.div_ceil(cb);
    let cow_clusters = end_vcn - start_vcn;
    let cow_byte_start = start_vcn * cb;
    let cow_bytes = (cow_clusters * cb) as usize;

    let mut buf = vec![0_u8; cow_bytes];
    if cow_byte_start < j_init {
        let existing_len = (j_init - cow_byte_start).min(cow_bytes as u64) as usize;
        // Read existing initialized bytes in this cluster window (sparse holes stay zero).
        let mut done = 0_usize;
        while done < existing_len {
            let cur_off = cow_byte_start + done as u64;
            let vcn = cur_off / cb;
            let within = (cur_off % cb) as usize;
            if let Some(run) = j_runs
                .iter()
                .find(|r| vcn >= r.vcn && vcn < r.vcn + r.clusters)
            {
                let rel_vcn = vcn - run.vcn;
                let avail = (((run.clusters - rel_vcn) * cb) - within as u64) as usize;
                let chunk = (existing_len - done).min(avail);
                if let Some(base_lcn) = run.lcn {
                    let phys = engine
                        .geometry
                        .cluster_offset(base_lcn + rel_vcn)
                        .map_err(|err| parse_err(&err))?
                        + within as u64;
                    engine.device.read_exact_at(
                        cx,
                        ffs_types::ByteOffset(phys),
                        &mut buf[done..done + chunk],
                    )?;
                }
                done += chunk;
            } else {
                done += ((cb as usize) - within).min(existing_len - done);
            }
        }
    }
    for (usn_offset, encoded) in &staged_encoded {
        let rel_write = (*usn_offset - cow_byte_start) as usize;
        buf[rel_write..rel_write + encoded.len()].copy_from_slice(encoded);
    }

    let spans = alloc_clusters(cow_clusters)?;
    let mut stage_runs = Vec::with_capacity(spans.len());
    let mut sv = 0_u64;
    for &(lcn, scnt) in &spans {
        stage_runs.push(NtfsRun {
            vcn: sv,
            clusters: scnt,
            lcn: Some(lcn),
        });
        sv += scnt;
    }
    stage_runs_writes(&engine.geometry, &stage_runs, &buf, pre_payload_writes)?;

    // Splice COW tail runs into `j_runs` (preserving any preceding sparse holes).
    let mut next_runs = Vec::new();
    let mut displaced = Vec::new();
    for run in &j_runs {
        let r_start = run.vcn;
        let r_end = run.vcn + run.clusters;
        if r_start < start_vcn {
            next_runs.push(NtfsRun {
                vcn: r_start,
                clusters: r_end.min(start_vcn) - r_start,
                lcn: run.lcn,
            });
        }
        let ov_start = r_start.max(start_vcn);
        let ov_end = r_end.min(end_vcn);
        if ov_start < ov_end
            && let Some(base_lcn) = run.lcn
        {
            displaced.push((base_lcn + (ov_start - r_start), ov_end - ov_start));
        }
        if r_end > end_vcn {
            let tail_start = r_start.max(end_vcn);
            next_runs.push(NtfsRun {
                vcn: tail_start,
                clusters: r_end - tail_start,
                lcn: run.lcn.map(|b| b + (tail_start - r_start)),
            });
        }
    }
    let prefix_cov: u64 = next_runs.iter().map(|r| r.clusters).sum();
    if prefix_cov < start_vcn {
        next_runs.push(NtfsRun {
            vcn: prefix_cov,
            clusters: start_vcn - prefix_cov,
            lcn: None,
        });
    }
    let mut ins_vcn = start_vcn;
    for &(lcn, scnt) in &spans {
        next_runs.push(NtfsRun {
            vcn: ins_vcn,
            clusters: scnt,
            lcn: Some(lcn),
        });
        ins_vcn += scnt;
    }
    next_runs.sort_unstable_by_key(|r| r.vcn);
    j_runs = normalize_ntfs_runs(next_runs);
    freed_clusters.extend(coalesce_physical_spans(displaced));

    // Trim sparse head strictly before `start_vcn` when active journal span exceeds
    // `maximum_size + allocation_delta` (never freeing clusters allocated in this TX).
    let active_span = new_end.saturating_sub(max_data.lowest_valid_usn);
    if active_span
        > max_data
            .maximum_size
            .saturating_add(max_data.allocation_delta)
    {
        // Records cannot cross a USN page, but can cross a smaller cluster.
        // Reclaim whole clusters and whole pages so the retained head cannot
        // begin inside a record when $Max's byte-sized delta is unaligned.
        let trim_granularity = cb.max(USN_PAGE_BYTES);
        let trim_step = max_data.allocation_delta.max(trim_granularity);
        let trim_to = max_data
            .lowest_valid_usn
            .saturating_add(trim_step)
            .min(start_vcn * cb)
            / trim_granularity
            * trim_granularity;
        let trim_vcns = trim_to / cb;
        if trim_vcns > 0 && trim_to > max_data.lowest_valid_usn {
            let mut trimmed_runs = Vec::new();
            let mut trim_freed = Vec::new();
            trimmed_runs.push(NtfsRun {
                vcn: 0,
                clusters: trim_vcns,
                lcn: None,
            });
            for run in &j_runs {
                let r_start = run.vcn;
                let r_end = run.vcn + run.clusters;
                let ov_end = r_end.min(trim_vcns);
                if r_start < ov_end
                    && let Some(base_lcn) = run.lcn
                {
                    trim_freed.push((base_lcn, ov_end - r_start));
                }
                if r_end > trim_vcns {
                    let keep_start = r_start.max(trim_vcns);
                    trimmed_runs.push(NtfsRun {
                        vcn: keep_start,
                        clusters: r_end - keep_start,
                        lcn: run.lcn.map(|b| b + (keep_start - r_start)),
                    });
                }
            }
            j_runs = normalize_ntfs_runs(trimmed_runs);
            freed_clusters.extend(coalesce_physical_spans(trim_freed));
            max_data.lowest_valid_usn = trim_to;
        }
    }

    usn_cat.data_streams[max_idx].storage =
        EditableStreamStorage::Resident(max_data.encode().to_vec());
    usn_cat.data_streams[j_idx].storage = EditableStreamStorage::NonResident {
        runs: j_runs,
        sparse: true,
        compressed: false,
        encrypted: false,
        compression_unit: 0,
        data_bytes: new_end,
        initialized_bytes: new_end,
    };
    Ok(assigned)
}
