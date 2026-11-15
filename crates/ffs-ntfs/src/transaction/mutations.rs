//! Reference-addressed native NTFS 3.1 namespace, positioned stream, ADS,
//! hard-link, rename-overwrite, truncate, and metadata transactions for [`NtfsFs`]
//! and companion CLI operations.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::logfile_writer::NtfsClientUpdateSpec;
use ffs_ondisk::ntfs::recovery::{
    FileEdit, FileEditResult, FileOperation, RecoveryPass, apply_file_edit,
};
use ffs_ondisk::ntfs::{DATA, NtfsFileRecord, NtfsLogOp, NtfsReference, NtfsRun, restore_record};

use super::btree::I30RawEntry;
use super::catalog::{
    EditableCatalog, EditableDataStream, EditableDirIndex, EditableFileName, EditableStreamStorage,
    allocate_cluster_runs, coalesce_physical_spans, dirty_bitmap_range, is_bit_set,
    normalize_ntfs_runs, physical_spans_of_runs, set_or_clear_run_list, stage_runs_writes,
};
use super::dir_index::{
    DirPrePayloadWrite, I30_NAME, build_empty_small_index_root, directory_has_external_indx,
    find_attr_offset_in_restored,
};
use super::ops::{
    FILE_ATTR_ARCHIVE, FILE_ATTR_DIRECTORY, MAX_RESIDENT_DATA_PAYLOAD, PreparedTxPlan,
    TargetWriteKind, encode_standard_information, extract_parent_security,
    find_contiguous_zero_bits, set_or_clear_bits,
};
use super::{
    NtfsTransactionEngine, NtfsTxOutcome, OpenAttrRuntime, checkpoint, corrupt,
    extract_plain_nonresident_stream, parse_err, read_mapped_runs, read_mft_record_raw_via_runs,
    read_mft_record_via_runs, unsupported,
};

const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const FILE_ATTR_READONLY: u32 = 0x0000_0001;
const MIN_USER_MFT_SLOT: u64 = 24;
const FIRST_NON_RESERVED_SLOT: u64 = 16;

/// Result of a committed [`NtfsTransactionEngine::rename_entry_at`] transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsRenameOutcome {
    pub moved_reference: NtfsReference,
    pub overwritten_reference: Option<NtfsReference>,
    pub overwritten_remaining_links: u32,
    pub overwritten_retained_as_orphan: bool,
    pub noop_same_inode: bool,
}

/// Validate a UTF-16 directory entry component (`1..=255` code units, not `.`/`..`,
/// no NUL `0x0000`, `/` `0x002F`, `\` `0x005C`, or `:` `0x003A`).
pub fn validate_ntfs_component_utf16(units: &[u16]) -> Result<()> {
    if units.is_empty() || units == [0x2E] || units == [0x2E, 0x2E] {
        return Err(FfsError::Format(
            "invalid empty, '.' or '..' NTFS component".into(),
        ));
    }
    if units.len() > 255 {
        return Err(FfsError::NameTooLong);
    }
    if units
        .iter()
        .any(|&u| matches!(u, 0x0000 | 0x002F | 0x005C | 0x003A))
    {
        return Err(FfsError::Format(
            "NUL, slash, backslash or colon in NTFS directory component".into(),
        ));
    }
    Ok(())
}

/// Validate a UTF-16 `$DATA` stream name (`0..=255` code units; unnamed `[]` or
/// named ADS without NUL `0x0000`, `/` `0x002F`, `\` `0x005C`, or `:` `0x003A`).
pub fn validate_ntfs_stream_name_utf16(units: &[u16]) -> Result<()> {
    if units.len() > 255 {
        return Err(FfsError::NameTooLong);
    }
    if units
        .iter()
        .any(|&u| matches!(u, 0x0000 | 0x002F | 0x005C | 0x003A))
    {
        return Err(FfsError::Format(
            "invalid character in NTFS alternate data stream name".into(),
        ));
    }
    Ok(())
}

/// Select native `FILE_NAME` namespace flag (`3 = WIN32_AND_DOS`, `1 = WIN32`, `0 = POSIX`).
fn choose_ntfs_namespace(name: &[u16]) -> u8 {
    let has_posix_only = name
        .iter()
        .any(|&u| u < 0x20 || matches!(u, 0x22 | 0x2A | 0x3C | 0x3E | 0x3F | 0x7C))
        || name.last().is_some_and(|&u| u == 0x20 || u == 0x2E);
    if has_posix_only {
        return 0; // FILE_NAME_POSIX
    }
    if is_strict_dos_8_3(name) {
        3 // FILE_NAME_WIN32_AND_DOS
    } else {
        1 // FILE_NAME_WIN32
    }
}

fn is_strict_dos_8_3(name: &[u16]) -> bool {
    if name.is_empty() || name.len() > 12 {
        return false;
    }
    let valid_dos_char = |u: u16| -> bool {
        (0x30..=0x39).contains(&u)
            || (0x41..=0x5A).contains(&u)
            || matches!(
                u,
                0x21 | 0x23..=0x29 | 0x2D | 0x40 | 0x5E | 0x5F | 0x60 | 0x7B | 0x7D | 0x7E
            )
    };
    let mut dot_pos = None;
    for (idx, &u) in name.iter().enumerate() {
        if u == 0x2E {
            if dot_pos.is_some() || idx == 0 {
                return false;
            }
            dot_pos = Some(idx);
        } else if !valid_dos_char(u) {
            return false;
        }
    }
    dot_pos.map_or(name.len() <= 8, |pos| {
        pos <= 8 && (1..=3).contains(&(name.len() - pos - 1))
    })
}

/// Read `[0..read_len]` from an [`EditableDataStream`] (`0` beyond `initialized_bytes` or sparse holes).
fn read_editable_stream_prefix(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    stream: &EditableDataStream,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    match &stream.storage {
        EditableStreamStorage::Resident(bytes) => {
            let mut out = vec![0_u8; len];
            if (offset as usize) < bytes.len() {
                let avail = (bytes.len() - offset as usize).min(len);
                out[..avail].copy_from_slice(&bytes[offset as usize..offset as usize + avail]);
            }
            Ok(out)
        }
        EditableStreamStorage::NonResident {
            runs,
            data_bytes,
            initialized_bytes,
            ..
        } => {
            let valid_limit = (*initialized_bytes).min(*data_bytes);
            let mut out = vec![0_u8; len];
            if offset >= valid_limit {
                return Ok(out);
            }
            let readable = ((valid_limit - offset) as usize).min(len);
            let cb = u64::from(engine.geometry.cluster_bytes());
            let mut done = 0_usize;
            while done < readable {
                checkpoint(cx)?;
                let cur_off = offset + done as u64;
                let vcn = cur_off / cb;
                let within = (cur_off % cb) as usize;
                let idx = runs
                    .partition_point(|r| r.vcn <= vcn)
                    .checked_sub(1)
                    .ok_or_else(|| corrupt(cur_off, "offset precedes NTFS stream runs"))?;
                let run = &runs[idx];
                let rel_vcn = vcn - run.vcn;
                if rel_vcn >= run.clusters {
                    return Err(corrupt(cur_off, "gap in NTFS stream runs"));
                }
                let avail_in_run = ((run.clusters - rel_vcn) * cb - within as u64) as usize;
                let chunk = (readable - done).min(avail_in_run);
                if let Some(base_lcn) = run.lcn {
                    let phys = engine
                        .geometry
                        .cluster_offset(base_lcn + rel_vcn)
                        .map_err(|err| parse_err(&err))?
                        + within as u64;
                    engine.device.read_exact_at(
                        cx,
                        ffs_types::ByteOffset(phys),
                        &mut out[done..done + chunk],
                    )?;
                }
                done += chunk;
            }
            Ok(out)
        }
    }
}

type SplicedRunPlan = (Vec<NtfsRun>, Vec<(u64, u64)>);

/// Splice `new_runs` covering `[start_vcn .. end_vcn)` into `old_runs`, returning
/// `(merged_runs, displaced_physical_spans)` and filling any gap `< start_vcn`
/// with sparse holes (`if sparse`) or error.
fn splice_vcn_interval(
    old_runs: &[NtfsRun],
    start_vcn: u64,
    end_vcn: u64,
    replacement_spans: &[(u64, u64)],
    sparse: bool,
) -> Result<SplicedRunPlan> {
    let old_total_vcns: u64 = old_runs.iter().map(|r| r.clusters).sum();
    let mut prefix: Vec<NtfsRun> = Vec::new();
    let mut suffix: Vec<NtfsRun> = Vec::new();
    let mut displaced: Vec<(u64, u64)> = Vec::new();

    for run in old_runs {
        let r_start = run.vcn;
        let r_end = run.vcn + run.clusters;
        // Part strictly before `start_vcn`:
        if r_start < start_vcn {
            let keep_end = r_end.min(start_vcn);
            let keep_len = keep_end - r_start;
            prefix.push(NtfsRun {
                vcn: r_start,
                clusters: keep_len,
                lcn: run.lcn,
            });
        }
        // Part overlapping `[start_vcn .. end_vcn)`:
        let ov_start = r_start.max(start_vcn);
        let ov_end = r_end.min(end_vcn);
        if ov_start < ov_end
            && let Some(base_lcn) = run.lcn
        {
            displaced.push((base_lcn + (ov_start - r_start), ov_end - ov_start));
        }
        // Part strictly after `end_vcn`:
        if r_end > end_vcn {
            let tail_start = r_start.max(end_vcn);
            let suffix_clusters = r_end - tail_start;
            let suffix_lcn = run.lcn.map(|base| base + (tail_start - r_start));
            suffix.push(NtfsRun {
                vcn: tail_start,
                clusters: suffix_clusters,
                lcn: suffix_lcn,
            });
        }
    }

    if old_total_vcns < start_vcn {
        if !sparse {
            return Err(corrupt(0, "non-sparse stream splice left unallocated hole"));
        }
        prefix.push(NtfsRun {
            vcn: old_total_vcns,
            clusters: start_vcn - old_total_vcns,
            lcn: None,
        });
    }

    let mut cur_vcn = start_vcn;
    for &(lcn, cnt) in replacement_spans {
        prefix.push(NtfsRun {
            vcn: cur_vcn,
            clusters: cnt,
            lcn: Some(lcn),
        });
        cur_vcn += cnt;
    }
    if cur_vcn != end_vcn {
        return Err(corrupt(
            0,
            "replacement cluster spans mismatch VCN interval",
        ));
    }
    prefix.extend(suffix);
    Ok((
        normalize_ntfs_runs(prefix),
        coalesce_physical_spans(displaced),
    ))
}

struct TxWorkspace {
    cur_mft0_raw: Vec<u8>,
    mft0_modified: bool,
    mft_runs: Vec<NtfsRun>,
    mft_data_bytes: u64,
    cur_mft_init_bytes: u64,
    logical_records: u64,
    cur_init_records: u64,
    mft_bm: Vec<u8>,
    vol_bm_orig: Vec<u8>,
    vol_bm: Vec<u8>,
    bm_runs: Vec<NtfsRun>,
    bm_rec_seq: u16,
    vol_clusters: u64,
    staged_open: BTreeMap<u32, OpenAttrRuntime>,
    open_regs: Vec<(u32, OpenAttrRuntime, NtfsClientUpdateSpec)>,
    mft_attr_slot: u16,
    pre_payload_writes: Vec<DirPrePayloadWrite>,
    mft_zero_writes: Vec<DirPrePayloadWrite>,
    mutation_specs: Vec<NtfsClientUpdateSpec>,
    target_writes: Vec<TargetWriteKind>,
    catalogs: BTreeMap<u64, EditableCatalog>,
    dirty_catalogs: BTreeSet<u64>,
    deallocated_records: BTreeSet<u64>,
    dir_entries_cache: BTreeMap<u64, Vec<I30RawEntry>>,
    dirty_dirs: BTreeSet<u64>,
    allocated_clusters: Vec<(u64, u64)>,
    freed_clusters: Vec<(u64, u64)>,
    alloc_cursor: u64,
}

impl TxWorkspace {
    fn load(engine: &NtfsTransactionEngine, cx: &Cx) -> Result<Self> {
        let mft0 = engine.read_mft_record_zero(cx)?;
        let (mft_runs, mft_data_bytes, mft_init_bytes) =
            extract_plain_nonresident_stream(&engine.geometry, &mft0, DATA, &[])?;
        let cur_mft0_raw =
            read_mft_record_raw_via_runs(&engine.device, cx, &engine.geometry, &mft_runs, 0)?;
        let rec_bytes = u64::from(engine.geometry.record_bytes());
        let logical_records = mft_data_bytes / rec_bytes;
        let cur_init_records = mft_init_bytes / rec_bytes;
        let mft_bm = engine.read_mft_bitmap_bytes(cx, &mft0, logical_records)?;

        let bm_rec = read_mft_record_via_runs(&engine.device, cx, &engine.geometry, &mft_runs, 6)?;
        let (bm_runs, bm_size, _) =
            extract_plain_nonresident_stream(&engine.geometry, &bm_rec, DATA, &[])?;
        let vol_bm = read_mapped_runs(
            &engine.device,
            cx,
            &engine.geometry,
            &bm_runs,
            0,
            bm_size as usize,
        )?;
        let vol_bm_orig = vol_bm.clone();

        let mut staged_open = engine.open_attrs.clone();
        let mut open_regs = Vec::new();
        let mft_attr_slot = engine.plan_open_attr(
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

        Ok(Self {
            cur_mft0_raw,
            mft0_modified: false,
            mft_runs,
            mft_data_bytes,
            cur_mft_init_bytes: mft_init_bytes,
            logical_records,
            cur_init_records,
            mft_bm,
            vol_bm_orig,
            vol_bm,
            bm_runs,
            bm_rec_seq: bm_rec.sequence,
            vol_clusters: engine.geometry.cluster_count(),
            staged_open,
            open_regs,
            mft_attr_slot,
            pre_payload_writes: Vec::new(),
            mft_zero_writes: Vec::new(),
            mutation_specs: Vec::new(),
            target_writes: Vec::new(),
            catalogs: BTreeMap::new(),
            dirty_catalogs: BTreeSet::new(),
            deallocated_records: BTreeSet::new(),
            dir_entries_cache: BTreeMap::new(),
            dirty_dirs: BTreeSet::new(),
            allocated_clusters: Vec::new(),
            freed_clusters: Vec::new(),
            alloc_cursor: 1,
        })
    }

    fn load_catalog(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        target_ref: NtfsReference,
    ) -> Result<&EditableCatalog> {
        if !self.catalogs.contains_key(&target_ref.record) {
            let cat = engine.load_editable_catalog(cx, &self.mft_runs, target_ref)?;
            self.catalogs.insert(target_ref.record, cat);
        }
        let cat = self
            .catalogs
            .get(&target_ref.record)
            .expect("inserted catalog");
        if cat.base_ref.sequence != target_ref.sequence {
            return Err(FfsError::NotFound("stale NTFS MFT sequence".into()));
        }
        Ok(cat)
    }

    fn catalog_mut(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        target_ref: NtfsReference,
    ) -> Result<&mut EditableCatalog> {
        let _ = self.load_catalog(engine, cx, target_ref)?;
        self.dirty_catalogs.insert(target_ref.record);
        Ok(self
            .catalogs
            .get_mut(&target_ref.record)
            .expect("loaded catalog"))
    }

    fn dir_entries(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        dir_ref: NtfsReference,
    ) -> Result<&Vec<I30RawEntry>> {
        if !self.dir_entries_cache.contains_key(&dir_ref.record) {
            let cat = self.load_catalog(engine, cx, dir_ref)?;
            if !cat.is_directory {
                return Err(FfsError::NotDirectory);
            }
            let dir_idx = cat
                .dir_index
                .as_ref()
                .ok_or_else(|| corrupt(0, "directory lacks $I30"))?;
            let entries = engine.collect_catalog_i30_entries(cx, dir_idx)?;
            self.dir_entries_cache.insert(dir_ref.record, entries);
        }
        let cat = self.catalogs.get(&dir_ref.record).expect("dir catalog");
        if cat.base_ref.sequence != dir_ref.sequence {
            return Err(FfsError::NotFound("stale directory reference".into()));
        }
        Ok(self.dir_entries_cache.get(&dir_ref.record).expect("cached"))
    }

    fn dir_entries_mut(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        dir_ref: NtfsReference,
    ) -> Result<&mut Vec<I30RawEntry>> {
        let _ = self.dir_entries(engine, cx, dir_ref)?;
        self.dirty_dirs.insert(dir_ref.record);
        self.dirty_catalogs.insert(dir_ref.record);
        Ok(self
            .dir_entries_cache
            .get_mut(&dir_ref.record)
            .expect("cached dir entries"))
    }

    fn lookup_in_dir(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        dir_ref: NtfsReference,
        query_utf16: &[u16],
    ) -> Result<Option<I30RawEntry>> {
        if let Some(entries) = self.dir_entries_cache.get(&dir_ref.record) {
            let target_upper = engine.fold_upcase(query_utf16);
            let matches: Vec<&I30RawEntry> = entries
                .iter()
                .filter(|e| engine.fold_upcase(&e.file_name.name) == target_upper)
                .collect();
            if matches.is_empty() {
                return Ok(None);
            }
            if let Some(exact) = matches
                .iter()
                .find(|m| m.file_name.name == query_utf16 && m.file_name.namespace != 2)
                .or_else(|| matches.iter().find(|m| m.file_name.name == query_utf16))
            {
                return Ok(Some((*exact).clone()));
            }
            let first_ref = matches[0].reference;
            if matches.iter().any(|m| m.reference != first_ref) {
                return Err(unsupported(
                    "ambiguous POSIX case-variant collision in case-folded NTFS lookup",
                ));
            }
            if let Some(non_dos) = matches.iter().find(|m| m.file_name.namespace != 2) {
                return Ok(Some((*non_dos).clone()));
            }
            return Ok(Some(matches[0].clone()));
        }
        let cat = self.load_catalog(engine, cx, dir_ref)?;
        if !cat.is_directory {
            return Err(FfsError::NotDirectory);
        }
        let dir_idx = cat
            .dir_index
            .as_ref()
            .ok_or_else(|| corrupt(0, "directory lacks $I30"))?;
        engine.lookup_in_catalog_i30(cx, dir_idx, query_utf16)
    }

    fn alloc_clusters(&mut self, needed: u64, min_chunk: u64) -> Result<Vec<(u64, u64)>> {
        let spans = allocate_cluster_runs(
            &self.vol_bm,
            self.vol_clusters,
            needed,
            min_chunk,
            self.alloc_cursor,
        )?;
        set_or_clear_run_list(&mut self.vol_bm, &spans, true);
        if let Some(&(last_lcn, last_cnt)) = spans.last() {
            self.alloc_cursor = (last_lcn + last_cnt) % self.vol_clusters.max(1);
        }
        self.allocated_clusters.extend_from_slice(&spans);
        Ok(spans)
    }

    fn free_clusters_deferred(&mut self, spans: &[(u64, u64)]) {
        for &(start, len) in spans {
            if len > 0 {
                self.freed_clusters.push((start, len));
            }
        }
    }

    /// Allocate a free MFT slot (`>= 24`, falling back to `16..24`), advancing `$MFT`
    /// initialized length if the chosen slot lies beyond `cur_init_records` and logging
    /// the `$MFT::$BITMAP` bit transition immediately on `cur_mft0_raw`.
    fn alloc_mft_slot(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
    ) -> Result<(u32, u16, Vec<u8>)> {
        let slot_u64 =
            find_contiguous_zero_bits(&self.mft_bm, self.logical_records, 1, MIN_USER_MFT_SLOT)
                .or_else(|| {
                    find_contiguous_zero_bits(
                        &self.mft_bm,
                        self.logical_records.min(MIN_USER_MFT_SLOT),
                        1,
                        FIRST_NON_RESERVED_SLOT,
                    )
                })
                .ok_or(FfsError::NoSpace)?;
        let slot = u32::try_from(slot_u64).map_err(|_| FfsError::NoSpace)?;
        let rec_bytes = u64::from(engine.geometry.record_bytes());

        if slot_u64 >= self.cur_init_records {
            let new_init_records = (slot_u64 + 1).min(self.logical_records);
            for slot_to_zero in self.cur_init_records..new_init_records {
                let (phys, avail, _) = super::map_logical_offset(
                    &engine.geometry,
                    &self.mft_runs,
                    slot_to_zero * rec_bytes,
                )?;
                if avail < rec_bytes {
                    return Err(unsupported("sub-record fragmented MFT cluster"));
                }
                self.mft_zero_writes.push(DirPrePayloadWrite {
                    phys_offset: phys,
                    bytes: vec![0_u8; rec_bytes as usize],
                });
            }
            let new_init_bytes = new_init_records * rec_bytes;
            let rest0 =
                restore_record(&self.cur_mft0_raw, b"FILE").map_err(|err| parse_err(&err))?;
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
            redo_sz.extend_from_slice(&self.mft_data_bytes.to_le_bytes());
            let mut undo_sz = Vec::with_capacity(24);
            undo_sz.extend_from_slice(&alloc0.to_le_bytes());
            undo_sz.extend_from_slice(&self.cur_mft_init_bytes.to_le_bytes());
            undo_sz.extend_from_slice(&self.mft_data_bytes.to_le_bytes());

            let (m0_vcn, m0_cbo, m0_lcns) = engine.map_mft_record_transfer(&self.mft_runs, 0)?;
            let FileEditResult::Applied(upd0) = apply_file_edit(
                &self.cur_mft0_raw,
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
                return Err(corrupt(0, "AlreadyApplied on $MFT SetSizes"));
            };
            self.mutation_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::SetNewAttributeSizes,
                undo_op: NtfsLogOp::SetNewAttributeSizes,
                target_attribute: self.mft_attr_slot,
                record_offset: u16::try_from(d_at).map_err(|_| corrupt(0, "d_at"))?,
                attribute_offset: 0,
                cluster_block_offset: m0_cbo,
                target_vcn: m0_vcn,
                target_lcns: m0_lcns,
                redo_data: redo_sz,
                undo_data: undo_sz,
            });
            self.cur_mft0_raw = upd0;
            self.cur_init_records = new_init_records;
            self.cur_mft_init_bytes = new_init_bytes;
            self.mft0_modified = true;
        }

        // Read existing slot raw if previously initialized (before advancing `cur_init_records`? Note if we just zeroed it, it's all zeros!).
        let existing_raw = if is_slot_in_original_mft(engine, cx, &self.mft_runs, slot)? {
            read_mft_record_raw_via_runs(
                &engine.device,
                cx,
                &engine.geometry,
                &self.mft_runs,
                slot,
            )?
        } else {
            vec![0_u8; rec_bytes as usize]
        };
        let next_seq = if let Ok(prev_rec) = NtfsFileRecord::parse(&existing_raw) {
            if prev_rec.in_use() {
                prev_rec.sequence.wrapping_add(1).max(1)
            } else {
                prev_rec.sequence.max(1)
            }
        } else {
            1_u16
        };

        set_or_clear_bits(&mut self.mft_bm, slot_u64, 1, true);
        engine.append_mft_bitmap_mutation(
            &mut self.staged_open,
            &mut self.open_regs,
            &mut self.mutation_specs,
            &mut self.target_writes,
            &mut self.cur_mft0_raw,
            &mut self.mft0_modified,
            self.mft_attr_slot,
            &self.mft_runs,
            slot_u64,
            true,
            &self.mft_bm,
        )?;
        Ok((slot, next_seq, existing_raw))
    }

    fn deallocate_entire_catalog(
        &mut self,
        engine: &NtfsTransactionEngine,
        rec_no: u64,
    ) -> Result<()> {
        let cat = self
            .catalogs
            .get(&rec_no)
            .ok_or_else(|| corrupt(0, "missing catalog for deallocation"))?
            .clone();
        self.dirty_catalogs.remove(&rec_no);
        self.dirty_dirs.remove(&rec_no);
        self.deallocated_records.insert(rec_no);

        // Free all physical clusters owned by `cat`.
        for stream in &cat.data_streams {
            if let EditableStreamStorage::NonResident { ref runs, .. } = stream.storage {
                self.free_clusters_deferred(&physical_spans_of_runs(runs));
            }
        }
        if let Some(EditableDirIndex {
            external: Some((ref a0_runs, _, _)),
            ..
        }) = cat.dir_index
        {
            self.free_clusters_deferred(&physical_spans_of_runs(a0_runs));
        }
        self.free_clusters_deferred(&physical_spans_of_runs(&cat.old_nonres_attrlist_runs));

        // Deallocate extension MFT slots first, then base MFT slot.
        for &(ext_slot, _, ref old_ext_raw) in &cat.old_extensions {
            let protected_dealloc = engine.emit_mft_slot_dealloc_spec(
                self.mft_attr_slot,
                &self.mft_runs,
                ext_slot,
                old_ext_raw,
                &mut self.mutation_specs,
            )?;
            self.target_writes.push(TargetWriteKind::MftRecord {
                runs: self.mft_runs.clone(),
                record_no: ext_slot,
                raw_protected: protected_dealloc,
            });
            set_or_clear_bits(&mut self.mft_bm, u64::from(ext_slot), 1, false);
            engine.append_mft_bitmap_mutation(
                &mut self.staged_open,
                &mut self.open_regs,
                &mut self.mutation_specs,
                &mut self.target_writes,
                &mut self.cur_mft0_raw,
                &mut self.mft0_modified,
                self.mft_attr_slot,
                &self.mft_runs,
                u64::from(ext_slot),
                false,
                &self.mft_bm,
            )?;
        }

        let base_slot = u32::try_from(rec_no).map_err(|_| corrupt(0, "base_slot u32"))?;
        let protected_base_dealloc = engine.emit_mft_slot_dealloc_spec(
            self.mft_attr_slot,
            &self.mft_runs,
            base_slot,
            &cat.old_base_raw,
            &mut self.mutation_specs,
        )?;
        self.target_writes.push(TargetWriteKind::MftRecord {
            runs: self.mft_runs.clone(),
            record_no: base_slot,
            raw_protected: protected_base_dealloc,
        });
        set_or_clear_bits(&mut self.mft_bm, rec_no, 1, false);
        engine.append_mft_bitmap_mutation(
            &mut self.staged_open,
            &mut self.open_regs,
            &mut self.mutation_specs,
            &mut self.target_writes,
            &mut self.cur_mft0_raw,
            &mut self.mft0_modified,
            self.mft_attr_slot,
            &self.mft_runs,
            rec_no,
            false,
            &self.mft_bm,
        )?;
        Ok(())
    }

    /// Update duplicated `FILE_NAME` fields across all parent `$I30` entries of `target_ref`.
    fn sync_target_into_parent_dirs(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        target_ref: NtfsReference,
    ) -> Result<()> {
        let fn_list = {
            let cat = self
                .catalogs
                .get_mut(&target_ref.record)
                .ok_or_else(|| corrupt(0, "missing target catalog"))?;
            cat.sync_filename_duplicated_fields(engine.geometry.cluster_bytes());
            cat.file_names.clone()
        };
        for fn_item in fn_list {
            if target_ref.record == 5 && fn_item.file_name.parent.record == 5 {
                continue;
            }
            let encoded = fn_item.encode()?;
            let entries = self.dir_entries_mut(engine, cx, fn_item.file_name.parent)?;
            let mut updated_any = false;
            for ent in entries.iter_mut() {
                if ent.reference == target_ref
                    && ent.file_name.namespace == fn_item.file_name.namespace
                    && ent.file_name.name == fn_item.file_name.name
                {
                    ent.raw_fn_bytes.clone_from(&encoded);
                    updated_any = true;
                }
            }
            if !updated_any {
                return Err(corrupt(
                    0,
                    "parent $I30 missing expected entry for target FILE_NAME",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn finalize<T>(
        mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        operation: &'static str,
        operation_digest: [u8; 32],
        result_value: T,
    ) -> Result<PreparedTxPlan<T>> {
        let rec_bytes = engine.geometry.record_bytes() as usize;
        let usa_count = rec_bytes / super::SECTOR_BYTES + 1;
        let first_attr = (48 + usa_count * 2 + 7) & !7;
        // Leave generous room in base directory record for `0x10` (72B), `0x30` (~120B), `0x20` (128B),
        // `0xA0` (~96B), `0xB0` (~40B): max_root_value_bytes = ~420 bytes on 1024B MFT records!
        let max_root_value_bytes = rec_bytes.saturating_sub(first_attr + 540).max(96);

        // 1. Rebuild modified directory `$I30` B-trees via COW rebalancer!
        let dirty_dir_ids: Vec<u64> = self.dirty_dirs.iter().copied().collect();
        for dir_id in dirty_dir_ids {
            if self.deallocated_records.contains(&dir_id) {
                continue;
            }
            let entries = self
                .dir_entries_cache
                .get(&dir_id)
                .ok_or_else(|| corrupt(0, "missing dirty dir entries"))?
                .clone();
            let old_a0_spans = self
                .catalogs
                .get(&dir_id)
                .and_then(|c| c.dir_index.as_ref())
                .and_then(|d| d.external.as_ref())
                .map(|(runs, _, _)| physical_spans_of_runs(runs))
                .unwrap_or_default();

            let mut alloc_err = None;
            let rebalanced = engine.rebalance_catalog_i30_tree(
                entries,
                max_root_value_bytes,
                |needed, min_chunk| match self.alloc_clusters(needed, min_chunk) {
                    Ok(spans) => Ok(spans),
                    Err(e) => {
                        alloc_err = Some(e);
                        Err(FfsError::NoSpace)
                    }
                },
            );
            let rebalanced = match rebalanced {
                Ok(r) => r,
                Err(e) => return Err(alloc_err.unwrap_or(e)),
            };
            self.free_clusters_deferred(&old_a0_spans);
            self.pre_payload_writes
                .extend(rebalanced.pre_payload_writes);
            let cat = self.catalogs.get_mut(&dir_id).expect("dir catalog");
            cat.dir_index = Some(rebalanced.dir_index);
        }

        // 2. Pack all modified live base/extension catalogs!
        let dirty_cat_ids: Vec<u64> = self.dirty_catalogs.iter().copied().collect();
        for rec_id in dirty_cat_ids {
            if self.deallocated_records.contains(&rec_id) {
                continue;
            }
            let cat = self
                .catalogs
                .get(&rec_id)
                .ok_or_else(|| corrupt(0, "missing dirty catalog"))?
                .clone();
            let mft_runs_clone = self.mft_runs.clone();
            let mft_attr_slot = self.mft_attr_slot;

            // Pack catalog, allocating extension MFT slots / non-resident 0x20 clusters if needed.
            let packed = {
                // Capture mutable workspace borrows cleanly via explicit closures?
                // Both closures would borrow `self` mutably if passed simultaneously; instead,
                // pre-collect or run a 2-phase pack or pass `&RefCell<&mut Self>`!
                let ws_cell = std::cell::RefCell::new(&mut self);
                engine.pack_editable_catalog(
                    &cat,
                    mft_attr_slot,
                    &mft_runs_clone,
                    || ws_cell.borrow_mut().alloc_mft_slot(engine, cx),
                    |need_cl| ws_cell.borrow_mut().alloc_clusters(need_cl, 1),
                )?
            };

            self.pre_payload_writes.extend(packed.pre_payload_writes);
            self.free_clusters_deferred(&packed.freed_clusters);
            for freed_slot in packed.freed_mft_slots {
                set_or_clear_bits(&mut self.mft_bm, u64::from(freed_slot), 1, false);
                engine.append_mft_bitmap_mutation(
                    &mut self.staged_open,
                    &mut self.open_regs,
                    &mut self.mutation_specs,
                    &mut self.target_writes,
                    &mut self.cur_mft0_raw,
                    &mut self.mft0_modified,
                    self.mft_attr_slot,
                    &self.mft_runs,
                    u64::from(freed_slot),
                    false,
                    &self.mft_bm,
                )?;
            }
            self.mutation_specs.extend(packed.log_specs);
            for (slot_no, raw_protected) in packed.mft_record_writes {
                self.target_writes.push(TargetWriteKind::MftRecord {
                    runs: self.mft_runs.clone(),
                    record_no: slot_no,
                    raw_protected,
                });
            }
        }

        // 3. Apply deferred freed clusters in `$Bitmap` (NEVER reused during Stage 1 of this tx!)
        // and emit `$Bitmap` log specs + minimal dirty `BitmapStream` target write!
        let alloc_spans = coalesce_physical_spans(self.allocated_clusters);
        let free_spans = coalesce_physical_spans(self.freed_clusters);
        for &(a_lcn, a_cnt) in &alloc_spans {
            for &(f_lcn, f_cnt) in &free_spans {
                if a_lcn < f_lcn + f_cnt && f_lcn < a_lcn + a_cnt {
                    return Err(corrupt(
                        0,
                        "Stage-1 allocated cluster overlapped deferred-free cluster",
                    ));
                }
            }
        }
        set_or_clear_run_list(&mut self.vol_bm, &free_spans, false);

        if !alloc_spans.is_empty() || !free_spans.is_empty() {
            let bm_attr_slot = engine.plan_open_attr(
                &mut self.staged_open,
                &mut self.open_regs,
                NtfsReference {
                    record: 6,
                    sequence: self.bm_rec_seq,
                },
                DATA,
                &[],
                0,
            )?;
            for &(lcn, cnt) in &alloc_spans {
                self.mutation_specs.extend(engine.build_bitmap_range_specs(
                    bm_attr_slot,
                    &self.bm_runs,
                    lcn,
                    cnt,
                    true,
                )?);
            }
            for &(lcn, cnt) in &free_spans {
                self.mutation_specs.extend(engine.build_bitmap_range_specs(
                    bm_attr_slot,
                    &self.bm_runs,
                    lcn,
                    cnt,
                    false,
                )?);
            }
            if let Some((dirty_off, dirty_bytes)) =
                dirty_bitmap_range(&self.vol_bm_orig, &self.vol_bm)
            {
                self.target_writes.push(TargetWriteKind::BitmapStream {
                    runs: self.bm_runs,
                    byte_offset: dirty_off,
                    bytes: dirty_bytes,
                });
            }
        }

        if self.mft0_modified {
            self.target_writes.push(TargetWriteKind::MftRecord {
                runs: self.mft_runs,
                record_no: 0,
                raw_protected: self.cur_mft0_raw,
            });
        }

        Ok(PreparedTxPlan {
            operation,
            operation_digest,
            result_value,
            pre_payload_writes: self.pre_payload_writes,
            mft_zero_writes: self.mft_zero_writes,
            open_attr_registrations: self.open_regs,
            mutation_specs: self.mutation_specs,
            target_writes: self.target_writes,
        })
    }
}

fn is_slot_in_original_mft(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    mft_runs: &[NtfsRun],
    slot: u32,
) -> Result<bool> {
    let mft0 = engine.read_mft_record_zero(cx)?;
    let (_, _, mft_init_bytes) =
        extract_plain_nonresident_stream(&engine.geometry, &mft0, DATA, &[])?;
    let _ = mft_runs;
    let init_records = mft_init_bytes / u64::from(engine.geometry.record_bytes());
    Ok(u64::from(slot) < init_records)
}

impl NtfsTransactionEngine {
    /// Ensure `$MFT::$BITMAP` has at least `min_free_slots` free MFT records, auto-growing
    /// `$MFT` cleanly if needed AND only when sufficient free clusters remain for both
    /// `$MFT` growth and `payload_clusters_reserve` (preventing residue on `ENOSPC`).
    fn ensure_mft_headroom(
        &mut self,
        cx: &Cx,
        min_free_slots: u64,
        payload_clusters_reserve: u64,
    ) -> Result<()> {
        let mft0 = self.read_mft_record_zero(cx)?;
        let (mft_runs, mft_data_bytes, _) =
            extract_plain_nonresident_stream(&self.geometry, &mft0, DATA, &[])?;
        let rec_bytes = u64::from(self.geometry.record_bytes());
        let logical_records = mft_data_bytes / rec_bytes;
        let mft_bm = self.read_mft_bitmap_bytes(cx, &mft0, logical_records)?;

        let mut free_slots = 0_u64;
        for bit in FIRST_NON_RESERVED_SLOT..logical_records {
            if !is_bit_set(&mft_bm, bit) {
                free_slots += 1;
                if free_slots >= min_free_slots {
                    return Ok(());
                }
            }
        }

        // Count total free clusters on volume before growing $MFT!
        let bm_rec = read_mft_record_via_runs(&self.device, cx, &self.geometry, &mft_runs, 6)?;
        let (bm_runs, bm_size, _) =
            extract_plain_nonresident_stream(&self.geometry, &bm_rec, DATA, &[])?;
        let vol_bm = read_mapped_runs(
            &self.device,
            cx,
            &self.geometry,
            &bm_runs,
            0,
            bm_size as usize,
        )?;
        let vol_clusters = self.geometry.cluster_count();
        let total_free_clusters: u64 = (0..vol_clusters)
            .filter(|&b| !is_bit_set(&vol_bm, b))
            .count() as u64;

        let cb = u64::from(self.geometry.cluster_bytes());
        let recs_per_cluster = (cb / rec_bytes).max(1);
        let missing_slots = min_free_slots - free_slots;
        let min_add_clusters = missing_slots.div_ceil(recs_per_cluster);
        if total_free_clusters < min_add_clusters.saturating_add(payload_clusters_reserve) {
            return Err(FfsError::NoSpace);
        }

        // Prefer growing by 64 records (e.g. 16 clusters) if plenty of free space exists,
        // else grow by exact `min_add_clusters * recs_per_cluster`.
        let pref_records = 64_u32.max(u32::try_from(missing_slots).unwrap_or(64));
        let pref_clusters = u64::from(pref_records).div_ceil(recs_per_cluster);
        let grow_records = if total_free_clusters
            >= pref_clusters.saturating_add(payload_clusters_reserve)
            && find_contiguous_zero_bits(&vol_bm, vol_clusters, pref_clusters, 1).is_some()
        {
            u32::try_from(pref_clusters * recs_per_cluster).unwrap_or(pref_records)
        } else {
            u32::try_from(min_add_clusters * recs_per_cluster).map_err(|_| FfsError::NoSpace)?
        };

        match self.grow_mft(cx, grow_records) {
            NtfsTxOutcome::Committed { .. } => Ok(()),
            NtfsTxOutcome::NotCommitted(err) => Err(err),
            NtfsTxOutcome::Uncertain { reason, .. } => Err(reason),
        }
    }

    /// Create a regular file or directory inside `parent_ref` with exact UTF-16 `name_utf16`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_entry_at(
        &mut self,
        cx: &Cx,
        parent_ref: NtfsReference,
        name_utf16: &[u16],
        is_dir: bool,
        read_only: bool,
        initial_data: &[u8],
        now_ticks: u64,
    ) -> NtfsTxOutcome<NtfsReference> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.create_entry_at:");
        hasher.update(&parent_ref.record.to_le_bytes());
        hasher.update(&parent_ref.sequence.to_le_bytes());
        for &u in name_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&[u8::from(is_dir), u8::from(read_only)]);
        hasher.update(&(initial_data.len() as u64).to_le_bytes());
        hasher.update(blake3::hash(initial_data).as_bytes());
        let digest = *hasher.finalize().as_bytes();

        let cb = u64::from(self.geometry.cluster_bytes());
        let data_cl = if !is_dir && initial_data.len() > MAX_RESIDENT_DATA_PAYLOAD {
            (initial_data.len() as u64).div_ceil(cb)
        } else {
            0
        };
        if let Err(err) = self.ensure_mft_headroom(cx, 2, data_cl) {
            return NtfsTxOutcome::NotCommitted(err);
        }

        let plan_res = (|| -> Result<PreparedTxPlan<NtfsReference>> {
            validate_ntfs_component_utf16(name_utf16)?;
            let mut ws = TxWorkspace::load(self, cx)?;
            if ws
                .lookup_in_dir(self, cx, parent_ref, name_utf16)?
                .is_some()
            {
                return Err(FfsError::Exists);
            }

            let parent_raw_rec = read_mft_record_via_runs(
                &self.device,
                cx,
                &self.geometry,
                &ws.mft_runs,
                u32::try_from(parent_ref.record).map_err(|_| corrupt(0, "parent u32"))?,
            )?;
            let security = extract_parent_security(&parent_raw_rec);
            let mut std_info = encode_standard_information(is_dir, &security);
            let mut base_flags = if is_dir { 0_u32 } else { FILE_ATTR_ARCHIVE };
            if read_only {
                base_flags |= FILE_ATTR_READONLY;
            }
            std_info[32..36].copy_from_slice(&base_flags.to_le_bytes());
            for off in [0_usize, 8, 16, 24] {
                std_info[off..off + 8].copy_from_slice(&now_ticks.to_le_bytes());
            }

            let (new_slot, next_seq, existing_raw) = ws.alloc_mft_slot(self, cx)?;
            let child_ref = NtfsReference {
                record: u64::from(new_slot),
                sequence: next_seq,
            };

            let mut data_streams = Vec::new();
            let dir_index = if is_dir {
                Some(EditableDirIndex {
                    index_root: build_empty_small_index_root(
                        self.geometry.index_bytes(),
                        self.geometry.cluster_bytes(),
                    )?,
                    external: None,
                })
            } else {
                let storage = if initial_data.len() <= MAX_RESIDENT_DATA_PAYLOAD {
                    EditableStreamStorage::Resident(initial_data.to_vec())
                } else {
                    let n_cl = (initial_data.len() as u64).div_ceil(cb);
                    let spans = ws.alloc_clusters(n_cl, 1)?;
                    let mut runs = Vec::new();
                    let mut cur_vcn = 0_u64;
                    for &(lcn, cnt) in &spans {
                        runs.push(NtfsRun {
                            vcn: cur_vcn,
                            clusters: cnt,
                            lcn: Some(lcn),
                        });
                        cur_vcn += cnt;
                    }
                    let mut padded = vec![0_u8; (n_cl * cb) as usize];
                    padded[..initial_data.len()].copy_from_slice(initial_data);
                    stage_runs_writes(&self.geometry, &runs, &padded, &mut ws.pre_payload_writes)?;
                    EditableStreamStorage::NonResident {
                        runs,
                        sparse: false,
                        compression_unit: 0,
                        data_bytes: initial_data.len() as u64,
                        initialized_bytes: initial_data.len() as u64,
                    }
                };
                data_streams.push(EditableDataStream {
                    name: Vec::new(),
                    storage,
                });
                None
            };

            let ns = choose_ntfs_namespace(name_utf16);
            let fn_attr = EditableFileName {
                file_name: NtfsFileName {
                    parent: parent_ref,
                    namespace: ns,
                    name: name_utf16.to_vec(),
                },
                ctime: now_ticks,
                mtime: now_ticks,
                mft_time: now_ticks,
                atime: now_ticks,
                allocated_size: 0,
                data_size: 0,
                flags: if is_dir {
                    base_flags | FILE_ATTR_DIRECTORY
                } else {
                    base_flags
                },
                reparse: 0,
            };
            let sd_opt = match security {
                super::ops::InheritedSecurity::SharedId(_) => None,
                super::ops::InheritedSecurity::Descriptor(sd) => Some(sd),
            };
            let mut child_cat = EditableCatalog {
                base_ref: child_ref,
                is_directory: is_dir,
                std_info,
                file_names: vec![fn_attr],
                security_descriptor: sd_opt,
                data_streams,
                dir_index,
                preserved: Vec::new(),
                old_base_raw: existing_raw.clone(),
                old_extensions: Vec::new(),
                old_nonres_attrlist_runs: Vec::new(),
            };
            child_cat.sync_filename_duplicated_fields(self.geometry.cluster_bytes());
            let raw_fn_bytes = child_cat.file_names[0].encode()?;
            let fn_struct = child_cat.file_names[0].file_name.clone();

            // Pack new child slot using fresh-allocation semantics (`undo = DeallocateFileRecordSegment`)!
            let mft_runs_clone = ws.mft_runs.clone();
            let mft_attr_slot = ws.mft_attr_slot;
            {
                // Temporarily build base/extension for fresh child: note base slot itself is freshly allocated!
                let mut tmp_cat = child_cat;
                // Mark `old_base_raw` as fresh by emitting via `pack_fresh_child_catalog`.
                let ws_cell = std::cell::RefCell::new(&mut ws);
                let packed = self.pack_fresh_base_catalog(
                    &mut tmp_cat,
                    &existing_raw,
                    mft_attr_slot,
                    &mft_runs_clone,
                    || ws_cell.borrow_mut().alloc_mft_slot(self, cx),
                    |need_cl| ws_cell.borrow_mut().alloc_clusters(need_cl, 1),
                )?;
                ws.pre_payload_writes.extend(packed.pre_payload_writes);
                ws.mutation_specs.extend(packed.log_specs);
                for (slot_no, raw_protected) in packed.mft_record_writes {
                    ws.target_writes.push(TargetWriteKind::MftRecord {
                        runs: ws.mft_runs.clone(),
                        record_no: slot_no,
                        raw_protected,
                    });
                }
            }

            // Insert into `parent_ref`'s `$I30` and update parent timestamps!
            ws.dir_entries_mut(self, cx, parent_ref)?.push(I30RawEntry {
                reference: child_ref,
                file_name: fn_struct,
                raw_fn_bytes,
            });
            ws.catalog_mut(self, cx, parent_ref)?.set_std_times(
                None,
                Some(now_ticks),
                Some(now_ticks),
                None,
            );

            ws.finalize(
                self,
                cx,
                if is_dir { "mkdir_at" } else { "create_at" },
                digest,
                child_ref,
            )
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn pack_fresh_base_catalog<FSlot, FClus>(
        &self,
        catalog: &mut EditableCatalog,
        existing_slot_raw: &[u8],
        mft_attr_slot: u16,
        mft_runs: &[NtfsRun],
        allocate_mft_slot: FSlot,
        allocate_clusters: FClus,
    ) -> Result<super::catalog::PackedCatalogPlan>
    where
        FSlot: FnMut() -> Result<(u32, u16, Vec<u8>)>,
        FClus: FnMut(u64) -> Result<Vec<(u64, u64)>>,
    {
        // Seed `old_base_raw` with a dummy active record so `pack_editable_catalog` builds the new
        // image, then replace the base slot's undo op with `DeallocateFileRecordSegment`!
        let base_no = u32::try_from(catalog.base_ref.record).map_err(|_| corrupt(0, "base_no"))?;
        let dummy_restored = super::catalog::build_restored_mft_record(
            self.geometry.record_bytes(),
            base_no,
            catalog.base_ref.sequence,
            catalog.is_directory,
            1,
            None,
            &[],
            0,
        )?;
        let FileEditResult::Applied(dummy_protected) =
            ffs_ondisk::ntfs::recovery::initialize_file_record_slot(
                existing_slot_raw,
                base_no,
                RecoveryPass::Undo,
                &dummy_restored,
            )
            .map_err(|err| parse_err(&err))?
        else {
            return Err(corrupt(0, "AlreadyApplied on dummy init"));
        };
        catalog.old_base_raw = dummy_protected;
        let mut packed = self.pack_editable_catalog(
            catalog,
            mft_attr_slot,
            mft_runs,
            allocate_mft_slot,
            allocate_clusters,
        )?;
        // Fix base slot's log spec: `undo_op = DeallocateFileRecordSegment`, `undo_data = []`,
        // and recompute `protected_new` against true `existing_slot_raw` so USA token is exact!
        let (base_vcn, base_cbo, _) = self.map_mft_record_transfer(mft_runs, base_no)?;
        for spec in &mut packed.log_specs {
            if spec.target_attribute == mft_attr_slot
                && spec.target_vcn == base_vcn
                && spec.cluster_block_offset == base_cbo
                && spec.redo_op == NtfsLogOp::InitializeFileRecordSegment
            {
                spec.undo_op = NtfsLogOp::DeallocateFileRecordSegment;
                spec.undo_data.clear();
                let FileEditResult::Applied(true_protected) =
                    ffs_ondisk::ntfs::recovery::initialize_file_record_slot(
                        existing_slot_raw,
                        base_no,
                        RecoveryPass::Undo,
                        &spec.redo_data,
                    )
                    .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "AlreadyApplied on fresh child init"));
                };
                for (slot_no, raw_prot) in &mut packed.mft_record_writes {
                    if *slot_no == base_no {
                        raw_prot.clone_from(&true_protected);
                    }
                }
            }
        }
        Ok(packed)
    }

    /// Positioned write to unnamed `$DATA` (`stream_utf16 == &[]`) or a named ADS (`stream_utf16 != &[]`),
    /// returning the updated logical byte size of the stream.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub fn write_stream_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        offset: u64,
        data: &[u8],
        create_stream_if_missing: bool,
        now_ticks: u64,
    ) -> NtfsTxOutcome<u64> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.write_stream_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        for &u in stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&offset.to_le_bytes());
        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(blake3::hash(data).as_bytes());
        let digest = *hasher.finalize().as_bytes();

        let cb = u64::from(self.geometry.cluster_bytes());
        let est_cl = (data.len() as u64).div_ceil(cb) + 2;
        // Reserve 1 extension MFT slot headroom if possible (ignore NoSpace here if free slots >= 1 or no extension needed).
        let _ = self.ensure_mft_headroom(cx, 1, est_cl);

        let plan_res = (|| -> Result<PreparedTxPlan<u64>> {
            validate_ntfs_stream_name_utf16(stream_utf16)?;
            let end_offset = offset
                .checked_add(data.len() as u64)
                .filter(|&e| i64::try_from(e).is_ok())
                .ok_or_else(|| FfsError::Format("NTFS write offset overflow".into()))?;

            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            if cat_ro.is_directory && stream_utf16.is_empty() {
                return Err(FfsError::IsDirectory);
            }

            let target_folded = self.fold_upcase(stream_utf16);
            let existing_idx = cat_ro
                .data_streams
                .iter()
                .position(|s| self.fold_upcase(&s.name) == target_folded);

            if existing_idx.is_none() && !create_stream_if_missing {
                return Err(FfsError::NotFound("NTFS data stream not found".into()));
            }

            let cur_stream = match existing_idx {
                Some(i) => cat_ro.data_streams[i].clone(),
                None => EditableDataStream {
                    name: stream_utf16.to_vec(),
                    storage: EditableStreamStorage::Resident(Vec::new()),
                },
            };

            let old_size = cur_stream.logical_size();
            if data.is_empty() && existing_idx.is_some() {
                // Zero-length write on existing stream returns current size without mutating payload.
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
                if stream_utf16.is_empty() {
                    ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
                }
                return ws.finalize(self, cx, "write_stream_at", digest, old_size);
            }

            let (old_sparse, old_comp_unit, old_init, old_runs) = match &cur_stream.storage {
                EditableStreamStorage::Resident(b) => (false, 0_u16, b.len() as u64, Vec::new()),
                EditableStreamStorage::NonResident {
                    runs,
                    sparse,
                    compression_unit,
                    initialized_bytes,
                    ..
                } => (*sparse, *compression_unit, *initialized_bytes, runs.clone()),
            };

            let new_size = old_size.max(end_offset);
            let updated_storage = if !old_sparse && new_size <= MAX_RESIDENT_DATA_PAYLOAD as u64 {
                let mut buf =
                    read_editable_stream_prefix(self, cx, &cur_stream, 0, new_size as usize)?;
                if !data.is_empty() {
                    buf[offset as usize..end_offset as usize].copy_from_slice(data);
                }
                ws.free_clusters_deferred(&physical_spans_of_runs(&old_runs));
                EditableStreamStorage::Resident(buf)
            } else if old_sparse {
                // Sparse stream: preserve holes (`lcn: None`) outside touched VCNs!
                // If `old_init` ended mid-cluster strictly before `offset / cb`, COW-zero that partial tail cluster first.
                let write_start_vcn = offset / cb;
                let write_end_vcn = end_offset
                    .div_ceil(cb)
                    .max(write_start_vcn + u64::from(!data.is_empty()));
                let mut working_runs = old_runs;
                let init_vcn = old_init / cb;
                if old_init % cb != 0 && init_vcn < write_start_vcn {
                    let partial_cluster = read_editable_stream_prefix(
                        self,
                        cx,
                        &cur_stream,
                        init_vcn * cb,
                        cb as usize,
                    )?;
                    let span = ws.alloc_clusters(1, 1)?;
                    let new_run = [NtfsRun {
                        vcn: 0,
                        clusters: 1,
                        lcn: Some(span[0].0),
                    }];
                    stage_runs_writes(
                        &self.geometry,
                        &new_run,
                        &partial_cluster,
                        &mut ws.pre_payload_writes,
                    )?;
                    let (spliced, disp) =
                        splice_vcn_interval(&working_runs, init_vcn, init_vcn + 1, &span, true)?;
                    ws.free_clusters_deferred(&disp);
                    working_runs = spliced;
                }
                // Replace any uninitialized preallocated clusters strictly in `[old_init.div_ceil(cb) .. write_start_vcn)` with sparse holes!
                let hole_start_vcn = old_init.div_ceil(cb);
                if hole_start_vcn < write_start_vcn {
                    let cur_cov: u64 = working_runs.iter().map(|r| r.clusters).sum();
                    if cur_cov > hole_start_vcn {
                        let hole_end = write_start_vcn.min(cur_cov);
                        let (without, disp) = splice_vcn_interval(
                            &working_runs,
                            hole_start_vcn,
                            hole_end,
                            &[],
                            true,
                        )?;
                        ws.free_clusters_deferred(&disp);
                        // Insert explicit sparse hole `[hole_start_vcn .. hole_end)` before suffix!
                        let mut rebuilt = Vec::new();
                        let mut inserted = false;
                        for r in without {
                            if !inserted && r.vcn >= hole_start_vcn {
                                rebuilt.push(NtfsRun {
                                    vcn: hole_start_vcn,
                                    clusters: hole_end - hole_start_vcn,
                                    lcn: None,
                                });
                                inserted = true;
                            }
                            rebuilt.push(r);
                        }
                        if !inserted {
                            rebuilt.push(NtfsRun {
                                vcn: hole_start_vcn,
                                clusters: hole_end - hole_start_vcn,
                                lcn: None,
                            });
                        }
                        working_runs = normalize_ntfs_runs(rebuilt);
                    }
                }
                if write_end_vcn > write_start_vcn {
                    let cow_clusters = write_end_vcn - write_start_vcn;
                    let cow_bytes_u64 = cow_clusters
                        .checked_mul(cb)
                        .filter(|&n| n <= super::MAX_FILE_EDIT_BYTES)
                        .ok_or_else(|| {
                            FfsError::Io(std::io::Error::from_raw_os_error(libc::EFBIG))
                        })?;
                    let cow_bytes_len = cow_bytes_u64 as usize;
                    let cow_byte_start = write_start_vcn * cb;
                    let mut merged_buf = read_editable_stream_prefix(
                        self,
                        cx,
                        &cur_stream,
                        cow_byte_start,
                        cow_bytes_len,
                    )?;
                    let rel_off = (offset - cow_byte_start) as usize;
                    merged_buf[rel_off..rel_off + data.len()].copy_from_slice(data);
                    let spans = ws.alloc_clusters(cow_clusters, 1)?;
                    let mut stage_runs = Vec::with_capacity(spans.len());
                    let mut sv = 0_u64;
                    for &(lcn, cnt) in &spans {
                        stage_runs.push(NtfsRun {
                            vcn: sv,
                            clusters: cnt,
                            lcn: Some(lcn),
                        });
                        sv += cnt;
                    }
                    stage_runs_writes(
                        &self.geometry,
                        &stage_runs,
                        &merged_buf,
                        &mut ws.pre_payload_writes,
                    )?;
                    let (spliced, disp) = splice_vcn_interval(
                        &working_runs,
                        write_start_vcn,
                        write_end_vcn,
                        &spans,
                        true,
                    )?;
                    ws.free_clusters_deferred(&disp);
                    working_runs = spliced;
                }
                EditableStreamStorage::NonResident {
                    runs: working_runs,
                    sparse: true,
                    compression_unit: old_comp_unit,
                    data_bytes: new_size,
                    initialized_bytes: old_init.max(end_offset),
                }
            } else {
                // Non-sparse non-resident stream: COW-replace `[min(offset, old_init)/cb .. end_offset.div_ceil(cb))`
                // so any VDL gap `[old_init..offset]` is 100% zero-filled in Stage 1 on newly allocated clusters!
                let cow_start_vcn = offset.min(old_init) / cb;
                let cow_end_vcn = end_offset.div_ceil(cb).max(1);
                let cow_clusters = cow_end_vcn - cow_start_vcn;
                let cow_byte_start = cow_start_vcn * cb;
                let cow_bytes_u64 = cow_clusters
                    .checked_mul(cb)
                    .filter(|&n| n <= super::MAX_FILE_EDIT_BYTES)
                    .ok_or_else(|| FfsError::Io(std::io::Error::from_raw_os_error(libc::EFBIG)))?;
                let cow_bytes_len = cow_bytes_u64 as usize;

                let mut merged_buf = read_editable_stream_prefix(
                    self,
                    cx,
                    &cur_stream,
                    cow_byte_start,
                    cow_bytes_len,
                )?;
                let rel_off = (offset - cow_byte_start) as usize;
                merged_buf[rel_off..rel_off + data.len()].copy_from_slice(data);

                let spans = ws.alloc_clusters(cow_clusters, 1)?;
                let mut stage_runs = Vec::with_capacity(spans.len());
                let mut sv = 0_u64;
                for &(lcn, cnt) in &spans {
                    stage_runs.push(NtfsRun {
                        vcn: sv,
                        clusters: cnt,
                        lcn: Some(lcn),
                    });
                    sv += cnt;
                }
                stage_runs_writes(
                    &self.geometry,
                    &stage_runs,
                    &merged_buf,
                    &mut ws.pre_payload_writes,
                )?;

                // If resident -> non-resident (`old_runs.is_empty()`), `cow_start_vcn` is `0`!
                let (mut working_runs, disp) =
                    splice_vcn_interval(&old_runs, cow_start_vcn, cow_end_vcn, &spans, false)?;
                ws.free_clusters_deferred(&disp);

                let needed_total_vcns = new_size.div_ceil(cb).max(1);
                let cur_cov_vcns: u64 = working_runs.iter().map(|r| r.clusters).sum();
                if cur_cov_vcns < needed_total_vcns {
                    let extra = ws.alloc_clusters(needed_total_vcns - cur_cov_vcns, 1)?;
                    let mut v = cur_cov_vcns;
                    for &(lcn, cnt) in &extra {
                        working_runs.push(NtfsRun {
                            vcn: v,
                            clusters: cnt,
                            lcn: Some(lcn),
                        });
                        v += cnt;
                    }
                    working_runs = normalize_ntfs_runs(working_runs);
                }

                EditableStreamStorage::NonResident {
                    runs: working_runs,
                    sparse: false,
                    compression_unit: 0,
                    data_bytes: new_size,
                    initialized_bytes: old_init.max(end_offset),
                }
            };

            {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                match existing_idx {
                    Some(i) => {
                        cat.data_streams[i].storage = updated_storage;
                    }
                    None => {
                        cat.data_streams.push(EditableDataStream {
                            name: stream_utf16.to_vec(),
                            storage: updated_storage,
                        });
                    }
                }
                cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
            }
            if stream_utf16.is_empty() {
                ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            }

            ws.finalize(self, cx, "write_stream_at", digest, new_size)
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Truncate or extend unnamed `$DATA` (`stream_utf16 == &[]`) or a named ADS (`stream_utf16 != &[]`).
    #[allow(clippy::too_many_lines)]
    pub fn truncate_stream_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        new_size: u64,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.truncate_stream_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        for &u in stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&new_size.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            validate_ntfs_stream_name_utf16(stream_utf16)?;
            if new_size > i64::MAX as u64 {
                return Err(FfsError::Format(
                    "NTFS truncate size exceeds i64::MAX".into(),
                ));
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            if cat_ro.is_directory && stream_utf16.is_empty() {
                return Err(FfsError::IsDirectory);
            }
            let target_folded = self.fold_upcase(stream_utf16);
            let stream_idx = cat_ro
                .data_streams
                .iter()
                .position(|s| self.fold_upcase(&s.name) == target_folded)
                .ok_or_else(|| FfsError::NotFound("NTFS data stream not found".into()))?;
            let cur_stream = cat_ro.data_streams[stream_idx].clone();
            let cb = u64::from(self.geometry.cluster_bytes());

            let updated_storage = match cur_stream.storage {
                EditableStreamStorage::Resident(ref old_bytes) => {
                    if new_size <= MAX_RESIDENT_DATA_PAYLOAD as u64 {
                        let mut next = old_bytes.clone();
                        next.resize(new_size as usize, 0);
                        EditableStreamStorage::Resident(next)
                    } else {
                        let need_vcns = new_size.div_ceil(cb);
                        let spans = ws.alloc_clusters(need_vcns, 1)?;
                        let mut runs = Vec::new();
                        let mut v = 0_u64;
                        for &(lcn, cnt) in &spans {
                            runs.push(NtfsRun {
                                vcn: v,
                                clusters: cnt,
                                lcn: Some(lcn),
                            });
                            v += cnt;
                        }
                        let init_len = if old_bytes.is_empty() {
                            0_u64
                        } else {
                            let mut first_cl = vec![0_u8; cb as usize];
                            first_cl[..old_bytes.len()].copy_from_slice(old_bytes);
                            stage_runs_writes(
                                &self.geometry,
                                &runs[..1],
                                &first_cl,
                                &mut ws.pre_payload_writes,
                            )?;
                            old_bytes.len() as u64
                        };
                        EditableStreamStorage::NonResident {
                            runs: normalize_ntfs_runs(runs),
                            sparse: false,
                            compression_unit: 0,
                            data_bytes: new_size,
                            initialized_bytes: init_len,
                        }
                    }
                }
                EditableStreamStorage::NonResident {
                    ref runs,
                    sparse,
                    compression_unit,
                    data_bytes: old_size,
                    initialized_bytes: old_init,
                } => {
                    if !sparse && new_size <= MAX_RESIDENT_DATA_PAYLOAD as u64 {
                        let prefix = read_editable_stream_prefix(
                            self,
                            cx,
                            &cur_stream,
                            0,
                            new_size as usize,
                        )?;
                        ws.free_clusters_deferred(&physical_spans_of_runs(runs));
                        EditableStreamStorage::Resident(prefix)
                    } else if new_size == 0 && sparse {
                        ws.free_clusters_deferred(&physical_spans_of_runs(runs));
                        EditableStreamStorage::NonResident {
                            runs: Vec::new(),
                            sparse: true,
                            compression_unit,
                            data_bytes: 0,
                            initialized_bytes: 0,
                        }
                    } else {
                        let need_vcns = new_size.div_ceil(cb);
                        let old_vcns: u64 = runs.iter().map(|r| r.clusters).sum();
                        if new_size <= old_size {
                            let (mut kept, disp) = splice_vcn_interval(
                                runs,
                                need_vcns,
                                old_vcns.max(need_vcns),
                                &[],
                                sparse,
                            )?;
                            ws.free_clusters_deferred(&disp);
                            kept.retain(|r| r.vcn < need_vcns);
                            EditableStreamStorage::NonResident {
                                runs: normalize_ntfs_runs(kept),
                                sparse,
                                compression_unit,
                                data_bytes: new_size,
                                initialized_bytes: old_init.min(new_size),
                            }
                        } else {
                            let mut next_runs = runs.clone();
                            if need_vcns > old_vcns {
                                let add = need_vcns - old_vcns;
                                if sparse {
                                    next_runs.push(NtfsRun {
                                        vcn: old_vcns,
                                        clusters: add,
                                        lcn: None,
                                    });
                                } else {
                                    let spans = ws.alloc_clusters(add, 1)?;
                                    let mut v = old_vcns;
                                    for &(lcn, cnt) in &spans {
                                        next_runs.push(NtfsRun {
                                            vcn: v,
                                            clusters: cnt,
                                            lcn: Some(lcn),
                                        });
                                        v += cnt;
                                    }
                                }
                            }
                            EditableStreamStorage::NonResident {
                                runs: normalize_ntfs_runs(next_runs),
                                sparse,
                                compression_unit,
                                data_bytes: new_size,
                                initialized_bytes: old_init,
                            }
                        }
                    }
                }
            };

            {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.data_streams[stream_idx].storage = updated_storage;
                cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
            }
            if stream_utf16.is_empty() {
                ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            }
            ws.finalize(self, cx, "truncate_stream_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Delete a named Alternate Data Stream (`stream_utf16` must be non-empty) from `target_ref`,
    /// reclaiming all of its clusters and any emptied extension MFT records.
    pub fn unlink_stream_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.unlink_stream_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        for &u in stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if stream_utf16.is_empty() {
                return Err(FfsError::Format(
                    "cannot unlink unnamed $DATA stream via ADS unlink".into(),
                ));
            }
            validate_ntfs_stream_name_utf16(stream_utf16)?;
            let mut ws = TxWorkspace::load(self, cx)?;
            let target_folded = self.fold_upcase(stream_utf16);
            let freed = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                let idx = cat
                    .data_streams
                    .iter()
                    .position(|s| self.fold_upcase(&s.name) == target_folded)
                    .ok_or_else(|| FfsError::NotFound("NTFS ADS stream not found".into()))?;
                let removed = cat.data_streams.remove(idx);
                cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
                match removed.storage {
                    EditableStreamStorage::Resident(_) => Vec::new(),
                    EditableStreamStorage::NonResident { runs, .. } => {
                        physical_spans_of_runs(&runs)
                    }
                }
            };
            ws.free_clusters_deferred(&freed);
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "unlink_stream_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Rename a named Alternate Data Stream on `target_ref` (used to hide open-unlinked ADS streams).
    pub fn rename_stream_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        old_stream_utf16: &[u16],
        new_stream_utf16: &[u16],
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.rename_stream_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        for &u in old_stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        for &u in new_stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if old_stream_utf16.is_empty() || new_stream_utf16.is_empty() {
                return Err(FfsError::Format(
                    "ADS rename requires non-empty names".into(),
                ));
            }
            validate_ntfs_stream_name_utf16(old_stream_utf16)?;
            validate_ntfs_stream_name_utf16(new_stream_utf16)?;
            let mut ws = TxWorkspace::load(self, cx)?;
            let old_folded = self.fold_upcase(old_stream_utf16);
            let new_folded = self.fold_upcase(new_stream_utf16);
            {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                if old_folded != new_folded
                    && cat
                        .data_streams
                        .iter()
                        .any(|s| self.fold_upcase(&s.name) == new_folded)
                {
                    return Err(FfsError::Exists);
                }
                let idx = cat
                    .data_streams
                    .iter()
                    .position(|s| self.fold_upcase(&s.name) == old_folded)
                    .ok_or_else(|| FfsError::NotFound("NTFS ADS stream not found".into()))?;
                cat.data_streams[idx].name = new_stream_utf16.to_vec();
                cat.set_std_times(None, None, Some(now_ticks), None);
            }
            ws.finalize(self, cx, "rename_stream_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Add a hard link `(new_parent_ref, new_name_utf16)` to an existing regular file `target_ref`.
    pub fn link_entry_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        new_parent_ref: NtfsReference,
        new_name_utf16: &[u16],
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.link_entry_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        hasher.update(&new_parent_ref.record.to_le_bytes());
        for &u in new_name_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        let digest = *hasher.finalize().as_bytes();

        let _ = self.ensure_mft_headroom(cx, 1, 1);

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            validate_ntfs_component_utf16(new_name_utf16)?;
            if target_ref.record < FIRST_NON_RESERVED_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let target_ro = ws.load_catalog(self, cx, target_ref)?;
            if target_ro.is_directory {
                return Err(FfsError::PermissionDenied);
            }
            if target_ro.file_names.len() >= usize::from(u16::MAX) {
                return Err(FfsError::NoSpace);
            }
            if ws
                .lookup_in_dir(self, cx, new_parent_ref, new_name_utf16)?
                .is_some()
            {
                return Err(FfsError::Exists);
            }

            let ns = choose_ntfs_namespace(new_name_utf16);
            let new_fn_struct = NtfsFileName {
                parent: new_parent_ref,
                namespace: ns,
                name: new_name_utf16.to_vec(),
            };
            let raw_fn_bytes = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.file_names.push(EditableFileName {
                    file_name: new_fn_struct.clone(),
                    ctime: 0,
                    mtime: 0,
                    mft_time: 0,
                    atime: 0,
                    allocated_size: 0,
                    data_size: 0,
                    flags: 0,
                    reparse: 0,
                });
                cat.sync_filename_duplicated_fields(self.geometry.cluster_bytes());
                cat.file_names.last().expect("pushed").encode()?
            };

            ws.dir_entries_mut(self, cx, new_parent_ref)?
                .push(I30RawEntry {
                    reference: target_ref,
                    file_name: new_fn_struct,
                    raw_fn_bytes,
                });
            ws.catalog_mut(self, cx, new_parent_ref)?.set_std_times(
                None,
                Some(now_ticks),
                Some(now_ticks),
                None,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;

            ws.finalize(self, cx, "link_entry_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Unlink a regular file (`expect_dir == Some(false)`), remove an empty directory
    /// (`expect_dir == Some(true)`), or remove either (`expect_dir == None`), returning
    /// `(target_reference, remaining_visible_links)`.
    pub fn unlink_entry_at(
        &mut self,
        cx: &Cx,
        parent_ref: NtfsReference,
        name_utf16: &[u16],
        expect_dir: Option<bool>,
        now_ticks: u64,
    ) -> NtfsTxOutcome<(NtfsReference, u32)> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.unlink_entry_at:");
        hasher.update(&parent_ref.record.to_le_bytes());
        for &u in name_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<(NtfsReference, u32)>> {
            validate_ntfs_component_utf16(name_utf16)?;
            let mut ws = TxWorkspace::load(self, cx)?;
            let matched = ws
                .lookup_in_dir(self, cx, parent_ref, name_utf16)?
                .ok_or_else(|| FfsError::NotFound("NTFS directory entry not found".into()))?;
            let target_ref = matched.reference;
            if target_ref.record < FIRST_NON_RESERVED_SLOT {
                return Err(FfsError::PermissionDenied);
            }

            let target_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            match expect_dir {
                Some(true) if !target_ro.is_directory => return Err(FfsError::NotDirectory),
                Some(false) if target_ro.is_directory => return Err(FfsError::IsDirectory),
                _ => {}
            }
            if target_ro.is_directory {
                let dir_idx = target_ro
                    .dir_index
                    .as_ref()
                    .ok_or_else(|| corrupt(0, "directory lacks $I30"))?;
                if !self.catalog_directory_is_empty(cx, dir_idx)? {
                    return Err(FfsError::NotEmpty);
                }
            }

            let remaining_visible = remove_link_from_workspace(
                self,
                cx,
                &mut ws,
                parent_ref,
                target_ref,
                &matched.file_name,
                now_ticks,
            )?;
            if remaining_visible == 0 {
                ws.deallocate_entire_catalog(self, target_ref.record)?;
            } else {
                ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            }

            ws.finalize(
                self,
                cx,
                if expect_dir == Some(true) {
                    "rmdir_at"
                } else {
                    "unlink_at"
                },
                digest,
                (target_ref, remaining_visible),
            )
        })();

        let final_plan = match plan_res {
            Ok(plan) => Ok(plan),
            Err(FfsError::NoSpace) => self
                .plan_unlink_zero_cluster_fallback(cx, digest, parent_ref, name_utf16, expect_dir)
                .map_err(|_| FfsError::NoSpace),
            Err(err) => Err(err),
        };

        match final_plan {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Zero-cluster in-place `$LogFile` `$I30` delete fallback so `unlink` / `rmdir` succeeds
    /// even when 100% of volume clusters are allocated (`ENOSPC` on COW `INDX` rebalance).
    fn plan_unlink_zero_cluster_fallback(
        &self,
        cx: &Cx,
        digest: [u8; 32],
        parent_ref: NtfsReference,
        name_utf16: &[u16],
        expect_dir: Option<bool>,
    ) -> Result<PreparedTxPlan<(NtfsReference, u32)>> {
        validate_ntfs_component_utf16(name_utf16)?;
        let mut ws = TxWorkspace::load(self, cx)?;
        let matched = ws
            .lookup_in_dir(self, cx, parent_ref, name_utf16)?
            .ok_or_else(|| FfsError::NotFound("NTFS directory entry not found".into()))?;
        let target_ref = matched.reference;
        if target_ref.record < FIRST_NON_RESERVED_SLOT {
            return Err(FfsError::PermissionDenied);
        }
        let parent_cat = ws.load_catalog(self, cx, parent_ref)?.clone();
        if !parent_cat.old_extensions.is_empty() || matched.file_name.namespace == 2 {
            return Err(FfsError::NoSpace);
        }
        let target_ro = ws.load_catalog(self, cx, target_ref)?.clone();
        match expect_dir {
            Some(true) if !target_ro.is_directory => return Err(FfsError::NotDirectory),
            Some(false) if target_ro.is_directory => return Err(FfsError::IsDirectory),
            _ => {}
        }
        if target_ro.is_directory {
            let dir_idx = target_ro
                .dir_index
                .as_ref()
                .ok_or_else(|| corrupt(0, "directory lacks $I30"))?;
            if !self.catalog_directory_is_empty(cx, dir_idx)? {
                return Err(FfsError::NotEmpty);
            }
        }
        let visible_links = target_ro
            .file_names
            .iter()
            .filter(|f| f.file_name.namespace != 2)
            .count();
        if visible_links != 1 {
            return Err(FfsError::NoSpace);
        }

        let parent_no = u32::try_from(parent_ref.record).map_err(|_| FfsError::NoSpace)?;
        let parent_record =
            NtfsFileRecord::parse(&parent_cat.old_base_raw).map_err(|err| parse_err(&err))?;
        let p_indx_slot = if let Some(bb) = directory_has_external_indx(&parent_record)? {
            Some(self.plan_open_attr(
                &mut ws.staged_open,
                &mut ws.open_regs,
                parent_ref,
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
                bb,
            )?)
        } else {
            None
        };
        let (p_vcn, p_cbo, p_lcns) = self.map_mft_record_transfer(&ws.mft_runs, parent_no)?;
        let del_plan = self.plan_directory_delete(
            cx,
            parent_no,
            &parent_cat.old_base_raw,
            &parent_record,
            ws.mft_attr_slot,
            p_vcn,
            p_cbo,
            &p_lcns,
            p_indx_slot,
            &matched.file_name.name,
        )?;
        ws.mutation_specs.extend(del_plan.log_specs);
        if del_plan.updated_dir_raw != parent_cat.old_base_raw {
            ws.target_writes.push(TargetWriteKind::MftRecord {
                runs: ws.mft_runs.clone(),
                record_no: parent_no,
                raw_protected: del_plan.updated_dir_raw,
            });
        }
        if !del_plan.updated_indx_blocks.is_empty() {
            let (a0_runs, _, _) = extract_plain_nonresident_stream(
                &self.geometry,
                &parent_record,
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
            )?;
            for (boff, raw_blk) in del_plan.updated_indx_blocks {
                ws.target_writes.push(TargetWriteKind::IndxBlock {
                    runs: a0_runs.clone(),
                    byte_offset: boff,
                    raw_protected: raw_blk,
                });
            }
        }

        ws.deallocate_entire_catalog(self, target_ref.record)?;
        ws.finalize(
            self,
            cx,
            if expect_dir == Some(true) {
                "rmdir_at"
            } else {
                "unlink_at"
            },
            digest,
            (target_ref, 0),
        )
    }

    /// Rename `(src_parent_ref, src_name_utf16)` to `(dst_parent_ref, dst_name_utf16)`,
    /// supporting `no_replace` (`RENAME_NOREPLACE`), case-only self-rename, POSIX same-inode
    /// hard-link no-op, directory ancestry cycle prevention, atomic target replacement, and
    /// optional root orphan retention (`retain_dst_orphan_name`) when an overwritten file's
    /// last visible link is still pinned by open file handles.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn rename_entry_at(
        &mut self,
        cx: &Cx,
        src_parent_ref: NtfsReference,
        src_name_utf16: &[u16],
        dst_parent_ref: NtfsReference,
        dst_name_utf16: &[u16],
        no_replace: bool,
        retain_dst_orphan_name: Option<&[u16]>,
        now_ticks: u64,
    ) -> NtfsTxOutcome<NtfsRenameOutcome> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.rename_entry_at:");
        hasher.update(&src_parent_ref.record.to_le_bytes());
        for &u in src_name_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&dst_parent_ref.record.to_le_bytes());
        for &u in dst_name_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&[u8::from(no_replace)]);
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<NtfsRenameOutcome>> {
            validate_ntfs_component_utf16(src_name_utf16)?;
            validate_ntfs_component_utf16(dst_name_utf16)?;
            let mut ws = TxWorkspace::load(self, cx)?;

            let src_match = ws
                .lookup_in_dir(self, cx, src_parent_ref, src_name_utf16)?
                .ok_or_else(|| FfsError::NotFound("NTFS rename source not found".into()))?;
            let src_ref = src_match.reference;
            if src_ref.record < FIRST_NON_RESERVED_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let src_ro = ws.load_catalog(self, cx, src_ref)?.clone();

            let dst_match_opt = ws.lookup_in_dir(self, cx, dst_parent_ref, dst_name_utf16)?;
            if let Some(ref dst_match) = dst_match_opt {
                if no_replace {
                    return Err(FfsError::Exists);
                }
                if dst_match.reference == src_ref {
                    let same_folded_in_same_dir = src_parent_ref == dst_parent_ref
                        && self.fold_upcase(&src_match.file_name.name)
                            == self.fold_upcase(dst_name_utf16);
                    if !same_folded_in_same_dir || src_match.file_name.name == dst_name_utf16 {
                        // POSIX hard-link same-inode rename OR exact self-rename: atomic no-op!
                        return ws.finalize(
                            self,
                            cx,
                            "rename_entry_at",
                            digest,
                            NtfsRenameOutcome {
                                moved_reference: src_ref,
                                overwritten_reference: None,
                                overwritten_remaining_links: 0,
                                overwritten_retained_as_orphan: false,
                                noop_same_inode: true,
                            },
                        );
                    }
                    // Case-only rename (`foo.txt` -> `FOO.txt`) of the SAME directory entry!
                }
            }

            // Directory ancestry cycle check (`src` cannot become a descendant of itself!).
            if src_ro.is_directory && src_parent_ref != dst_parent_ref {
                let mut cursor = dst_parent_ref;
                for _ in 0..4096 {
                    if cursor == src_ref {
                        return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                            libc::EINVAL,
                        )));
                    }
                    if cursor.record == 5 {
                        break;
                    }
                    let cur_cat = ws.load_catalog(self, cx, cursor)?;
                    let Some(first_fn) = cur_cat.file_names.first() else {
                        break;
                    };
                    cursor = first_fn.file_name.parent;
                }
            }

            let mut overwritten_ref = None;
            let mut overwritten_remaining = 0_u32;
            let mut overwritten_retained = false;

            if let Some(ref dst_match) = dst_match_opt
                && dst_match.reference != src_ref
            {
                let dst_ref = dst_match.reference;
                if dst_ref.record < FIRST_NON_RESERVED_SLOT {
                    return Err(FfsError::PermissionDenied);
                }
                let dst_ro = ws.load_catalog(self, cx, dst_ref)?.clone();
                if src_ro.is_directory && !dst_ro.is_directory {
                    return Err(FfsError::NotDirectory);
                }
                if !src_ro.is_directory && dst_ro.is_directory {
                    return Err(FfsError::IsDirectory);
                }
                if dst_ro.is_directory {
                    let dst_idx = dst_ro
                        .dir_index
                        .as_ref()
                        .ok_or_else(|| corrupt(0, "dst dir lacks $I30"))?;
                    if !self.catalog_directory_is_empty(cx, dst_idx)? {
                        return Err(FfsError::NotEmpty);
                    }
                }

                let rem = remove_link_from_workspace(
                    self,
                    cx,
                    &mut ws,
                    dst_parent_ref,
                    dst_ref,
                    &dst_match.file_name,
                    now_ticks,
                )?;
                overwritten_ref = Some(dst_ref);
                overwritten_remaining = rem;
                if rem == 0 {
                    if let Some(orphan_utf16) = retain_dst_orphan_name {
                        validate_ntfs_component_utf16(orphan_utf16)?;
                        let root_record = read_mft_record_via_runs(
                            &self.device,
                            cx,
                            &self.geometry,
                            &ws.mft_runs,
                            5,
                        )?;
                        let root_dir_ref = NtfsReference {
                            record: 5,
                            sequence: root_record.sequence,
                        };
                        let orphan_fn = NtfsFileName {
                            parent: root_dir_ref,
                            namespace: 1,
                            name: orphan_utf16.to_vec(),
                        };
                        let raw_orphan_fn = {
                            let dst_cat = ws.catalog_mut(self, cx, dst_ref)?;
                            dst_cat.file_names.push(EditableFileName {
                                file_name: orphan_fn.clone(),
                                ctime: 0,
                                mtime: 0,
                                mft_time: 0,
                                atime: 0,
                                allocated_size: 0,
                                data_size: 0,
                                flags: 0,
                                reparse: 0,
                            });
                            dst_cat.sync_filename_duplicated_fields(self.geometry.cluster_bytes());
                            dst_cat.file_names.last().expect("orphan").encode()?
                        };
                        ws.dir_entries_mut(self, cx, root_dir_ref)?
                            .push(I30RawEntry {
                                reference: dst_ref,
                                file_name: orphan_fn,
                                raw_fn_bytes: raw_orphan_fn,
                            });
                        overwritten_retained = true;
                    } else {
                        ws.deallocate_entire_catalog(self, dst_ref.record)?;
                    }
                } else {
                    ws.sync_target_into_parent_dirs(self, cx, dst_ref)?;
                }
            }

            // Now move `src` from `(src_parent_ref, src_match)` to `(dst_parent_ref, dst_name_utf16)`!
            let _ = remove_link_from_workspace(
                self,
                cx,
                &mut ws,
                src_parent_ref,
                src_ref,
                &src_match.file_name,
                now_ticks,
            )?;
            let new_ns = choose_ntfs_namespace(dst_name_utf16);
            let new_src_fn = NtfsFileName {
                parent: dst_parent_ref,
                namespace: new_ns,
                name: dst_name_utf16.to_vec(),
            };
            let new_src_raw_fn = {
                let src_cat = ws.catalog_mut(self, cx, src_ref)?;
                src_cat.set_std_times(None, None, Some(now_ticks), None);
                src_cat.file_names.push(EditableFileName {
                    file_name: new_src_fn.clone(),
                    ctime: 0,
                    mtime: 0,
                    mft_time: 0,
                    atime: 0,
                    allocated_size: 0,
                    data_size: 0,
                    flags: 0,
                    reparse: 0,
                });
                src_cat.sync_filename_duplicated_fields(self.geometry.cluster_bytes());
                src_cat.file_names.last().expect("src fn").encode()?
            };
            ws.dir_entries_mut(self, cx, dst_parent_ref)?
                .push(I30RawEntry {
                    reference: src_ref,
                    file_name: new_src_fn,
                    raw_fn_bytes: new_src_raw_fn,
                });
            ws.catalog_mut(self, cx, dst_parent_ref)?.set_std_times(
                None,
                Some(now_ticks),
                Some(now_ticks),
                None,
            );
            ws.sync_target_into_parent_dirs(self, cx, src_ref)?;

            ws.finalize(
                self,
                cx,
                "rename_entry_at",
                digest,
                NtfsRenameOutcome {
                    moved_reference: src_ref,
                    overwritten_reference: overwritten_ref,
                    overwritten_remaining_links: overwritten_remaining,
                    overwritten_retained_as_orphan: overwritten_retained,
                    noop_same_inode: false,
                },
            )
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Update file/directory metadata (`FILE_ATTR_READONLY`, `atime`, `mtime`, `mft_time`)
    /// on `target_ref` and synchronize duplicated `FILE_NAME` fields in all parent `$I30` indexes.
    pub fn set_metadata_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        read_only: Option<bool>,
        atime_ticks: Option<u64>,
        mtime_ticks: Option<u64>,
        mft_time_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.set_metadata_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        hasher.update(&mft_time_ticks.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            let mut ws = TxWorkspace::load(self, cx)?;
            {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                if let Some(ro) = read_only {
                    let mut flags = cat.std_flags();
                    if ro {
                        flags |= FILE_ATTR_READONLY;
                    } else {
                        flags &= !FILE_ATTR_READONLY;
                    }
                    cat.set_std_flags(flags);
                }
                cat.set_std_times(None, mtime_ticks, Some(mft_time_ticks), atime_ticks);
            }
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "set_metadata_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }
}

/// Remove `matched_fn` (plus any paired DOS `namespace == 2` alias in `parent_ref` when no
/// non-DOS link of `target_ref` remains in `parent_ref`) from `target_ref`'s `file_names`
/// AND from `parent_ref`'s `$I30` entries, returning remaining visible (`namespace != 2`) links.
fn remove_link_from_workspace(
    engine: &NtfsTransactionEngine,
    cx: &Cx,
    ws: &mut TxWorkspace,
    parent_ref: NtfsReference,
    target_ref: NtfsReference,
    matched_fn: &NtfsFileName,
    now_ticks: u64,
) -> Result<u32> {
    let mut removed_identities: Vec<(u8, Vec<u16>)> = Vec::new();
    let remaining_visible = {
        let cat = ws.catalog_mut(engine, cx, target_ref)?;
        let pos = cat
            .file_names
            .iter()
            .position(|f| {
                f.file_name.parent == parent_ref
                    && f.file_name.namespace == matched_fn.namespace
                    && f.file_name.name == matched_fn.name
            })
            .ok_or_else(|| corrupt(0, "target record lacks matched FILE_NAME"))?;
        let primary = cat.file_names.remove(pos);
        removed_identities.push((primary.file_name.namespace, primary.file_name.name));

        // If `matched_fn.namespace == 2` (unlinked via DOS 8.3 alias) and a single paired
        // `namespace == 1` (`WIN32`) entry exists in `parent_ref`, remove that `WIN32` entry too!
        if matched_fn.namespace == 2 {
            let win32_in_parent: Vec<usize> = cat
                .file_names
                .iter()
                .enumerate()
                .filter(|(_, f)| f.file_name.parent == parent_ref && f.file_name.namespace == 1)
                .map(|(i, _)| i)
                .collect();
            if win32_in_parent.len() == 1 {
                let paired = cat.file_names.remove(win32_in_parent[0]);
                removed_identities.push((paired.file_name.namespace, paired.file_name.name));
            }
        }

        // If no non-DOS (`namespace != 2`) link remains in `parent_ref`, remove any paired
        // `namespace == 2` (`DOS`) alias in `parent_ref` so no orphaned DOS-only link remains!
        let non_dos_in_parent = cat
            .file_names
            .iter()
            .any(|f| f.file_name.parent == parent_ref && f.file_name.namespace != 2);
        if !non_dos_in_parent {
            let mut i = 0_usize;
            while i < cat.file_names.len() {
                if cat.file_names[i].file_name.parent == parent_ref
                    && cat.file_names[i].file_name.namespace == 2
                {
                    let dos = cat.file_names.remove(i);
                    removed_identities.push((dos.file_name.namespace, dos.file_name.name));
                } else {
                    i += 1;
                }
            }
        }

        cat.set_std_times(None, None, Some(now_ticks), None);
        cat.file_names
            .iter()
            .filter(|f| f.file_name.namespace != 2)
            .count() as u32
    };

    let parent_entries = ws.dir_entries_mut(engine, cx, parent_ref)?;
    for (rem_ns, rem_name) in &removed_identities {
        parent_entries.retain(|ent| {
            !(ent.reference == target_ref
                && ent.file_name.namespace == *rem_ns
                && ent.file_name.name == *rem_name)
        });
    }
    ws.catalog_mut(engine, cx, parent_ref)?.set_std_times(
        None,
        Some(now_ticks),
        Some(now_ticks),
        None,
    );
    Ok(remaining_visible)
}
