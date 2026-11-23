//! Reference-addressed native NTFS 3.1 namespace, positioned stream, ADS,
//! hard-link, rename-overwrite, truncate, and metadata transactions for [`NtfsFs`]
//! and companion CLI operations.

mod ea;
mod sparse;

pub use ea::NtfsEaSetMode;

use std::collections::{BTreeMap, BTreeSet};

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::logfile_writer::NtfsClientUpdateSpec;
use ffs_ondisk::ntfs::recovery::{
    FileEdit, FileEditResult, FileOperation, RecoveryPass, apply_file_edit,
};
use ffs_ondisk::ntfs::reparse::NtfsReparsePoint;
use ffs_ondisk::ntfs::usn::{
    USN_REASON_BASIC_INFO_CHANGE, USN_REASON_CLOSE, USN_REASON_DATA_EXTEND,
    USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_TRUNCATION, USN_REASON_FILE_CREATE,
    USN_REASON_FILE_DELETE, USN_REASON_HARD_LINK_CHANGE, USN_REASON_RENAME_NEW_NAME,
    USN_REASON_RENAME_OLD_NAME, UsnRecordV2,
};
use ffs_ondisk::ntfs::view_index::ViewCollation;
use ffs_ondisk::ntfs::{
    ATTRIBUTE_LIST, COMPRESSED, DATA, EA, EA_INFORMATION, ENCRYPTED, LOGGED_UTILITY_STREAM,
    NtfsFileRecord, NtfsLogOp, NtfsReference, NtfsRun, OBJECT_ID, REPARSE_POINT, SPARSE,
    restore_record,
};
use ffs_ondisk::ntfs_security::{
    ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_OBJECT_INHERIT, NtfsSecurityDescriptor,
    inherit_security_descriptor,
};

use crate::reader::wof::BACKING_NAME as WOF_BACKING_NAME;
use crate::reparse_provider::{ReparseCapability, classify_reparse_point};
use crate::security_policy::NtfsSecurityPatch;

use super::btree::I30RawEntry;
use super::catalog::{
    EditableCatalog, EditableDataStream, EditableDirIndex, EditableFileName, EditableStreamStorage,
    allocate_cluster_runs, coalesce_physical_spans, dirty_bitmap_range, is_bit_set,
    normalize_ntfs_runs, physical_spans_of_runs, set_or_clear_run_list, stage_runs_writes,
    stale_reference,
};
use super::compression::{self, UNIT_CLUSTERS};
use super::dir_index::{
    DirPrePayloadWrite, I30_NAME, build_empty_small_index_root, directory_has_external_indx,
    find_attr_offset_in_restored,
};
use super::ops::{
    DEFAULT_NTFS_FILETIME, FILE_ATTR_ARCHIVE, FILE_ATTR_DIRECTORY, FileDataEdit,
    MAX_RESIDENT_DATA_PAYLOAD, PreparedTxPlan, TargetWriteKind, encode_standard_information,
    extract_parent_security, find_contiguous_zero_bits, set_or_clear_bits,
};
use super::secondary::{
    EXTEND_OBJID_UPPER, EXTEND_REPARSE_UPPER, EXTEND_USNJRNL_UPPER, NtfsObjectIdData, OBJID_O_NAME,
    REPARSE_R_NAME, append_usn_records_to_catalog, encode_objid_o_data, encode_reparse_r_key,
    flush_view_index_into_catalog, remove_view_entries_matching, upsert_view_entry,
};
use super::secure::SecureStoreState;
use super::{
    MAX_FILE_EDIT_BYTES, NtfsTransactionEngine, NtfsTxOutcome, OpenAttrRuntime, SECTOR_BYTES,
    checkpoint, corrupt, extract_plain_nonresident_stream, parse_err, read_mapped_runs,
    read_mft_record_raw_via_runs, read_mft_record_via_runs, unsupported,
};

const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
pub(super) const FILE_ATTR_READONLY: u32 = 0x0000_0001;
pub(super) const FILE_ATTR_SPARSE_FILE: u32 = 0x0000_0200;
pub(super) const FILE_ATTR_REPARSE_POINT: u32 = 0x0000_0400;
pub(super) const FILE_ATTR_COMPRESSED: u32 = 0x0000_0800;
pub(super) const FILE_ATTR_ENCRYPTED: u32 = 0x0000_4000;
pub(super) const MIN_USER_MFT_SLOT: u64 = 24;
pub(super) const FIRST_NON_RESERVED_SLOT: u64 = 16;

/// Objects participating in one completed native rename transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsRenameOutcome {
    pub source: NtfsReference,
    pub replaced: Option<NtfsReference>,
}

/// Extended rename outcome including orphan-retention and remaining-link metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsExtendedRenameOutcome {
    pub moved_reference: NtfsReference,
    pub overwritten_reference: Option<NtfsReference>,
    pub overwritten_remaining_links: u32,
    pub overwritten_retained_as_orphan: bool,
    pub noop_same_inode: bool,
}

/// Native changes that become visible and recover together in one logged
/// transaction. Explicit modification time takes precedence over a resize.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtfsSetAttributes {
    /// New unnamed DATA length; omitted for metadata-only requests.
    pub size: Option<u64>,
    /// Native `FILE_ATTRIBUTE_READONLY` value.
    pub read_only: Option<bool>,
    /// Access time in signed-range NTFS FILETIME ticks.
    pub atime_ticks: Option<u64>,
    /// Modification time in signed-range NTFS FILETIME ticks.
    pub mtime_ticks: Option<u64>,
    /// Descriptor edit preserving unrelated native security information.
    pub security: Option<NtfsSecurityPatch>,
}

/// Validate a native filename without normalizing or replacing code units.
pub fn validate_ntfs_component_utf16(name: &[u16]) -> Result<()> {
    if name.len() > 255 {
        return Err(FfsError::NameTooLong);
    }
    if name.is_empty()
        || name == [46]
        || name == [46, 46]
        || name
            .iter()
            .any(|unit| matches!(unit, 0 | 0x2F | 0x5C | 0x3A))
    {
        return Err(FfsError::RequestRejected {
            errno: libc::EINVAL,
            detail: "invalid NTFS native filename component".into(),
        });
    }
    Ok(())
}

/// Validate a DATA attribute name. Empty selects the unnamed DATA stream.
pub fn validate_ntfs_stream_name_utf16(name: &[u16]) -> Result<()> {
    if name.len() > 255 {
        return Err(FfsError::NameTooLong);
    }
    if name
        .iter()
        .any(|unit| matches!(unit, 0 | 0x2F | 0x5C | 0x3A))
    {
        return Err(FfsError::RequestRejected {
            errno: libc::EINVAL,
            detail: "invalid NTFS native stream name".into(),
        });
    }
    Ok(())
}

fn stale_target() -> FfsError {
    FfsError::RequestRejected {
        errno: libc::ESTALE,
        detail: "NTFS directory link no longer identifies the requested FILE reference".into(),
    }
}

pub(super) fn too_large_edit() -> FfsError {
    FfsError::RequestRejected {
        errno: libc::EFBIG,
        detail: "NTFS stream edit exceeds the 16 MiB staging limit".into(),
    }
}

/// Select native `FILE_NAME` namespace flag (`3 = WIN32_AND_DOS`, `1 = WIN32`, `0 = POSIX`).
pub(super) fn choose_ntfs_namespace(name: &[u16]) -> u8 {
    let has_posix_only = name
        .iter()
        .any(|&u| u < 0x20 || matches!(u, 0x22 | 0x2A | 0x3C | 0x3E | 0x3F | 0x7C))
        || name.last().is_some_and(|&u| u == 0x20 || u == 0x2E);
    if has_posix_only {
        return 0;
    }
    if is_strict_dos_8_3(name) { 3 } else { 1 }
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

/// Read `[offset .. offset + len]` from an [`EditableDataStream`] (`0` beyond `initialized_bytes` or sparse holes).
pub(super) fn read_editable_stream_prefix(
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
            if let Ok(start) = usize::try_from(offset)
                && start < bytes.len()
            {
                let avail = (bytes.len() - start).min(len);
                out[..avail].copy_from_slice(&bytes[start..start + avail]);
            }
            Ok(out)
        }
        EditableStreamStorage::NonResident {
            runs,
            compressed: true,
            data_bytes,
            initialized_bytes,
            ..
        } => {
            let valid_limit = (*initialized_bytes).min(*data_bytes);
            let mut out = vec![0_u8; len];
            if offset >= valid_limit {
                return Ok(out);
            }
            let readable = usize::try_from(valid_limit - offset)
                .unwrap_or(usize::MAX)
                .min(len);
            let cb = u64::from(engine.geometry.cluster_bytes());
            let unit_bytes = UNIT_CLUSTERS * cb;
            let end_offset = offset + readable as u64;
            let first_u = offset / unit_bytes;
            let last_u = end_offset.div_ceil(unit_bytes);
            for u in first_u..last_u {
                let logical = compression::read_compressed_unit_plaintext(
                    engine,
                    cx,
                    runs,
                    *initialized_bytes,
                    u,
                )?;
                let u_start = u * unit_bytes;
                let u_end = u_start + unit_bytes;
                let ov_start = offset.max(u_start);
                let ov_end = end_offset.min(u_end);
                if ov_start < ov_end {
                    let src_off = (ov_start - u_start) as usize;
                    let dst_off = (ov_start - offset) as usize;
                    let cnt = (ov_end - ov_start) as usize;
                    out[dst_off..dst_off + cnt].copy_from_slice(&logical[src_off..src_off + cnt]);
                }
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
            let readable = usize::try_from(valid_limit - offset)
                .unwrap_or(usize::MAX)
                .min(len);
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
                let avail_in_run = usize::try_from((run.clusters - rel_vcn) * cb - within as u64)
                    .unwrap_or(usize::MAX);
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

pub(super) type SplicedRunPlan = (Vec<NtfsRun>, Vec<(u64, u64)>);

pub(super) fn splice_vcn_interval(
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
        if r_start < start_vcn {
            let keep_end = r_end.min(start_vcn);
            let keep_len = keep_end - r_start;
            prefix.push(NtfsRun {
                vcn: r_start,
                clusters: keep_len,
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
    if replacement_spans.is_empty() && start_vcn < end_vcn {
        if sparse {
            prefix.push(NtfsRun {
                vcn: start_vcn,
                clusters: end_vcn - start_vcn,
                lcn: None,
            });
        } else if end_vcn < old_total_vcns {
            return Err(corrupt(
                0,
                "non-sparse splice cannot remove an interior range",
            ));
        }
        // Empty replacement means a sparse hole or removal of the final
        // allocation suffix during truncation, never a shifted VCN mapping.
    } else if cur_vcn != end_vcn {
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

pub(super) struct PendingUsnEvent {
    pub(super) file_ref: NtfsReference,
    pub(super) parent_ref: NtfsReference,
    pub(super) reason: u32,
    pub(super) file_attributes: u32,
    pub(super) timestamp: u64,
    pub(super) file_name: Vec<u16>,
}

pub(super) struct TxWorkspace {
    pub(super) cur_mft0_raw: Vec<u8>,
    pub(super) mft0_modified: bool,
    pub(super) mft_runs: Vec<NtfsRun>,
    pub(super) mft_data_bytes: u64,
    pub(super) cur_mft_init_bytes: u64,
    pub(super) logical_records: u64,
    pub(super) cur_init_records: u64,
    pub(super) mft_bm: Vec<u8>,
    pub(super) vol_bm_orig: Vec<u8>,
    pub(super) vol_bm: Vec<u8>,
    pub(super) bm_runs: Vec<NtfsRun>,
    pub(super) bm_rec_seq: u16,
    pub(super) vol_clusters: u64,
    pub(super) staged_open: BTreeMap<u32, OpenAttrRuntime>,
    pub(super) open_regs: Vec<(u32, OpenAttrRuntime, NtfsClientUpdateSpec)>,
    pub(super) mft_attr_slot: u16,
    pub(super) pre_payload_writes: Vec<DirPrePayloadWrite>,
    pub(super) mft_zero_writes: Vec<DirPrePayloadWrite>,
    pub(super) mutation_specs: Vec<NtfsClientUpdateSpec>,
    pub(super) target_writes: Vec<TargetWriteKind>,
    pub(super) catalogs: BTreeMap<u64, EditableCatalog>,
    pub(super) dirty_catalogs: BTreeSet<u64>,
    pub(super) fresh_base_records: BTreeMap<u64, Vec<u8>>,
    pub(super) deallocated_records: BTreeSet<u64>,
    pub(super) dir_entries_cache: BTreeMap<u64, Vec<I30RawEntry>>,
    pub(super) dirty_dirs: BTreeSet<u64>,
    pub(super) claimed_spans: Vec<(u64, u64)>,
    pub(super) allocated_clusters: Vec<(u64, u64)>,
    pub(super) freed_clusters: Vec<(u64, u64)>,
    pub(super) alloc_cursor: u64,
    pub(super) secure_store: Option<SecureStoreState>,
    pub(super) pending_usn_events: Vec<PendingUsnEvent>,
}

impl TxWorkspace {
    pub(super) fn load(engine: &NtfsTransactionEngine, cx: &Cx) -> Result<Self> {
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
            fresh_base_records: BTreeMap::new(),
            deallocated_records: BTreeSet::new(),
            dir_entries_cache: BTreeMap::new(),
            dirty_dirs: BTreeSet::new(),
            claimed_spans: Vec::new(),
            allocated_clusters: Vec::new(),
            freed_clusters: Vec::new(),
            alloc_cursor: 1,
            secure_store: None,
            pending_usn_events: Vec::new(),
        })
    }

    pub(super) fn mft_slot_is_allocated(&self, slot: u64) -> bool {
        slot < self.logical_records && is_bit_set(&self.mft_bm, slot)
    }

    fn verify_and_register_runs(&mut self, runs: &[NtfsRun]) -> Result<()> {
        for run in runs {
            let Some(lcn) = run.lcn else {
                continue;
            };
            if lcn == 0 || run.clusters == 0 {
                return Err(corrupt(0, "invalid physical LCN 0 or zero cluster run"));
            }
            let end = lcn
                .checked_add(run.clusters)
                .filter(|&e| e <= self.vol_clusters)
                .ok_or_else(|| corrupt(0, "NTFS run exceeds volume cluster count"))?;
            for bit in lcn..end {
                if !is_bit_set(&self.vol_bm_orig, bit) {
                    return Err(corrupt(
                        0,
                        "NTFS stream references unallocated cluster in $Bitmap",
                    ));
                }
            }
            for &(prev_start, prev_len) in &self.claimed_spans {
                if lcn < prev_start + prev_len && prev_start < end {
                    return Err(corrupt(0, "cross-linked NTFS cluster allocation"));
                }
            }
            self.claimed_spans.push((lcn, run.clusters));
        }
        Ok(())
    }

    fn load_catalog_inner(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        target_ref: NtfsReference,
        allow_view_index: bool,
    ) -> Result<&EditableCatalog> {
        if !self.catalogs.contains_key(&target_ref.record) {
            if target_ref.record >= self.logical_records
                || !is_bit_set(&self.mft_bm, target_ref.record)
            {
                return Err(stale_reference(target_ref));
            }
            let cat = if allow_view_index {
                engine.load_view_index_catalog(cx, &self.mft_runs, target_ref)?
            } else {
                engine.load_editable_catalog(cx, &self.mft_runs, target_ref)?
            };
            for &(ext_no, _, _) in &cat.old_extensions {
                if !is_bit_set(&self.mft_bm, u64::from(ext_no)) {
                    return Err(corrupt(
                        0,
                        "extension MFT record marked free in $MFT::$BITMAP",
                    ));
                }
            }
            for stream in &cat.data_streams {
                if let EditableStreamStorage::NonResident { ref runs, .. } = stream.storage {
                    self.verify_and_register_runs(runs)?;
                }
            }
            if let Some(EditableDirIndex {
                external: Some((ref a0_runs, _, _)),
                ..
            }) = cat.dir_index
            {
                self.verify_and_register_runs(a0_runs)?;
            }
            for view in &cat.view_indexes {
                if let Some((ref a0_runs, _, _)) = view.external {
                    self.verify_and_register_runs(a0_runs)?;
                }
            }
            let pres_runs = cat.preserved_nonresident_runs(engine.geometry.cluster_count())?;
            self.verify_and_register_runs(&pres_runs)?;
            self.verify_and_register_runs(&cat.old_nonres_attrlist_runs)?;
            self.verify_and_register_runs(&cat.old_owned_extra_runs)?;
            self.catalogs.insert(target_ref.record, cat);
        }
        let cat = self
            .catalogs
            .get(&target_ref.record)
            .expect("inserted catalog");
        if cat.base_ref.sequence != target_ref.sequence {
            return Err(stale_reference(target_ref));
        }
        Ok(cat)
    }

    pub(super) fn load_catalog(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        target_ref: NtfsReference,
    ) -> Result<&EditableCatalog> {
        self.load_catalog_inner(engine, cx, target_ref, false)
    }

    pub(super) fn load_view_catalog(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        target_ref: NtfsReference,
    ) -> Result<&EditableCatalog> {
        self.load_catalog_inner(engine, cx, target_ref, true)
    }

    pub(super) fn catalog_mut(
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

    pub(super) fn register_fresh_catalog(
        &mut self,
        cat: EditableCatalog,
        existing_slot_raw: Vec<u8>,
    ) {
        let rec = cat.base_ref.record;
        self.catalogs.insert(rec, cat);
        self.dirty_catalogs.insert(rec);
        self.fresh_base_records.insert(rec, existing_slot_raw);
    }

    pub(super) fn ensure_secure_store(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
    ) -> Result<&mut SecureStoreState> {
        if self.secure_store.is_none() {
            if !self.mft_slot_is_allocated(9) {
                return Err(unsupported(
                    "$Secure (Record 9) is not allocated on this volume",
                ));
            }
            let rec9 =
                read_mft_record_via_runs(&engine.device, cx, &engine.geometry, &self.mft_runs, 9)?;
            let sec_ref = NtfsReference {
                record: 9,
                sequence: rec9.sequence,
            };
            let sec_cat = self.load_view_catalog(engine, cx, sec_ref)?.clone();
            let store = SecureStoreState::load(engine, cx, &sec_cat)?;
            self.secure_store = Some(store);
        }
        Ok(self.secure_store.as_mut().expect("loaded secure store"))
    }

    pub(super) fn intern_security_descriptor(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        descriptor_bytes: &[u8],
    ) -> Result<u32> {
        let _ = self.ensure_secure_store(engine, cx)?;
        let mut store = self.secure_store.take().expect("secure store loaded");
        let mut pre_writes = Vec::new();
        let mut freed = Vec::new();
        let res = store.intern_descriptor(
            engine,
            cx,
            descriptor_bytes,
            &mut pre_writes,
            &mut freed,
            |need_cl| self.alloc_clusters(need_cl, 1),
        );
        self.secure_store = Some(store);
        let id = res?;
        self.pre_payload_writes.extend(pre_writes);
        self.free_clusters_deferred(&freed);
        Ok(id)
    }

    pub(super) fn read_catalog_security_descriptor(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        cat: &EditableCatalog,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(ref raw) = cat.security_descriptor {
            return Ok(Some(raw.clone()));
        }
        if let Some(sec_id) = cat.std_security_id()
            && self.mft_slot_is_allocated(9)
        {
            let _ = self.ensure_secure_store(engine, cx)?;
            let store = self.secure_store.as_ref().expect("secure store");
            let desc = store.read_descriptor_by_id(engine, cx, sec_id)?;
            return Ok(Some(desc));
        }
        Ok(None)
    }

    pub(super) fn lookup_extend_child(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        upper_name: &[u16],
    ) -> Result<Option<NtfsReference>> {
        if !self.mft_slot_is_allocated(11) {
            return Ok(None);
        }
        let rec11 =
            read_mft_record_via_runs(&engine.device, cx, &engine.geometry, &self.mft_runs, 11)?;
        if !rec11.is_directory() {
            return Ok(None);
        }
        let ext_ref = NtfsReference {
            record: 11,
            sequence: rec11.sequence,
        };
        let _ = self.load_view_catalog(engine, cx, ext_ref)?;
        Ok(self
            .lookup_in_dir(engine, cx, ext_ref, upper_name)?
            .map(|e| e.reference))
    }

    pub(super) fn max_view_root_value_bytes(engine: &NtfsTransactionEngine) -> usize {
        let rec_bytes = engine.geometry.record_bytes() as usize;
        let usa_count = rec_bytes / SECTOR_BYTES + 1;
        let hdr_base = if engine.version == [3, 0] { 42 } else { 48 };
        let first_attr = (hdr_base + usa_count * 2).next_multiple_of(8);
        rec_bytes.saturating_sub(first_attr + 540).max(96)
    }

    pub(super) fn sync_reparse_r_index(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        target_ref: NtfsReference,
        new_tag: Option<u32>,
    ) -> Result<()> {
        let Some(reparse_ref) = self.lookup_extend_child(engine, cx, &EXTEND_REPARSE_UPPER)? else {
            return Ok(());
        };
        let _ = self.load_view_catalog(engine, cx, reparse_ref)?;
        let mut rep_cat = self
            .catalogs
            .remove(&reparse_ref.record)
            .ok_or_else(|| corrupt(0, "missing $Extend/$Reparse catalog"))?;
        let res = (|| -> Result<()> {
            let mut entries = if let Some(view) = rep_cat
                .view_indexes
                .iter()
                .find(|v| v.index_name == REPARSE_R_NAME)
            {
                engine.collect_view_index_entries(cx, view)?
            } else {
                Vec::new()
            };
            let removed = remove_view_entries_matching(&mut entries, |e| {
                e.key.len() >= 12
                    && (u64::from_le_bytes([
                        e.key[4], e.key[5], e.key[6], e.key[7], e.key[8], e.key[9], e.key[10],
                        e.key[11],
                    ]) & 0x0000_FFFF_FFFF_FFFF)
                        == target_ref.record
            });
            if let Some(tag) = new_tag {
                let key = encode_reparse_r_key(tag, target_ref)?;
                upsert_view_entry(&mut entries, key, Vec::new(), ViewCollation::U32Slice);
            } else if !removed {
                return Ok(());
            }
            let max_root = Self::max_view_root_value_bytes(engine);
            let mut pre = Vec::new();
            let mut freed = Vec::new();
            flush_view_index_into_catalog(
                &engine.geometry,
                &mut rep_cat,
                &REPARSE_R_NAME,
                ViewCollation::U32Slice,
                entries,
                max_root,
                &mut pre,
                &mut freed,
                |n, min_c| self.alloc_clusters(n, min_c),
            )?;
            self.pre_payload_writes.extend(pre);
            self.free_clusters_deferred(&freed);
            self.dirty_catalogs.insert(reparse_ref.record);
            Ok(())
        })();
        self.catalogs.insert(reparse_ref.record, rep_cat);
        res
    }

    pub(super) fn sync_objid_o_index(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        target_ref: NtfsReference,
        new_objid: Option<&NtfsObjectIdData>,
    ) -> Result<()> {
        let Some(objid_ref) = self.lookup_extend_child(engine, cx, &EXTEND_OBJID_UPPER)? else {
            return Ok(());
        };
        let _ = self.load_view_catalog(engine, cx, objid_ref)?;
        let mut obj_cat = self
            .catalogs
            .remove(&objid_ref.record)
            .ok_or_else(|| corrupt(0, "missing $Extend/$ObjId catalog"))?;
        let res = (|| -> Result<()> {
            let (collation, mut entries) = if let Some(view) = obj_cat
                .view_indexes
                .iter()
                .find(|v| v.index_name == OBJID_O_NAME)
            {
                (view.collation, engine.collect_view_index_entries(cx, view)?)
            } else {
                (ViewCollation::U32Slice, Vec::new())
            };
            if let Some(data) = new_objid {
                let colliding_other = entries.iter().any(|e| {
                    e.key.as_slice() == data.object_id
                        && e.data.len() >= 8
                        && (u64::from_le_bytes([
                            e.data[0], e.data[1], e.data[2], e.data[3], e.data[4], e.data[5],
                            e.data[6], e.data[7],
                        ]) & 0x0000_FFFF_FFFF_FFFF)
                            != target_ref.record
                });
                if colliding_other {
                    return Err(FfsError::Exists);
                }
            }
            let removed = remove_view_entries_matching(&mut entries, |e| {
                e.data.len() >= 8
                    && (u64::from_le_bytes([
                        e.data[0], e.data[1], e.data[2], e.data[3], e.data[4], e.data[5],
                        e.data[6], e.data[7],
                    ]) & 0x0000_FFFF_FFFF_FFFF)
                        == target_ref.record
            });
            if let Some(data) = new_objid {
                let val = encode_objid_o_data(target_ref, data)?;
                upsert_view_entry(&mut entries, data.object_id.to_vec(), val, collation);
            } else if !removed {
                return Ok(());
            }
            let max_root = Self::max_view_root_value_bytes(engine);
            let mut pre = Vec::new();
            let mut freed = Vec::new();
            flush_view_index_into_catalog(
                &engine.geometry,
                &mut obj_cat,
                &OBJID_O_NAME,
                collation,
                entries,
                max_root,
                &mut pre,
                &mut freed,
                |n, min_c| self.alloc_clusters(n, min_c),
            )?;
            self.pre_payload_writes.extend(pre);
            self.free_clusters_deferred(&freed);
            self.dirty_catalogs.insert(objid_ref.record);
            Ok(())
        })();
        self.catalogs.insert(objid_ref.record, obj_cat);
        res
    }

    pub(super) fn push_usn_event_for_catalog(
        &mut self,
        cat: &EditableCatalog,
        reason: u32,
        timestamp: u64,
    ) {
        if let Some(fn_attr) = cat
            .file_names
            .iter()
            .find(|f| f.file_name.namespace != 2)
            .or_else(|| cat.file_names.first())
        {
            self.pending_usn_events.push(PendingUsnEvent {
                file_ref: cat.base_ref,
                parent_ref: fn_attr.file_name.parent,
                reason,
                file_attributes: cat.std_flags(),
                timestamp,
                file_name: fn_attr.file_name.name.clone(),
            });
        }
    }

    pub(super) fn push_usn_event_explicit(
        &mut self,
        file_ref: NtfsReference,
        parent_ref: NtfsReference,
        reason: u32,
        file_attributes: u32,
        timestamp: u64,
        file_name: Vec<u16>,
    ) {
        self.pending_usn_events.push(PendingUsnEvent {
            file_ref,
            parent_ref,
            reason,
            file_attributes,
            timestamp,
            file_name,
        });
    }

    pub(super) fn dir_entries(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        dir_ref: NtfsReference,
    ) -> Result<&Vec<I30RawEntry>> {
        if !self.dir_entries_cache.contains_key(&dir_ref.record) {
            let cat = if dir_ref.record == 11 {
                self.load_view_catalog(engine, cx, dir_ref)?
            } else {
                self.load_catalog(engine, cx, dir_ref)?
            };
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
            return Err(stale_reference(dir_ref));
        }
        Ok(self.dir_entries_cache.get(&dir_ref.record).expect("cached"))
    }

    pub(super) fn dir_entries_mut(
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

    pub(super) fn lookup_in_dir(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        dir_ref: NtfsReference,
        query_utf16: &[u16],
    ) -> Result<Option<I30RawEntry>> {
        if let Some(entries) = self.dir_entries_cache.get(&dir_ref.record) {
            let cat = self.catalogs.get(&dir_ref.record).expect("dir catalog");
            if cat.base_ref.sequence != dir_ref.sequence {
                return Err(stale_reference(dir_ref));
            }
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
            let folded_matches: Vec<&I30RawEntry> = matches
                .iter()
                .copied()
                .filter(|m| m.file_name.namespace != 0)
                .collect();
            if folded_matches.is_empty() {
                return Ok(None);
            }
            let first_ref = folded_matches[0].reference;
            if folded_matches.iter().any(|m| m.reference != first_ref) {
                return Err(corrupt(0, "ambiguous folded NTFS mutation target"));
            }
            if let Some(non_dos) = folded_matches.iter().find(|m| m.file_name.namespace != 2) {
                return Ok(Some((*non_dos).clone()));
            }
            return Ok(Some(folded_matches[0].clone()));
        }
        let cat = if dir_ref.record == 11 {
            self.load_view_catalog(engine, cx, dir_ref)?
        } else {
            self.load_catalog(engine, cx, dir_ref)?
        };
        if !cat.is_directory {
            return Err(FfsError::NotDirectory);
        }
        let dir_idx = cat
            .dir_index
            .as_ref()
            .ok_or_else(|| corrupt(0, "directory lacks $I30"))?;
        engine.lookup_in_catalog_i30(cx, dir_idx, query_utf16)
    }

    pub(super) fn alloc_clusters(
        &mut self,
        needed: u64,
        min_chunk: u64,
    ) -> Result<Vec<(u64, u64)>> {
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

    pub(super) fn free_clusters_deferred(&mut self, spans: &[(u64, u64)]) {
        for &(start, len) in spans {
            if len > 0 {
                self.freed_clusters.push((start, len));
            }
        }
    }

    pub(super) fn alloc_mft_slot(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
    ) -> Result<(u32, u16, Vec<u8>)> {
        let slot_u64 =
            find_contiguous_zero_bits(&self.mft_bm, self.logical_records, 1, MIN_USER_MFT_SLOT)
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

        let existing_raw = if is_slot_in_original_mft(engine, cx, slot)? {
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

    pub(super) fn deallocate_entire_catalog(
        &mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        rec_no: u64,
    ) -> Result<()> {
        let cat = self
            .catalogs
            .get(&rec_no)
            .ok_or_else(|| corrupt(0, "missing catalog for deallocation"))?
            .clone();
        if cat.reparse_point.is_some() {
            self.sync_reparse_r_index(engine, cx, cat.base_ref, None)?;
        }
        if cat.object_id.is_some() {
            self.sync_objid_o_index(engine, cx, cat.base_ref, None)?;
        }
        self.dirty_catalogs.remove(&rec_no);
        self.dirty_dirs.remove(&rec_no);
        self.deallocated_records.insert(rec_no);

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
        for view in &cat.view_indexes {
            if let Some((ref a0_runs, _, _)) = view.external {
                self.free_clusters_deferred(&physical_spans_of_runs(a0_runs));
            }
        }
        let pres_runs = cat.preserved_nonresident_runs(engine.geometry.cluster_count())?;
        self.free_clusters_deferred(&physical_spans_of_runs(&pres_runs));
        self.free_clusters_deferred(&physical_spans_of_runs(&cat.old_nonres_attrlist_runs));
        self.free_clusters_deferred(&physical_spans_of_runs(&cat.old_owned_extra_runs));

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

    pub(super) fn sync_target_into_parent_dirs(
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
    pub(super) fn finalize<T>(
        mut self,
        engine: &NtfsTransactionEngine,
        cx: &Cx,
        operation: &'static str,
        operation_digest: [u8; 32],
        result_value: T,
    ) -> Result<PreparedTxPlan<T>> {
        let max_root_value_bytes = Self::max_view_root_value_bytes(engine);

        // 1. Flush any modified `$Secure` (Record 9) state into its catalog before packing.
        if let Some(store) = self.secure_store.take()
            && store.modified
        {
            let mut sec_cat = self
                .catalogs
                .remove(&9)
                .ok_or_else(|| corrupt(0, "$Secure catalog missing during finalize"))?;
            let mut pre = Vec::new();
            let mut freed = Vec::new();
            let res = store.flush_into_catalog(
                &engine.geometry,
                &mut sec_cat,
                max_root_value_bytes,
                &mut pre,
                &mut freed,
                |n, min_c| self.alloc_clusters(n, min_c),
            );
            self.catalogs.insert(9, sec_cat);
            res?;
            self.pre_payload_writes.extend(pre);
            self.free_clusters_deferred(&freed);
            self.dirty_catalogs.insert(9);
        }

        // 2. Append any pending USN events to active `$Extend/$UsnJrnl` and stamp target USNs.
        let pending_usn = std::mem::take(&mut self.pending_usn_events);
        if !pending_usn.is_empty()
            && let Some(usn_ref) = self.lookup_extend_child(engine, cx, &EXTEND_USNJRNL_UPPER)?
        {
            let _ = self.load_view_catalog(engine, cx, usn_ref)?;
            let mut usn_cat = self
                .catalogs
                .remove(&usn_ref.record)
                .ok_or_else(|| corrupt(0, "missing $UsnJrnl catalog"))?;
            let mut pre = Vec::new();
            let mut freed = Vec::new();
            let mut usn_records = Vec::with_capacity(pending_usn.len());
            let mut target_recs = Vec::with_capacity(pending_usn.len());
            for ev in pending_usn {
                let sec_id = self
                    .catalogs
                    .get(&ev.file_ref.record)
                    .and_then(EditableCatalog::std_security_id)
                    .unwrap_or(0);
                target_recs.push(ev.file_ref.record);
                usn_records.push(UsnRecordV2 {
                    file_ref: ev.file_ref,
                    parent_ref: ev.parent_ref,
                    usn: 0,
                    timestamp: ev.timestamp,
                    reason: ev.reason,
                    source_info: 0,
                    security_id: sec_id,
                    file_attributes: ev.file_attributes,
                    name: ev.file_name,
                });
            }
            let append_res = append_usn_records_to_catalog(
                engine,
                cx,
                &mut usn_cat,
                &mut usn_records,
                &mut pre,
                &mut freed,
                |n| self.alloc_clusters(n, 1),
            );
            self.catalogs.insert(usn_ref.record, usn_cat);
            let assigned_offsets = append_res?;
            self.pre_payload_writes.extend(pre);
            self.free_clusters_deferred(&freed);
            self.dirty_catalogs.insert(usn_ref.record);
            for (target_rec, usn) in target_recs.into_iter().zip(assigned_offsets) {
                if !self.deallocated_records.contains(&target_rec)
                    && let Some(target_cat) = self.catalogs.get_mut(&target_rec)
                {
                    target_cat.set_std_usn(usn);
                    self.dirty_catalogs.insert(target_rec);
                }
            }
        }

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

        let dirty_cat_ids: Vec<u64> = self.dirty_catalogs.iter().copied().collect();
        for rec_id in dirty_cat_ids {
            if self.deallocated_records.contains(&rec_id) {
                continue;
            }
            let mut cat = self
                .catalogs
                .get(&rec_id)
                .ok_or_else(|| corrupt(0, "missing dirty catalog"))?
                .clone();
            let mft_runs_clone = self.mft_runs.clone();
            let mft_attr_slot = self.mft_attr_slot;
            let fresh_existing = self.fresh_base_records.get(&rec_id).cloned();

            let packed = {
                let ws_cell = std::cell::RefCell::new(&mut self);
                if let Some(ref existing_raw) = fresh_existing {
                    engine.pack_fresh_base_catalog(
                        &mut cat,
                        existing_raw,
                        mft_attr_slot,
                        &mft_runs_clone,
                        || ws_cell.borrow_mut().alloc_mft_slot(engine, cx),
                        |need_cl| ws_cell.borrow_mut().alloc_clusters(need_cl, 1),
                    )?
                } else {
                    engine.pack_editable_catalog(
                        &cat,
                        mft_attr_slot,
                        &mft_runs_clone,
                        || ws_cell.borrow_mut().alloc_mft_slot(engine, cx),
                        |need_cl| ws_cell.borrow_mut().alloc_clusters(need_cl, 1),
                    )?
                }
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

fn is_slot_in_original_mft(engine: &NtfsTransactionEngine, cx: &Cx, slot: u32) -> Result<bool> {
    let mft0 = engine.read_mft_record_zero(cx)?;
    let (_, _, mft_init_bytes) =
        extract_plain_nonresident_stream(&engine.geometry, &mft0, DATA, &[])?;
    let init_records = mft_init_bytes / u64::from(engine.geometry.record_bytes());
    Ok(u64::from(slot) < init_records)
}

impl NtfsTransactionEngine {
    fn has_active_usn_journal(&self, cx: &Cx) -> Result<bool> {
        let vol = self.volume_view(cx)?;
        Ok(vol.usn_summary(cx)?.is_some())
    }

    fn record_uses_extended_catalog_or_sparse(
        &self,
        cx: &Cx,
        reference: NtfsReference,
    ) -> Result<bool> {
        if self.version != [3, 1] || self.has_active_usn_journal(cx)? {
            return Ok(true);
        }
        let volume = self.volume_view(cx)?;
        let record = Self::checked_reference(&volume, cx, reference)?;
        let attrs = record.attributes().map_err(|err| parse_err(&err))?;
        for a in &attrs {
            if matches!(
                a.kind,
                ATTRIBUTE_LIST
                    | OBJECT_ID
                    | REPARSE_POINT
                    | EA_INFORMATION
                    | EA
                    | LOGGED_UTILITY_STREAM
            ) {
                return Ok(true);
            }
            if a.kind == DATA && (a.flags & (SPARSE | COMPRESSED | ENCRYPTED)) != 0 {
                return Ok(true);
            }
            if a.kind == 0x10
                && a.name.is_empty()
                && let ffs_ondisk::ntfs::NtfsValue::Resident(std_raw) = a.value
                && std_raw.len() >= 36
            {
                let f = u32::from_le_bytes([std_raw[32], std_raw[33], std_raw[34], std_raw[35]]);
                if f & (FILE_ATTR_COMPRESSED | FILE_ATTR_REPARSE_POINT | FILE_ATTR_ENCRYPTED) != 0 {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn parent_requires_extended_create(&self, cx: &Cx, parent: NtfsReference) -> Result<bool> {
        if self.record_uses_extended_catalog_or_sparse(cx, parent)? {
            return Ok(true);
        }
        let volume = self.volume_view(cx)?;
        let record = Self::checked_reference(&volume, cx, parent)?;
        if let Ok(info) = volume.security_descriptor(cx, &record)
            && info.descriptor.dacl.present
            && info.descriptor.dacl.aces.iter().any(|ace| {
                (ace.flags & (ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT)) != 0
            })
        {
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn ensure_mft_headroom(
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
        for bit in MIN_USER_MFT_SLOT..logical_records {
            if !is_bit_set(&mft_bm, bit) {
                free_slots += 1;
                if free_slots >= min_free_slots {
                    return Ok(());
                }
            }
        }

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
        let missing_slots = MIN_USER_MFT_SLOT
            .saturating_sub(logical_records)
            .saturating_add(min_free_slots - free_slots);
        let min_add_clusters = missing_slots.div_ceil(recs_per_cluster);
        if total_free_clusters < min_add_clusters.saturating_add(payload_clusters_reserve) {
            return Err(FfsError::NoSpace);
        }

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

    /// Create a file relative to a sequence-bound directory reference.
    pub fn create_file_at(
        &mut self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
        data: &[u8],
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = validate_ntfs_component_utf16(name) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let use_extended = self
            .parent_requires_extended_create(cx, parent)
            .unwrap_or(true);
        if !use_extended
            && let Ok(path) = self.resolve_reference_path(cx, parent)
            && let Ok(text) = String::from_utf16(name)
        {
            match self.lookup_reference(cx, parent, name) {
                Ok(_) => return NtfsTxOutcome::NotCommitted(FfsError::Exists),
                Err(FfsError::NotFound(_)) => {}
                Err(err) => return NtfsTxOutcome::NotCommitted(err),
            }
            let outcome = self.create_file(cx, &path, &text, data);
            if !matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
            ) || self.requires_recovery()
            {
                return outcome;
            }
        }
        self.create_entry_at(cx, parent, name, false, false, data, DEFAULT_NTFS_FILETIME)
    }

    /// Create a directory relative to a sequence-bound parent reference.
    pub fn mkdir_at(
        &mut self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = validate_ntfs_component_utf16(name) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let use_extended = self
            .parent_requires_extended_create(cx, parent)
            .unwrap_or(true);
        if !use_extended
            && let Ok(path) = self.resolve_reference_path(cx, parent)
            && let Ok(text) = String::from_utf16(name)
        {
            match self.lookup_reference(cx, parent, name) {
                Ok(_) => return NtfsTxOutcome::NotCommitted(FfsError::Exists),
                Err(FfsError::NotFound(_)) => {}
                Err(err) => return NtfsTxOutcome::NotCommitted(err),
            }
            let outcome = self.mkdir(cx, &path, &text);
            if !matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
            ) || self.requires_recovery()
            {
                return outcome;
            }
        }
        self.create_entry_at(cx, parent, name, true, false, &[], DEFAULT_NTFS_FILETIME)
    }

    /// Add a directory link to a sequence-bound ordinary FILE reference.
    pub fn link_at(
        &mut self,
        cx: &Cx,
        reference: NtfsReference,
        parent: NtfsReference,
        name: &[u16],
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = validate_ntfs_component_utf16(name) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let use_extended = self
            .record_uses_extended_catalog_or_sparse(cx, reference)
            .unwrap_or(true)
            || self
                .record_uses_extended_catalog_or_sparse(cx, parent)
                .unwrap_or(true);
        if !use_extended
            && let Ok(source) = self.resolve_reference_path(cx, reference)
            && let Ok(destination_parent) = self.resolve_reference_path(cx, parent)
            && let Ok(text) = String::from_utf16(name)
        {
            match self.lookup_reference(cx, parent, name) {
                Ok(_) => return NtfsTxOutcome::NotCommitted(FfsError::Exists),
                Err(FfsError::NotFound(_)) => {}
                Err(err) => return NtfsTxOutcome::NotCommitted(err),
            }
            let outcome = self.link_file(cx, &source, &destination_parent, &text);
            if !matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
            ) || self.requires_recovery()
            {
                return outcome;
            }
        }
        match self.link_entry_at(cx, reference, parent, name, DEFAULT_NTFS_FILETIME) {
            NtfsTxOutcome::Committed { token, .. } => NtfsTxOutcome::Committed {
                value: reference,
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
    }

    /// Write an existing DATA stream by stable FILE reference and exact native UTF-16 name.
    pub fn write_stream_range(
        &mut self,
        cx: &Cx,
        reference: NtfsReference,
        stream: &[u16],
        offset: u64,
        data: &[u8],
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = validate_ntfs_stream_name_utf16(stream) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let use_extended = match self.record_uses_extended_catalog_or_sparse(cx, reference) {
            Ok(flag) => flag,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        if !use_extended && let Ok(path) = self.resolve_reference_path(cx, reference) {
            let outcome =
                self.edit_stream_data(cx, &path, stream, FileDataEdit::Write { offset, data });
            if !matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
            ) || self.requires_recovery()
            {
                return outcome;
            }
        }
        match self.write_stream_at(
            cx,
            reference,
            stream,
            offset,
            data,
            false,
            DEFAULT_NTFS_FILETIME,
        ) {
            NtfsTxOutcome::Committed { token, .. } => NtfsTxOutcome::Committed {
                value: reference,
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
    }

    /// Truncate an existing DATA stream selected by exact native name.
    pub fn truncate_stream(
        &mut self,
        cx: &Cx,
        reference: NtfsReference,
        stream: &[u16],
        size: u64,
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = validate_ntfs_stream_name_utf16(stream) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let use_extended = match self.record_uses_extended_catalog_or_sparse(cx, reference) {
            Ok(flag) => flag,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        if !use_extended && let Ok(path) = self.resolve_reference_path(cx, reference) {
            let outcome = self.edit_stream_data(cx, &path, stream, FileDataEdit::Truncate { size });
            if !matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
            ) || self.requires_recovery()
            {
                return outcome;
            }
        }
        match self.truncate_stream_at(cx, reference, stream, size, DEFAULT_NTFS_FILETIME) {
            NtfsTxOutcome::Committed { token, .. } => NtfsTxOutcome::Committed {
                value: reference,
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
    }

    /// Create a named DATA stream on a sequence-bound ordinary FILE, automatically
    /// spilling into extension MFT records (`$ATTRIBUTE_LIST`) when base capacity fills.
    pub fn create_stream(
        &mut self,
        cx: &Cx,
        reference: NtfsReference,
        stream: &[u16],
        data: &[u8],
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = validate_ntfs_stream_name_utf16(stream) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if stream.is_empty() {
            return NtfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                errno: libc::EINVAL,
                detail: "creating DATA requires a nonempty stream name".into(),
            });
        }
        if data.len() as u64 > MAX_FILE_EDIT_BYTES {
            return NtfsTxOutcome::NotCommitted(too_large_edit());
        }
        let use_extended = match self.record_uses_extended_catalog_or_sparse(cx, reference) {
            Ok(flag) => flag,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        if !use_extended && let Ok(path) = self.resolve_reference_path(cx, reference) {
            let outcome = self.edit_named_stream(cx, &path, stream, Some(data));
            if !matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
            ) || self.requires_recovery()
            {
                return outcome;
            }
        }
        self.create_stream_at(cx, reference, stream, data, DEFAULT_NTFS_FILETIME)
    }

    /// Remove a named DATA stream without retiring its FILE or any other stream,
    /// reclaiming any emptied extension MFT records.
    pub fn remove_stream(
        &mut self,
        cx: &Cx,
        reference: NtfsReference,
        stream: &[u16],
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = validate_ntfs_stream_name_utf16(stream) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if stream.is_empty() {
            return NtfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                errno: libc::EINVAL,
                detail: "removing DATA requires a nonempty stream name".into(),
            });
        }
        let use_extended = match self.record_uses_extended_catalog_or_sparse(cx, reference) {
            Ok(flag) => flag,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        if !use_extended && let Ok(path) = self.resolve_reference_path(cx, reference) {
            let outcome = self.edit_named_stream(cx, &path, stream, None);
            if !matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
            ) || self.requires_recovery()
            {
                return outcome;
            }
        }
        match self.unlink_stream_at(cx, reference, stream, DEFAULT_NTFS_FILETIME) {
            NtfsTxOutcome::Committed { token, .. } => NtfsTxOutcome::Committed {
                value: reference,
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
    }

    /// Remove exactly the selected current directory link.
    pub fn unlink_at(
        &mut self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
        expected: NtfsReference,
    ) -> NtfsTxOutcome<NtfsReference> {
        match self.lookup_reference(cx, parent, name) {
            Ok(found) if found != expected => return NtfsTxOutcome::NotCommitted(stale_target()),
            Ok(_) => {}
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        }
        let use_extended = self
            .record_uses_extended_catalog_or_sparse(cx, expected)
            .unwrap_or(true)
            || self
                .record_uses_extended_catalog_or_sparse(cx, parent)
                .unwrap_or(true);
        if !use_extended
            && let Ok(path) = self.child_mutation_path(cx, parent, name)
            && self
                .validate_mutation_path_reference(cx, &path, expected)
                .is_ok()
        {
            let outcome = self.unlink_file(cx, &path);
            if !matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_))
            ) || self.requires_recovery()
            {
                return outcome;
            }
        }
        match self.unlink_entry_at(cx, parent, name, None, DEFAULT_NTFS_FILETIME) {
            NtfsTxOutcome::Committed {
                value: (removed, _),
                token,
            } => NtfsTxOutcome::Committed {
                value: removed,
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
    }

    /// Rename an existing native link without losing its stable FILE identity.
    #[allow(clippy::too_many_arguments)]
    pub fn rename_at(
        &mut self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
        new_parent: NtfsReference,
        new_name: &[u16],
        expected: NtfsReference,
        no_replace: bool,
    ) -> NtfsTxOutcome<NtfsRenameOutcome> {
        match self.lookup_reference(cx, parent, name) {
            Ok(found) if found != expected => return NtfsTxOutcome::NotCommitted(stale_target()),
            Ok(_) => {}
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        }
        let replaced = match self.lookup_reference(cx, new_parent, new_name) {
            Ok(_) if no_replace => return NtfsTxOutcome::NotCommitted(FfsError::Exists),
            Ok(destination) => (destination != expected).then_some(destination),
            Err(FfsError::NotFound(_)) => None,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        let use_extended = self
            .record_uses_extended_catalog_or_sparse(cx, expected)
            .unwrap_or(true)
            || self
                .record_uses_extended_catalog_or_sparse(cx, parent)
                .unwrap_or(true)
            || self
                .record_uses_extended_catalog_or_sparse(cx, new_parent)
                .unwrap_or(true)
            || replaced.is_some_and(|dst| {
                self.record_uses_extended_catalog_or_sparse(cx, dst)
                    .unwrap_or(true)
            });
        if !use_extended
            && let Ok(source) = self.child_mutation_path(cx, parent, name)
            && self
                .validate_mutation_path_reference(cx, &source, expected)
                .is_ok()
            && let Ok(destination) = self.child_mutation_path(cx, new_parent, new_name)
        {
            let outcome = if no_replace {
                self.rename_entry_no_replace(cx, &source, &destination, Some(expected))
            } else {
                self.rename_entry(cx, &source, &destination, Some(expected))
            };
            if !matches!(
                outcome,
                NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
            ) || self.requires_recovery()
            {
                return match outcome {
                    NtfsTxOutcome::Committed { value, token } => NtfsTxOutcome::Committed {
                        value: NtfsRenameOutcome {
                            source: value,
                            replaced,
                        },
                        token,
                    },
                    NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
                    NtfsTxOutcome::Uncertain {
                        reason,
                        transaction_id,
                        commit_lsn,
                    } => NtfsTxOutcome::Uncertain {
                        reason,
                        transaction_id,
                        commit_lsn,
                    },
                };
            }
        }
        match self.rename_entry_at(
            cx,
            parent,
            name,
            new_parent,
            new_name,
            no_replace,
            None,
            DEFAULT_NTFS_FILETIME,
        ) {
            NtfsTxOutcome::Committed { value, token } => NtfsTxOutcome::Committed {
                value: NtfsRenameOutcome {
                    source: value.moved_reference,
                    replaced: value.overwritten_reference,
                },
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
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
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_ntfs_component_utf16(name_utf16) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if !is_dir && initial_data.len() as u64 > MAX_FILE_EDIT_BYTES {
            return NtfsTxOutcome::NotCommitted(too_large_edit());
        }
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

        // Preflight parent existence & collision before touching MFT growth!
        {
            let preflight = (|| -> Result<()> {
                let mut ws = TxWorkspace::load(self, cx)?;
                if ws
                    .lookup_in_dir(self, cx, parent_ref, name_utf16)?
                    .is_some()
                {
                    return Err(FfsError::Exists);
                }
                Ok(())
            })();
            if let Err(err) = preflight {
                return NtfsTxOutcome::NotCommitted(err);
            }
        }

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
            let mut ws = TxWorkspace::load(self, cx)?;
            if ws
                .lookup_in_dir(self, cx, parent_ref, name_utf16)?
                .is_some()
            {
                return Err(FfsError::Exists);
            }

            let parent_cat = ws.load_catalog(self, cx, parent_ref)?.clone();
            if parent_cat.reparse_point.is_some() {
                return Err(unsupported(
                    "cannot create NTFS child inside a reparse directory",
                ));
            }
            let inherit_compressed = (parent_cat.std_flags() & FILE_ATTR_COMPRESSED) != 0;
            if inherit_compressed && !is_dir {
                compression::check_lznt1_geometry(&self.geometry)?;
            }

            let mut base_flags = if is_dir { 0_u32 } else { FILE_ATTR_ARCHIVE };
            if read_only {
                base_flags |= FILE_ATTR_READONLY;
            }
            if inherit_compressed {
                base_flags |= FILE_ATTR_COMPRESSED;
            }

            let (mut std_info, sd_opt) = if let Some(parent_sd_raw) =
                ws.read_catalog_security_descriptor(self, cx, &parent_cat)?
                && let Ok(parent_sd) = NtfsSecurityDescriptor::parse(&parent_sd_raw)
            {
                let default_owner = ffs_ondisk::ntfs_security::NtfsSid::administrators();
                let default_group = ffs_ondisk::ntfs_security::NtfsSid::local_system();
                let child_owner = parent_sd.owner.as_ref().unwrap_or(&default_owner);
                let child_group = parent_sd.group.as_ref().unwrap_or(&default_group);
                let inherited_sd =
                    inherit_security_descriptor(&parent_sd, is_dir, child_owner, child_group)
                        .map_err(|err| parse_err(&err))?;
                let inherited_bytes = inherited_sd.encode().map_err(|err| parse_err(&err))?;
                if self.version == [3, 1] && ws.mft_slot_is_allocated(9) {
                    let sec_id = ws.intern_security_descriptor(self, cx, &inherited_bytes)?;
                    let info = encode_standard_information(
                        is_dir,
                        &super::ops::InheritedSecurity::SharedId(sec_id),
                    );
                    (info, None)
                } else {
                    let info = encode_standard_information(
                        is_dir,
                        &super::ops::InheritedSecurity::Descriptor(inherited_bytes.clone()),
                    );
                    (info, Some(inherited_bytes))
                }
            } else {
                let parent_raw_rec = read_mft_record_via_runs(
                    &self.device,
                    cx,
                    &self.geometry,
                    &ws.mft_runs,
                    u32::try_from(parent_ref.record).map_err(|_| corrupt(0, "parent u32"))?,
                )?;
                let security = extract_parent_security(&parent_raw_rec);
                let info = encode_standard_information(is_dir, &security);
                let sd = match security {
                    super::ops::InheritedSecurity::SharedId(_) => None,
                    super::ops::InheritedSecurity::Descriptor(sd) => Some(sd),
                };
                (info, sd)
            };
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
                let storage = if inherit_compressed {
                    let mut pre = Vec::new();
                    let st = compression::rebuild_stream_for_compression_toggle(
                        &self.geometry,
                        initial_data,
                        true,
                        &mut pre,
                        |n| ws.alloc_clusters(n, 1),
                    )?;
                    ws.pre_payload_writes.extend(pre);
                    st
                } else if initial_data.len() <= MAX_RESIDENT_DATA_PAYLOAD {
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
                        compressed: false,
                        encrypted: false,
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
            let mut child_cat = EditableCatalog {
                base_ref: child_ref,
                is_directory: is_dir,
                std_info,
                file_names: vec![fn_attr],
                object_id: None,
                security_descriptor: sd_opt,
                data_streams,
                dir_index,
                view_indexes: Vec::new(),
                reparse_point: None,
                efs_stream: None,
                preserved: Vec::new(),
                old_base_raw: existing_raw.clone(),
                old_extensions: Vec::new(),
                old_nonres_attrlist_runs: Vec::new(),
                old_owned_extra_runs: Vec::new(),
            };
            child_cat.sync_filename_duplicated_fields(self.geometry.cluster_bytes());
            let raw_fn_bytes = child_cat.file_names[0].encode()?;
            let fn_struct = child_cat.file_names[0].file_name.clone();
            ws.push_usn_event_explicit(
                child_ref,
                parent_ref,
                USN_REASON_FILE_CREATE | USN_REASON_CLOSE,
                child_cat.std_flags(),
                now_ticks,
                name_utf16.to_vec(),
            );
            ws.register_fresh_catalog(child_cat, existing_raw);

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
        let base_no = u32::try_from(catalog.base_ref.record).map_err(|_| corrupt(0, "base_no"))?;
        let dummy_restored = super::catalog::build_restored_mft_record(
            self.geometry.record_bytes(),
            self.version,
            base_no,
            catalog.base_ref.sequence,
            catalog.is_directory,
            0,
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

    /// Create a named Alternate Data Stream on `target_ref` with initial `data`,
    /// automatically spilling into extension MFT records (`$ATTRIBUTE_LIST`) when needed.
    pub fn create_stream_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        data: &[u8],
        now_ticks: u64,
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_ntfs_stream_name_utf16(stream_utf16) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if stream_utf16.is_empty() {
            return NtfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                errno: libc::EINVAL,
                detail: "creating DATA requires a nonempty stream name".into(),
            });
        }
        if data.len() as u64 > MAX_FILE_EDIT_BYTES {
            return NtfsTxOutcome::NotCommitted(too_large_edit());
        }
        {
            let preflight = (|| -> Result<()> {
                let mut ws = TxWorkspace::load(self, cx)?;
                let cat = ws.load_catalog(self, cx, target_ref)?;
                if cat.is_directory {
                    return Err(FfsError::IsDirectory);
                }
                if target_ref.record < MIN_USER_MFT_SLOT {
                    return Err(FfsError::PermissionDenied);
                }
                let target_folded = self.fold_upcase(stream_utf16);
                if cat
                    .data_streams
                    .iter()
                    .any(|s| self.fold_upcase(&s.name) == target_folded)
                {
                    return Err(FfsError::Exists);
                }
                Ok(())
            })();
            if let Err(err) = preflight {
                return NtfsTxOutcome::NotCommitted(err);
            }
        }
        let cb = u64::from(self.geometry.cluster_bytes());
        let data_cl = if data.len() > MAX_RESIDENT_DATA_PAYLOAD {
            (data.len() as u64).div_ceil(cb)
        } else {
            0
        };
        if let Err(err) = self.ensure_mft_headroom(cx, 1, data_cl) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        match self.write_stream_at(cx, target_ref, stream_utf16, 0, data, true, now_ticks) {
            NtfsTxOutcome::Committed { token, .. } => NtfsTxOutcome::Committed {
                value: target_ref,
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
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
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_ntfs_stream_name_utf16(stream_utf16) {
            return NtfsTxOutcome::NotCommitted(err);
        }
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

        let plan = self.plan_stream_write(
            cx,
            target_ref,
            stream_utf16,
            offset,
            data,
            create_stream_if_missing,
            now_ticks,
            digest,
        );
        match plan {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(FfsError::NoSpace) => {
                let cb = u64::from(self.geometry.cluster_bytes());
                let est_cl = (data.len() as u64).div_ceil(cb) + 2;
                if self.ensure_mft_headroom(cx, 1, est_cl).is_err() {
                    return NtfsTxOutcome::NotCommitted(FfsError::NoSpace);
                }
                // Rebuild the same checked plan after MFT growth. A separate
                // retry implementation must not lose sparse-gap initialization,
                // exact stream identity, or the staging budget.
                match self.plan_stream_write(
                    cx,
                    target_ref,
                    stream_utf16,
                    offset,
                    data,
                    create_stream_if_missing,
                    now_ticks,
                    digest,
                ) {
                    Ok(plan) => self.execute_logged_tx(cx, plan),
                    Err(err) => NtfsTxOutcome::NotCommitted(err),
                }
            }
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Materialize a WOF-compressed file's unnamed `$DATA` stream into plain plaintext on
    /// write (removing `WofCompressedData`, `$REPARSE_POINT`, `FILE_ATTR_REPARSE_POINT`, and
    /// its `$Extend/$Reparse::$R` entry), or refuse any non-WOF reparse point for `$DATA` edits.
    fn prepare_reparse_unnamed_data_write(
        &self,
        cx: &Cx,
        ws: &mut TxWorkspace,
        target_ref: NtfsReference,
        cat_ro: &EditableCatalog,
    ) -> Result<Option<Vec<u8>>> {
        let Some(ref rp_bytes) = cat_ro.reparse_point else {
            return Ok(None);
        };
        let point = NtfsReparsePoint::parse(rp_bytes).map_err(|err| parse_err(&err))?;
        match classify_reparse_point(&point) {
            ReparseCapability::WofFileProvider => {
                let vol = self.volume_view(cx)?;
                let rec = vol.record(cx, target_ref.record, Some(target_ref.sequence))?;
                let decoded = vol.read_wof_all(cx, &rec, MAX_FILE_EDIT_BYTES as usize)?;
                let wof_folded = self.fold_upcase(WOF_BACKING_NAME);
                let mut freed_spans = Vec::new();
                {
                    let cat = ws.catalog_mut(self, cx, target_ref)?;
                    // Free old unnamed $DATA runs (if non-resident) and remove WofCompressedData.
                    for s in &cat.data_streams {
                        if (s.name.is_empty() || self.fold_upcase(&s.name) == wof_folded)
                            && let EditableStreamStorage::NonResident { ref runs, .. } = s.storage
                        {
                            freed_spans.extend(physical_spans_of_runs(runs));
                        }
                    }
                    cat.data_streams
                        .retain(|s| self.fold_upcase(&s.name) != wof_folded);
                    cat.reparse_point = None;
                    let flags = cat.std_flags() & !FILE_ATTR_REPARSE_POINT;
                    cat.set_std_flags(flags);
                }
                ws.free_clusters_deferred(&freed_spans);
                ws.sync_reparse_r_index(self, cx, target_ref, None)?;
                Ok(Some(decoded))
            }
            ReparseCapability::Symlink { .. }
            | ReparseCapability::MountPoint
            | ReparseCapability::OpaquePreserved { .. } => Err(unsupported(
                "ordinary NTFS $DATA write/truncate refused on reparse point; remove reparse metadata explicitly first",
            )),
        }
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub(super) fn plan_stream_write(
        &self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        offset: u64,
        data: &[u8],
        create_stream_if_missing: bool,
        now_ticks: u64,
        digest: [u8; 32],
    ) -> Result<PreparedTxPlan<u64>> {
        checkpoint(cx)?;
        if data.len() as u64 > MAX_FILE_EDIT_BYTES
            || (!data.is_empty()
                && offset
                    .checked_add(data.len() as u64)
                    .is_none_or(|end| end > i64::MAX as u64))
        {
            return Err(too_large_edit());
        }
        let cb = u64::from(self.geometry.cluster_bytes());
        let mut ws = TxWorkspace::load(self, cx)?;
        let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
        if cat_ro.is_directory {
            return Err(FfsError::IsDirectory);
        }
        if target_ref.record < MIN_USER_MFT_SLOT {
            return Err(FfsError::PermissionDenied);
        }
        if stream_utf16.is_empty() && (cat_ro.std_flags() & FILE_ATTR_ENCRYPTED) != 0 {
            return Err(unsupported(
                "ordinary NTFS write refused on encrypted file; use explicit keyed EFS write",
            ));
        }
        let wof_decoded = if stream_utf16.is_empty() {
            self.prepare_reparse_unnamed_data_write(cx, &mut ws, target_ref, &cat_ro)?
        } else {
            None
        };
        let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();

        let target_folded = self.fold_upcase(stream_utf16);
        let existing_idx = cat_ro
            .data_streams
            .iter()
            .position(|s| self.fold_upcase(&s.name) == target_folded);

        if existing_idx.is_none() && !create_stream_if_missing {
            return Err(FfsError::NotFound("NTFS data stream not found".into()));
        }
        if let Some(i) = existing_idx
            && !stream_utf16.is_empty()
            && cat_ro.data_streams[i].name != stream_utf16
        {
            return Err(FfsError::NotFound(
                "NTFS exact named stream not found".into(),
            ));
        }

        let wof_materialized = wof_decoded.is_some();
        let cur_stream = if let Some(decoded) = wof_decoded {
            EditableDataStream {
                name: Vec::new(),
                storage: EditableStreamStorage::Resident(decoded),
            }
        } else {
            match existing_idx {
                Some(i) => cat_ro.data_streams[i].clone(),
                None => EditableDataStream {
                    name: stream_utf16.to_vec(),
                    storage: EditableStreamStorage::Resident(Vec::new()),
                },
            }
        };
        if matches!(
            cur_stream.storage,
            EditableStreamStorage::NonResident {
                encrypted: true,
                ..
            }
        ) {
            return Err(unsupported(
                "ordinary NTFS write refused on encrypted DATA stream; use explicit keyed EFS write",
            ));
        }

        let old_size = cur_stream.logical_size();
        if data.is_empty() && existing_idx.is_some() && !wof_materialized {
            let cat = ws.catalog_mut(self, cx, target_ref)?;
            cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
            if stream_utf16.is_empty() {
                ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            }
            return ws.finalize(self, cx, "write_stream_at", digest, old_size);
        }

        let end_offset = offset
            .checked_add(data.len() as u64)
            .filter(|&end| i64::try_from(end).is_ok())
            .ok_or_else(too_large_edit)?;

        let (old_sparse, old_compressed, old_comp_unit, old_init, old_runs) = match &cur_stream
            .storage
        {
            EditableStreamStorage::Resident(b) => (false, false, 0_u16, b.len() as u64, Vec::new()),
            EditableStreamStorage::NonResident {
                runs,
                sparse,
                compressed,
                compression_unit,
                initialized_bytes,
                ..
            } => (
                *sparse,
                *compressed,
                *compression_unit,
                *initialized_bytes,
                runs.clone(),
            ),
        };

        if !old_sparse
            && !old_compressed
            && end_offset.saturating_sub(offset.min(old_init)) > MAX_FILE_EDIT_BYTES
        {
            return Err(too_large_edit());
        }
        let new_size = old_size.max(end_offset);
        let old_coverage_vcns = old_runs.last().map_or(0, |run| run.vcn + run.clusters);
        if new_size.div_ceil(cb).max(old_coverage_vcns) > i64::MAX as u64 / cb {
            return Err(too_large_edit());
        }
        let updated_storage = if old_compressed {
            let mut pre = Vec::new();
            let (st, disp) = compression::rewrite_compressed_stream_range(
                self,
                cx,
                &old_runs,
                old_size,
                old_init,
                offset,
                data,
                &mut pre,
                |n| ws.alloc_clusters(n, 1),
            )?;
            ws.pre_payload_writes.extend(pre);
            ws.free_clusters_deferred(&disp);
            st
        } else if !old_sparse && new_size <= MAX_RESIDENT_DATA_PAYLOAD as u64 {
            let mut buf = read_editable_stream_prefix(self, cx, &cur_stream, 0, new_size as usize)?;
            if !data.is_empty() {
                buf[offset as usize..end_offset as usize].copy_from_slice(data);
            }
            ws.free_clusters_deferred(&physical_spans_of_runs(&old_runs));
            EditableStreamStorage::Resident(buf)
        } else if old_sparse {
            let write_start_vcn = offset / cb;
            let write_end_vcn = end_offset
                .div_ceil(cb)
                .max(write_start_vcn + u64::from(!data.is_empty()));
            let mut working_runs = old_runs;
            let init_vcn = old_init / cb;
            if old_init % cb != 0 && init_vcn < write_start_vcn {
                let partial_cluster =
                    read_editable_stream_prefix(self, cx, &cur_stream, init_vcn * cb, cb as usize)?;
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
            let hole_start_vcn = old_init.div_ceil(cb);
            if hole_start_vcn < write_start_vcn {
                let cur_cov: u64 = working_runs.iter().map(|r| r.clusters).sum();
                if cur_cov > hole_start_vcn {
                    let hole_end = write_start_vcn.min(cur_cov);
                    let (without, disp) =
                        splice_vcn_interval(&working_runs, hole_start_vcn, hole_end, &[], true)?;
                    ws.free_clusters_deferred(&disp);
                    working_runs = without;
                }
            }
            if write_end_vcn > write_start_vcn {
                let cow_clusters = write_end_vcn - write_start_vcn;
                let cow_bytes_u64 = cow_clusters
                    .checked_mul(cb)
                    .filter(|&n| n <= MAX_FILE_EDIT_BYTES + 2 * cb)
                    .ok_or_else(too_large_edit)?;
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
                compressed: false,
                encrypted: false,
                compression_unit: old_comp_unit,
                data_bytes: new_size,
                initialized_bytes: old_init.max(end_offset),
            }
        } else {
            let cow_start_vcn = offset.min(old_init) / cb;
            let cow_end_vcn = end_offset.div_ceil(cb).max(1);
            let cow_clusters = cow_end_vcn - cow_start_vcn;
            let cow_byte_start = cow_start_vcn * cb;
            let cow_bytes_u64 = cow_clusters
                .checked_mul(cb)
                .filter(|&n| n <= MAX_FILE_EDIT_BYTES + 2 * cb)
                .ok_or_else(too_large_edit)?;
            let cow_bytes_len = cow_bytes_u64 as usize;

            let mut merged_buf =
                read_editable_stream_prefix(self, cx, &cur_stream, cow_byte_start, cow_bytes_len)?;
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
                compressed: false,
                encrypted: false,
                compression_unit: 0,
                data_bytes: new_size,
                initialized_bytes: old_init.max(end_offset),
            }
        };

        let usn_snapshot = {
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
            cat.clone()
        };
        let reason = if new_size > old_size {
            USN_REASON_DATA_EXTEND | USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE
        } else {
            USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE
        };
        ws.push_usn_event_for_catalog(&usn_snapshot, reason, now_ticks);
        if stream_utf16.is_empty() {
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
        }

        ws.finalize(self, cx, "write_stream_at", digest, new_size)
    }

    /// Truncate or extend unnamed `$DATA` (`stream_utf16 == &[]`) or a named ADS (`stream_utf16 != &[]`).
    /// The staging budget bounds newly initialized bytes, not the logical size:
    /// shrinking and sparse growth preserve untouched extents without reading them.
    pub fn truncate_stream_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        new_size: u64,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_ntfs_stream_name_utf16(stream_utf16) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.truncate_stream_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        for &u in stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&new_size.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        match self.plan_stream_truncate(cx, target_ref, stream_utf16, new_size, now_ticks, digest) {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub(super) fn plan_stream_truncate(
        &self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        new_size: u64,
        now_ticks: u64,
        digest: [u8; 32],
    ) -> Result<PreparedTxPlan<()>> {
        let mut ws = TxWorkspace::load(self, cx)?;
        if !self.stage_stream_truncate(
            cx,
            &mut ws,
            target_ref,
            stream_utf16,
            new_size,
            now_ticks,
        )? {
            // An unchanged length retains its WAL token without rewriting the
            // FILE or allocation, including on full volumes.
            return Ok(PreparedTxPlan {
                operation: "truncate_stream_at",
                operation_digest: digest,
                result_value: (),
                pre_payload_writes: Vec::new(),
                mft_zero_writes: Vec::new(),
                open_attr_registrations: Vec::new(),
                mutation_specs: Vec::new(),
                target_writes: Vec::new(),
            });
        }
        ws.finalize(self, cx, "truncate_stream_at", digest, ())
    }

    /// Stage a stream resize without publishing a log, target, or allocation
    /// write. Compound metadata edits use the same workspace and commit point.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    fn stage_stream_truncate(
        &self,
        cx: &Cx,
        ws: &mut TxWorkspace,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        new_size: u64,
        now_ticks: u64,
    ) -> Result<bool> {
        checkpoint(cx)?;
        let cb = u64::from(self.geometry.cluster_bytes());
        // Both native byte counts and the cluster-rounded virtual allocation
        // are signed. Sparse holes must obey the same representability limit
        // even though they require no physical allocation or payload staging.
        if new_size > i64::MAX as u64 || new_size.div_ceil(cb) > i64::MAX as u64 / cb {
            return Err(FfsError::RequestRejected {
                errno: libc::EFBIG,
                detail: "NTFS stream length or rounded allocation exceeds the signed 64-bit native limit".into(),
            });
        }
        let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
        if cat_ro.is_directory {
            return Err(FfsError::IsDirectory);
        }
        if target_ref.record < MIN_USER_MFT_SLOT {
            return Err(FfsError::PermissionDenied);
        }
        if stream_utf16.is_empty() && (cat_ro.std_flags() & FILE_ATTR_ENCRYPTED) != 0 {
            return Err(unsupported(
                "ordinary NTFS truncate refused on encrypted file; decrypt explicitly first",
            ));
        }
        let wof_decoded = if stream_utf16.is_empty() {
            self.prepare_reparse_unnamed_data_write(cx, ws, target_ref, &cat_ro)?
        } else {
            None
        };
        let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
        let target_folded = self.fold_upcase(stream_utf16);
        let stream_idx = cat_ro
            .data_streams
            .iter()
            .position(|s| self.fold_upcase(&s.name) == target_folded)
            .ok_or_else(|| FfsError::NotFound("NTFS data stream not found".into()))?;
        if !stream_utf16.is_empty() && cat_ro.data_streams[stream_idx].name != stream_utf16 {
            return Err(FfsError::NotFound(
                "NTFS exact named stream not found".into(),
            ));
        }
        let wof_materialized = wof_decoded.is_some();
        let cur_stream = if let Some(decoded) = wof_decoded {
            EditableDataStream {
                name: Vec::new(),
                storage: EditableStreamStorage::Resident(decoded),
            }
        } else {
            cat_ro.data_streams[stream_idx].clone()
        };
        let old_size = cur_stream.logical_size();
        // A same-size truncate is a WAL no-op, except when WOF plaintext was
        // just materialized: that workspace change still has to commit.
        if new_size == old_size && !wof_materialized {
            return Ok(false);
        }
        let (sparse, compressed, initialized) = match &cur_stream.storage {
            EditableStreamStorage::Resident(bytes) => (false, false, bytes.len() as u64),
            EditableStreamStorage::NonResident {
                sparse,
                compressed,
                initialized_bytes,
                ..
            } => (*sparse, *compressed, *initialized_bytes),
        };
        // An ordinary extension must initialize the whole exposed tail,
        // including pre-existing allocation beyond ValidDataLength. Bound
        // that span before allocation or payload reads. Sparse/compressed
        // extension preserves ValidDataLength and adds only mapping-pair holes.
        if !sparse
            && !compressed
            && new_size > old_size
            && new_size.saturating_sub(initialized) > MAX_FILE_EDIT_BYTES
        {
            return Err(too_large_edit());
        }

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
                    let staged_bytes =
                        usize::try_from(need_vcns * cb).map_err(|_| too_large_edit())?;
                    let mut full_zeroed = vec![0_u8; staged_bytes];
                    let retained = old_bytes.len().min(new_size as usize);
                    full_zeroed[..retained].copy_from_slice(&old_bytes[..retained]);
                    stage_runs_writes(
                        &self.geometry,
                        &runs,
                        &full_zeroed,
                        &mut ws.pre_payload_writes,
                    )?;
                    EditableStreamStorage::NonResident {
                        runs: normalize_ntfs_runs(runs),
                        sparse: false,
                        compressed: false,
                        encrypted: false,
                        compression_unit: 0,
                        data_bytes: new_size,
                        initialized_bytes: new_size,
                    }
                }
            }
            EditableStreamStorage::NonResident {
                encrypted: true, ..
            } => {
                return Err(unsupported(
                    "ordinary NTFS truncate refused on encrypted stream",
                ));
            }
            EditableStreamStorage::NonResident {
                ref runs,
                compressed: true,
                data_bytes: old_sz,
                initialized_bytes: old_init,
                ..
            } => {
                let mut pre = Vec::new();
                let (st, disp) = compression::truncate_compressed_stream(
                    self,
                    cx,
                    runs,
                    old_sz,
                    old_init,
                    new_size,
                    &mut pre,
                    |n| ws.alloc_clusters(n, 1),
                )?;
                ws.pre_payload_writes.extend(pre);
                ws.free_clusters_deferred(&disp);
                st
            }
            EditableStreamStorage::NonResident {
                ref runs,
                sparse,
                compressed: false,
                encrypted: false,
                compression_unit,
                data_bytes: old_sz,
                initialized_bytes: old_init,
            } => {
                if !sparse && new_size <= MAX_RESIDENT_DATA_PAYLOAD as u64 {
                    let prefix =
                        read_editable_stream_prefix(self, cx, &cur_stream, 0, new_size as usize)?;
                    ws.free_clusters_deferred(&physical_spans_of_runs(runs));
                    EditableStreamStorage::Resident(prefix)
                } else if new_size == 0 && sparse {
                    ws.free_clusters_deferred(&physical_spans_of_runs(runs));
                    EditableStreamStorage::NonResident {
                        runs: Vec::new(),
                        sparse: true,
                        compressed: false,
                        encrypted: false,
                        compression_unit,
                        data_bytes: 0,
                        initialized_bytes: 0,
                    }
                } else {
                    let need_vcns = new_size.div_ceil(cb);
                    let old_vcns: u64 = runs.iter().map(|r| r.clusters).sum();
                    if new_size <= old_sz {
                        let (mut kept, disp) = splice_vcn_interval(
                            runs,
                            need_vcns,
                            old_vcns.max(need_vcns),
                            &[],
                            sparse,
                        )?;
                        ws.free_clusters_deferred(&disp);
                        // Splicing a sparse hole can coalesce it with the
                        // retained prefix hole. Clip that merged run as well
                        // as dropping runs wholly beyond the new EOF.
                        kept.retain_mut(|run| {
                            if run.vcn >= need_vcns {
                                return false;
                            }
                            run.clusters = run.clusters.min(need_vcns - run.vcn);
                            true
                        });
                        EditableStreamStorage::NonResident {
                            runs: normalize_ntfs_runs(kept),
                            sparse,
                            compressed: false,
                            encrypted: false,
                            compression_unit,
                            data_bytes: new_size,
                            initialized_bytes: old_init.min(new_size),
                        }
                    } else if sparse {
                        let mut next_runs = runs.clone();
                        if need_vcns > old_vcns {
                            next_runs.push(NtfsRun {
                                vcn: old_vcns,
                                clusters: need_vcns - old_vcns,
                                lcn: None,
                            });
                        }
                        EditableStreamStorage::NonResident {
                            runs: normalize_ntfs_runs(next_runs),
                            sparse: true,
                            compressed: false,
                            encrypted: false,
                            compression_unit,
                            data_bytes: new_size,
                            initialized_bytes: old_init,
                        }
                    } else {
                        let cow_start_vcn = old_init / cb;
                        let cow_clusters = need_vcns - cow_start_vcn;
                        let cow_byte_start = cow_start_vcn * cb;
                        let merged_buf = read_editable_stream_prefix(
                            self,
                            cx,
                            &cur_stream,
                            cow_byte_start,
                            usize::try_from(cow_clusters * cb).map_err(|_| too_large_edit())?,
                        )?;
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
                        let (working_runs, disp) =
                            splice_vcn_interval(runs, cow_start_vcn, need_vcns, &spans, false)?;
                        ws.free_clusters_deferred(&disp);
                        EditableStreamStorage::NonResident {
                            runs: working_runs,
                            sparse: false,
                            compressed: false,
                            encrypted: false,
                            compression_unit,
                            data_bytes: new_size,
                            initialized_bytes: new_size,
                        }
                    }
                }
            }
        };

        let usn_snapshot = {
            let cat = ws.catalog_mut(self, cx, target_ref)?;
            cat.data_streams[stream_idx].storage = updated_storage;
            cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
            cat.clone()
        };
        let reason = if new_size < old_size {
            USN_REASON_DATA_TRUNCATION | USN_REASON_CLOSE
        } else {
            USN_REASON_DATA_EXTEND | USN_REASON_CLOSE
        };
        ws.push_usn_event_for_catalog(&usn_snapshot, reason, now_ticks);
        if stream_utf16.is_empty() {
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
        }
        Ok(true)
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
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
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
                return Err(FfsError::RequestRejected {
                    errno: libc::EINVAL,
                    detail: "removing DATA requires a nonempty stream name".into(),
                });
            }
            validate_ntfs_stream_name_utf16(stream_utf16)?;
            let mut ws = TxWorkspace::load(self, cx)?;
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let target_folded = self.fold_upcase(stream_utf16);
            let freed = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                if cat.is_directory {
                    return Err(FfsError::IsDirectory);
                }
                let idx = cat
                    .data_streams
                    .iter()
                    .position(|s| self.fold_upcase(&s.name) == target_folded)
                    .ok_or_else(|| FfsError::NotFound("NTFS ADS stream not found".into()))?;
                if cat.data_streams[idx].name != stream_utf16 {
                    return Err(FfsError::NotFound("NTFS exact ADS stream not found".into()));
                }
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

    /// Rename a named Alternate Data Stream on `target_ref`.
    pub fn rename_stream_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        old_stream_utf16: &[u16],
        new_stream_utf16: &[u16],
        no_replace: bool,
        now_ticks: u64,
    ) -> NtfsTxOutcome<bool> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.rename_stream_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        for &u in old_stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        for &u in new_stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&[u8::from(no_replace)]);
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<bool>> {
            if old_stream_utf16.is_empty() || new_stream_utf16.is_empty() {
                return Err(FfsError::RequestRejected {
                    errno: libc::EINVAL,
                    detail: "ADS rename requires non-empty stream names".into(),
                });
            }
            validate_ntfs_stream_name_utf16(old_stream_utf16)?;
            validate_ntfs_stream_name_utf16(new_stream_utf16)?;
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let old_folded = self.fold_upcase(old_stream_utf16);
            let new_folded = self.fold_upcase(new_stream_utf16);
            let mut freed = Vec::new();
            let mut replaced_existing = false;
            {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                if cat.is_directory {
                    return Err(FfsError::IsDirectory);
                }
                let src_idx = cat
                    .data_streams
                    .iter()
                    .position(|s| self.fold_upcase(&s.name) == old_folded)
                    .ok_or_else(|| FfsError::NotFound("NTFS ADS stream not found".into()))?;
                if old_folded != new_folded
                    && let Some(dst_idx) = cat
                        .data_streams
                        .iter()
                        .position(|s| self.fold_upcase(&s.name) == new_folded)
                {
                    if no_replace {
                        return Err(FfsError::Exists);
                    }
                    replaced_existing = true;
                    let removed_dst = cat.data_streams.remove(dst_idx);
                    if let EditableStreamStorage::NonResident { runs, .. } = removed_dst.storage {
                        freed.extend(physical_spans_of_runs(&runs));
                    }
                    let adjusted_src = if dst_idx < src_idx {
                        src_idx - 1
                    } else {
                        src_idx
                    };
                    cat.data_streams[adjusted_src].name = new_stream_utf16.to_vec();
                } else {
                    cat.data_streams[src_idx].name = new_stream_utf16.to_vec();
                }
                cat.set_std_times(None, None, Some(now_ticks), None);
            }
            ws.free_clusters_deferred(&freed);
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "rename_stream_at", digest, replaced_existing)
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(FfsError::NoSpace) => {
                if self.ensure_mft_headroom(cx, 1, 0).is_ok() {
                    return self.rename_stream_at_after_headroom(
                        cx,
                        target_ref,
                        old_stream_utf16,
                        new_stream_utf16,
                        no_replace,
                        now_ticks,
                        digest,
                    );
                }
                NtfsTxOutcome::NotCommitted(FfsError::NoSpace)
            }
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rename_stream_at_after_headroom(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        old_stream_utf16: &[u16],
        new_stream_utf16: &[u16],
        no_replace: bool,
        now_ticks: u64,
        digest: [u8; 32],
    ) -> NtfsTxOutcome<bool> {
        let plan_res = (|| -> Result<PreparedTxPlan<bool>> {
            let mut ws = TxWorkspace::load(self, cx)?;
            let old_folded = self.fold_upcase(old_stream_utf16);
            let new_folded = self.fold_upcase(new_stream_utf16);
            let mut freed = Vec::new();
            let mut replaced_existing = false;
            {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                let src_idx = cat
                    .data_streams
                    .iter()
                    .position(|s| self.fold_upcase(&s.name) == old_folded)
                    .ok_or_else(|| FfsError::NotFound("NTFS ADS stream not found".into()))?;
                if old_folded != new_folded
                    && let Some(dst_idx) = cat
                        .data_streams
                        .iter()
                        .position(|s| self.fold_upcase(&s.name) == new_folded)
                {
                    if no_replace {
                        return Err(FfsError::Exists);
                    }
                    replaced_existing = true;
                    let removed_dst = cat.data_streams.remove(dst_idx);
                    if let EditableStreamStorage::NonResident { runs, .. } = removed_dst.storage {
                        freed.extend(physical_spans_of_runs(&runs));
                    }
                    let adjusted_src = if dst_idx < src_idx {
                        src_idx - 1
                    } else {
                        src_idx
                    };
                    cat.data_streams[adjusted_src].name = new_stream_utf16.to_vec();
                } else {
                    cat.data_streams[src_idx].name = new_stream_utf16.to_vec();
                }
                cat.set_std_times(None, None, Some(now_ticks), None);
            }
            ws.free_clusters_deferred(&freed);
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "rename_stream_at", digest, replaced_existing)
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
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_ntfs_component_utf16(new_name_utf16) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if target_ref.record < FIRST_NON_RESERVED_SLOT {
            return NtfsTxOutcome::NotCommitted(FfsError::PermissionDenied);
        }
        {
            let preflight = (|| -> Result<()> {
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
                Ok(())
            })();
            if let Err(err) = preflight {
                return NtfsTxOutcome::NotCommitted(err);
            }
        }
        let _ = self.ensure_mft_headroom(cx, 1, 1);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.link_entry_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        hasher.update(&new_parent_ref.record.to_le_bytes());
        for &u in new_name_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
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
            let target_flags = ws
                .catalogs
                .get(&target_ref.record)
                .map_or(0, EditableCatalog::std_flags);
            ws.push_usn_event_explicit(
                target_ref,
                new_parent_ref,
                USN_REASON_HARD_LINK_CHANGE | USN_REASON_CLOSE,
                target_flags,
                now_ticks,
                new_name_utf16.to_vec(),
            );

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
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
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
                ws.push_usn_event_explicit(
                    target_ref,
                    parent_ref,
                    USN_REASON_FILE_DELETE | USN_REASON_CLOSE,
                    target_ro.std_flags(),
                    now_ticks,
                    matched.file_name.name.clone(),
                );
                ws.deallocate_entire_catalog(self, cx, target_ref.record)?;
            } else {
                ws.push_usn_event_explicit(
                    target_ref,
                    parent_ref,
                    USN_REASON_HARD_LINK_CHANGE | USN_REASON_CLOSE,
                    target_ro.std_flags(),
                    now_ticks,
                    matched.file_name.name.clone(),
                );
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
        if self.version != [3, 1] {
            return Err(FfsError::NoSpace);
        }
        let parent_cat = ws.load_catalog(self, cx, parent_ref)?.clone();
        if !parent_cat.old_extensions.is_empty() || matched.file_name.namespace == 2 {
            return Err(FfsError::NoSpace);
        }
        let target_ro = ws.load_catalog(self, cx, target_ref)?.clone();
        if target_ro.reparse_point.is_some() || target_ro.object_id.is_some() {
            return Err(FfsError::NoSpace);
        }
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

        ws.deallocate_entire_catalog(self, cx, target_ref.record)?;
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
    ) -> NtfsTxOutcome<NtfsExtendedRenameOutcome> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
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

        let plan_res = (|| -> Result<PreparedTxPlan<NtfsExtendedRenameOutcome>> {
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
                        return ws.finalize(
                            self,
                            cx,
                            "rename_entry_at",
                            digest,
                            NtfsExtendedRenameOutcome {
                                moved_reference: src_ref,
                                overwritten_reference: None,
                                overwritten_remaining_links: 0,
                                overwritten_retained_as_orphan: false,
                                noop_same_inode: true,
                            },
                        );
                    }
                }
            }

            if src_ro.is_directory && src_parent_ref != dst_parent_ref {
                let mut cursor = dst_parent_ref;
                for _ in 0..4096 {
                    if cursor == src_ref {
                        return Err(FfsError::RequestRejected {
                            errno: libc::EINVAL,
                            detail: "cannot rename NTFS directory into its own subtree".into(),
                        });
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
                        if ws
                            .lookup_in_dir(self, cx, root_dir_ref, orphan_utf16)?
                            .is_some()
                        {
                            return Err(FfsError::Exists);
                        }
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
                        ws.push_usn_event_explicit(
                            dst_ref,
                            dst_parent_ref,
                            USN_REASON_FILE_DELETE | USN_REASON_CLOSE,
                            dst_ro.std_flags(),
                            now_ticks,
                            dst_match.file_name.name.clone(),
                        );
                        ws.deallocate_entire_catalog(self, cx, dst_ref.record)?;
                    }
                } else {
                    ws.sync_target_into_parent_dirs(self, cx, dst_ref)?;
                }
            }

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
            ws.push_usn_event_explicit(
                src_ref,
                src_parent_ref,
                USN_REASON_RENAME_OLD_NAME,
                src_ro.std_flags(),
                now_ticks,
                src_match.file_name.name,
            );
            ws.push_usn_event_explicit(
                src_ref,
                dst_parent_ref,
                USN_REASON_RENAME_NEW_NAME | USN_REASON_CLOSE,
                src_ro.std_flags(),
                now_ticks,
                dst_name_utf16.to_vec(),
            );

            ws.finalize(
                self,
                cx,
                "rename_entry_at",
                digest,
                NtfsExtendedRenameOutcome {
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

    /// Publish a compound unnamed-DATA resize and metadata/security edit with
    /// one native commit. Planning has no backing writes, including MFT growth:
    /// insufficient catalog capacity refuses the complete request before WAL
    /// publication. The caller retains its host authorization policy.
    pub fn set_attributes_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        attributes: &NtfsSetAttributes,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        match self.plan_attributes(cx, target_ref, attributes, now_ticks) {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    fn plan_attributes(
        &self,
        cx: &Cx,
        target_ref: NtfsReference,
        attributes: &NtfsSetAttributes,
        now_ticks: u64,
    ) -> Result<PreparedTxPlan<()>> {
        checkpoint(cx)?;
        if target_ref.record < 5
            || (target_ref.record > 5 && target_ref.record < FIRST_NON_RESERVED_SLOT)
        {
            return Err(FfsError::PermissionDenied);
        }
        if target_ref.record == 5 && attributes.read_only == Some(true) {
            return Err(unsupported(
                "setting FILE_ATTR_READONLY on NTFS root directory is refused",
            ));
        }
        if [
            Some(now_ticks),
            attributes.atime_ticks,
            attributes.mtime_ticks,
        ]
        .into_iter()
        .flatten()
        .any(|ticks| ticks > i64::MAX as u64)
        {
            return Err(unsupported("timestamp exceeds signed NTFS FILETIME range"));
        }
        let security = attributes
            .security
            .as_ref()
            .map(|patch| self.prepare_security_patch(cx, target_ref, patch))
            .transpose()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.set_attributes_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        hasher.update(&now_ticks.to_le_bytes());
        hasher.update(&[attributes.read_only.map_or(0, |value| 1 + u8::from(value))]);
        for value in [
            attributes.size,
            attributes.atime_ticks,
            attributes.mtime_ticks,
        ] {
            hasher.update(&[u8::from(value.is_some())]);
            if let Some(value) = value {
                hasher.update(&value.to_le_bytes());
            }
        }
        if let Some(security) = &security {
            hasher.update(blake3::hash(security).as_bytes());
        }
        let digest = *hasher.finalize().as_bytes();
        let mut ws = TxWorkspace::load(self, cx)?;
        let _ = ws.load_catalog(self, cx, target_ref)?;
        if let Some(security) = &security {
            self.stage_security_descriptor(cx, &mut ws, target_ref, security, now_ticks)?;
        }
        if let Some(size) = attributes.size {
            self.stage_stream_truncate(cx, &mut ws, target_ref, &[], size, now_ticks)?;
        }
        // Apply explicit metadata last: resizing sets automatic mtime, but an
        // explicit caller-supplied value belongs to the same final transaction.
        if attributes.read_only.is_some()
            || attributes.atime_ticks.is_some()
            || attributes.mtime_ticks.is_some()
        {
            let snapshot = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                if let Some(read_only) = attributes.read_only {
                    let flags = if read_only {
                        cat.std_flags() | FILE_ATTR_READONLY
                    } else {
                        cat.std_flags() & !FILE_ATTR_READONLY
                    };
                    cat.set_std_flags(flags);
                }
                cat.set_std_times(
                    None,
                    attributes.mtime_ticks,
                    Some(now_ticks),
                    attributes.atime_ticks,
                );
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &snapshot,
                USN_REASON_BASIC_INFO_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
        }
        ws.finalize(self, cx, "set_attributes_at", digest, ())
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
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.set_metadata_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        hasher.update(&mft_time_ticks.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if target_ref.record < 5
                || (target_ref.record > 5 && target_ref.record < FIRST_NON_RESERVED_SLOT)
            {
                return Err(FfsError::PermissionDenied);
            }
            if target_ref.record == 5 && read_only == Some(true) {
                return Err(unsupported(
                    "setting FILE_ATTR_READONLY on NTFS root directory is refused",
                ));
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let usn_snap = {
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
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_BASIC_INFO_CHANGE | USN_REASON_CLOSE,
                mft_time_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "set_metadata_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }
}

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

impl NtfsTransactionEngine {
    /// Resolve a `/` or `\` separated UTF-8 path from the volume root (`FILE 5`)
    /// through `$UpCase`-folded multi-level `$I30` B-trees.
    pub fn resolve_path_reference(&self, cx: &Cx, path: &str) -> Result<NtfsReference> {
        checkpoint(cx)?;
        let vol = self.volume_view(cx)?;
        let root_rec = vol.record(cx, 5, None)?;
        let mut cur = NtfsReference {
            record: 5,
            sequence: root_rec.sequence,
        };
        let trimmed = path.trim_matches(['/', '\\']);
        if trimmed.is_empty() {
            return Ok(cur);
        }
        for comp in trimmed.split(['/', '\\']) {
            if comp.is_empty() || comp == "." {
                continue;
            }
            let units: Vec<u16> = comp.encode_utf16().collect();
            validate_ntfs_component_utf16(&units)?;
            cur = self.lookup_reference(cx, cur, &units)?;
        }
        Ok(cur)
    }

    /// Rename a named `$DATA` stream on `path` via a native logged transaction.
    pub fn rename_file_stream(
        &mut self,
        cx: &Cx,
        path: &str,
        old_stream: &[u16],
        new_stream: &[u16],
        no_replace: bool,
    ) -> NtfsTxOutcome<NtfsReference> {
        let base_ref = match self.resolve_path_reference(cx, path) {
            Ok(r) => r,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        match self.rename_stream_at(
            cx,
            base_ref,
            old_stream,
            new_stream,
            no_replace,
            DEFAULT_NTFS_FILETIME,
        ) {
            NtfsTxOutcome::Committed { token, .. } => NtfsTxOutcome::Committed {
                value: base_ref,
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
    }

    /// Update read-only flag and/or timestamps (`mtime_ft`, `atime_ft` in 100ns
    /// NTFS FILETIME ticks) on `path` via a native logged transaction.
    pub fn set_file_metadata(
        &mut self,
        cx: &Cx,
        path: &str,
        read_only: Option<bool>,
        mtime_ft: Option<u64>,
        atime_ft: Option<u64>,
    ) -> NtfsTxOutcome<NtfsReference> {
        let base_ref = match self.resolve_path_reference(cx, path) {
            Ok(r) => r,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        let now_ft = mtime_ft.or(atime_ft).unwrap_or(DEFAULT_NTFS_FILETIME);
        match self.set_metadata_at(cx, base_ref, read_only, atime_ft, mtime_ft, now_ft) {
            NtfsTxOutcome::Committed { token, .. } => NtfsTxOutcome::Committed {
                value: base_ref,
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
    }

    /// Split a `/` or `\` separated UTF-8 path into its parent directory
    /// [`NtfsReference`] (resolved through multi-level `$I30` B-trees) and validated
    /// native UTF-16 leaf component.
    pub fn resolve_parent_and_leaf(
        &self,
        cx: &Cx,
        path: &str,
    ) -> Result<(NtfsReference, Vec<u16>)> {
        checkpoint(cx)?;
        let trimmed = path.trim_matches(['/', '\\']);
        if trimmed.is_empty() {
            return Err(FfsError::RequestRejected {
                errno: libc::EINVAL,
                detail: "root directory '/' has no parent/leaf split".into(),
            });
        }
        let (parent_path, leaf_str) = trimmed.rfind(['/', '\\']).map_or_else(
            || ("/".to_owned(), trimmed),
            |idx| (format!("/{}", &trimmed[..idx]), &trimmed[idx + 1..]),
        );
        let leaf_utf16: Vec<u16> = leaf_str.encode_utf16().collect();
        validate_ntfs_component_utf16(&leaf_utf16)?;
        let parent_ref = self.resolve_path_reference(cx, &parent_path)?;
        Ok((parent_ref, leaf_utf16))
    }

    /// Atomically replace an existing unnamed or named `$DATA` stream on `target_ref`
    /// in a single native WAL transaction, supporting `$ATTRIBUTE_LIST`, `SPARSE`,
    /// fragmented allocations, and multi-level `$I30` parent directories.
    pub fn replace_stream_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        new_data: &[u8],
        now_ticks: u64,
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_ntfs_stream_name_utf16(stream_utf16) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if new_data.len() as u64 > MAX_FILE_EDIT_BYTES {
            return NtfsTxOutcome::NotCommitted(too_large_edit());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.replace_stream_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        for &u in stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&(new_data.len() as u64).to_le_bytes());
        hasher.update(blake3::hash(new_data).as_bytes());
        let digest = *hasher.finalize().as_bytes();

        let cb = u64::from(self.geometry.cluster_bytes());
        let plan_res = (|| -> Result<PreparedTxPlan<NtfsReference>> {
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            if cat_ro.is_directory {
                return Err(FfsError::IsDirectory);
            }
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            if stream_utf16.is_empty() && (cat_ro.std_flags() & FILE_ATTR_ENCRYPTED) != 0 {
                return Err(unsupported(
                    "ordinary NTFS replace refused on encrypted file; use explicit keyed EFS write",
                ));
            }
            let _wof_decoded = if stream_utf16.is_empty() {
                self.prepare_reparse_unnamed_data_write(cx, &mut ws, target_ref, &cat_ro)?
            } else {
                None
            };
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            let target_folded = self.fold_upcase(stream_utf16);
            let stream_idx = cat_ro
                .data_streams
                .iter()
                .position(|s| self.fold_upcase(&s.name) == target_folded)
                .ok_or_else(|| FfsError::NotFound("NTFS data stream not found".into()))?;
            if !stream_utf16.is_empty() && cat_ro.data_streams[stream_idx].name != stream_utf16 {
                return Err(FfsError::NotFound(
                    "NTFS exact named stream not found".into(),
                ));
            }
            let was_compressed = matches!(
                cat_ro.data_streams[stream_idx].storage,
                EditableStreamStorage::NonResident {
                    compressed: true,
                    ..
                }
            );
            if matches!(
                cat_ro.data_streams[stream_idx].storage,
                EditableStreamStorage::NonResident {
                    encrypted: true,
                    ..
                }
            ) {
                return Err(unsupported(
                    "ordinary NTFS replace refused on encrypted stream",
                ));
            }
            if let EditableStreamStorage::NonResident { ref runs, .. } =
                cat_ro.data_streams[stream_idx].storage
            {
                ws.free_clusters_deferred(&physical_spans_of_runs(runs));
            }

            let updated_storage = if was_compressed {
                let mut pre = Vec::new();
                let st = compression::rebuild_stream_for_compression_toggle(
                    &self.geometry,
                    new_data,
                    true,
                    &mut pre,
                    |n| ws.alloc_clusters(n, 1),
                )?;
                ws.pre_payload_writes.extend(pre);
                st
            } else if new_data.len() <= MAX_RESIDENT_DATA_PAYLOAD {
                EditableStreamStorage::Resident(new_data.to_vec())
            } else {
                let need_vcns = (new_data.len() as u64).div_ceil(cb);
                let spans = ws.alloc_clusters(need_vcns, 1)?;
                let mut runs = Vec::with_capacity(spans.len());
                let mut cur_vcn = 0_u64;
                for &(lcn, cnt) in &spans {
                    runs.push(NtfsRun {
                        vcn: cur_vcn,
                        clusters: cnt,
                        lcn: Some(lcn),
                    });
                    cur_vcn += cnt;
                }
                let mut padded = vec![0_u8; (need_vcns * cb) as usize];
                padded[..new_data.len()].copy_from_slice(new_data);
                stage_runs_writes(&self.geometry, &runs, &padded, &mut ws.pre_payload_writes)?;
                EditableStreamStorage::NonResident {
                    runs: normalize_ntfs_runs(runs),
                    sparse: false,
                    compressed: false,
                    encrypted: false,
                    compression_unit: 0,
                    data_bytes: new_data.len() as u64,
                    initialized_bytes: new_data.len() as u64,
                }
            };

            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.data_streams[stream_idx].storage = updated_storage;
                cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_TRUNCATION | USN_REASON_CLOSE,
                now_ticks,
            );
            if stream_utf16.is_empty() {
                ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            }
            ws.finalize(self, cx, "replace_stream_at", digest, target_ref)
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Replace `path`'s unnamed `$DATA` stream, falling back from the single-record
    /// fast path to [`Self::replace_stream_at`] when `$ATTRIBUTE_LIST`, `SPARSE`,
    /// or multi-level `$I30` directories participate.
    pub fn write_file_data_extended(
        &mut self,
        cx: &Cx,
        path: &str,
        new_data: &[u8],
    ) -> NtfsTxOutcome<NtfsReference> {
        let outcome = self.write_file_data(cx, path, new_data);
        if !matches!(
            outcome,
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
        ) || self.requires_recovery()
        {
            return outcome;
        }
        let target_ref = match self.resolve_path_reference(cx, path) {
            Ok(r) => r,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        self.replace_stream_at(cx, target_ref, &[], new_data, DEFAULT_NTFS_FILETIME)
    }

    /// Rename `source_path` to `destination_path`, falling back from the single-record
    /// fast path to [`Self::rename_at`] for `$ATTRIBUTE_LIST`, `SPARSE`, or multi-level
    /// `$I30` directories while preserving `--expected-record`/`--expected-sequence`
    /// post-commit retry idempotency.
    pub fn rename_path_extended(
        &mut self,
        cx: &Cx,
        source_path: &str,
        destination_path: &str,
        expected_source_ref: Option<NtfsReference>,
        no_replace: bool,
    ) -> NtfsTxOutcome<NtfsReference> {
        let outcome = if no_replace {
            self.rename_entry_no_replace(cx, source_path, destination_path, expected_source_ref)
        } else {
            self.rename_entry(cx, source_path, destination_path, expected_source_ref)
        };
        if !matches!(
            outcome,
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
        ) || self.requires_recovery()
        {
            return outcome;
        }

        if !no_replace
            && let Some(expected_ref) = expected_source_ref
            && matches!(
                self.resolve_path_reference(cx, source_path),
                Err(FfsError::NotFound(_))
            )
            && self.resolve_path_reference(cx, destination_path).ok() == Some(expected_ref)
        {
            if let Err(err) = self.check_clean_consistency(cx) {
                return NtfsTxOutcome::NotCommitted(err);
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"ntfs.rename_path_extended:");
            hasher.update(source_path.as_bytes());
            hasher.update(b"->");
            hasher.update(destination_path.as_bytes());
            let digest = *hasher.finalize().as_bytes();
            let cur_lsn = self.ring.as_ref().map_or(1, |r| r.current_lsn().max(1));
            let ckpt_lsn = self
                .ring
                .as_ref()
                .map(ffs_ondisk::ntfs::logfile_writer::NtfsLogRingWriter::client_restart_lsn);
            let token = self.make_token(0, cur_lsn, ckpt_lsn, digest);
            return NtfsTxOutcome::Committed {
                value: expected_ref,
                token,
            };
        }

        let (source_parent, source_leaf) = match self.resolve_parent_and_leaf(cx, source_path) {
            Ok(pair) => pair,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        let source_ref = match self.lookup_reference(cx, source_parent, &source_leaf) {
            Ok(r) => r,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        if let Some(expected_ref) = expected_source_ref
            && expected_ref != source_ref
        {
            return NtfsTxOutcome::NotCommitted(stale_target());
        }
        let (dest_parent, dest_leaf) = match self.resolve_parent_and_leaf(cx, destination_path) {
            Ok(pair) => pair,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        match self.rename_at(
            cx,
            source_parent,
            &source_leaf,
            dest_parent,
            &dest_leaf,
            source_ref,
            no_replace,
        ) {
            NtfsTxOutcome::Committed { value, token } => NtfsTxOutcome::Committed {
                value: value.source,
                token,
            },
            NtfsTxOutcome::NotCommitted(err) => NtfsTxOutcome::NotCommitted(err),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
    }

    /// Unlink `path`, falling back from the single-record fast path to [`Self::unlink_at`]
    /// for `$ATTRIBUTE_LIST`, `SPARSE`, or multi-level `$I30` directories.
    pub fn unlink_path_extended(&mut self, cx: &Cx, path: &str) -> NtfsTxOutcome<NtfsReference> {
        let outcome = self.unlink_file(cx, path);
        if !matches!(
            outcome,
            NtfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(_) | FfsError::NoSpace)
        ) || self.requires_recovery()
        {
            return outcome;
        }
        let (parent_ref, leaf_utf16) = match self.resolve_parent_and_leaf(cx, path) {
            Ok(pair) => pair,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        let expected_ref = match self.lookup_reference(cx, parent_ref, &leaf_utf16) {
            Ok(r) => r,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        self.unlink_at(cx, parent_ref, &leaf_utf16, expected_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_ntfs_component_utf16, validate_ntfs_stream_name_utf16};

    #[test]
    fn component_validation_preserves_native_units_and_rejects_ambiguous_paths() {
        assert!(validate_ntfs_component_utf16(&[0xD800]).is_ok());
        assert!(validate_ntfs_component_utf16(&vec![65; 255]).is_ok());
        assert!(validate_ntfs_component_utf16(&vec![65; 256]).is_err());
        for invalid in [
            vec![],
            vec![46],
            vec![46, 46],
            vec![0],
            vec![47],
            vec![92],
            vec![58],
        ] {
            assert!(
                validate_ntfs_component_utf16(&invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert!(validate_ntfs_stream_name_utf16(&[]).is_ok());
        assert!(validate_ntfs_stream_name_utf16(&[46]).is_ok());
        assert!(validate_ntfs_stream_name_utf16(&[0]).is_err());
        assert!(validate_ntfs_stream_name_utf16(&[58]).is_err());
    }
}
