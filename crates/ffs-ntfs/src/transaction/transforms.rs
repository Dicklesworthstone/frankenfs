//! Native NTFS writable transforms, security descriptors (`$Secure` & `0x50`),
//! reparse points (`$Reparse::$R`), object IDs (`$ObjId::$O`), active change
//! journal (`$UsnJrnl`), extended attributes (`$EA`), and explicit key-scoped
//! EFS encryption/decryption (`$EFS` `0x100`).

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::ea::{
    NtfsEa, NtfsEaInformation, encode_extended_attributes, parse_extended_attributes,
};
use ffs_ondisk::ntfs::efs::{
    EFS_ALG_AES_256, EFS_SECTOR_BYTES, NtfsEfsMetadata, compute_efs_key_commitment,
    derive_efs_key_id, efs_decrypt_sector, efs_encrypt_sector,
};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::reparse::{NtfsReparseData, NtfsReparsePoint, SYMLINK_TAG};
use ffs_ondisk::ntfs::usn::{
    USN_REASON_BASIC_INFO_CHANGE, USN_REASON_CLOSE, USN_REASON_COMPRESSION_CHANGE,
    USN_REASON_DATA_OVERWRITE, USN_REASON_EA_CHANGE, USN_REASON_ENCRYPTION_CHANGE,
    USN_REASON_FILE_CREATE, USN_REASON_OBJECT_ID_CHANGE, USN_REASON_REPARSE_POINT_CHANGE,
    USN_REASON_SECURITY_CHANGE, UsnMaxData,
};
use ffs_ondisk::ntfs::{NtfsReference, NtfsRun};
use ffs_ondisk::ntfs_security::{
    NtfsAccessToken, NtfsSecurityDescriptor, evaluate_dacl_access, inherit_security_descriptor,
};

use crate::efs::{NtfsEfsKey, NtfsEfsKeyScope};
use crate::reader::wof::BACKING_NAME as WOF_BACKING_NAME;
use crate::reparse_provider::{
    ReparseCapability, classify_reparse_point, validate_writable_reparse_point,
};
use crate::security_policy::{NtfsSecurityPatch, apply_security_patch};

use super::btree::I30RawEntry;
use super::catalog::{
    EditableCatalog, EditableDataStream, EditableDirIndex, EditableFileName, EditableStreamStorage,
    normalize_ntfs_runs, physical_spans_of_runs, stage_runs_writes,
};
use super::compression;
use super::dir_index::build_empty_small_index_root;
use super::mutations::{
    FILE_ATTR_COMPRESSED, FILE_ATTR_ENCRYPTED, FILE_ATTR_REPARSE_POINT, FILE_ATTR_SPARSE_FILE,
    FIRST_NON_RESERVED_SLOT, MIN_USER_MFT_SLOT, TxWorkspace, choose_ntfs_namespace,
    read_editable_stream_prefix, splice_vcn_interval, too_large_edit,
    validate_ntfs_component_utf16, validate_ntfs_stream_name_utf16,
};
use super::ops::{
    FILE_ATTR_ARCHIVE, FILE_ATTR_DIRECTORY, MAX_RESIDENT_DATA_PAYLOAD, PreparedTxPlan,
    encode_standard_information, extract_parent_security,
};
use super::secondary::{EXTEND_USNJRNL_UPPER, NtfsObjectIdData, USN_J_NAME, USN_MAX_NAME};
use super::{
    MAX_FILE_EDIT_BYTES, NtfsTransactionEngine, NtfsTxOutcome, checkpoint, corrupt, parse_err,
    read_mapped_runs, read_mft_record_via_runs, unsupported,
};

const FILE_ATTR_HIDDEN: u32 = 0x0000_0002;
const FILE_ATTR_SYSTEM: u32 = 0x0000_0004;

impl NtfsTransactionEngine {
    /// Toggle the native `SPARSE` (`0x8000`) flag on unnamed `$DATA` or a named ADS.
    ///
    /// Enabling sparse promotes resident streams to non-resident `SPARSE` storage.
    /// Disabling sparse materializes any sparse holes into allocated zero clusters
    /// (bounded by `MAX_FILE_EDIT_BYTES`) and clears `FILE_ATTRIBUTE_SPARSE_FILE`
    /// when targeting the unnamed `$DATA` stream.
    #[allow(clippy::too_many_lines)]
    pub fn set_sparse_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        enable_sparse: bool,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_ntfs_stream_name_utf16(stream_utf16) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.set_sparse_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        for &u in stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&[u8::from(enable_sparse)]);
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            let mut ws = TxWorkspace::load(self, cx)?;
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            if cat_ro.is_directory {
                return Err(FfsError::IsDirectory);
            }
            if stream_utf16.is_empty() && (cat_ro.std_flags() & FILE_ATTR_ENCRYPTED) != 0 {
                return Err(unsupported(
                    "cannot toggle SPARSE on an encrypted NTFS file",
                ));
            }
            if stream_utf16.is_empty() && cat_ro.reparse_point.is_some() {
                return Err(unsupported(
                    "cannot toggle SPARSE on an NTFS reparse point without removing reparse metadata",
                ));
            }
            let target_folded = self.fold_upcase(stream_utf16);
            let stream_idx = cat_ro
                .data_streams
                .iter()
                .position(|s| self.fold_upcase(&s.name) == target_folded)
                .ok_or_else(|| FfsError::NotFound("NTFS data stream not found".into()))?;
            let cur_stream = cat_ro.data_streams[stream_idx].clone();
            let cb = u64::from(self.geometry.cluster_bytes());

            let next_storage = match &cur_stream.storage {
                EditableStreamStorage::Resident(bytes) => {
                    if !enable_sparse {
                        cur_stream.storage.clone()
                    } else if bytes.is_empty() {
                        EditableStreamStorage::NonResident {
                            runs: Vec::new(),
                            sparse: true,
                            compressed: false,
                            encrypted: false,
                            compression_unit: 0,
                            data_bytes: 0,
                            initialized_bytes: 0,
                        }
                    } else {
                        let n_cl = (bytes.len() as u64).div_ceil(cb);
                        let spans = ws.alloc_clusters(n_cl, 1)?;
                        let mut runs = Vec::with_capacity(spans.len());
                        let mut v = 0_u64;
                        for &(lcn, cnt) in &spans {
                            runs.push(NtfsRun {
                                vcn: v,
                                clusters: cnt,
                                lcn: Some(lcn),
                            });
                            v += cnt;
                        }
                        let mut padded = vec![0_u8; (n_cl * cb) as usize];
                        padded[..bytes.len()].copy_from_slice(bytes);
                        stage_runs_writes(
                            &self.geometry,
                            &runs,
                            &padded,
                            &mut ws.pre_payload_writes,
                        )?;
                        EditableStreamStorage::NonResident {
                            runs: normalize_ntfs_runs(runs),
                            sparse: true,
                            compressed: false,
                            encrypted: false,
                            compression_unit: 0,
                            data_bytes: bytes.len() as u64,
                            initialized_bytes: bytes.len() as u64,
                        }
                    }
                }
                EditableStreamStorage::NonResident {
                    compressed: true, ..
                } => {
                    return Err(unsupported(
                        "cannot toggle SPARSE flag directly on an LZNT1-compressed stream",
                    ));
                }
                EditableStreamStorage::NonResident {
                    encrypted: true, ..
                } => {
                    return Err(unsupported(
                        "cannot toggle SPARSE flag on an encrypted stream",
                    ));
                }
                EditableStreamStorage::NonResident {
                    runs,
                    sparse,
                    data_bytes,
                    initialized_bytes,
                    ..
                } => {
                    if *sparse == enable_sparse {
                        cur_stream.storage.clone()
                    } else if enable_sparse {
                        EditableStreamStorage::NonResident {
                            runs: runs.clone(),
                            sparse: true,
                            compressed: false,
                            encrypted: false,
                            compression_unit: 0,
                            data_bytes: *data_bytes,
                            initialized_bytes: *initialized_bytes,
                        }
                    } else {
                        // Materialize sparse holes into plain storage (bounded by MAX_FILE_EDIT_BYTES).
                        if *data_bytes > MAX_FILE_EDIT_BYTES {
                            return Err(too_large_edit());
                        }
                        let full = read_editable_stream_prefix(
                            self,
                            cx,
                            &cur_stream,
                            0,
                            *data_bytes as usize,
                        )?;
                        ws.free_clusters_deferred(&physical_spans_of_runs(runs));
                        if full.len() <= MAX_RESIDENT_DATA_PAYLOAD {
                            EditableStreamStorage::Resident(full)
                        } else {
                            let n_cl = (*data_bytes).div_ceil(cb);
                            let spans = ws.alloc_clusters(n_cl, 1)?;
                            let mut next_runs = Vec::with_capacity(spans.len());
                            let mut v = 0_u64;
                            for &(lcn, cnt) in &spans {
                                next_runs.push(NtfsRun {
                                    vcn: v,
                                    clusters: cnt,
                                    lcn: Some(lcn),
                                });
                                v += cnt;
                            }
                            let mut padded = vec![0_u8; (n_cl * cb) as usize];
                            padded[..full.len()].copy_from_slice(&full);
                            stage_runs_writes(
                                &self.geometry,
                                &next_runs,
                                &padded,
                                &mut ws.pre_payload_writes,
                            )?;
                            EditableStreamStorage::NonResident {
                                runs: normalize_ntfs_runs(next_runs),
                                sparse: false,
                                compressed: false,
                                encrypted: false,
                                compression_unit: 0,
                                data_bytes: *data_bytes,
                                initialized_bytes: *data_bytes,
                            }
                        }
                    }
                }
            };

            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.data_streams[stream_idx].storage = next_storage;
                if stream_utf16.is_empty() {
                    let mut flags = cat.std_flags();
                    if enable_sparse {
                        flags |= FILE_ATTR_SPARSE_FILE;
                    } else {
                        flags &= !FILE_ATTR_SPARSE_FILE;
                    }
                    cat.set_std_flags(flags);
                }
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_BASIC_INFO_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            if stream_utf16.is_empty() {
                ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            }
            ws.finalize(self, cx, "set_sparse_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Punch a zeroed sparse hole over `[offset .. offset + length)` on `stream_utf16`,
    /// zeroing partial cluster edges via COW and deallocating full interior clusters into
    /// sparse holes (`lcn = None`). Returns the number of clusters reclaimed.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub fn punch_hole_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        stream_utf16: &[u16],
        offset: u64,
        length: u64,
        auto_enable_sparse: bool,
        now_ticks: u64,
    ) -> NtfsTxOutcome<u64> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_ntfs_stream_name_utf16(stream_utf16) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.punch_hole_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        for &u in stream_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&offset.to_le_bytes());
        hasher.update(&length.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<u64>> {
            let mut ws = TxWorkspace::load(self, cx)?;
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            if cat_ro.is_directory {
                return Err(FfsError::IsDirectory);
            }
            if stream_utf16.is_empty() && (cat_ro.std_flags() & FILE_ATTR_ENCRYPTED) != 0 {
                return Err(unsupported("cannot punch hole in an encrypted NTFS file"));
            }
            if stream_utf16.is_empty() && cat_ro.reparse_point.is_some() {
                return Err(unsupported("cannot punch hole in an NTFS reparse point"));
            }
            let target_folded = self.fold_upcase(stream_utf16);
            let stream_idx = cat_ro
                .data_streams
                .iter()
                .position(|s| self.fold_upcase(&s.name) == target_folded)
                .ok_or_else(|| FfsError::NotFound("NTFS data stream not found".into()))?;
            let cur_stream = cat_ro.data_streams[stream_idx].clone();
            let stream_size = cur_stream.logical_size();
            if length == 0 || offset >= stream_size {
                return ws.finalize(self, cx, "punch_hole_at", digest, 0);
            }
            let punch_end = offset.saturating_add(length).min(stream_size);
            let cb = u64::from(self.geometry.cluster_bytes());

            let (mut working_runs, data_bytes, init_bytes) = match &cur_stream.storage {
                EditableStreamStorage::Resident(bytes) => {
                    if !auto_enable_sparse {
                        return Err(unsupported(
                            "punch_hole requires a SPARSE NTFS stream (or auto_enable_sparse)",
                        ));
                    }
                    let mut next = bytes.clone();
                    next[offset as usize..punch_end as usize].fill(0);
                    let usn_snap = {
                        let cat = ws.catalog_mut(self, cx, target_ref)?;
                        cat.data_streams[stream_idx].storage =
                            EditableStreamStorage::Resident(next);
                        cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
                        cat.clone()
                    };
                    ws.push_usn_event_for_catalog(
                        &usn_snap,
                        USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE,
                        now_ticks,
                    );
                    if stream_utf16.is_empty() {
                        ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
                    }
                    return ws.finalize(self, cx, "punch_hole_at", digest, 0);
                }
                EditableStreamStorage::NonResident {
                    compressed: true, ..
                } => {
                    return Err(unsupported(
                        "punch_hole is not supported directly on LZNT1-compressed streams",
                    ));
                }
                EditableStreamStorage::NonResident {
                    encrypted: true, ..
                } => {
                    return Err(unsupported(
                        "punch_hole is not supported on encrypted NTFS streams",
                    ));
                }
                EditableStreamStorage::NonResident {
                    runs,
                    sparse,
                    data_bytes,
                    initialized_bytes,
                    ..
                } => {
                    if !*sparse && !auto_enable_sparse {
                        return Err(unsupported(
                            "punch_hole requires SPARSE stream flag (enable sparse first)",
                        ));
                    }
                    (runs.clone(), *data_bytes, *initialized_bytes)
                }
            };

            let mut reclaimed = 0_u64;
            let start_vcn = offset / cb;
            let last_byte_vcn = (punch_end - 1) / cb;

            if start_vcn == last_byte_vcn {
                let c_start = start_vcn * cb;
                let mut cluster_buf =
                    read_editable_stream_prefix(self, cx, &cur_stream, c_start, cb as usize)?;
                cluster_buf[(offset - c_start) as usize..(punch_end - c_start) as usize].fill(0);
                if cluster_buf.iter().all(|&b| b == 0) {
                    let (spliced, disp) =
                        splice_vcn_interval(&working_runs, start_vcn, start_vcn + 1, &[], true)?;
                    reclaimed += disp.iter().map(|&(_, c)| c).sum::<u64>();
                    ws.free_clusters_deferred(&disp);
                    working_runs = spliced;
                } else {
                    let span = ws.alloc_clusters(1, 1)?;
                    let st_run = [NtfsRun {
                        vcn: 0,
                        clusters: 1,
                        lcn: Some(span[0].0),
                    }];
                    stage_runs_writes(
                        &self.geometry,
                        &st_run,
                        &cluster_buf,
                        &mut ws.pre_payload_writes,
                    )?;
                    let (spliced, disp) =
                        splice_vcn_interval(&working_runs, start_vcn, start_vcn + 1, &span, true)?;
                    ws.free_clusters_deferred(&disp);
                    working_runs = spliced;
                }
            } else {
                // Leading partial cluster (if unaligned).
                let full_start_vcn = if offset.is_multiple_of(cb) {
                    start_vcn
                } else {
                    let c_start = start_vcn * cb;
                    let mut buf =
                        read_editable_stream_prefix(self, cx, &cur_stream, c_start, cb as usize)?;
                    buf[(offset - c_start) as usize..].fill(0);
                    if buf.iter().all(|&b| b == 0) {
                        let (spliced, disp) = splice_vcn_interval(
                            &working_runs,
                            start_vcn,
                            start_vcn + 1,
                            &[],
                            true,
                        )?;
                        reclaimed += disp.iter().map(|&(_, c)| c).sum::<u64>();
                        ws.free_clusters_deferred(&disp);
                        working_runs = spliced;
                    } else {
                        let span = ws.alloc_clusters(1, 1)?;
                        let st_run = [NtfsRun {
                            vcn: 0,
                            clusters: 1,
                            lcn: Some(span[0].0),
                        }];
                        stage_runs_writes(
                            &self.geometry,
                            &st_run,
                            &buf,
                            &mut ws.pre_payload_writes,
                        )?;
                        let (spliced, disp) = splice_vcn_interval(
                            &working_runs,
                            start_vcn,
                            start_vcn + 1,
                            &span,
                            true,
                        )?;
                        ws.free_clusters_deferred(&disp);
                        working_runs = spliced;
                    }
                    start_vcn + 1
                };

                // Trailing partial cluster (if unaligned and not hitting EOF on cluster boundary).
                let full_end_vcn = if punch_end.is_multiple_of(cb) {
                    punch_end / cb
                } else {
                    let c_start = last_byte_vcn * cb;
                    let mut buf =
                        read_editable_stream_prefix(self, cx, &cur_stream, c_start, cb as usize)?;
                    buf[..(punch_end - c_start) as usize].fill(0);
                    if buf.iter().all(|&b| b == 0) {
                        let (spliced, disp) = splice_vcn_interval(
                            &working_runs,
                            last_byte_vcn,
                            last_byte_vcn + 1,
                            &[],
                            true,
                        )?;
                        reclaimed += disp.iter().map(|&(_, c)| c).sum::<u64>();
                        ws.free_clusters_deferred(&disp);
                        working_runs = spliced;
                    } else {
                        let span = ws.alloc_clusters(1, 1)?;
                        let st_run = [NtfsRun {
                            vcn: 0,
                            clusters: 1,
                            lcn: Some(span[0].0),
                        }];
                        stage_runs_writes(
                            &self.geometry,
                            &st_run,
                            &buf,
                            &mut ws.pre_payload_writes,
                        )?;
                        let (spliced, disp) = splice_vcn_interval(
                            &working_runs,
                            last_byte_vcn,
                            last_byte_vcn + 1,
                            &span,
                            true,
                        )?;
                        ws.free_clusters_deferred(&disp);
                        working_runs = spliced;
                    }
                    last_byte_vcn
                };

                if full_start_vcn < full_end_vcn {
                    let (spliced, disp) = splice_vcn_interval(
                        &working_runs,
                        full_start_vcn,
                        full_end_vcn,
                        &[],
                        true,
                    )?;
                    reclaimed += disp.iter().map(|&(_, c)| c).sum::<u64>();
                    ws.free_clusters_deferred(&disp);
                    working_runs = spliced;
                }
            }

            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.data_streams[stream_idx].storage = EditableStreamStorage::NonResident {
                    runs: working_runs,
                    sparse: true,
                    compressed: false,
                    encrypted: false,
                    compression_unit: 0,
                    data_bytes,
                    initialized_bytes: init_bytes,
                };
                if stream_utf16.is_empty() {
                    let flags = cat.std_flags() | FILE_ATTR_SPARSE_FILE;
                    cat.set_std_flags(flags);
                }
                cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE,
                now_ticks,
            );
            if stream_utf16.is_empty() {
                ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            }
            ws.finalize(self, cx, "punch_hole_at", digest, reclaimed)
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Enable or disable native NTFS LZNT1 compression (`FILE_ATTRIBUTE_COMPRESSED`).
    ///
    /// On directories, this sets/clears the inheritance default for newly created children.
    /// On regular files, this re-encodes unnamed `$DATA` via COW into 16-cluster LZNT1
    /// compression units (or decompresses back to plain storage), including materializing
    /// WOF-compressed files cleanly.
    #[allow(clippy::too_many_lines)]
    pub fn set_compression_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        enable_compression: bool,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if enable_compression && let Err(err) = compression::check_lznt1_geometry(&self.geometry) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.set_compression_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        hasher.update(&[u8::from(enable_compression)]);
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            let mut ws = TxWorkspace::load(self, cx)?;
            if target_ref.record < 5
                || (target_ref.record > 5 && target_ref.record < FIRST_NON_RESERVED_SLOT)
            {
                return Err(FfsError::PermissionDenied);
            }
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            if (cat_ro.std_flags() & FILE_ATTR_ENCRYPTED) != 0 {
                return Err(unsupported(
                    "NTFS compression and encryption are mutually exclusive",
                ));
            }
            if cat_ro.is_directory {
                let usn_snap = {
                    let cat = ws.catalog_mut(self, cx, target_ref)?;
                    let mut flags = cat.std_flags();
                    if enable_compression {
                        flags |= FILE_ATTR_COMPRESSED;
                    } else {
                        flags &= !FILE_ATTR_COMPRESSED;
                    }
                    cat.set_std_flags(flags);
                    cat.set_std_times(None, None, Some(now_ticks), None);
                    cat.clone()
                };
                ws.push_usn_event_for_catalog(
                    &usn_snap,
                    USN_REASON_COMPRESSION_CHANGE | USN_REASON_CLOSE,
                    now_ticks,
                );
                ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
                return ws.finalize(self, cx, "set_compression_at", digest, ());
            }

            // Regular file: decode full plaintext (handling WOF if present).
            let mut was_wof = false;
            let plaintext = if let Some(ref rp_bytes) = cat_ro.reparse_point {
                let rp = NtfsReparsePoint::parse(rp_bytes).map_err(|err| parse_err(&err))?;
                if classify_reparse_point(&rp) != ReparseCapability::WofFileProvider {
                    return Err(unsupported(
                        "cannot toggle compression on a non-WOF NTFS reparse point",
                    ));
                }
                was_wof = true;
                let vol = self.volume_view(cx)?;
                let rec = vol.record(cx, target_ref.record, Some(target_ref.sequence))?;
                vol.read_wof_all(cx, &rec, MAX_FILE_EDIT_BYTES as usize)?
            } else {
                let stream = cat_ro
                    .data_streams
                    .iter()
                    .find(|s| s.name.is_empty())
                    .ok_or_else(|| {
                        FfsError::NotFound("unnamed NTFS $DATA stream missing".into())
                    })?;
                let sz = stream.logical_size();
                if sz > MAX_FILE_EDIT_BYTES {
                    return Err(too_large_edit());
                }
                read_editable_stream_prefix(self, cx, stream, 0, sz as usize)?
            };

            let mut freed_spans = Vec::new();
            let wof_folded = self.fold_upcase(WOF_BACKING_NAME);
            for s in &cat_ro.data_streams {
                if (s.name.is_empty() || (was_wof && self.fold_upcase(&s.name) == wof_folded))
                    && let EditableStreamStorage::NonResident { ref runs, .. } = s.storage
                {
                    freed_spans.extend(physical_spans_of_runs(runs));
                }
            }
            ws.free_clusters_deferred(&freed_spans);
            if was_wof {
                ws.sync_reparse_r_index(self, cx, target_ref, None)?;
            }

            let mut pre = Vec::new();
            let next_storage = compression::rebuild_stream_for_compression_toggle(
                &self.geometry,
                &plaintext,
                enable_compression,
                &mut pre,
                |n| ws.alloc_clusters(n, 1),
            )?;
            ws.pre_payload_writes.extend(pre);

            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                if was_wof {
                    cat.data_streams
                        .retain(|s| self.fold_upcase(&s.name) != wof_folded);
                    cat.reparse_point = None;
                }
                if let Some(unnamed) = cat.data_streams.iter_mut().find(|s| s.name.is_empty()) {
                    unnamed.storage = next_storage;
                } else {
                    cat.data_streams.push(EditableDataStream {
                        name: Vec::new(),
                        storage: next_storage,
                    });
                }
                let mut flags = cat.std_flags() & !FILE_ATTR_REPARSE_POINT;
                if enable_compression {
                    flags = (flags | FILE_ATTR_COMPRESSED) & !FILE_ATTR_SPARSE_FILE;
                } else {
                    flags &= !FILE_ATTR_COMPRESSED;
                }
                cat.set_std_flags(flags);
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_COMPRESSION_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "set_compression_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Replace an object's native MS-DTYP security descriptor, interning it in `$Secure`
    /// (`$SDS`/`$SII`/`$SDH`) on NTFS 3.1 or storing `0x50` `$SECURITY_DESCRIPTOR` on
    /// NTFS 3.0. Returns `Some(security_id)` when backed by `$Secure`, or `None` for `0x50`.
    pub fn set_security_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        descriptor_bytes: &[u8],
        now_ticks: u64,
    ) -> NtfsTxOutcome<Option<u32>> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let canonical =
            match NtfsSecurityDescriptor::parse(descriptor_bytes).and_then(|sd| sd.encode()) {
                Ok(bytes) => bytes,
                Err(err) => return NtfsTxOutcome::NotCommitted(parse_err(&err)),
            };
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.set_security_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        hasher.update(blake3::hash(&canonical).as_bytes());
        let digest = *hasher.finalize().as_bytes();

        let _ = self.ensure_mft_headroom(cx, 2, 4);

        let plan_res = (|| -> Result<PreparedTxPlan<Option<u32>>> {
            if target_ref.record < 5
                || (target_ref.record > 5 && target_ref.record < FIRST_NON_RESERVED_SLOT)
            {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let _ = ws.load_catalog(self, cx, target_ref)?;
            let assigned_id = if self.version == [3, 1] && ws.mft_slot_is_allocated(9) {
                let sec_id = ws.intern_security_descriptor(self, cx, &canonical)?;
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.set_std_security_id(sec_id);
                cat.security_descriptor = None;
                cat.set_std_times(None, None, Some(now_ticks), None);
                Some(sec_id)
            } else {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.security_descriptor = Some(canonical);
                if cat.std_info.len() == 72 {
                    cat.std_info[52..56].copy_from_slice(&0_u32.to_le_bytes());
                }
                cat.set_std_times(None, None, Some(now_ticks), None);
                None
            };
            let snap = ws.load_catalog(self, cx, target_ref)?.clone();
            ws.push_usn_event_for_catalog(
                &snap,
                USN_REASON_SECURITY_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "set_security_at", digest, assigned_id)
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Apply a declarative [`NtfsSecurityPatch`] (owner/group/DACL/POSIX mode) onto
    /// `target_ref`'s current security descriptor while preserving SACLs and non-POSIX ACEs.
    pub fn patch_security_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        patch: &NtfsSecurityPatch,
        now_ticks: u64,
    ) -> NtfsTxOutcome<Option<u32>> {
        let base_sd = match (|| -> Result<NtfsSecurityDescriptor> {
            checkpoint(cx)?;
            let vol = self.volume_view(cx)?;
            let rec = Self::checked_reference(&vol, cx, target_ref)?;
            match vol.security_descriptor(cx, &rec) {
                Ok(info) => Ok(info.descriptor),
                Err(FfsError::NotFound(_)) => {
                    // Synthesize a minimal empty self-relative descriptor when none existed.
                    let empty_raw = [
                        1_u8, 0, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ];
                    NtfsSecurityDescriptor::parse(&empty_raw).map_err(|err| parse_err(&err))
                }
                Err(err) => Err(err),
            }
        })() {
            Ok(sd) => sd,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        let patched_bytes = match apply_security_patch(&base_sd, patch) {
            Ok(bytes) => bytes,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        self.set_security_at(cx, target_ref, &patched_bytes, now_ticks)
    }

    /// Evaluate MS-DTYP DACL access (`DENY` before `ALLOW`) for `token` against `target_ref`.
    pub fn check_access(
        &self,
        cx: &Cx,
        target_ref: NtfsReference,
        token: &NtfsAccessToken,
        desired_mask: u32,
    ) -> Result<bool> {
        checkpoint(cx)?;
        let vol = self.volume_view(cx)?;
        let rec = Self::checked_reference(&vol, cx, target_ref)?;
        match vol.security_descriptor(cx, &rec) {
            Ok(info) => evaluate_dacl_access(&info.descriptor, token, desired_mask)
                .map_err(|err| parse_err(&err)),
            Err(FfsError::NotFound(_)) => Ok(true),
            Err(err) => Err(err),
        }
    }

    /// Create a native NTFS symbolic link (`IO_REPARSE_TAG_SYMLINK`, `0xA000_000C`)
    /// inside `parent_ref` and register it in `$Extend/$Reparse::$R`.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn create_symlink_at(
        &mut self,
        cx: &Cx,
        parent_ref: NtfsReference,
        name_utf16: &[u16],
        target_utf16: &[u16],
        relative: bool,
        is_dir: bool,
        now_ticks: u64,
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_ntfs_component_utf16(name_utf16) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let point = NtfsReparsePoint {
            tag: SYMLINK_TAG,
            guid: None,
            data: NtfsReparseData::SymbolicLink {
                substitute: target_utf16.to_vec(),
                print: target_utf16.to_vec(),
                relative,
            },
        };
        let encoded_rp = match validate_writable_reparse_point(&point, is_dir, false) {
            Ok(bytes) => bytes,
            Err(err) => return NtfsTxOutcome::NotCommitted(err),
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.create_symlink_at:");
        hasher.update(&parent_ref.record.to_le_bytes());
        for &u in name_utf16 {
            hasher.update(&u.to_le_bytes());
        }
        hasher.update(&encoded_rp);
        let digest = *hasher.finalize().as_bytes();

        if let Err(err) = self.ensure_mft_headroom(cx, 2, 2) {
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
                    "cannot create NTFS symlink inside a reparse directory",
                ));
            }

            let base_flags = if is_dir {
                FILE_ATTR_REPARSE_POINT
            } else {
                FILE_ATTR_ARCHIVE | FILE_ATTR_REPARSE_POINT
            };
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
                    (
                        encode_standard_information(
                            is_dir,
                            &super::ops::InheritedSecurity::SharedId(sec_id),
                        ),
                        None,
                    )
                } else {
                    (
                        encode_standard_information(
                            is_dir,
                            &super::ops::InheritedSecurity::Descriptor(inherited_bytes.clone()),
                        ),
                        Some(inherited_bytes),
                    )
                }
            } else {
                let parent_raw = read_mft_record_via_runs(
                    &self.device,
                    cx,
                    &self.geometry,
                    &ws.mft_runs,
                    u32::try_from(parent_ref.record).map_err(|_| corrupt(0, "parent u32"))?,
                )?;
                let sec = extract_parent_security(&parent_raw);
                let info = encode_standard_information(is_dir, &sec);
                let sd = match sec {
                    super::ops::InheritedSecurity::SharedId(_) => None,
                    super::ops::InheritedSecurity::Descriptor(d) => Some(d),
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

            let dir_index = if is_dir {
                Some(EditableDirIndex {
                    index_root: build_empty_small_index_root(
                        self.geometry.index_bytes(),
                        self.geometry.cluster_bytes(),
                    )?,
                    external: None,
                })
            } else {
                None
            };
            let data_streams = if is_dir {
                Vec::new()
            } else {
                vec![EditableDataStream {
                    name: Vec::new(),
                    storage: EditableStreamStorage::Resident(Vec::new()),
                }]
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
                reparse: SYMLINK_TAG,
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
                reparse_point: Some(encoded_rp),
                ea_pair: None,
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
                USN_REASON_FILE_CREATE | USN_REASON_REPARSE_POINT_CHANGE | USN_REASON_CLOSE,
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
            ws.sync_reparse_r_index(self, cx, child_ref, Some(SYMLINK_TAG))?;

            ws.finalize(self, cx, "create_symlink_at", digest, child_ref)
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Install or replace a `$REPARSE_POINT` (`0xC0`) attribute on `target_ref` and
    /// synchronize `$Extend/$Reparse::$R` and parent `FILE_NAME` duplicated tags.
    pub fn set_reparse_point_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        point: &NtfsReparsePoint,
        allow_opaque: bool,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.set_reparse_point_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&point.tag.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        let _ = self.ensure_mft_headroom(cx, 1, 2);

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            let encoded =
                validate_writable_reparse_point(point, cat_ro.is_directory, allow_opaque)?;
            if cat_ro.is_directory {
                let dir_idx = cat_ro
                    .dir_index
                    .as_ref()
                    .ok_or_else(|| corrupt(0, "directory lacks $I30"))?;
                if !self.catalog_directory_is_empty(cx, dir_idx)? {
                    return Err(FfsError::NotEmpty);
                }
            }
            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.reparse_point = Some(encoded);
                let flags = cat.std_flags() | FILE_ATTR_REPARSE_POINT;
                cat.set_std_flags(flags);
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.sync_reparse_r_index(self, cx, target_ref, Some(point.tag))?;
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_REPARSE_POINT_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "set_reparse_point_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Remove `$REPARSE_POINT` (`0xC0`) from `target_ref`, synchronizing `$Extend/$Reparse::$R`.
    /// On a WOF-compressed file, this materializes full plaintext into unnamed `$DATA` and
    /// reclaims `WofCompressedData` so user data is never lost.
    pub fn remove_reparse_point_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.remove_reparse_point_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            let Some(ref rp_bytes) = cat_ro.reparse_point else {
                return Err(FfsError::NotFound("NTFS $REPARSE_POINT not present".into()));
            };
            let parsed = NtfsReparsePoint::parse(rp_bytes).map_err(|err| parse_err(&err))?;
            let is_wof = classify_reparse_point(&parsed) == ReparseCapability::WofFileProvider;
            if is_wof {
                let vol = self.volume_view(cx)?;
                let rec = vol.record(cx, target_ref.record, Some(target_ref.sequence))?;
                let decoded = vol.read_wof_all(cx, &rec, MAX_FILE_EDIT_BYTES as usize)?;
                let wof_folded = self.fold_upcase(WOF_BACKING_NAME);
                let mut freed = Vec::new();
                for s in &cat_ro.data_streams {
                    if (s.name.is_empty() || self.fold_upcase(&s.name) == wof_folded)
                        && let EditableStreamStorage::NonResident { ref runs, .. } = s.storage
                    {
                        freed.extend(physical_spans_of_runs(runs));
                    }
                }
                ws.free_clusters_deferred(&freed);
                let mut pre = Vec::new();
                let plain = compression::rebuild_stream_for_compression_toggle(
                    &self.geometry,
                    &decoded,
                    false,
                    &mut pre,
                    |n| ws.alloc_clusters(n, 1),
                )?;
                ws.pre_payload_writes.extend(pre);
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.data_streams
                    .retain(|s| self.fold_upcase(&s.name) != wof_folded);
                if let Some(unnamed) = cat.data_streams.iter_mut().find(|s| s.name.is_empty()) {
                    unnamed.storage = plain;
                } else {
                    cat.data_streams.push(EditableDataStream {
                        name: Vec::new(),
                        storage: plain,
                    });
                }
            }
            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.reparse_point = None;
                let flags = cat.std_flags() & !FILE_ATTR_REPARSE_POINT;
                cat.set_std_flags(flags);
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.sync_reparse_r_index(self, cx, target_ref, None)?;
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_REPARSE_POINT_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "remove_reparse_point_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Set `$OBJECT_ID` (`0x40`) on `target_ref` and synchronize `$Extend/$ObjId::$O`.
    pub fn set_object_id_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        objid: NtfsObjectIdData,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.set_object_id_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&objid.object_id);
        let digest = *hasher.finalize().as_bytes();

        let _ = self.ensure_mft_headroom(cx, 1, 2);

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let _ = ws.load_catalog(self, cx, target_ref)?;
            ws.sync_objid_o_index(self, cx, target_ref, Some(&objid))?;
            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.object_id = Some(objid.encode());
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_OBJECT_ID_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "set_object_id_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Remove `$OBJECT_ID` (`0x40`) from `target_ref` and synchronize `$Extend/$ObjId::$O`.
    pub fn remove_object_id_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.remove_object_id_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?;
            if cat_ro.object_id.is_none() {
                return Err(FfsError::NotFound("NTFS $OBJECT_ID not present".into()));
            }
            ws.sync_objid_o_index(self, cx, target_ref, None)?;
            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.object_id = None;
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_OBJECT_ID_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "remove_object_id_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Enable or configure an active `$Extend/$UsnJrnl` (`$Max` + sparse `$J`) change journal
    /// on an NTFS 3.1 volume. Once active, all subsequent native transactions append
    /// `USN_RECORD_V2` entries and update `$STANDARD_INFORMATION.usn`.
    pub fn enable_usn_journal(
        &mut self,
        cx: &Cx,
        maximum_size: u64,
        allocation_delta: u64,
        now_ticks: u64,
    ) -> NtfsTxOutcome<NtfsReference> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        if self.version != [3, 1] {
            return NtfsTxOutcome::NotCommitted(unsupported(
                "$Extend/$UsnJrnl requires an NTFS 3.1 volume",
            ));
        }
        if maximum_size < 4096 || allocation_delta < 4096 {
            return NtfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                errno: libc::EINVAL,
                detail: "$UsnJrnl maximum_size and allocation_delta must be >= 4096".into(),
            });
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.enable_usn_journal:");
        hasher.update(&maximum_size.to_le_bytes());
        hasher.update(&allocation_delta.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        if let Err(err) = self.ensure_mft_headroom(cx, 2, 2) {
            return NtfsTxOutcome::NotCommitted(err);
        }

        let plan_res = (|| -> Result<PreparedTxPlan<NtfsReference>> {
            let mut ws = TxWorkspace::load(self, cx)?;
            if !ws.mft_slot_is_allocated(11) {
                return Err(unsupported("$Extend (Record 11) is not allocated"));
            }
            if let Some(existing) = ws.lookup_extend_child(self, cx, &EXTEND_USNJRNL_UPPER)? {
                let _ = ws.load_view_catalog(self, cx, existing)?;
                let usn_cat = ws
                    .catalogs
                    .get_mut(&existing.record)
                    .ok_or_else(|| corrupt(0, "missing existing $UsnJrnl"))?;
                if let Some(max_stream) = usn_cat
                    .data_streams
                    .iter_mut()
                    .find(|s| s.name == USN_MAX_NAME)
                    && let EditableStreamStorage::Resident(ref bytes) = max_stream.storage
                {
                    let mut parsed = UsnMaxData::parse(bytes).map_err(|err| parse_err(&err))?;
                    parsed.maximum_size = maximum_size;
                    parsed.allocation_delta = allocation_delta;
                    max_stream.storage = EditableStreamStorage::Resident(parsed.encode().to_vec());
                    ws.dirty_catalogs.insert(existing.record);
                }
                return ws.finalize(self, cx, "enable_usn_journal", digest, existing);
            }

            let rec11 =
                read_mft_record_via_runs(&self.device, cx, &self.geometry, &ws.mft_runs, 11)?;
            let extend_ref = NtfsReference {
                record: 11,
                sequence: rec11.sequence,
            };
            let extend_cat = ws.load_view_catalog(self, cx, extend_ref)?.clone();
            let (mut std_info, sd_opt) = extend_cat.std_security_id().map_or_else(
                || {
                    let sec = extract_parent_security(&rec11);
                    let info = encode_standard_information(false, &sec);
                    let sd = match sec {
                        super::ops::InheritedSecurity::SharedId(_) => None,
                        super::ops::InheritedSecurity::Descriptor(d) => Some(d),
                    };
                    (info, sd)
                },
                |sec_id| {
                    (
                        encode_standard_information(
                            false,
                            &super::ops::InheritedSecurity::SharedId(sec_id),
                        ),
                        None,
                    )
                },
            );
            let flags = FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM | FILE_ATTR_SPARSE_FILE;
            std_info[32..36].copy_from_slice(&flags.to_le_bytes());
            for off in [0_usize, 8, 16, 24] {
                std_info[off..off + 8].copy_from_slice(&now_ticks.to_le_bytes());
            }

            let (new_slot, next_seq, existing_raw) = ws.alloc_mft_slot(self, cx)?;
            let usn_ref = NtfsReference {
                record: u64::from(new_slot),
                sequence: next_seq,
            };
            let usn_name: Vec<u16> = "$UsnJrnl".encode_utf16().collect();
            let max_data = UsnMaxData {
                maximum_size,
                allocation_delta,
                usn_id: now_ticks.max(1),
                lowest_valid_usn: 0,
            };
            let data_streams = vec![
                EditableDataStream {
                    name: USN_J_NAME.to_vec(),
                    storage: EditableStreamStorage::NonResident {
                        runs: Vec::new(),
                        sparse: true,
                        compressed: false,
                        encrypted: false,
                        compression_unit: 0,
                        data_bytes: 0,
                        initialized_bytes: 0,
                    },
                },
                EditableDataStream {
                    name: USN_MAX_NAME.to_vec(),
                    storage: EditableStreamStorage::Resident(max_data.encode().to_vec()),
                },
            ];
            let fn_attr = EditableFileName {
                file_name: NtfsFileName {
                    parent: extend_ref,
                    namespace: 3,
                    name: usn_name,
                },
                ctime: now_ticks,
                mtime: now_ticks,
                mft_time: now_ticks,
                atime: now_ticks,
                allocated_size: 0,
                data_size: 0,
                flags,
                reparse: 0,
            };
            let mut usn_cat = EditableCatalog {
                base_ref: usn_ref,
                is_directory: false,
                std_info,
                file_names: vec![fn_attr],
                object_id: None,
                security_descriptor: sd_opt,
                data_streams,
                dir_index: None,
                view_indexes: Vec::new(),
                reparse_point: None,
                ea_pair: None,
                efs_stream: None,
                preserved: Vec::new(),
                old_base_raw: existing_raw.clone(),
                old_extensions: Vec::new(),
                old_nonres_attrlist_runs: Vec::new(),
                old_owned_extra_runs: Vec::new(),
            };
            usn_cat.sync_filename_duplicated_fields(self.geometry.cluster_bytes());
            let raw_fn_bytes = usn_cat.file_names[0].encode()?;
            let fn_struct = usn_cat.file_names[0].file_name.clone();
            ws.register_fresh_catalog(usn_cat, existing_raw);

            ws.dir_entries_mut(self, cx, extend_ref)?.push(I30RawEntry {
                reference: usn_ref,
                file_name: fn_struct,
                raw_fn_bytes,
            });
            ws.finalize(self, cx, "enable_usn_journal", digest, usn_ref)
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Set or replace a native NTFS Extended Attribute (`$EA` `0xE0` + `$EA_INFORMATION` `0xD0`)
    /// on `target_ref`.
    pub fn set_ea_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        name: &[u8],
        value: &[u8],
        flags: u8,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.set_ea_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(name);
        hasher.update(blake3::hash(value).as_bytes());
        let digest = *hasher.finalize().as_bytes();

        let _ = self.ensure_mft_headroom(cx, 1, 2);

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            let mut entries = if let Some((ref info, ref data)) = cat_ro.ea_pair {
                let parsed_info = NtfsEaInformation::parse(info).map_err(|err| parse_err(&err))?;
                parse_extended_attributes(&parsed_info, data).map_err(|err| parse_err(&err))?
            } else {
                Vec::new()
            };
            if let Some(existing) = entries
                .iter_mut()
                .find(|e| e.name.eq_ignore_ascii_case(name))
            {
                existing.name = name.to_vec();
                existing.value = value.to_vec();
                existing.flags = flags;
            } else {
                entries.push(NtfsEa {
                    flags,
                    name: name.to_vec(),
                    value: value.to_vec(),
                });
            }
            let (ea_info, ea_data_bytes) =
                encode_extended_attributes(&entries).map_err(|err| parse_err(&err))?;

            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.ea_pair = Some((ea_info.encode().to_vec(), ea_data_bytes));
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_EA_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "set_ea_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Remove a native NTFS Extended Attribute by name from `target_ref`. Returns `true`
    /// if the attribute existed and was removed, or `false` if it was absent.
    pub fn remove_ea_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        name: &[u8],
        now_ticks: u64,
    ) -> NtfsTxOutcome<bool> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.remove_ea_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(name);
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<bool>> {
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            let Some((ref info, ref data)) = cat_ro.ea_pair else {
                return ws.finalize(self, cx, "remove_ea_at", digest, false);
            };
            let parsed_info = NtfsEaInformation::parse(info).map_err(|err| parse_err(&err))?;
            let mut entries =
                parse_extended_attributes(&parsed_info, data).map_err(|err| parse_err(&err))?;
            let before = entries.len();
            entries.retain(|e| !e.name.eq_ignore_ascii_case(name));
            if entries.len() == before {
                return ws.finalize(self, cx, "remove_ea_at", digest, false);
            }
            let next_pair = if entries.is_empty() {
                None
            } else {
                let (ea_info, ea_data_bytes) =
                    encode_extended_attributes(&entries).map_err(|err| parse_err(&err))?;
                Some((ea_info.encode().to_vec(), ea_data_bytes))
            };
            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.ea_pair = next_pair;
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_EA_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "remove_ea_at", digest, true)
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Encrypt an ordinary file's unnamed `$DATA` stream under an explicit scoped
    /// 256-bit FEK (`NtfsEfsKey`), writing 512-byte AES-256-CBC sectors via COW and
    /// installing `$EFS` (`0x100`) key-commitment metadata + `FILE_ATTRIBUTE_ENCRYPTED`.
    #[allow(clippy::too_many_lines)]
    pub fn encrypt_file_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        key: &NtfsEfsKey,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.encrypt_file_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&key.key_id());
        let digest = *hasher.finalize().as_bytes();

        let _ = self.ensure_mft_headroom(cx, 1, 2);

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            if cat_ro.is_directory {
                return Err(FfsError::IsDirectory);
            }
            if (cat_ro.std_flags() & FILE_ATTR_ENCRYPTED) != 0 || cat_ro.efs_stream.is_some() {
                return Err(unsupported("NTFS file is already EFS-encrypted"));
            }
            if (cat_ro.std_flags() & FILE_ATTR_COMPRESSED) != 0 || cat_ro.reparse_point.is_some() {
                return Err(unsupported(
                    "NTFS EFS encryption refuses compressed or reparse files",
                ));
            }
            let stream_idx = cat_ro
                .data_streams
                .iter()
                .position(|s| s.name.is_empty())
                .ok_or_else(|| FfsError::NotFound("unnamed NTFS $DATA stream missing".into()))?;
            let cur_stream = &cat_ro.data_streams[stream_idx];
            let logical_len = cur_stream.logical_size();
            if logical_len > MAX_FILE_EDIT_BYTES {
                return Err(too_large_edit());
            }
            let plaintext =
                read_editable_stream_prefix(self, cx, cur_stream, 0, logical_len as usize)?;
            if let EditableStreamStorage::NonResident { ref runs, .. } = cur_stream.storage {
                ws.free_clusters_deferred(&physical_spans_of_runs(runs));
            }

            let cb = u64::from(self.geometry.cluster_bytes());
            let padded_len = plaintext.len().next_multiple_of(EFS_SECTOR_BYTES);
            let mut cipher = vec![0_u8; padded_len];
            cipher[..plaintext.len()].copy_from_slice(&plaintext);
            for (idx, sector) in cipher
                .as_chunks_mut::<EFS_SECTOR_BYTES>()
                .0
                .iter_mut()
                .enumerate()
            {
                checkpoint(cx)?;
                let sec_off = (idx as u64) * (EFS_SECTOR_BYTES as u64);
                efs_encrypt_sector(key.raw_fek(), sec_off, sector)
                    .map_err(|err| parse_err(&err))?;
            }

            let enc_storage = if cipher.is_empty() {
                EditableStreamStorage::NonResident {
                    runs: Vec::new(),
                    sparse: false,
                    compressed: false,
                    encrypted: true,
                    compression_unit: 0,
                    data_bytes: 0,
                    initialized_bytes: 0,
                }
            } else {
                let n_cl = (cipher.len() as u64).div_ceil(cb);
                let spans = ws.alloc_clusters(n_cl, 1)?;
                let mut runs = Vec::with_capacity(spans.len());
                let mut v = 0_u64;
                for &(lcn, cnt) in &spans {
                    runs.push(NtfsRun {
                        vcn: v,
                        clusters: cnt,
                        lcn: Some(lcn),
                    });
                    v += cnt;
                }
                let runs = normalize_ntfs_runs(runs);
                let mut cluster_buf = vec![0_u8; (n_cl * cb) as usize];
                cluster_buf[..cipher.len()].copy_from_slice(&cipher);
                stage_runs_writes(
                    &self.geometry,
                    &runs,
                    &cluster_buf,
                    &mut ws.pre_payload_writes,
                )?;
                EditableStreamStorage::NonResident {
                    runs,
                    sparse: false,
                    compressed: false,
                    encrypted: true,
                    compression_unit: 0,
                    data_bytes: logical_len,
                    initialized_bytes: logical_len,
                }
            };

            let key_id = derive_efs_key_id(key.raw_fek());
            let key_commitment =
                compute_efs_key_commitment(key.raw_fek(), &key_id, self.geometry.serial());
            let efs_meta =
                NtfsEfsMetadata::encode_explicit(EFS_ALG_AES_256, key_id, key_commitment)
                    .map_err(|err| parse_err(&err))?;
            let efs_bytes = efs_meta.raw_bytes;

            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.data_streams[stream_idx].storage = enc_storage;
                cat.efs_stream = Some(efs_bytes);
                let flags = (cat.std_flags() | FILE_ATTR_ENCRYPTED) & !FILE_ATTR_SPARSE_FILE;
                cat.set_std_flags(flags);
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_ENCRYPTION_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "encrypt_file_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Key-scoped positioned write to an EFS-encrypted file's unnamed `$DATA` stream.
    /// Verifies the `$EFS` SHA-256 key commitment before decrypting, updating, and
    /// re-encrypting via COW; refuses missing/wrong keys with `PermissionDenied`.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub fn write_efs_stream_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        key_scope: &dyn NtfsEfsKeyScope,
        offset: u64,
        plaintext_write: &[u8],
        now_ticks: u64,
    ) -> NtfsTxOutcome<u64> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let end_offset = match offset.checked_add(plaintext_write.len() as u64) {
            Some(e) if e <= MAX_FILE_EDIT_BYTES => e,
            _ => return NtfsTxOutcome::NotCommitted(too_large_edit()),
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.write_efs_stream_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&offset.to_le_bytes());
        hasher.update(&(plaintext_write.len() as u64).to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<u64>> {
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            if cat_ro.is_directory {
                return Err(FfsError::IsDirectory);
            }
            let (meta, key) = self.verify_efs_catalog_key(&cat_ro, key_scope)?;
            let _ = meta;

            let stream_idx = cat_ro
                .data_streams
                .iter()
                .position(|s| s.name.is_empty())
                .ok_or_else(|| FfsError::NotFound("unnamed NTFS $DATA stream missing".into()))?;
            let (old_runs, old_size) = match &cat_ro.data_streams[stream_idx].storage {
                EditableStreamStorage::NonResident {
                    runs,
                    encrypted: true,
                    data_bytes,
                    ..
                } => (runs.clone(), *data_bytes),
                _ => {
                    return Err(unsupported(
                        "EFS keyed write requires an encrypted unnamed $DATA stream",
                    ));
                }
            };
            if old_size > MAX_FILE_EDIT_BYTES {
                return Err(too_large_edit());
            }
            let old_aligned = (old_size as usize).next_multiple_of(EFS_SECTOR_BYTES);
            let mut plain = if old_aligned == 0 {
                Vec::new()
            } else {
                let mut raw =
                    read_mapped_runs(&self.device, cx, &self.geometry, &old_runs, 0, old_aligned)?;
                for (idx, sector) in raw
                    .as_chunks_mut::<EFS_SECTOR_BYTES>()
                    .0
                    .iter_mut()
                    .enumerate()
                {
                    checkpoint(cx)?;
                    let sec_off = (idx as u64) * (EFS_SECTOR_BYTES as u64);
                    efs_decrypt_sector(key.raw_fek(), sec_off, sector)
                        .map_err(|err| parse_err(&err))?;
                }
                raw.truncate(old_size as usize);
                raw
            };
            let new_size = old_size.max(end_offset);
            if plain.len() < new_size as usize {
                plain.resize(new_size as usize, 0);
            }
            plain[offset as usize..end_offset as usize].copy_from_slice(plaintext_write);

            let padded_len = plain.len().next_multiple_of(EFS_SECTOR_BYTES);
            let mut cipher = vec![0_u8; padded_len];
            cipher[..plain.len()].copy_from_slice(&plain);
            for (idx, sector) in cipher
                .as_chunks_mut::<EFS_SECTOR_BYTES>()
                .0
                .iter_mut()
                .enumerate()
            {
                checkpoint(cx)?;
                let sec_off = (idx as u64) * (EFS_SECTOR_BYTES as u64);
                efs_encrypt_sector(key.raw_fek(), sec_off, sector)
                    .map_err(|err| parse_err(&err))?;
            }
            ws.free_clusters_deferred(&physical_spans_of_runs(&old_runs));

            let cb = u64::from(self.geometry.cluster_bytes());
            let next_storage = if cipher.is_empty() {
                EditableStreamStorage::NonResident {
                    runs: Vec::new(),
                    sparse: false,
                    compressed: false,
                    encrypted: true,
                    compression_unit: 0,
                    data_bytes: 0,
                    initialized_bytes: 0,
                }
            } else {
                let n_cl = (cipher.len() as u64).div_ceil(cb);
                let spans = ws.alloc_clusters(n_cl, 1)?;
                let mut runs = Vec::with_capacity(spans.len());
                let mut v = 0_u64;
                for &(lcn, cnt) in &spans {
                    runs.push(NtfsRun {
                        vcn: v,
                        clusters: cnt,
                        lcn: Some(lcn),
                    });
                    v += cnt;
                }
                let runs = normalize_ntfs_runs(runs);
                let mut cluster_buf = vec![0_u8; (n_cl * cb) as usize];
                cluster_buf[..cipher.len()].copy_from_slice(&cipher);
                stage_runs_writes(
                    &self.geometry,
                    &runs,
                    &cluster_buf,
                    &mut ws.pre_payload_writes,
                )?;
                EditableStreamStorage::NonResident {
                    runs,
                    sparse: false,
                    compressed: false,
                    encrypted: true,
                    compression_unit: 0,
                    data_bytes: new_size,
                    initialized_bytes: new_size,
                }
            };

            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.data_streams[stream_idx].storage = next_storage;
                cat.set_std_times(None, Some(now_ticks), Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "write_efs_stream_at", digest, new_size)
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    /// Decrypt an EFS-encrypted file back to plain unnamed `$DATA` using an explicit
    /// authorized [`NtfsEfsKeyScope`], removing `$EFS` (`0x100`) and clearing
    /// `FILE_ATTRIBUTE_ENCRYPTED`.
    #[allow(clippy::too_many_lines)]
    pub fn decrypt_file_at(
        &mut self,
        cx: &Cx,
        target_ref: NtfsReference,
        key_scope: &dyn NtfsEfsKeyScope,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        if let Err(err) = checkpoint(cx) {
            return NtfsTxOutcome::NotCommitted(err);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ntfs.decrypt_file_at:");
        hasher.update(&target_ref.record.to_le_bytes());
        hasher.update(&target_ref.sequence.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();

        let plan_res = (|| -> Result<PreparedTxPlan<()>> {
            if target_ref.record < MIN_USER_MFT_SLOT {
                return Err(FfsError::PermissionDenied);
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let cat_ro = ws.load_catalog(self, cx, target_ref)?.clone();
            if cat_ro.is_directory {
                return Err(FfsError::IsDirectory);
            }
            let (_meta, key) = self.verify_efs_catalog_key(&cat_ro, key_scope)?;
            let stream_idx = cat_ro
                .data_streams
                .iter()
                .position(|s| s.name.is_empty())
                .ok_or_else(|| FfsError::NotFound("unnamed NTFS $DATA stream missing".into()))?;
            let (old_runs, old_size) = match &cat_ro.data_streams[stream_idx].storage {
                EditableStreamStorage::NonResident {
                    runs,
                    encrypted: true,
                    data_bytes,
                    ..
                } => (runs.clone(), *data_bytes),
                _ => {
                    return Err(unsupported(
                        "EFS decrypt requires an encrypted unnamed $DATA stream",
                    ));
                }
            };
            if old_size > MAX_FILE_EDIT_BYTES {
                return Err(too_large_edit());
            }
            let old_aligned = (old_size as usize).next_multiple_of(EFS_SECTOR_BYTES);
            let mut plain = if old_aligned == 0 {
                Vec::new()
            } else {
                let mut raw =
                    read_mapped_runs(&self.device, cx, &self.geometry, &old_runs, 0, old_aligned)?;
                for (idx, sector) in raw
                    .as_chunks_mut::<EFS_SECTOR_BYTES>()
                    .0
                    .iter_mut()
                    .enumerate()
                {
                    checkpoint(cx)?;
                    let sec_off = (idx as u64) * (EFS_SECTOR_BYTES as u64);
                    efs_decrypt_sector(key.raw_fek(), sec_off, sector)
                        .map_err(|err| parse_err(&err))?;
                }
                raw.truncate(old_size as usize);
                raw
            };
            ws.free_clusters_deferred(&physical_spans_of_runs(&old_runs));
            let mut pre = Vec::new();
            let plain_storage = compression::rebuild_stream_for_compression_toggle(
                &self.geometry,
                &plain,
                false,
                &mut pre,
                |n| ws.alloc_clusters(n, 1),
            )?;
            ws.pre_payload_writes.extend(pre);
            // Scrub temporary plaintext vector before drop.
            for b in &mut plain {
                *b = std::hint::black_box(0);
            }

            let usn_snap = {
                let cat = ws.catalog_mut(self, cx, target_ref)?;
                cat.data_streams[stream_idx].storage = plain_storage;
                cat.efs_stream = None;
                let flags = cat.std_flags() & !FILE_ATTR_ENCRYPTED;
                cat.set_std_flags(flags);
                cat.set_std_times(None, None, Some(now_ticks), None);
                cat.clone()
            };
            ws.push_usn_event_for_catalog(
                &usn_snap,
                USN_REASON_ENCRYPTION_CHANGE | USN_REASON_CLOSE,
                now_ticks,
            );
            ws.sync_target_into_parent_dirs(self, cx, target_ref)?;
            ws.finalize(self, cx, "decrypt_file_at", digest, ())
        })();

        match plan_res {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(err) => NtfsTxOutcome::NotCommitted(err),
        }
    }

    fn verify_efs_catalog_key(
        &self,
        cat: &EditableCatalog,
        key_scope: &dyn NtfsEfsKeyScope,
    ) -> Result<(NtfsEfsMetadata, NtfsEfsKey)> {
        if (cat.std_flags() & FILE_ATTR_ENCRYPTED) == 0 {
            return Err(unsupported(
                "NTFS file does not carry FILE_ATTRIBUTE_ENCRYPTED",
            ));
        }
        let Some(ref efs_raw) = cat.efs_stream else {
            return Err(unsupported(
                "NTFS encrypted file lacks $EFS (0x100) metadata",
            ));
        };
        let meta = NtfsEfsMetadata::parse(efs_raw).map_err(|err| parse_err(&err))?;
        if !meta.explicit_fek_profile || meta.algorithm_id != EFS_ALG_AES_256 {
            return Err(unsupported(
                "EFS keyed write/decrypt requires explicit AES-256 FEK profile (Windows DPAPI headers remain opaque)",
            ));
        }
        let key = key_scope
            .resolve_key(&meta.key_id)
            .ok_or(FfsError::PermissionDenied)?;
        let expected =
            compute_efs_key_commitment(key.raw_fek(), &meta.key_id, self.geometry.serial());
        if expected != meta.key_commitment {
            return Err(FfsError::PermissionDenied);
        }
        Ok((meta, key))
    }
}
