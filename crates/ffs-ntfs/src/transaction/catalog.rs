//! Sequence-bound reference path reconstruction and base + extension MFT record
//! catalog loader/packer (`$ATTRIBUTE_LIST` `0x20`), multi-extent `DATA` /
//! `SPARSE` (`0x8000`) stream encoding, and fragmented multi-run cluster
//! allocation for native NTFS 3.1 transactions.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::attribute_list::{
    NtfsAttributeListEntry, encode_attribute_list, parse_attribute_list,
};
use ffs_ondisk::ntfs::efs::EFS_STREAM_NAME;
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::logfile_writer::NtfsClientUpdateSpec;
use ffs_ondisk::ntfs::recovery::{
    FileEditResult, RecoveryPass, deallocate_file_record_slot, initialize_file_record_slot,
};
use ffs_ondisk::ntfs::view_index::{ViewCollation, parse_view_index_root};
use ffs_ondisk::ntfs::{
    ATTRIBUTE_LIST, COMPRESSED, DATA, EA, EA_INFORMATION, ENCRYPTED, LOGGED_UTILITY_STREAM,
    NtfsAttribute, NtfsFileRecord, NtfsGeometry, NtfsLogOp, NtfsReference, NtfsRun, NtfsValue,
    OBJECT_ID, REPARSE_POINT, SPARSE, decode_mapping_pairs, encode_mapping_pairs, restore_record,
};

use super::dir_index::{DirPrePayloadWrite, I30_NAME, encode_resident_attribute};
use super::view_index::EditableViewIndex;
use super::{
    NtfsTransactionEngine, SECTOR_BYTES, checkpoint, corrupt, map_logical_offset, parse_err,
    read_mapped_runs, read_mft_record_raw_via_runs, unsupported,
};
use crate::NtfsVolume;

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_SECURITY_DESCRIPTOR: u32 = 0x50;
const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const ATTR_BITMAP: u32 = 0xB0;

const MAX_CLIENT_SINGLE_RECORD_BYTES: usize = 3800;

pub(super) fn stale_reference(reference: NtfsReference) -> FfsError {
    FfsError::RequestRejected {
        errno: libc::ESTALE,
        detail: format!(
            "stale NTFS FILE reference {}:{}",
            reference.record, reference.sequence
        ),
    }
}

fn check_raw_resident_data_flags(raw_record: &[u8]) -> Result<()> {
    let restored = restore_record(raw_record, b"FILE").map_err(|err| parse_err(&err))?;
    let mut at = usize::from(u16::from_le_bytes([restored[20], restored[21]]));
    let used = usize::try_from(u32::from_le_bytes([
        restored[24],
        restored[25],
        restored[26],
        restored[27],
    ]))
    .map_err(|_| corrupt(0, "record used overflow"))?;
    while at + 4 <= used {
        let kind = u32::from_le_bytes([
            restored[at],
            restored[at + 1],
            restored[at + 2],
            restored[at + 3],
        ]);
        if kind == u32::MAX {
            break;
        }
        if at + 24 > used {
            return Err(corrupt(0, "truncated attribute header"));
        }
        let len = usize::try_from(u32::from_le_bytes([
            restored[at + 4],
            restored[at + 5],
            restored[at + 6],
            restored[at + 7],
        ]))
        .map_err(|_| corrupt(0, "attribute length overflow"))?;
        if len < 24 || at + len > used {
            return Err(corrupt(0, "attribute exceeds record bounds"));
        }
        if kind == DATA
            && restored[at + 8] == 0
            && (restored[at + 22] != 0 || restored[at + 23] != 0)
        {
            return Err(unsupported(
                "NTFS resident DATA carries indexed or reserved flags",
            ));
        }
        at += len;
    }
    Ok(())
}

fn refuse_unsupported_record_metadata(
    record: &NtfsFileRecord,
    raw_record: &[u8],
    attrs: &[NtfsAttribute<'_>],
    allow_view_index_record: bool,
) -> Result<()> {
    // Bit 0x0008 (MFT_RECORD_IS_VIEW_INDEX, e.g. $Secure/$ObjId/$Quota/$Reparse) and
    // bit 0x0004 (MFT_RECORD_IN_EXTEND) are only admitted on explicit view-index/extend
    // system records (and bit 0x0004 on Record 5 as emitted by mkntfs).
    if !allow_view_index_record
        && (record.flags & 0x0008 != 0 || (record.number != 5 && record.flags & 0x0004 != 0))
    {
        return Err(unsupported(format!(
            "record {} carries metadata or view-index FILE flags {:#x}",
            record.number, record.flags
        )));
    }
    check_raw_resident_data_flags(raw_record)?;
    for attr in attrs {
        if attr.flags & !(SPARSE | COMPRESSED | ENCRYPTED) != 0 {
            return Err(unsupported(format!(
                "record {} carries unknown attribute flags {:#x}",
                record.number, attr.flags
            )));
        }
        if (attr.flags & COMPRESSED != 0) && (attr.flags & ENCRYPTED != 0) {
            return Err(unsupported(format!(
                "record {} combines COMPRESSED and ENCRYPTED on attribute {:#x}",
                record.number, attr.kind
            )));
        }
        if (attr.flags & (COMPRESSED | ENCRYPTED) != 0) && attr.kind != DATA {
            return Err(unsupported(format!(
                "record {} carries compressed or encrypted non-DATA attribute {:#x}",
                record.number, attr.kind
            )));
        }
        match attr.kind {
            ATTR_STANDARD_INFORMATION if attr.name.is_empty() => {
                if let NtfsValue::Resident(std_bytes) = attr.value
                    && std_bytes.len() == 72
                {
                    let owner_id = u32::from_le_bytes([
                        std_bytes[48],
                        std_bytes[49],
                        std_bytes[50],
                        std_bytes[51],
                    ]);
                    let quota_charged = u64::from_le_bytes([
                        std_bytes[56],
                        std_bytes[57],
                        std_bytes[58],
                        std_bytes[59],
                        std_bytes[60],
                        std_bytes[61],
                        std_bytes[62],
                        std_bytes[63],
                    ]);
                    if owner_id != 0 || quota_charged != 0 {
                        return Err(unsupported(format!(
                            "record {} carries active NTFS quota accounting (owner_id={owner_id}, quota_charged={quota_charged})",
                            record.number
                        )));
                    }
                }
            }
            LOGGED_UTILITY_STREAM => {
                if attr.name != EFS_STREAM_NAME {
                    return Err(unsupported(format!(
                        "record {} carries unsupported logged utility stream ($TXF_DATA / unknown 0x100)",
                        record.number
                    )));
                }
            }
            0xF0 => {
                return Err(unsupported(format!(
                    "record {} carries unsupported attribute 0xF0",
                    record.number
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Allocate `needed` clusters from `bitmap[..limit_bits]` in runs whose lengths are
/// multiples of `min_chunk` (`>= 1`), preferring a single contiguous run at or after
/// `min_start`, then `< min_start`, and finally falling back to fragmented multi-run
/// allocation when free space is non-contiguous.
pub(super) fn allocate_cluster_runs(
    bitmap: &[u8],
    limit_bits: u64,
    needed: u64,
    min_chunk: u64,
    min_start: u64,
) -> Result<Vec<(u64, u64)>> {
    if needed == 0 {
        return Ok(Vec::new());
    }
    let chunk = min_chunk.max(1);
    let rounded_needed = needed.next_multiple_of(chunk);
    let max_bit = limit_bits.min((bitmap.len() as u64) * 8);
    if max_bit == 0 {
        return Err(FfsError::NoSpace);
    }
    let anchor = min_start.min(max_bit);

    if let Some(start) =
        find_aligned_zero_run(bitmap, anchor, max_bit, rounded_needed).or_else(|| {
            find_aligned_zero_run(
                bitmap,
                0,
                anchor + rounded_needed.min(max_bit - anchor),
                rounded_needed,
            )
        })
    {
        return Ok(vec![(start, rounded_needed)]);
    }

    let mut remaining = rounded_needed;
    let mut out = Vec::new();
    for (scan_start, scan_end) in [(anchor, max_bit), (0, anchor)] {
        let mut bit = scan_start;
        while bit < scan_end && remaining > 0 {
            if is_bit_set(bitmap, bit) {
                bit += 1;
                continue;
            }
            let span_start = bit;
            while bit < scan_end && !is_bit_set(bitmap, bit) {
                bit += 1;
            }
            let usable = ((bit - span_start) / chunk) * chunk;
            if usable == 0 {
                continue;
            }
            let take = usable.min(remaining);
            out.push((span_start, take));
            remaining -= take;
        }
    }
    if remaining != 0 {
        return Err(FfsError::NoSpace);
    }
    Ok(coalesce_physical_spans(out))
}

fn find_aligned_zero_run(bitmap: &[u8], start: u64, end: u64, count: u64) -> Option<u64> {
    let limit = end.min((bitmap.len() as u64) * 8);
    if start >= limit || limit - start < count {
        return None;
    }
    let mut run_start = start;
    let mut run_len = 0_u64;
    for bit_idx in start..limit {
        if is_bit_set(bitmap, bit_idx) {
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

#[inline]
pub(super) fn is_bit_set(bitmap: &[u8], bit_idx: u64) -> bool {
    let byte_idx = (bit_idx / 8) as usize;
    byte_idx < bitmap.len() && (bitmap[byte_idx] & (1_u8 << (bit_idx % 8))) != 0
}

pub(super) fn set_or_clear_run_list(bitmap: &mut [u8], spans: &[(u64, u64)], set: bool) {
    for &(start, len) in spans {
        for b in start..start + len {
            let idx = (b / 8) as usize;
            let mask = 1_u8 << (b % 8);
            if set {
                bitmap[idx] |= mask;
            } else {
                bitmap[idx] &= !mask;
            }
        }
    }
}

pub(super) fn coalesce_physical_spans(mut spans: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    spans.retain(|&(_, len)| len > 0);
    spans.sort_unstable_by_key(|&(start, _)| start);
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(spans.len());
    for (start, len) in spans {
        if let Some(last) = merged.last_mut()
            && last.0 + last.1 == start
        {
            last.1 += len;
        } else {
            merged.push((start, len));
        }
    }
    merged
}

pub(super) fn physical_spans_of_runs(runs: &[NtfsRun]) -> Vec<(u64, u64)> {
    coalesce_physical_spans(
        runs.iter()
            .filter_map(|r| r.lcn.map(|lcn| (lcn, r.clusters)))
            .collect(),
    )
}

/// Coalesce adjacent `NtfsRun`s (adjacent physical LCNs or adjacent sparse holes)
/// and normalize `vcn` offsets starting from `0`.
pub(super) fn normalize_ntfs_runs(runs: Vec<NtfsRun>) -> Vec<NtfsRun> {
    let mut out: Vec<NtfsRun> = Vec::with_capacity(runs.len());
    let mut cur_vcn = 0_u64;
    for run in runs {
        if run.clusters == 0 {
            continue;
        }
        if let Some(prev) = out.last_mut() {
            let mergeable = match (prev.lcn, run.lcn) {
                (None, None) => true,
                (Some(a), Some(b)) => a + prev.clusters == b,
                _ => false,
            };
            if mergeable {
                prev.clusters += run.clusters;
                cur_vcn += run.clusters;
                continue;
            }
        }
        out.push(NtfsRun {
            vcn: cur_vcn,
            clusters: run.clusters,
            lcn: run.lcn,
        });
        cur_vcn += run.clusters;
    }
    out
}

/// Compute the minimal dirty `[byte_offset, slice)` bounding box between `old_bm` and `new_bm`.
pub(super) fn dirty_bitmap_range(old_bm: &[u8], new_bm: &[u8]) -> Option<(u64, Vec<u8>)> {
    let first = old_bm.iter().zip(new_bm.iter()).position(|(a, b)| a != b)?;
    let last = old_bm
        .iter()
        .zip(new_bm.iter())
        .rposition(|(a, b)| a != b)?;
    Some((first as u64, new_bm[first..=last].to_vec()))
}

#[derive(Debug, Clone)]
pub(super) struct EditableFileName {
    pub(super) file_name: NtfsFileName,
    pub(super) ctime: u64,
    pub(super) mtime: u64,
    pub(super) mft_time: u64,
    pub(super) atime: u64,
    pub(super) allocated_size: u64,
    pub(super) data_size: u64,
    pub(super) flags: u32,
    pub(super) reparse: u32,
}

impl EditableFileName {
    pub(super) fn parse_raw(raw: &[u8]) -> Result<Self> {
        let parsed = NtfsFileName::parse(raw).map_err(|err| parse_err(&err))?;
        if raw.len() < 66 {
            return Err(corrupt(0, "short FILE_NAME payload"));
        }
        let rd64 = |off: usize| -> u64 {
            u64::from_le_bytes(raw[off..off + 8].try_into().unwrap_or([0; 8]))
        };
        let rd32 = |off: usize| -> u32 {
            u32::from_le_bytes(raw[off..off + 4].try_into().unwrap_or([0; 4]))
        };
        Ok(Self {
            file_name: parsed,
            ctime: rd64(8),
            mtime: rd64(16),
            mft_time: rd64(24),
            atime: rd64(32),
            allocated_size: rd64(40),
            data_size: rd64(48),
            flags: rd32(56),
            reparse: rd32(60),
        })
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        self.file_name
            .encode(
                self.ctime,
                self.mtime,
                self.mft_time,
                self.atime,
                self.allocated_size,
                self.data_size,
                self.flags,
                self.reparse,
            )
            .map_err(|err| parse_err(&err))
    }
}

#[derive(Debug, Clone)]
pub(super) enum EditableStreamStorage {
    Resident(Vec<u8>),
    NonResident {
        runs: Vec<NtfsRun>,
        sparse: bool,
        compressed: bool,
        encrypted: bool,
        compression_unit: u16,
        data_bytes: u64,
        initialized_bytes: u64,
    },
}

#[derive(Debug, Clone)]
pub(super) struct EditableDataStream {
    pub(super) name: Vec<u16>,
    pub(super) storage: EditableStreamStorage,
}

impl EditableDataStream {
    pub(super) fn logical_size(&self) -> u64 {
        match &self.storage {
            EditableStreamStorage::Resident(bytes) => bytes.len() as u64,
            EditableStreamStorage::NonResident { data_bytes, .. } => *data_bytes,
        }
    }

    pub(super) fn allocated_for_filename(&self, cluster_bytes: u32) -> u64 {
        match &self.storage {
            EditableStreamStorage::Resident(bytes) => (bytes.len() as u64).next_multiple_of(8),
            EditableStreamStorage::NonResident {
                runs,
                sparse,
                compressed,
                ..
            } => {
                let cb = u64::from(cluster_bytes);
                if *sparse || *compressed {
                    runs.iter()
                        .filter(|r| r.lcn.is_some())
                        .map(|r| r.clusters * cb)
                        .sum()
                } else {
                    runs.iter().map(|r| r.clusters * cb).sum()
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct EditableDirIndex {
    pub(super) index_root: Vec<u8>,
    pub(super) external: Option<(Vec<NtfsRun>, u64, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub(super) struct PreservedAttribute {
    pub(super) kind: u32,
    pub(super) flags: u16,
    pub(super) name: Vec<u16>,
    pub(super) raw_without_id: PreservedValue,
}

#[derive(Debug, Clone)]
pub(super) enum PreservedValue {
    Resident {
        indexed: bool,
        bytes: Vec<u8>,
    },
    NonResident {
        first_vcn: u64,
        last_vcn: u64,
        compression_unit: u16,
        allocated_bytes: u64,
        data_bytes: u64,
        initialized_bytes: u64,
        mapping_pairs: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub(super) struct EditableCatalog {
    pub(super) base_ref: NtfsReference,
    pub(super) is_directory: bool,
    pub(super) std_info: Vec<u8>,
    pub(super) file_names: Vec<EditableFileName>,
    pub(super) object_id: Option<Vec<u8>>,
    pub(super) security_descriptor: Option<Vec<u8>>,
    pub(super) data_streams: Vec<EditableDataStream>,
    pub(super) dir_index: Option<EditableDirIndex>,
    pub(super) view_indexes: Vec<EditableViewIndex>,
    pub(super) reparse_point: Option<Vec<u8>>,
    pub(super) efs_stream: Option<Vec<u8>>,
    pub(super) preserved: Vec<PreservedAttribute>,
    pub(super) old_base_raw: Vec<u8>,
    pub(super) old_extensions: Vec<(u32, u16, Vec<u8>)>,
    pub(super) old_nonres_attrlist_runs: Vec<NtfsRun>,
    // Original nonresident $I30::$BITMAP runs, plus view-bitmap, reparse, and
    // $EFS runs. Held on the catalog so index rebalancing can replace dir_index
    // without dropping bitmap ownership. Verified before mutation and retired
    // once through the deferred-free path on repack or deletion.
    pub(super) old_owned_extra_runs: Vec<NtfsRun>,
}

impl EditableCatalog {
    pub(super) fn preserved_nonresident_runs(&self, cluster_count: u64) -> Result<Vec<NtfsRun>> {
        let mut out = Vec::new();
        for pres in &self.preserved {
            if let PreservedValue::NonResident {
                first_vcn,
                last_vcn,
                mapping_pairs,
                ..
            } = &pres.raw_without_id
            {
                let runs =
                    decode_mapping_pairs(mapping_pairs, *first_vcn, *last_vcn, cluster_count)
                        .map_err(|err| parse_err(&err))?;
                out.extend(runs);
            }
        }
        Ok(out)
    }

    pub(super) fn std_flags(&self) -> u32 {
        if self.std_info.len() >= 36 {
            u32::from_le_bytes([
                self.std_info[32],
                self.std_info[33],
                self.std_info[34],
                self.std_info[35],
            ])
        } else {
            0
        }
    }

    pub(super) fn set_std_flags(&mut self, flags: u32) {
        if self.std_info.len() >= 36 {
            self.std_info[32..36].copy_from_slice(&flags.to_le_bytes());
        }
    }

    pub(super) fn std_times(&self) -> (u64, u64, u64, u64) {
        let rd = |off: usize| -> u64 {
            if self.std_info.len() >= off + 8 {
                u64::from_le_bytes(self.std_info[off..off + 8].try_into().unwrap_or([0; 8]))
            } else {
                0
            }
        };
        (rd(0), rd(8), rd(16), rd(24))
    }

    pub(super) fn set_std_times(
        &mut self,
        ctime: Option<u64>,
        mtime: Option<u64>,
        mft_time: Option<u64>,
        atime: Option<u64>,
    ) {
        if self.std_info.len() < 32 {
            return;
        }
        if let Some(t) = ctime {
            self.std_info[0..8].copy_from_slice(&t.to_le_bytes());
        }
        if let Some(t) = mtime {
            self.std_info[8..16].copy_from_slice(&t.to_le_bytes());
        }
        if let Some(t) = mft_time {
            self.std_info[16..24].copy_from_slice(&t.to_le_bytes());
        }
        if let Some(t) = atime {
            self.std_info[24..32].copy_from_slice(&t.to_le_bytes());
        }
    }

    pub(super) fn std_security_id(&self) -> Option<u32> {
        if self.std_info.len() == 72 {
            let id = u32::from_le_bytes([
                self.std_info[52],
                self.std_info[53],
                self.std_info[54],
                self.std_info[55],
            ]);
            (id != 0).then_some(id)
        } else {
            None
        }
    }

    pub(super) fn set_std_security_id(&mut self, sec_id: u32) {
        if self.std_info.len() < 72 {
            self.std_info.resize(72, 0);
        }
        self.std_info[52..56].copy_from_slice(&sec_id.to_le_bytes());
    }

    pub(super) fn set_std_usn(&mut self, usn: u64) {
        if self.std_info.len() == 72 {
            self.std_info[64..72].copy_from_slice(&usn.to_le_bytes());
        }
    }

    /// Synchronize duplicated timestamps, file-attribute flags, reparse/EA tag, and
    /// unnamed `$DATA` sizes onto all `0x30` `FILE_NAME` attributes of this record.
    pub(super) fn sync_filename_duplicated_fields(&mut self, cluster_bytes: u32) {
        let (ctime, mtime, mft_time, atime) = self.std_times();
        let base_flags = self.std_flags() & !0x1000_0000;
        let dup_flags = if self.is_directory {
            base_flags | 0x1000_0000
        } else {
            base_flags
        };
        let dup_reparse = if let Some(ref rp) = self.reparse_point
            && rp.len() >= 4
        {
            u32::from_le_bytes([rp[0], rp[1], rp[2], rp[3]])
        } else {
            self.preserved
                .iter()
                .find_map(|p| {
                    if p.kind == EA_INFORMATION
                        && p.name.is_empty()
                        && let PreservedValue::Resident { bytes, .. } = &p.raw_without_id
                        && bytes.len() >= 2
                    {
                        Some(u32::from(u16::from_le_bytes([bytes[0], bytes[1]])))
                    } else {
                        None
                    }
                })
                .unwrap_or_default()
        };
        let (alloc_sz, data_sz) = if self.is_directory {
            (0_u64, 0_u64)
        } else if let Some(unnamed) = self.data_streams.iter().find(|s| s.name.is_empty()) {
            (
                unnamed.allocated_for_filename(cluster_bytes),
                unnamed.logical_size(),
            )
        } else {
            (0_u64, 0_u64)
        };
        for fn_attr in &mut self.file_names {
            fn_attr.ctime = ctime;
            fn_attr.mtime = mtime;
            fn_attr.mft_time = mft_time;
            fn_attr.atime = atime;
            fn_attr.allocated_size = alloc_sz;
            fn_attr.data_size = data_sz;
            fn_attr.flags = dup_flags;
            fn_attr.reparse = dup_reparse;
        }
    }
}

type EncodeWithIdFn = Box<dyn Fn(u16) -> Result<Vec<u8>>>;

struct CandidateAttr {
    kind: u32,
    name: Vec<u16>,
    folded_name: Vec<u16>,
    first_vcn: u64,
    keep_in_base_priority: u8,
    encode_with_id: EncodeWithIdFn,
    estimated_len: usize,
}

#[derive(Debug)]
pub(super) struct PackedCatalogPlan {
    pub(super) pre_payload_writes: Vec<DirPrePayloadWrite>,
    pub(super) freed_clusters: Vec<(u64, u64)>,
    pub(super) freed_mft_slots: Vec<u32>,
    pub(super) mft_record_writes: Vec<(u32, Vec<u8>)>,
    pub(super) log_specs: Vec<NtfsClientUpdateSpec>,
}

/// Encode a general non-resident attribute extent (`first_vcn >= 0`), supporting both
/// plain (`flags = 0`, 64-byte header) and `SPARSE` (`flags = 0x8000`, 72-byte header).
#[allow(clippy::too_many_arguments)]
pub(super) fn encode_nonresident_extent(
    kind: u32,
    id: u16,
    flags: u16,
    name: &[u16],
    runs_slice: &[NtfsRun],
    first_vcn: u64,
    compression_unit: u16,
    allocated_bytes: u64,
    data_bytes: u64,
    initialized_bytes: u64,
    sparse_physical_bytes: u64,
    volume_clusters: u64,
) -> Result<Vec<u8>> {
    let (pairs, last_vcn) = encode_mapping_pairs(runs_slice, first_vcn, volume_clusters)
        .map_err(|err| parse_err(&err))?;
    let header_len: usize = if flags & (SPARSE | COMPRESSED) != 0 {
        72
    } else {
        64
    };
    let name_bytes = name.len() * 2;
    let mapping_off = (header_len + name_bytes).next_multiple_of(8);
    let total_len = (mapping_off + pairs.len()).next_multiple_of(8);
    let mut out = vec![0_u8; total_len];
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
    out[8] = 1; // nonresident
    out[9] = u8::try_from(name.len()).map_err(|_| corrupt(0, "attr name too long"))?;
    out[10..12].copy_from_slice(&(header_len as u16).to_le_bytes());
    out[12..14].copy_from_slice(&flags.to_le_bytes());
    out[14..16].copy_from_slice(&id.to_le_bytes());
    out[16..24].copy_from_slice(&first_vcn.to_le_bytes());
    out[24..32].copy_from_slice(&last_vcn.to_le_bytes());
    out[32..34].copy_from_slice(&(mapping_off as u16).to_le_bytes());
    out[34..36].copy_from_slice(&compression_unit.to_le_bytes());
    if first_vcn == 0 {
        out[40..48].copy_from_slice(&allocated_bytes.to_le_bytes());
        out[48..56].copy_from_slice(&data_bytes.to_le_bytes());
        out[56..64].copy_from_slice(&initialized_bytes.to_le_bytes());
        if header_len == 72 {
            out[64..72].copy_from_slice(&sparse_physical_bytes.to_le_bytes());
        }
    }
    for (i, &unit) in name.iter().enumerate() {
        out[header_len + i * 2..header_len + 2 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    out[mapping_off..mapping_off + pairs.len()].copy_from_slice(&pairs);
    Ok(out)
}

/// Split `runs` into one or more non-resident extents so each extent fits within `max_attr_bytes`.
#[allow(clippy::too_many_arguments)]
fn split_nonresident_stream_extents(
    geometry: &NtfsGeometry,
    kind: u32,
    name: &[u16],
    folded_name: &[u16],
    runs: &[NtfsRun],
    flags: u16,
    compression_unit: u16,
    data_bytes: u64,
    initialized_bytes: u64,
    max_attr_bytes: usize,
) -> Result<Vec<CandidateAttr>> {
    let cb = u64::from(geometry.cluster_bytes());
    let total_vcns: u64 = runs.iter().map(|r| r.clusters).sum();
    let coverage = total_vcns
        .checked_mul(cb)
        .ok_or_else(|| corrupt(0, "stream coverage overflow"))?;
    let sparse_phys: u64 = runs
        .iter()
        .filter(|r| r.lcn.is_some())
        .map(|r| r.clusters * cb)
        .sum();
    let vol_clusters = geometry.cluster_count();

    if runs.is_empty() {
        let nm = name.to_vec();
        let sample = encode_nonresident_extent(
            kind,
            0,
            flags,
            &nm,
            &[],
            0,
            compression_unit,
            0,
            data_bytes,
            initialized_bytes,
            0,
            vol_clusters,
        )?;
        let est = sample.len();
        let nm_cl = nm.clone();
        return Ok(vec![CandidateAttr {
            kind,
            name: nm,
            folded_name: folded_name.to_vec(),
            first_vcn: 0,
            keep_in_base_priority: 2,
            encode_with_id: Box::new(move |id| {
                encode_nonresident_extent(
                    kind,
                    id,
                    flags,
                    &nm_cl,
                    &[],
                    0,
                    compression_unit,
                    0,
                    data_bytes,
                    initialized_bytes,
                    0,
                    vol_clusters,
                )
            }),
            estimated_len: est,
        }]);
    }

    let mut extents = Vec::new();
    let mut idx = 0_usize;
    while idx < runs.len() {
        let first_vcn = runs[idx].vcn;
        let mut end = runs.len();
        let (chunk_end, est_len) = {
            let full_candidate = encode_nonresident_extent(
                kind,
                0,
                flags,
                name,
                &runs[idx..end],
                first_vcn,
                compression_unit,
                coverage,
                data_bytes,
                initialized_bytes,
                sparse_phys,
                vol_clusters,
            )?;
            if full_candidate.len() <= max_attr_bytes {
                (end, full_candidate.len())
            } else {
                while end > idx + 1 {
                    let mid = idx + (end - idx) / 2;
                    let mid_cand = encode_nonresident_extent(
                        kind,
                        0,
                        flags,
                        name,
                        &runs[idx..mid],
                        first_vcn,
                        compression_unit,
                        coverage,
                        data_bytes,
                        initialized_bytes,
                        sparse_phys,
                        vol_clusters,
                    )?;
                    end = mid;
                    if mid_cand.len() <= max_attr_bytes {
                        break;
                    }
                }
                let base_cand = encode_nonresident_extent(
                    kind,
                    0,
                    flags,
                    name,
                    &runs[idx..end],
                    first_vcn,
                    compression_unit,
                    coverage,
                    data_bytes,
                    initialized_bytes,
                    sparse_phys,
                    vol_clusters,
                )?;
                if base_cand.len() > max_attr_bytes {
                    return Err(unsupported(
                        "single NTFS run mapping exceeds MFT record attribute capacity",
                    ));
                }
                while end < runs.len() {
                    let probe = encode_nonresident_extent(
                        kind,
                        0,
                        flags,
                        name,
                        &runs[idx..=end],
                        first_vcn,
                        compression_unit,
                        coverage,
                        data_bytes,
                        initialized_bytes,
                        sparse_phys,
                        vol_clusters,
                    )?;
                    if probe.len() <= max_attr_bytes {
                        end += 1;
                    } else {
                        break;
                    }
                }
                let final_cand = encode_nonresident_extent(
                    kind,
                    0,
                    flags,
                    name,
                    &runs[idx..end],
                    first_vcn,
                    compression_unit,
                    coverage,
                    data_bytes,
                    initialized_bytes,
                    sparse_phys,
                    vol_clusters,
                )?;
                (end, final_cand.len())
            }
        };
        let slice_vec = runs[idx..chunk_end].to_vec();
        let nm = name.to_vec();
        let nm_cl = nm.clone();
        extents.push(CandidateAttr {
            kind,
            name: nm,
            folded_name: folded_name.to_vec(),
            first_vcn,
            keep_in_base_priority: if first_vcn == 0 && name.is_empty() {
                2
            } else {
                3
            },
            encode_with_id: Box::new(move |id| {
                encode_nonresident_extent(
                    kind,
                    id,
                    flags,
                    &nm_cl,
                    &slice_vec,
                    first_vcn,
                    compression_unit,
                    coverage,
                    data_bytes,
                    initialized_bytes,
                    sparse_phys,
                    vol_clusters,
                )
            }),
            estimated_len: est_len,
        });
        idx = chunk_end;
    }
    Ok(extents)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_restored_mft_record(
    record_bytes: u32,
    ntfs_version: [u8; 2],
    record_no: u32,
    sequence: u16,
    is_directory: bool,
    preserved_base_flags: u16,
    hard_links: u16,
    base_reference: Option<NtfsReference>,
    sorted_encoded_attrs: &[Vec<u8>],
    next_attr_id: u16,
) -> Result<Vec<u8>> {
    let len = record_bytes as usize;
    let usa_offset: u16 = if ntfs_version == [3, 0] { 42 } else { 48 };
    let usa_count = u16::try_from(len / SECTOR_BYTES + 1).map_err(|_| corrupt(0, "usa_count"))?;
    let first_attr = (usize::from(usa_offset) + usize::from(usa_count) * 2).next_multiple_of(8);
    let attrs_bytes: usize = sorted_encoded_attrs.iter().map(Vec::len).sum();
    let used = first_attr + attrs_bytes + 8;
    if used > len {
        return Err(FfsError::NoSpace);
    }
    let mut buf = vec![0_u8; len];
    buf[0..4].copy_from_slice(b"FILE");
    buf[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    buf[6..8].copy_from_slice(&usa_count.to_le_bytes());
    buf[16..18].copy_from_slice(&sequence.to_le_bytes());
    let links = if base_reference.is_some() {
        0
    } else {
        hard_links
    };
    buf[18..20].copy_from_slice(&links.to_le_bytes());
    buf[20..22].copy_from_slice(&(first_attr as u16).to_le_bytes());
    let flags: u16 = if base_reference.is_none() && is_directory {
        0x0003 | (preserved_base_flags & 0x000C)
    } else if base_reference.is_none() {
        0x0001 | (preserved_base_flags & 0x000C)
    } else {
        0x0001
    };
    buf[22..24].copy_from_slice(&flags.to_le_bytes());
    buf[24..28].copy_from_slice(&(used as u32).to_le_bytes());
    buf[28..32].copy_from_slice(&record_bytes.to_le_bytes());
    if let Some(base_ref) = base_reference {
        let enc = base_ref.encode().map_err(|err| parse_err(&err))?;
        buf[32..40].copy_from_slice(&enc.to_le_bytes());
    }
    buf[40..42].copy_from_slice(&next_attr_id.to_le_bytes());
    if usa_offset == 48 {
        buf[44..48].copy_from_slice(&record_no.to_le_bytes());
    }
    let mut pos = first_attr;
    for raw_attr in sorted_encoded_attrs {
        buf[pos..pos + raw_attr.len()].copy_from_slice(raw_attr);
        pos += raw_attr.len();
    }
    buf[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    Ok(buf)
}

impl NtfsTransactionEngine {
    pub(super) fn checked_reference(
        volume: &NtfsVolume,
        cx: &Cx,
        reference: NtfsReference,
    ) -> Result<NtfsFileRecord> {
        if reference.sequence == 0 {
            return Err(stale_reference(reference));
        }
        let record = volume.record(cx, reference.record, None).map_err(|err| {
            if matches!(err, FfsError::NotFound(_)) {
                stale_reference(reference)
            } else {
                err
            }
        })?;
        if record.sequence != reference.sequence {
            return Err(stale_reference(reference));
        }
        Ok(record)
    }

    /// Resolve a current object reference to a fully validated native path.
    ///
    /// The ordinary path-based planners own base-record name catalogs. An
    /// extension catalog or an unrepresentable UTF-16 component returns
    /// `UnsupportedFeature` so callers can either surface refusal or dispatch
    /// to the reference-bound multi-record catalog planners.
    pub fn resolve_reference_path(&self, cx: &Cx, reference: NtfsReference) -> Result<String> {
        checkpoint(cx)?;
        let volume = self.volume_view(cx)?;
        let root = volume.record(cx, 5, None)?;
        if !root.is_directory() {
            return Err(corrupt(0, "NTFS root is not a directory"));
        }
        let root_reference = NtfsReference {
            record: 5,
            sequence: root.sequence,
        };
        let mut current = reference;
        let mut visited = BTreeSet::new();
        let mut components = Vec::new();
        let mut path_bytes = 1_usize;
        for _ in 0..=256 {
            checkpoint(cx)?;
            let record = Self::checked_reference(&volume, cx, current)?;
            if current == root_reference {
                components.reverse();
                let path = format!("/{}", components.join("/"));
                self.validate_mutation_path_reference(cx, &path, reference)?;
                return Ok(path);
            }
            if !visited.insert((current.record, current.sequence)) {
                return Err(corrupt(0, "cycle in NTFS FILE_NAME parent chain"));
            }
            let attributes = record.attributes().map_err(|error| parse_err(&error))?;
            if attributes
                .iter()
                .any(|attribute| attribute.kind == ATTRIBUTE_LIST)
            {
                return Err(unsupported(
                    "NTFS reference mutation requires complete base-record name ownership",
                ));
            }
            let mut names = Vec::new();
            for attribute in attributes
                .iter()
                .filter(|attribute| attribute.kind == ATTR_FILE_NAME)
            {
                let NtfsValue::Resident(value) = attribute.value else {
                    return Err(corrupt(0, "nonresident NTFS FILE_NAME"));
                };
                let name = NtfsFileName::parse(value).map_err(|error| parse_err(&error))?;
                if name.namespace != 2 {
                    names.push(name);
                }
            }
            names.sort_by(|left, right| {
                (left.parent.record, left.parent.sequence, &left.name).cmp(&(
                    right.parent.record,
                    right.parent.sequence,
                    &right.name,
                ))
            });
            let name = names
                .first()
                .ok_or_else(|| corrupt(0, "NTFS object has no ordinary name"))?;
            super::validate_ntfs_component_utf16(&name.name)?;
            let component = String::from_utf16(&name.name)
                .map_err(|_| unsupported("NTFS mutation path is not lossless UTF-8"))?;
            path_bytes = path_bytes
                .checked_add(component.len() + 1)
                .filter(|length| *length <= 65_536)
                .ok_or(FfsError::NameTooLong)?;
            let parent = Self::checked_reference(&volume, cx, name.parent)?;
            if !parent.is_directory() {
                return Err(corrupt(0, "NTFS FILE_NAME parent is not a directory"));
            }
            if !volume
                .list_directory(cx, &parent)?
                .iter()
                .any(|entry| entry.reference == current && entry.filename == *name)
            {
                return Err(corrupt(
                    0,
                    "NTFS FILE_NAME is absent from its parent's index",
                ));
            }
            components.push(component);
            current = name.parent;
        }
        Err(FfsError::NameTooLong)
    }

    pub(super) fn validate_mutation_path_reference(
        &self,
        cx: &Cx,
        path: &str,
        reference: NtfsReference,
    ) -> Result<()> {
        let mft = self.read_mft_record_zero(cx)?;
        let runs = super::extract_plain_nonresident_runs(&self.geometry, &mft, DATA, &[])?;
        let (number, resolved) = self.resolve_path_raw(cx, &runs, path)?;
        if u64::from(number) != reference.record || resolved.sequence != reference.sequence {
            return Err(corrupt(
                0,
                "NTFS mutation path resolves to a different reference",
            ));
        }
        Ok(())
    }

    pub(super) fn child_mutation_path(
        &self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
    ) -> Result<String> {
        super::validate_ntfs_component_utf16(name)?;
        let component = String::from_utf16(name)
            .map_err(|_| unsupported("NTFS mutation component is not lossless UTF-8"))?;
        let parent_path = self.resolve_reference_path(cx, parent)?;
        let path = format!("{}/{component}", parent_path.trim_end_matches('/'));
        if path.len() > 65_536 {
            return Err(FfsError::NameTooLong);
        }
        Ok(path)
    }

    /// Load a complete base + extension MFT record catalog into an [`EditableCatalog`].
    pub(super) fn load_editable_catalog(
        &self,
        cx: &Cx,
        mft_runs: &[NtfsRun],
        base_ref: NtfsReference,
    ) -> Result<EditableCatalog> {
        self.load_editable_catalog_with_options(cx, mft_runs, base_ref, false)
    }

    /// Load a view-index / `$Extend` system record catalog (such as `$Secure`, `$Reparse`,
    /// `$ObjId`, or `$UsnJrnl`) whose FILE flags include `0x0008` / `0x0004`.
    pub(super) fn load_view_index_catalog(
        &self,
        cx: &Cx,
        mft_runs: &[NtfsRun],
        base_ref: NtfsReference,
    ) -> Result<EditableCatalog> {
        self.load_editable_catalog_with_options(cx, mft_runs, base_ref, true)
    }

    #[allow(clippy::too_many_lines)]
    fn load_editable_catalog_with_options(
        &self,
        cx: &Cx,
        mft_runs: &[NtfsRun],
        base_ref: NtfsReference,
        allow_view_index_record: bool,
    ) -> Result<EditableCatalog> {
        checkpoint(cx)?;
        if base_ref.sequence == 0 {
            return Err(stale_reference(base_ref));
        }
        let base_no = u32::try_from(base_ref.record).map_err(|_| stale_reference(base_ref))?;
        let mft0 = self.read_mft_record_zero(cx)?;
        let (_, mft_data_bytes, mft_init_bytes) =
            super::extract_plain_nonresident_stream(&self.geometry, &mft0, DATA, &[])?;
        let rec_bytes = u64::from(self.geometry.record_bytes());
        if base_ref.record >= mft_init_bytes / rec_bytes
            || base_ref.record >= mft_data_bytes / rec_bytes
        {
            return Err(stale_reference(base_ref));
        }
        let old_base_raw =
            read_mft_record_raw_via_runs(&self.device, cx, &self.geometry, mft_runs, base_no)?;
        let mut base_record =
            NtfsFileRecord::parse(&old_base_raw).map_err(|err| parse_err(&err))?;
        if base_record.self_number.is_none() {
            base_record.number = base_no;
        }
        if !base_record.in_use()
            || base_record.number != base_no
            || base_record.sequence != base_ref.sequence
        {
            return Err(stale_reference(base_ref));
        }
        if base_record.base.record != 0 || base_record.base.sequence != 0 {
            return Err(corrupt(0, "cannot load extension MFT record as base"));
        }

        let base_attrs = base_record.attributes().map_err(|err| parse_err(&err))?;
        refuse_unsupported_record_metadata(
            &base_record,
            &old_base_raw,
            &base_attrs,
            allow_view_index_record,
        )?;

        let mut old_extensions: Vec<(u32, u16, Vec<u8>)> = Vec::new();
        let mut ext_records: BTreeMap<u32, NtfsFileRecord> = BTreeMap::new();
        let mut old_nonres_attrlist_runs = Vec::new();

        if let Some(al_attr) = base_attrs.iter().find(|a| a.kind == ATTRIBUTE_LIST) {
            if !al_attr.name.is_empty() || al_attr.flags != 0 {
                return Err(corrupt(0, "named or transformed $ATTRIBUTE_LIST"));
            }
            let al_bytes = match &al_attr.value {
                NtfsValue::Resident(bytes) => bytes.to_vec(),
                NtfsValue::NonResident(nr) => {
                    if nr.first_vcn != 0 || nr.initialized_bytes < nr.data_bytes {
                        return Err(unsupported(
                            "fragmented or uninitialized nonresident $ATTRIBUTE_LIST",
                        ));
                    }
                    let runs = decode_mapping_pairs(
                        nr.mapping_pairs,
                        nr.first_vcn,
                        nr.last_vcn,
                        self.geometry.cluster_count(),
                    )
                    .map_err(|err| parse_err(&err))?;
                    let bytes = read_mapped_runs(
                        &self.device,
                        cx,
                        &self.geometry,
                        &runs,
                        0,
                        nr.data_bytes as usize,
                    )?;
                    old_nonres_attrlist_runs = runs;
                    bytes
                }
            };
            let entries = parse_attribute_list(&al_bytes).map_err(|err| parse_err(&err))?;
            for entry in &entries {
                if entry.reference.record == base_ref.record {
                    if entry.reference.sequence != base_ref.sequence {
                        return Err(corrupt(0, "stale base sequence in $ATTRIBUTE_LIST"));
                    }
                    continue;
                }
                let ext_no = u32::try_from(entry.reference.record)
                    .map_err(|_| corrupt(0, "extension record number overflow"))?;
                if ext_records.contains_key(&ext_no) {
                    continue;
                }
                let raw_ext = read_mft_record_raw_via_runs(
                    &self.device,
                    cx,
                    &self.geometry,
                    mft_runs,
                    ext_no,
                )?;
                let mut parsed_ext =
                    NtfsFileRecord::parse(&raw_ext).map_err(|err| parse_err(&err))?;
                if parsed_ext.self_number.is_none() {
                    parsed_ext.number = ext_no;
                }
                if !parsed_ext.in_use()
                    || parsed_ext.sequence != entry.reference.sequence
                    || parsed_ext.base != base_ref
                {
                    return Err(corrupt(
                        0,
                        "extension MFT record inactive, stale, or mismatched owner",
                    ));
                }
                let ext_attrs = parsed_ext.attributes().map_err(|err| parse_err(&err))?;
                refuse_unsupported_record_metadata(
                    &parsed_ext,
                    &raw_ext,
                    &ext_attrs,
                    allow_view_index_record,
                )?;
                old_extensions.push((ext_no, parsed_ext.sequence, raw_ext));
                ext_records.insert(ext_no, parsed_ext);
            }
        }

        let mut all_attrs: Vec<NtfsAttribute<'_>> = Vec::new();
        for a in base_attrs {
            if a.kind != ATTRIBUTE_LIST {
                all_attrs.push(a);
            }
        }
        let ext_attr_vecs: Vec<Vec<NtfsAttribute<'_>>> = ext_records
            .values()
            .map(|r| r.attributes().map_err(|err| parse_err(&err)))
            .collect::<Result<Vec<_>>>()?;
        for vec_a in ext_attr_vecs {
            for a in vec_a {
                if a.kind == ATTRIBUTE_LIST {
                    return Err(corrupt(0, "recursive $ATTRIBUTE_LIST in extension record"));
                }
                all_attrs.push(a);
            }
        }

        let mut std_info: Option<Vec<u8>> = None;
        let mut file_names: Vec<EditableFileName> = Vec::new();
        let mut object_id: Option<Vec<u8>> = None;
        let mut security_descriptor: Option<Vec<u8>> = None;
        let mut data_groups: BTreeMap<Vec<u16>, (Vec<u16>, Vec<NtfsAttribute<'_>>)> =
            BTreeMap::new();
        let mut i30_root: Option<Vec<u8>> = None;
        let mut i30_alloc_extents: Vec<NtfsAttribute<'_>> = Vec::new();
        let mut i30_bitmap: Option<Vec<u8>> = None;
        let mut view_roots: BTreeMap<Vec<u16>, Vec<u8>> = BTreeMap::new();
        let mut view_allocs: BTreeMap<Vec<u16>, Vec<NtfsAttribute<'_>>> = BTreeMap::new();
        let mut view_bitmaps: BTreeMap<Vec<u16>, Vec<u8>> = BTreeMap::new();
        let mut reparse_point: Option<Vec<u8>> = None;
        let mut efs_stream: Option<Vec<u8>> = None;
        let mut preserved: Vec<PreservedAttribute> = Vec::new();
        let mut old_owned_extra_runs: Vec<NtfsRun> = Vec::new();

        for attr in all_attrs {
            match attr.kind {
                ATTR_STANDARD_INFORMATION if attr.name.is_empty() => {
                    let NtfsValue::Resident(bytes) = attr.value else {
                        return Err(corrupt(0, "nonresident STANDARD_INFORMATION"));
                    };
                    std_info = Some(bytes.to_vec());
                }
                ATTR_FILE_NAME if attr.name.is_empty() => {
                    let NtfsValue::Resident(bytes) = attr.value else {
                        return Err(corrupt(0, "nonresident FILE_NAME"));
                    };
                    file_names.push(EditableFileName::parse_raw(bytes)?);
                }
                OBJECT_ID if attr.name.is_empty() => {
                    let NtfsValue::Resident(bytes) = attr.value else {
                        return Err(corrupt(0, "nonresident $OBJECT_ID"));
                    };
                    object_id = Some(bytes.to_vec());
                }
                ATTR_SECURITY_DESCRIPTOR if attr.name.is_empty() => match attr.value {
                    NtfsValue::Resident(bytes) => {
                        security_descriptor = Some(bytes.to_vec());
                    }
                    NtfsValue::NonResident(nr) => {
                        let runs = decode_mapping_pairs(
                            nr.mapping_pairs,
                            nr.first_vcn,
                            nr.last_vcn,
                            self.geometry.cluster_count(),
                        )
                        .map_err(|err| parse_err(&err))?;
                        if nr.first_vcn == 0 {
                            let bytes = read_mapped_runs(
                                &self.device,
                                cx,
                                &self.geometry,
                                &runs,
                                0,
                                nr.data_bytes as usize,
                            )?;
                            security_descriptor = Some(bytes);
                        }
                        old_owned_extra_runs.extend(runs);
                    }
                },
                DATA => {
                    let folded = self.fold_upcase(&attr.name);
                    if let Some((existing_name, _)) = data_groups.get(&folded)
                        && *existing_name != attr.name
                    {
                        return Err(corrupt(
                            0,
                            "case-colliding named DATA streams in NTFS record",
                        ));
                    }
                    let entry = data_groups
                        .entry(folded)
                        .or_insert_with(|| (attr.name.clone(), Vec::new()));
                    entry.1.push(attr);
                }
                ATTR_INDEX_ROOT if attr.name == I30_NAME => {
                    let NtfsValue::Resident(bytes) = attr.value else {
                        return Err(corrupt(0, "nonresident $I30 INDEX_ROOT"));
                    };
                    i30_root = Some(bytes.to_vec());
                }
                ATTR_INDEX_ALLOCATION if attr.name == I30_NAME => {
                    i30_alloc_extents.push(attr);
                }
                ATTR_BITMAP if attr.name == I30_NAME => match attr.value {
                    NtfsValue::Resident(bytes) => {
                        i30_bitmap = Some(bytes.to_vec());
                    }
                    NtfsValue::NonResident(nr) => {
                        let runs = decode_mapping_pairs(
                            nr.mapping_pairs,
                            nr.first_vcn,
                            nr.last_vcn,
                            self.geometry.cluster_count(),
                        )
                        .map_err(|err| parse_err(&err))?;
                        i30_bitmap = Some(read_mapped_runs(
                            &self.device,
                            cx,
                            &self.geometry,
                            &runs,
                            0,
                            nr.data_bytes as usize,
                        )?);
                        old_owned_extra_runs.extend(runs);
                    }
                },
                ATTR_INDEX_ROOT if allow_view_index_record && !attr.name.is_empty() => {
                    let NtfsValue::Resident(bytes) = attr.value else {
                        return Err(corrupt(0, "nonresident view INDEX_ROOT"));
                    };
                    view_roots.insert(attr.name, bytes.to_vec());
                }
                ATTR_INDEX_ALLOCATION if allow_view_index_record && !attr.name.is_empty() => {
                    view_allocs.entry(attr.name.clone()).or_default().push(attr);
                }
                ATTR_BITMAP if allow_view_index_record && !attr.name.is_empty() => {
                    match attr.value {
                        NtfsValue::Resident(bytes) => {
                            view_bitmaps.insert(attr.name, bytes.to_vec());
                        }
                        NtfsValue::NonResident(nr) => {
                            let runs = decode_mapping_pairs(
                                nr.mapping_pairs,
                                nr.first_vcn,
                                nr.last_vcn,
                                self.geometry.cluster_count(),
                            )
                            .map_err(|err| parse_err(&err))?;
                            let bm = read_mapped_runs(
                                &self.device,
                                cx,
                                &self.geometry,
                                &runs,
                                0,
                                nr.data_bytes as usize,
                            )?;
                            view_bitmaps.insert(attr.name, bm);
                            old_owned_extra_runs.extend(runs);
                        }
                    }
                }
                REPARSE_POINT if attr.name.is_empty() => match attr.value {
                    NtfsValue::Resident(bytes) => {
                        reparse_point = Some(bytes.to_vec());
                    }
                    NtfsValue::NonResident(nr) => {
                        let runs = decode_mapping_pairs(
                            nr.mapping_pairs,
                            nr.first_vcn,
                            nr.last_vcn,
                            self.geometry.cluster_count(),
                        )
                        .map_err(|err| parse_err(&err))?;
                        let bytes = read_mapped_runs(
                            &self.device,
                            cx,
                            &self.geometry,
                            &runs,
                            0,
                            nr.data_bytes as usize,
                        )?;
                        reparse_point = Some(bytes);
                        old_owned_extra_runs.extend(runs);
                    }
                },
                LOGGED_UTILITY_STREAM if attr.name == EFS_STREAM_NAME => match attr.value {
                    NtfsValue::Resident(bytes) => {
                        efs_stream = Some(bytes.to_vec());
                    }
                    NtfsValue::NonResident(nr) => {
                        let runs = decode_mapping_pairs(
                            nr.mapping_pairs,
                            nr.first_vcn,
                            nr.last_vcn,
                            self.geometry.cluster_count(),
                        )
                        .map_err(|err| parse_err(&err))?;
                        let bytes = read_mapped_runs(
                            &self.device,
                            cx,
                            &self.geometry,
                            &runs,
                            0,
                            nr.data_bytes as usize,
                        )?;
                        efs_stream = Some(bytes);
                        old_owned_extra_runs.extend(runs);
                    }
                },
                other => {
                    let raw_without_id = match attr.value {
                        NtfsValue::Resident(bytes) => PreservedValue::Resident {
                            indexed: false,
                            bytes: bytes.to_vec(),
                        },
                        NtfsValue::NonResident(nr) => PreservedValue::NonResident {
                            first_vcn: nr.first_vcn,
                            last_vcn: nr.last_vcn,
                            compression_unit: nr.compression_unit,
                            allocated_bytes: nr.allocated_bytes,
                            data_bytes: nr.data_bytes,
                            initialized_bytes: nr.initialized_bytes,
                            mapping_pairs: nr.mapping_pairs.to_vec(),
                        },
                    };
                    preserved.push(PreservedAttribute {
                        kind: other,
                        flags: attr.flags,
                        name: attr.name,
                        raw_without_id,
                    });
                }
            }
        }

        let std_info =
            std_info.ok_or_else(|| corrupt(0, "missing STANDARD_INFORMATION on base record"))?;

        let mut data_streams = Vec::new();
        for (_folded, (orig_name, mut extents)) in data_groups {
            if extents.len() == 1
                && let NtfsValue::Resident(bytes) = extents[0].value
            {
                if extents[0].flags != 0 {
                    return Err(corrupt(0, "transformed resident DATA attribute"));
                }
                data_streams.push(EditableDataStream {
                    name: orig_name,
                    storage: EditableStreamStorage::Resident(bytes.to_vec()),
                });
                continue;
            }
            extents.sort_by_key(|a| match &a.value {
                NtfsValue::Resident(_) => 0,
                NtfsValue::NonResident(nr) => nr.first_vcn,
            });
            let first_flags = extents[0].flags;
            let sparse = (first_flags & SPARSE) != 0;
            let compressed = (first_flags & COMPRESSED) != 0;
            let encrypted = (first_flags & ENCRYPTED) != 0;
            let mut combined_runs = Vec::new();
            let mut data_bytes = 0_u64;
            let mut init_bytes = 0_u64;
            let mut comp_unit = 0_u16;
            let mut expected_vcn = 0_u64;
            for (idx, ext) in extents.iter().enumerate() {
                let NtfsValue::NonResident(nr) = &ext.value else {
                    return Err(corrupt(0, "mixed resident/nonresident DATA extents"));
                };
                if ext.flags != first_flags {
                    return Err(corrupt(0, "inconsistent storage flags across DATA extents"));
                }
                if idx == 0 {
                    if nr.first_vcn != 0 {
                        return Err(corrupt(0, "DATA stream missing VCN 0 extent"));
                    }
                    data_bytes = nr.data_bytes;
                    init_bytes = nr.initialized_bytes;
                    comp_unit = nr.compression_unit;
                } else if nr.first_vcn != expected_vcn {
                    return Err(corrupt(0, "gap in multi-extent DATA stream"));
                }
                let decoded = decode_mapping_pairs(
                    nr.mapping_pairs,
                    nr.first_vcn,
                    nr.last_vcn,
                    self.geometry.cluster_count(),
                )
                .map_err(|err| parse_err(&err))?;
                if !sparse && !compressed && decoded.iter().any(|r| r.lcn.is_none()) {
                    return Err(corrupt(0, "sparse hole in non-SPARSE DATA stream"));
                }
                expected_vcn = decoded.last().map_or(expected_vcn, |r| r.vcn + r.clusters);
                combined_runs.extend(decoded);
            }
            let cb = u64::from(self.geometry.cluster_bytes());
            if expected_vcn * cb < data_bytes || init_bytes > data_bytes {
                return Err(corrupt(0, "incomplete or invalid DATA stream sizes"));
            }
            data_streams.push(EditableDataStream {
                name: orig_name,
                storage: EditableStreamStorage::NonResident {
                    runs: normalize_ntfs_runs(combined_runs),
                    sparse,
                    compressed,
                    encrypted,
                    compression_unit: comp_unit,
                    data_bytes,
                    initialized_bytes: init_bytes,
                },
            });
        }

        let dir_index = if base_record.is_directory() {
            let root = i30_root.ok_or_else(|| corrupt(0, "directory lacks $I30 INDEX_ROOT"))?;
            let external = if i30_alloc_extents.is_empty() {
                None
            } else {
                i30_alloc_extents.sort_by_key(|a| match &a.value {
                    NtfsValue::Resident(_) => 0,
                    NtfsValue::NonResident(nr) => nr.first_vcn,
                });
                let mut a0_runs = Vec::new();
                let mut a0_size = 0_u64;
                for (idx, ext) in i30_alloc_extents.iter().enumerate() {
                    let NtfsValue::NonResident(nr) = &ext.value else {
                        return Err(corrupt(0, "resident $I30 INDEX_ALLOCATION"));
                    };
                    if idx == 0 {
                        a0_size = nr.data_bytes;
                    }
                    let decoded = decode_mapping_pairs(
                        nr.mapping_pairs,
                        nr.first_vcn,
                        nr.last_vcn,
                        self.geometry.cluster_count(),
                    )
                    .map_err(|err| parse_err(&err))?;
                    a0_runs.extend(decoded);
                }
                let b0 = i30_bitmap.ok_or_else(|| corrupt(0, "missing $I30 BITMAP"))?;
                Some((normalize_ntfs_runs(a0_runs), a0_size, b0))
            };
            Some(EditableDirIndex {
                index_root: root,
                external,
            })
        } else {
            None
        };

        let mut view_indexes = Vec::new();
        for (idx_name, root_bytes) in view_roots {
            let parsed_root =
                parse_view_index_root(&root_bytes, self.geometry.cluster_bytes(), None)
                    .map_err(|err| parse_err(&err))?;
            let collation: ViewCollation = parsed_root.collation;
            let external = if let Some(mut allocs) = view_allocs.remove(&idx_name) {
                allocs.sort_by_key(|a| match &a.value {
                    NtfsValue::Resident(_) => 0,
                    NtfsValue::NonResident(nr) => nr.first_vcn,
                });
                let mut a0_runs = Vec::new();
                let mut a0_size = 0_u64;
                for (i, ext) in allocs.iter().enumerate() {
                    let NtfsValue::NonResident(nr) = &ext.value else {
                        return Err(corrupt(0, "resident view INDEX_ALLOCATION"));
                    };
                    if i == 0 {
                        a0_size = nr.data_bytes;
                    }
                    let decoded = decode_mapping_pairs(
                        nr.mapping_pairs,
                        nr.first_vcn,
                        nr.last_vcn,
                        self.geometry.cluster_count(),
                    )
                    .map_err(|err| parse_err(&err))?;
                    a0_runs.extend(decoded);
                }
                let bm = view_bitmaps
                    .remove(&idx_name)
                    .ok_or_else(|| corrupt(0, "missing view-index BITMAP"))?;
                Some((normalize_ntfs_runs(a0_runs), a0_size, bm))
            } else {
                None
            };
            view_indexes.push(EditableViewIndex {
                index_name: idx_name,
                collation,
                index_root: root_bytes,
                external,
            });
        }

        Ok(EditableCatalog {
            base_ref,
            is_directory: base_record.is_directory(),
            std_info,
            file_names,
            object_id,
            security_descriptor,
            data_streams,
            dir_index,
            view_indexes,
            reparse_point,
            efs_stream,
            preserved,
            old_base_raw,
            old_extensions,
            old_nonres_attrlist_runs,
            old_owned_extra_runs,
        })
    }

    /// Pack an [`EditableCatalog`] into its base MFT record (and extension MFT records
    /// with `$ATTRIBUTE_LIST` `0x20` when attributes exceed single-record capacity),
    /// emitting logged MFT record updates and deallocating any surplus extension slots.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub(super) fn pack_editable_catalog<FSlot, FClus>(
        &self,
        catalog: &EditableCatalog,
        mft_attr_slot: u16,
        mft_runs: &[NtfsRun],
        mut allocate_mft_slot: FSlot,
        mut allocate_clusters: FClus,
    ) -> Result<PackedCatalogPlan>
    where
        FSlot: FnMut() -> Result<(u32, u16, Vec<u8>)>,
        FClus: FnMut(u64) -> Result<Vec<(u64, u64)>>,
    {
        let rec_bytes = self.geometry.record_bytes();
        let usa_offset: usize = if self.version == [3, 0] { 42 } else { 48 };
        let usa_count = (rec_bytes as usize) / SECTOR_BYTES + 1;
        let first_attr = (usa_offset + usa_count * 2).next_multiple_of(8);
        let max_record_body = (rec_bytes as usize) - first_attr - 8;
        let max_ext_attr_bytes = max_record_body;

        let preserved_base_flags = if catalog.old_base_raw.len() >= 24 {
            u16::from_le_bytes([catalog.old_base_raw[22], catalog.old_base_raw[23]]) & 0x000C
        } else {
            0
        };
        let hard_links = if catalog.file_names.is_empty() && catalog.base_ref.record == 5 {
            if catalog.old_base_raw.len() >= 20 {
                u16::from_le_bytes([catalog.old_base_raw[18], catalog.old_base_raw[19]])
            } else {
                0
            }
        } else {
            u16::try_from(catalog.file_names.len()).map_err(|_| FfsError::NoSpace)?
        };
        if hard_links == 0 && catalog.base_ref.record != 5 {
            return Err(corrupt(
                0,
                "live base record requires at least one FILE_NAME",
            ));
        }

        let mut candidates: Vec<CandidateAttr> = Vec::new();
        let mut pre_payload_writes: Vec<DirPrePayloadWrite> = Vec::new();

        {
            let si = catalog.std_info.clone();
            let est =
                encode_resident_attribute(ATTR_STANDARD_INFORMATION, 0, &[], false, &si)?.len();
            candidates.push(CandidateAttr {
                kind: ATTR_STANDARD_INFORMATION,
                name: Vec::new(),
                folded_name: Vec::new(),
                first_vcn: 0,
                keep_in_base_priority: 0,
                encode_with_id: Box::new(move |id| {
                    encode_resident_attribute(ATTR_STANDARD_INFORMATION, id, &[], false, &si)
                }),
                estimated_len: est,
            });
        }

        for (idx, fn_item) in catalog.file_names.iter().enumerate() {
            let fn_bytes = fn_item.encode()?;
            let est = encode_resident_attribute(ATTR_FILE_NAME, 0, &[], true, &fn_bytes)?.len();
            candidates.push(CandidateAttr {
                kind: ATTR_FILE_NAME,
                name: Vec::new(),
                folded_name: Vec::new(),
                first_vcn: 0,
                keep_in_base_priority: if idx == 0 { 1 } else { 2 },
                encode_with_id: Box::new(move |id| {
                    encode_resident_attribute(ATTR_FILE_NAME, id, &[], true, &fn_bytes)
                }),
                estimated_len: est,
            });
        }

        if let Some(ref oid) = catalog.object_id {
            let oid_cl = oid.clone();
            let est = encode_resident_attribute(OBJECT_ID, 0, &[], false, &oid_cl)?.len();
            candidates.push(CandidateAttr {
                kind: OBJECT_ID,
                name: Vec::new(),
                folded_name: Vec::new(),
                first_vcn: 0,
                keep_in_base_priority: 2,
                encode_with_id: Box::new(move |id| {
                    encode_resident_attribute(OBJECT_ID, id, &[], false, &oid_cl)
                }),
                estimated_len: est,
            });
        }

        if let Some(ref sd) = catalog.security_descriptor {
            let sd_cl = sd.clone();
            let sample =
                encode_resident_attribute(ATTR_SECURITY_DESCRIPTOR, 0, &[], false, &sd_cl)?;
            if sample.len() <= max_ext_attr_bytes {
                let est = sample.len();
                candidates.push(CandidateAttr {
                    kind: ATTR_SECURITY_DESCRIPTOR,
                    name: Vec::new(),
                    folded_name: Vec::new(),
                    first_vcn: 0,
                    keep_in_base_priority: 2,
                    encode_with_id: Box::new(move |id| {
                        encode_resident_attribute(ATTR_SECURITY_DESCRIPTOR, id, &[], false, &sd_cl)
                    }),
                    estimated_len: est,
                });
            } else {
                let cb = u64::from(self.geometry.cluster_bytes());
                let need_cl = (sd_cl.len() as u64).div_ceil(cb);
                let spans = allocate_clusters(need_cl)?;
                let mut sd_runs = Vec::new();
                let mut cur_vcn = 0_u64;
                for &(lcn, cnt) in &spans {
                    sd_runs.push(NtfsRun {
                        vcn: cur_vcn,
                        clusters: cnt,
                        lcn: Some(lcn),
                    });
                    cur_vcn += cnt;
                }
                let mut padded = vec![0_u8; (need_cl * cb) as usize];
                padded[..sd_cl.len()].copy_from_slice(&sd_cl);
                stage_runs_writes(&self.geometry, &sd_runs, &padded, &mut pre_payload_writes)?;
                let sd_len = sd_cl.len() as u64;
                let sd_extents = split_nonresident_stream_extents(
                    &self.geometry,
                    ATTR_SECURITY_DESCRIPTOR,
                    &[],
                    &[],
                    &sd_runs,
                    0,
                    0,
                    sd_len,
                    sd_len,
                    max_ext_attr_bytes,
                )?;
                candidates.extend(sd_extents);
            }
        }

        let mut sorted_streams = catalog.data_streams.clone();
        sorted_streams.sort_by_key(|a| self.fold_upcase(&a.name));
        for stream in sorted_streams {
            let folded = self.fold_upcase(&stream.name);
            match stream.storage {
                EditableStreamStorage::Resident(bytes) => {
                    let nm = stream.name;
                    let nm_cl = nm.clone();
                    let est = encode_resident_attribute(DATA, 0, &nm, false, &bytes)?.len();
                    if est > max_ext_attr_bytes {
                        return Err(corrupt(0, "resident DATA exceeds single MFT record"));
                    }
                    let prio = if nm.is_empty() { 2 } else { 3 };
                    candidates.push(CandidateAttr {
                        kind: DATA,
                        name: nm,
                        folded_name: folded,
                        first_vcn: 0,
                        keep_in_base_priority: prio,
                        encode_with_id: Box::new(move |id| {
                            encode_resident_attribute(DATA, id, &nm_cl, false, &bytes)
                        }),
                        estimated_len: est,
                    });
                }
                EditableStreamStorage::NonResident {
                    runs,
                    sparse,
                    compressed,
                    encrypted,
                    compression_unit,
                    data_bytes,
                    initialized_bytes,
                } => {
                    let mut flags = 0_u16;
                    if sparse {
                        flags |= SPARSE;
                    }
                    if compressed {
                        flags |= COMPRESSED;
                    }
                    if encrypted {
                        flags |= ENCRYPTED;
                    }
                    let extents = split_nonresident_stream_extents(
                        &self.geometry,
                        DATA,
                        &stream.name,
                        &folded,
                        &runs,
                        flags,
                        compression_unit,
                        data_bytes,
                        initialized_bytes,
                        max_ext_attr_bytes,
                    )?;
                    candidates.extend(extents);
                }
            }
        }

        if let Some(ref dir_idx) = catalog.dir_index {
            let ir = dir_idx.index_root.clone();
            let est_ir =
                encode_resident_attribute(ATTR_INDEX_ROOT, 0, &I30_NAME, false, &ir)?.len();
            candidates.push(CandidateAttr {
                kind: ATTR_INDEX_ROOT,
                name: I30_NAME.to_vec(),
                folded_name: I30_NAME.to_vec(),
                first_vcn: 0,
                keep_in_base_priority: 0,
                encode_with_id: Box::new(move |id| {
                    encode_resident_attribute(ATTR_INDEX_ROOT, id, &I30_NAME, false, &ir)
                }),
                estimated_len: est_ir,
            });
            if let Some((ref a0_runs, a0_size, ref b0_bytes)) = dir_idx.external {
                let a0_extents = split_nonresident_stream_extents(
                    &self.geometry,
                    ATTR_INDEX_ALLOCATION,
                    &I30_NAME,
                    &I30_NAME,
                    a0_runs,
                    0,
                    0,
                    a0_size,
                    a0_size,
                    max_ext_attr_bytes,
                )?;
                candidates.extend(a0_extents);

                let b0_cl = b0_bytes.clone();
                let sample_b0 =
                    encode_resident_attribute(ATTR_BITMAP, 0, &I30_NAME, false, &b0_cl)?;
                if sample_b0.len() <= max_ext_attr_bytes {
                    let est_b0 = sample_b0.len();
                    candidates.push(CandidateAttr {
                        kind: ATTR_BITMAP,
                        name: I30_NAME.to_vec(),
                        folded_name: I30_NAME.to_vec(),
                        first_vcn: 0,
                        keep_in_base_priority: 2,
                        encode_with_id: Box::new(move |id| {
                            encode_resident_attribute(ATTR_BITMAP, id, &I30_NAME, false, &b0_cl)
                        }),
                        estimated_len: est_b0,
                    });
                } else {
                    let cb = u64::from(self.geometry.cluster_bytes());
                    let need_cl = (b0_cl.len() as u64).div_ceil(cb);
                    let spans = allocate_clusters(need_cl)?;
                    let mut b0_runs = Vec::new();
                    let mut cur_vcn = 0_u64;
                    for &(lcn, cnt) in &spans {
                        b0_runs.push(NtfsRun {
                            vcn: cur_vcn,
                            clusters: cnt,
                            lcn: Some(lcn),
                        });
                        cur_vcn += cnt;
                    }
                    let mut padded = vec![0_u8; (need_cl * cb) as usize];
                    padded[..b0_cl.len()].copy_from_slice(&b0_cl);
                    stage_runs_writes(&self.geometry, &b0_runs, &padded, &mut pre_payload_writes)?;
                    let b0_len = b0_cl.len() as u64;
                    let b0_extents = split_nonresident_stream_extents(
                        &self.geometry,
                        ATTR_BITMAP,
                        &I30_NAME,
                        &I30_NAME,
                        &b0_runs,
                        0,
                        0,
                        b0_len,
                        b0_len,
                        max_ext_attr_bytes,
                    )?;
                    candidates.extend(b0_extents);
                }
            }
        }

        for view in &catalog.view_indexes {
            let vname = view.index_name.clone();
            let vfolded = self.fold_upcase(&vname);
            let ir = view.index_root.clone();
            let vname_ir = vname.clone();
            let est_ir = encode_resident_attribute(ATTR_INDEX_ROOT, 0, &vname, false, &ir)?.len();
            candidates.push(CandidateAttr {
                kind: ATTR_INDEX_ROOT,
                name: vname.clone(),
                folded_name: vfolded.clone(),
                first_vcn: 0,
                keep_in_base_priority: 2,
                encode_with_id: Box::new(move |id| {
                    encode_resident_attribute(ATTR_INDEX_ROOT, id, &vname_ir, false, &ir)
                }),
                estimated_len: est_ir,
            });
            if let Some((ref a0_runs, a0_size, ref b0_bytes)) = view.external {
                let a0_extents = split_nonresident_stream_extents(
                    &self.geometry,
                    ATTR_INDEX_ALLOCATION,
                    &vname,
                    &vfolded,
                    a0_runs,
                    0,
                    0,
                    a0_size,
                    a0_size,
                    max_ext_attr_bytes,
                )?;
                candidates.extend(a0_extents);

                let b0_cl = b0_bytes.clone();
                let vname_b0 = vname.clone();
                let sample_b0 = encode_resident_attribute(ATTR_BITMAP, 0, &vname, false, &b0_cl)?;
                if sample_b0.len() <= max_ext_attr_bytes {
                    let est_b0 = sample_b0.len();
                    candidates.push(CandidateAttr {
                        kind: ATTR_BITMAP,
                        name: vname,
                        folded_name: vfolded,
                        first_vcn: 0,
                        keep_in_base_priority: 2,
                        encode_with_id: Box::new(move |id| {
                            encode_resident_attribute(ATTR_BITMAP, id, &vname_b0, false, &b0_cl)
                        }),
                        estimated_len: est_b0,
                    });
                } else {
                    let cb = u64::from(self.geometry.cluster_bytes());
                    let need_cl = (b0_cl.len() as u64).div_ceil(cb);
                    let spans = allocate_clusters(need_cl)?;
                    let mut b0_runs = Vec::new();
                    let mut cur_vcn = 0_u64;
                    for &(lcn, cnt) in &spans {
                        b0_runs.push(NtfsRun {
                            vcn: cur_vcn,
                            clusters: cnt,
                            lcn: Some(lcn),
                        });
                        cur_vcn += cnt;
                    }
                    let mut padded = vec![0_u8; (need_cl * cb) as usize];
                    padded[..b0_cl.len()].copy_from_slice(&b0_cl);
                    stage_runs_writes(&self.geometry, &b0_runs, &padded, &mut pre_payload_writes)?;
                    let b0_len = b0_cl.len() as u64;
                    let b0_extents = split_nonresident_stream_extents(
                        &self.geometry,
                        ATTR_BITMAP,
                        &vname,
                        &vfolded,
                        &b0_runs,
                        0,
                        0,
                        b0_len,
                        b0_len,
                        max_ext_attr_bytes,
                    )?;
                    candidates.extend(b0_extents);
                }
            }
        }

        // Helper for optional resident-or-spill blob attributes ($REPARSE_POINT, $EA, $EFS).
        let mut push_blob_attr = |kind: u32, name: &[u16], blob: &[u8]| -> Result<()> {
            let folded = self.fold_upcase(name);
            let nm = name.to_vec();
            let nm_cl = nm.clone();
            let data_cl = blob.to_vec();
            let sample = encode_resident_attribute(kind, 0, &nm, false, &data_cl)?;
            if sample.len() <= max_ext_attr_bytes {
                let est = sample.len();
                candidates.push(CandidateAttr {
                    kind,
                    name: nm,
                    folded_name: folded,
                    first_vcn: 0,
                    keep_in_base_priority: 2,
                    encode_with_id: Box::new(move |id| {
                        encode_resident_attribute(kind, id, &nm_cl, false, &data_cl)
                    }),
                    estimated_len: est,
                });
            } else {
                let cb = u64::from(self.geometry.cluster_bytes());
                let need_cl = (data_cl.len() as u64).div_ceil(cb);
                let spans = allocate_clusters(need_cl)?;
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
                let mut padded = vec![0_u8; (need_cl * cb) as usize];
                padded[..data_cl.len()].copy_from_slice(&data_cl);
                stage_runs_writes(&self.geometry, &runs, &padded, &mut pre_payload_writes)?;
                let blen = data_cl.len() as u64;
                let exts = split_nonresident_stream_extents(
                    &self.geometry,
                    kind,
                    &nm,
                    &folded,
                    &runs,
                    0,
                    0,
                    blen,
                    blen,
                    max_ext_attr_bytes,
                )?;
                candidates.extend(exts);
            }
            Ok(())
        };

        if let Some(ref rp) = catalog.reparse_point {
            push_blob_attr(REPARSE_POINT, &[], rp)?;
        }
        if let Some(ref efs_raw) = catalog.efs_stream {
            push_blob_attr(LOGGED_UTILITY_STREAM, &EFS_STREAM_NAME, efs_raw)?;
        }

        for pres in &catalog.preserved {
            let folded = self.fold_upcase(&pres.name);
            let nm = pres.name.clone();
            let nm_cl = nm.clone();
            let kind = pres.kind;
            let flags = pres.flags;
            match &pres.raw_without_id {
                PreservedValue::Resident { indexed, bytes } => {
                    let b_cl = bytes.clone();
                    let idx_flag = *indexed;
                    let est = encode_resident_attribute(kind, 0, &nm, idx_flag, &b_cl)?.len();
                    if kind == EA && est > max_ext_attr_bytes {
                        // EA_INFORMATION stays resident, while the bounded EA
                        // value may need several clusters or mapping extents.
                        // Initialize fresh storage before publishing any FILE
                        // record that references it, just like DATA and SDs.
                        let cb = u64::from(self.geometry.cluster_bytes());
                        let need_cl = (bytes.len() as u64).div_ceil(cb);
                        let spans = allocate_clusters(need_cl)?;
                        let mut runs = Vec::with_capacity(spans.len());
                        let mut vcn = 0;
                        for (lcn, clusters) in spans {
                            runs.push(NtfsRun {
                                vcn,
                                clusters,
                                lcn: Some(lcn),
                            });
                            vcn += clusters;
                        }
                        let mut padded = vec![0; (need_cl * cb) as usize];
                        padded[..bytes.len()].copy_from_slice(bytes);
                        stage_runs_writes(&self.geometry, &runs, &padded, &mut pre_payload_writes)?;
                        candidates.extend(split_nonresident_stream_extents(
                            &self.geometry,
                            kind,
                            &nm,
                            &folded,
                            &runs,
                            0,
                            0,
                            bytes.len() as u64,
                            bytes.len() as u64,
                            max_ext_attr_bytes,
                        )?);
                        continue;
                    }
                    candidates.push(CandidateAttr {
                        kind,
                        name: nm,
                        folded_name: folded,
                        first_vcn: 0,
                        keep_in_base_priority: 3,
                        encode_with_id: Box::new(move |id| {
                            encode_resident_attribute(kind, id, &nm_cl, idx_flag, &b_cl)
                        }),
                        estimated_len: est,
                    });
                }
                PreservedValue::NonResident {
                    first_vcn,
                    last_vcn,
                    compression_unit,
                    allocated_bytes,
                    data_bytes,
                    initialized_bytes,
                    mapping_pairs,
                } => {
                    let fv = *first_vcn;
                    let lv = *last_vcn;
                    let cu = *compression_unit;
                    let ab = *allocated_bytes;
                    let db = *data_bytes;
                    let ib = *initialized_bytes;
                    let mp = mapping_pairs.clone();
                    let hdr_len = if flags & (SPARSE | COMPRESSED) != 0 {
                        72
                    } else {
                        64
                    };
                    let mp_off = (hdr_len + nm.len() * 2).next_multiple_of(8);
                    let est = (mp_off + mp.len()).next_multiple_of(8);
                    candidates.push(CandidateAttr {
                        kind,
                        name: nm,
                        folded_name: folded,
                        first_vcn: fv,
                        keep_in_base_priority: 3,
                        encode_with_id: Box::new(move |id| {
                            let mut out = vec![0_u8; est];
                            out[0..4].copy_from_slice(&kind.to_le_bytes());
                            out[4..8].copy_from_slice(&(est as u32).to_le_bytes());
                            out[8] = 1;
                            out[9] = u8::try_from(nm_cl.len())
                                .map_err(|_| corrupt(0, "attr name len"))?;
                            out[10..12].copy_from_slice(&(hdr_len as u16).to_le_bytes());
                            out[12..14].copy_from_slice(&flags.to_le_bytes());
                            out[14..16].copy_from_slice(&id.to_le_bytes());
                            out[16..24].copy_from_slice(&fv.to_le_bytes());
                            out[24..32].copy_from_slice(&lv.to_le_bytes());
                            out[32..34].copy_from_slice(&(mp_off as u16).to_le_bytes());
                            out[34..36].copy_from_slice(&cu.to_le_bytes());
                            if fv == 0 {
                                out[40..48].copy_from_slice(&ab.to_le_bytes());
                                out[48..56].copy_from_slice(&db.to_le_bytes());
                                out[56..64].copy_from_slice(&ib.to_le_bytes());
                            }
                            for (i, &u) in nm_cl.iter().enumerate() {
                                out[hdr_len + i * 2..hdr_len + 2 + i * 2]
                                    .copy_from_slice(&u.to_le_bytes());
                            }
                            out[mp_off..mp_off + mp.len()].copy_from_slice(&mp);
                            Ok(out)
                        }),
                        estimated_len: est,
                    });
                }
            }
        }

        candidates.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then_with(|| a.folded_name.cmp(&b.folded_name))
                .then_with(|| a.first_vcn.cmp(&b.first_vcn))
        });

        let mut freed_clusters = physical_spans_of_runs(&catalog.old_nonres_attrlist_runs);
        freed_clusters.extend(physical_spans_of_runs(&catalog.old_owned_extra_runs));
        let freed_clusters = coalesce_physical_spans(freed_clusters);
        let mut freed_mft_slots = Vec::new();
        let mut mft_record_writes = Vec::new();
        let mut log_specs = Vec::new();

        let total_single_len: usize = candidates.iter().map(|c| c.estimated_len).sum();
        let base_no =
            u32::try_from(catalog.base_ref.record).map_err(|_| corrupt(0, "base_no u32"))?;

        if total_single_len <= max_record_body {
            let mut encoded = Vec::with_capacity(candidates.len());
            for (idx, cand) in candidates.iter().enumerate() {
                let id = u16::try_from(idx).map_err(|_| FfsError::NoSpace)?;
                encoded.push((cand.encode_with_id)(id)?);
            }
            let next_id = u16::try_from(encoded.len()).map_err(|_| FfsError::NoSpace)?;
            let new_base_restored = build_restored_mft_record(
                rec_bytes,
                self.version,
                base_no,
                catalog.base_ref.sequence,
                catalog.is_directory,
                preserved_base_flags,
                hard_links,
                None,
                &encoded,
                next_id,
            )?;
            let protected_base = self.emit_mft_slot_replace_specs(
                mft_attr_slot,
                mft_runs,
                base_no,
                &catalog.old_base_raw,
                &new_base_restored,
                false,
                &mut log_specs,
            )?;
            mft_record_writes.push((base_no, protected_base));

            for &(ext_no, _ext_seq, ref old_ext_raw) in &catalog.old_extensions {
                let protected_dealloc = self.emit_mft_slot_dealloc_spec(
                    mft_attr_slot,
                    mft_runs,
                    ext_no,
                    old_ext_raw,
                    &mut log_specs,
                )?;
                mft_record_writes.push((ext_no, protected_dealloc));
                freed_mft_slots.push(ext_no);
            }

            return Ok(PackedCatalogPlan {
                pre_payload_writes,
                freed_clusters,
                freed_mft_slots,
                mft_record_writes,
                log_specs,
            });
        }

        let attrlist_reserve = 128_usize;
        if max_record_body <= attrlist_reserve {
            return Err(corrupt(0, "MFT record too small for $ATTRIBUTE_LIST"));
        }
        let base_budget_without_0x20 = max_record_body - attrlist_reserve;

        let mut in_base = vec![false; candidates.len()];
        let mut base_used = 0_usize;
        for prio in [0_u8, 1] {
            for (idx, cand) in candidates.iter().enumerate() {
                if cand.keep_in_base_priority == prio {
                    if prio == 0 && base_used + cand.estimated_len > base_budget_without_0x20 {
                        return Err(FfsError::NoSpace);
                    }
                    if base_used + cand.estimated_len <= base_budget_without_0x20 {
                        in_base[idx] = true;
                        base_used += cand.estimated_len;
                    }
                }
            }
        }

        let mut ext_bins: Vec<Vec<usize>> = Vec::new();
        let mut ext_bin_used: Vec<usize> = Vec::new();
        for (idx, cand) in candidates.iter().enumerate() {
            if in_base[idx] {
                continue;
            }
            if cand.estimated_len > max_record_body {
                return Err(FfsError::NoSpace);
            }
            let placed = ext_bin_used
                .iter()
                .position(|&used| used + cand.estimated_len <= max_record_body);
            if let Some(bin_i) = placed {
                ext_bins[bin_i].push(idx);
                ext_bin_used[bin_i] += cand.estimated_len;
            } else {
                ext_bins.push(vec![idx]);
                ext_bin_used.push(cand.estimated_len);
            }
        }

        let mut assigned_ext_slots: Vec<(u32, u16, Vec<u8>, bool)> =
            Vec::with_capacity(ext_bins.len());
        for bin_i in 0..ext_bins.len() {
            if bin_i < catalog.old_extensions.len() {
                let (slot, seq, ref raw) = catalog.old_extensions[bin_i];
                assigned_ext_slots.push((slot, seq, raw.clone(), false));
            } else {
                let (slot, seq, raw) = allocate_mft_slot()?;
                assigned_ext_slots.push((slot, seq, raw, true));
            }
        }
        for &(unused_slot, _, ref old_ext_raw) in catalog.old_extensions.iter().skip(ext_bins.len())
        {
            let protected_dealloc = self.emit_mft_slot_dealloc_spec(
                mft_attr_slot,
                mft_runs,
                unused_slot,
                old_ext_raw,
                &mut log_specs,
            )?;
            mft_record_writes.push((unused_slot, protected_dealloc));
            freed_mft_slots.push(unused_slot);
        }

        let mut list_entries_sorted: Vec<(Vec<u16>, NtfsAttributeListEntry)> =
            Vec::with_capacity(candidates.len());

        let mut base_encoded_items: Vec<(u32, Vec<u16>, u64, Vec<u8>)> = Vec::new();
        let mut base_attr_id = 0_u16;
        for (idx, cand) in candidates.iter().enumerate() {
            if !in_base[idx] {
                continue;
            }
            let id = base_attr_id;
            base_attr_id = base_attr_id.checked_add(1).ok_or(FfsError::NoSpace)?;
            let raw_attr = (cand.encode_with_id)(id)?;
            list_entries_sorted.push((
                cand.folded_name.clone(),
                NtfsAttributeListEntry {
                    kind: cand.kind,
                    name: cand.name.clone(),
                    first_vcn: cand.first_vcn,
                    reference: catalog.base_ref,
                    id,
                },
            ));
            base_encoded_items.push((
                cand.kind,
                cand.folded_name.clone(),
                cand.first_vcn,
                raw_attr,
            ));
        }

        for (bin_indices, &(ext_slot, ext_seq, ref old_ext_raw, is_fresh_slot)) in
            ext_bins.iter().zip(assigned_ext_slots.iter())
        {
            let ext_ref = NtfsReference {
                record: u64::from(ext_slot),
                sequence: ext_seq,
            };
            let mut ext_encoded = Vec::with_capacity(bin_indices.len());
            for (local_i, &cand_idx) in bin_indices.iter().enumerate() {
                let id = u16::try_from(local_i).map_err(|_| FfsError::NoSpace)?;
                let cand = &candidates[cand_idx];
                ext_encoded.push((cand.encode_with_id)(id)?);
                list_entries_sorted.push((
                    cand.folded_name.clone(),
                    NtfsAttributeListEntry {
                        kind: cand.kind,
                        name: cand.name.clone(),
                        first_vcn: cand.first_vcn,
                        reference: ext_ref,
                        id,
                    },
                ));
            }
            let next_ext_id = u16::try_from(ext_encoded.len()).map_err(|_| FfsError::NoSpace)?;
            let new_ext_restored = build_restored_mft_record(
                rec_bytes,
                self.version,
                ext_slot,
                ext_seq,
                false,
                0,
                0,
                Some(catalog.base_ref),
                &ext_encoded,
                next_ext_id,
            )?;
            let protected_ext = self.emit_mft_slot_replace_specs(
                mft_attr_slot,
                mft_runs,
                ext_slot,
                old_ext_raw,
                &new_ext_restored,
                is_fresh_slot,
                &mut log_specs,
            )?;
            mft_record_writes.push((ext_slot, protected_ext));
        }

        list_entries_sorted.sort_by(|(fa, ea), (fb, eb)| {
            ea.kind
                .cmp(&eb.kind)
                .then_with(|| fa.cmp(fb))
                .then_with(|| ea.first_vcn.cmp(&eb.first_vcn))
                .then_with(|| ea.reference.record.cmp(&eb.reference.record))
                .then_with(|| ea.id.cmp(&eb.id))
        });
        let pure_entries: Vec<NtfsAttributeListEntry> =
            list_entries_sorted.into_iter().map(|(_, e)| e).collect();
        let al_value_bytes = encode_attribute_list(&pure_entries).map_err(|err| parse_err(&err))?;

        let al_id = base_attr_id;
        base_attr_id = base_attr_id.checked_add(1).ok_or(FfsError::NoSpace)?;
        let res_al = encode_resident_attribute(ATTRIBUTE_LIST, al_id, &[], false, &al_value_bytes)?;
        let encoded_al = if base_used + res_al.len() <= max_record_body {
            res_al
        } else {
            let cb = u64::from(self.geometry.cluster_bytes());
            let need_cl = (al_value_bytes.len() as u64).div_ceil(cb);
            let spans = allocate_clusters(need_cl)?;
            let mut al_runs = Vec::new();
            let mut cur_vcn = 0_u64;
            for &(lcn, cnt) in &spans {
                al_runs.push(NtfsRun {
                    vcn: cur_vcn,
                    clusters: cnt,
                    lcn: Some(lcn),
                });
                cur_vcn += cnt;
            }
            let mut padded = vec![0_u8; (need_cl * cb) as usize];
            padded[..al_value_bytes.len()].copy_from_slice(&al_value_bytes);
            stage_runs_writes(&self.geometry, &al_runs, &padded, &mut pre_payload_writes)?;
            let al_len = al_value_bytes.len() as u64;
            encode_nonresident_extent(
                ATTRIBUTE_LIST,
                al_id,
                0,
                &[],
                &al_runs,
                0,
                0,
                need_cl * cb,
                al_len,
                al_len,
                0,
                self.geometry.cluster_count(),
            )?
        };

        base_encoded_items.push((ATTRIBUTE_LIST, Vec::new(), 0, encoded_al));
        base_encoded_items.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
        });
        let final_base_attrs: Vec<Vec<u8>> = base_encoded_items
            .into_iter()
            .map(|(_, _, _, raw)| raw)
            .collect();
        let new_base_restored = build_restored_mft_record(
            rec_bytes,
            self.version,
            base_no,
            catalog.base_ref.sequence,
            catalog.is_directory,
            preserved_base_flags,
            hard_links,
            None,
            &final_base_attrs,
            base_attr_id,
        )?;
        let protected_base = self.emit_mft_slot_replace_specs(
            mft_attr_slot,
            mft_runs,
            base_no,
            &catalog.old_base_raw,
            &new_base_restored,
            false,
            &mut log_specs,
        )?;
        mft_record_writes.push((base_no, protected_base));

        Ok(PackedCatalogPlan {
            pre_payload_writes,
            freed_clusters,
            freed_mft_slots,
            mft_record_writes,
            log_specs,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit_mft_slot_replace_specs(
        &self,
        mft_attr_slot: u16,
        mft_runs: &[NtfsRun],
        record_no: u32,
        old_raw: &[u8],
        new_restored: &[u8],
        is_fresh_allocation: bool,
        log_specs: &mut Vec<NtfsClientUpdateSpec>,
    ) -> Result<Vec<u8>> {
        let FileEditResult::Applied(protected_new) =
            initialize_file_record_slot(old_raw, record_no, RecoveryPass::Undo, new_restored)
                .map_err(|err| parse_err(&err))?
        else {
            return Err(corrupt(
                0,
                "unexpected AlreadyApplied on InitializeFileRecordSegment",
            ));
        };
        let new_used = usize::try_from(u32::from_le_bytes([
            new_restored[24],
            new_restored[25],
            new_restored[26],
            new_restored[27],
        ]))
        .map_err(|_| corrupt(0, "new_used overflow"))?;
        let new_prefix = new_restored[..new_used].to_vec();
        let (target_vcn, cbo, target_lcns) = self.map_mft_record_transfer(mft_runs, record_no)?;

        if is_fresh_allocation {
            log_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::InitializeFileRecordSegment,
                undo_op: NtfsLogOp::DeallocateFileRecordSegment,
                target_attribute: mft_attr_slot,
                record_offset: 0,
                attribute_offset: 0,
                cluster_block_offset: cbo,
                target_vcn,
                target_lcns,
                redo_data: new_prefix,
                undo_data: Vec::new(),
            });
            return Ok(protected_new);
        }

        let old_restored = restore_record(old_raw, b"FILE").map_err(|err| parse_err(&err))?;
        let old_used = usize::try_from(u32::from_le_bytes([
            old_restored[24],
            old_restored[25],
            old_restored[26],
            old_restored[27],
        ]))
        .map_err(|_| corrupt(0, "old_used overflow"))?;
        let old_prefix = old_restored[..old_used].to_vec();

        if new_prefix.len() + old_prefix.len() <= MAX_CLIENT_SINGLE_RECORD_BYTES {
            log_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::InitializeFileRecordSegment,
                undo_op: NtfsLogOp::InitializeFileRecordSegment,
                target_attribute: mft_attr_slot,
                record_offset: 0,
                attribute_offset: 0,
                cluster_block_offset: cbo,
                target_vcn,
                target_lcns,
                redo_data: new_prefix,
                undo_data: old_prefix,
            });
        } else {
            let first_attr = u16::from_le_bytes([old_restored[20], old_restored[21]]);
            log_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::WriteEndOfFileRecordSegment,
                undo_op: NtfsLogOp::InitializeFileRecordSegment,
                target_attribute: mft_attr_slot,
                record_offset: first_attr,
                attribute_offset: 0,
                cluster_block_offset: cbo,
                target_vcn,
                target_lcns: target_lcns.clone(),
                redo_data: u32::MAX.to_le_bytes().to_vec(),
                undo_data: old_prefix,
            });
            log_specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::InitializeFileRecordSegment,
                undo_op: NtfsLogOp::Noop,
                target_attribute: mft_attr_slot,
                record_offset: 0,
                attribute_offset: 0,
                cluster_block_offset: cbo,
                target_vcn,
                target_lcns,
                redo_data: new_prefix,
                undo_data: Vec::new(),
            });
        }
        Ok(protected_new)
    }

    pub(super) fn emit_mft_slot_dealloc_spec(
        &self,
        mft_attr_slot: u16,
        mft_runs: &[NtfsRun],
        record_no: u32,
        old_raw: &[u8],
        log_specs: &mut Vec<NtfsClientUpdateSpec>,
    ) -> Result<Vec<u8>> {
        let old_restored = restore_record(old_raw, b"FILE").map_err(|err| parse_err(&err))?;
        let old_used = usize::try_from(u32::from_le_bytes([
            old_restored[24],
            old_restored[25],
            old_restored[26],
            old_restored[27],
        ]))
        .map_err(|_| corrupt(0, "old_used overflow"))?;
        let old_prefix = old_restored[..old_used].to_vec();
        let FileEditResult::Applied(protected_dealloc) =
            deallocate_file_record_slot(old_raw, record_no, RecoveryPass::Undo)
                .map_err(|err| parse_err(&err))?
        else {
            return Err(corrupt(
                0,
                "unexpected AlreadyApplied on DeallocateFileRecordSegment",
            ));
        };
        let (target_vcn, cbo, target_lcns) = self.map_mft_record_transfer(mft_runs, record_no)?;
        log_specs.push(NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::DeallocateFileRecordSegment,
            undo_op: NtfsLogOp::InitializeFileRecordSegment,
            target_attribute: mft_attr_slot,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: cbo,
            target_vcn,
            target_lcns,
            redo_data: Vec::new(),
            undo_data: old_prefix,
        });
        Ok(protected_dealloc)
    }
}

pub(super) fn stage_runs_writes(
    geometry: &NtfsGeometry,
    runs: &[NtfsRun],
    bytes: &[u8],
    out: &mut Vec<DirPrePayloadWrite>,
) -> Result<()> {
    let mut done = 0_usize;
    while done < bytes.len() {
        let (phys, avail, _) = map_logical_offset(geometry, runs, done as u64)?;
        let chunk = (bytes.len() - done).min(avail as usize);
        out.push(DirPrePayloadWrite {
            phys_offset: phys,
            bytes: bytes[done..done + chunk].to_vec(),
        });
        done += chunk;
    }
    Ok(())
}
