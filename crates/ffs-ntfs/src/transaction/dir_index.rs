//! `$UpCase`-collated `$I30` directory B-tree lookup and logged edit planning
//! across both resident `INDEX_ROOT` (`0x90`) and external `INDEX_ALLOCATION` (`0xA0`)
//! + `BITMAP` (`0xB0`) streams.

use std::cmp::Ordering;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::index::{
    NtfsFileName, NtfsIndexEntry, NtfsIndexRoot, encode_index_entry, parse_index_block,
};
use ffs_ondisk::ntfs::logfile_writer::{NtfsClientUpdateSpec, next_usa_token};
use ffs_ondisk::ntfs::recovery::{
    FileEdit, FileEditResult, FileOperation, IndexEdit, IndexOperation, RecoveryPass,
    apply_file_edit, apply_index_edit,
};
use ffs_ondisk::ntfs::{
    DATA, NtfsFileRecord, NtfsGeometry, NtfsLogOp, NtfsReference, NtfsRun, NtfsValue,
    decode_mapping_pairs, encode_mapping_pairs, restore_record,
};

use super::{
    NtfsTransactionEngine, SECTOR_BYTES, checkpoint, corrupt, extract_plain_nonresident_stream,
    extract_resident_attr, map_logical_offset, parse_err, read_mapped_runs,
    read_mft_record_via_runs, unsupported,
};

pub(super) const I30_NAME: [u16; 4] = [0x24, 0x49, 0x33, 0x30];
const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const ATTR_BITMAP: u32 = 0xB0;
const DUPLICATED_INFO_BYTES: usize = 56;

#[derive(Debug, Clone)]
pub(super) struct RawIndexEntrySpan {
    pub(super) offset_in_node: usize,
    pub(super) length: usize,
    pub(super) child_vcn: Option<u64>,
    pub(super) key: Option<(NtfsReference, NtfsFileName, Vec<u8>)>,
}

#[derive(Debug)]
pub(super) struct LocatedDirectoryEntry {
    /// `None` if in `INDEX_ROOT`, `Some((leaf_vcn, block_idx))` if in external `INDX`.
    pub(super) external_vcn: Option<(u64, u64)>,
    pub(super) span: RawIndexEntrySpan,
    pub(super) root_attr_offset: u16,
    pub(super) root_value_offset: u16,
}

#[derive(Debug)]
pub(super) struct DirPrePayloadWrite {
    pub(super) phys_offset: u64,
    pub(super) bytes: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct PlannedDirMutation {
    pub(super) pre_payload_writes: Vec<DirPrePayloadWrite>,
    pub(super) allocated_clusters: Option<(u64, u64)>,
    pub(super) log_specs: Vec<NtfsClientUpdateSpec>,
    pub(super) updated_dir_raw: Vec<u8>,
    pub(super) updated_indx_blocks: Vec<(u64, Vec<u8>)>,
}

type SplitCandidateEntry = (Vec<u16>, NtfsReference, Vec<u8>, Vec<u8>);

pub(super) fn utf8_component_to_utf16(component: &str) -> Result<Vec<u16>> {
    if component.is_empty() || component == "." || component == ".." {
        return Err(FfsError::Format(
            "invalid empty, '.' or '..' NTFS path component".into(),
        ));
    }
    let units: Vec<u16> = component.encode_utf16().collect();
    if units.is_empty() || units.len() > 255 {
        return Err(FfsError::NameTooLong);
    }
    if units.iter().any(|&u| matches!(u, 0 | 0x2F | 0x5C)) {
        return Err(FfsError::Format(
            "NUL or path separator in NTFS component".into(),
        ));
    }
    Ok(units)
}

pub(super) fn split_parent_and_leaf(path: &str) -> Result<(String, Vec<u16>)> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Err(FfsError::Format(
            "root directory '/' has no parent/leaf split".into(),
        ));
    }
    match trimmed.rfind('/') {
        Some(idx) => {
            let parent = format!("/{}", &trimmed[..idx]);
            let leaf = utf8_component_to_utf16(&trimmed[idx + 1..])?;
            Ok((parent, leaf))
        }
        None => Ok(("/".to_owned(), utf8_component_to_utf16(trimmed)?)),
    }
}

pub(super) fn parse_path_components(path: &str) -> Result<Vec<Vec<u16>>> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    trimmed.split('/').map(utf8_component_to_utf16).collect()
}

pub(super) fn protect_indx_block(mut restored: Vec<u8>, usa_token: u16) -> Result<Vec<u8>> {
    let usa = usize::from(u16::from_le_bytes([restored[4], restored[5]]));
    let count = usize::from(u16::from_le_bytes([restored[6], restored[7]]));
    if usa < 40 || count != restored.len() / SECTOR_BYTES + 1 || usa + count * 2 > 510 {
        return Err(corrupt(0, "invalid INDX USA geometry"));
    }
    let tok = if usa_token == 0 || usa_token == u16::MAX {
        1
    } else {
        usa_token
    };
    restored[usa..usa + 2].copy_from_slice(&tok.to_le_bytes());
    for sector in 1..count {
        let end = sector * SECTOR_BYTES;
        let saved = [restored[end - 2], restored[end - 1]];
        restored[usa + sector * 2..usa + sector * 2 + 2].copy_from_slice(&saved);
        restored[end - 2..end].copy_from_slice(&tok.to_le_bytes());
    }
    Ok(restored)
}

pub(super) fn build_fresh_leaf_indx_block(
    block_bytes: u32,
    vcn: u64,
    leaf_entries: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let len = block_bytes as usize;
    if !(512..=65_536).contains(&len) || !len.is_power_of_two() {
        return Err(corrupt(0, "invalid INDX block_bytes"));
    }
    let usa_offset: u16 = 40;
    let usa_count = u16::try_from(len / SECTOR_BYTES + 1).map_err(|_| corrupt(0, "usa_count"))?;
    let raw_entries_off = (usize::from(usa_offset) + usize::from(usa_count) * 2 + 7) & !7;
    let rel_entries_off = raw_entries_off - 24;
    let allocated = len - 24;
    let payload_len: usize = leaf_entries.iter().map(Vec::len).sum();
    let used = rel_entries_off + payload_len + 16;
    if used > allocated {
        return Err(FfsError::NoSpace);
    }

    let mut buf = vec![0_u8; len];
    buf[0..4].copy_from_slice(b"INDX");
    buf[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    buf[6..8].copy_from_slice(&usa_count.to_le_bytes());
    buf[8..16].copy_from_slice(&0_u64.to_le_bytes());
    buf[16..24].copy_from_slice(&vcn.to_le_bytes());
    buf[24..28].copy_from_slice(&(rel_entries_off as u32).to_le_bytes());
    buf[28..32].copy_from_slice(&(used as u32).to_le_bytes());
    buf[32..36].copy_from_slice(&(allocated as u32).to_le_bytes());
    buf[36..40].copy_from_slice(&0_u32.to_le_bytes()); // leaf flags = 0

    let mut pos = raw_entries_off;
    for ent in leaf_entries {
        buf[pos..pos + ent.len()].copy_from_slice(ent);
        pos += ent.len();
    }
    // Terminal leaf entry (16 bytes, length=16, flags=2).
    buf[pos + 8..pos + 10].copy_from_slice(&16_u16.to_le_bytes());
    buf[pos + 12..pos + 14].copy_from_slice(&2_u16.to_le_bytes());

    let protected = protect_indx_block(buf, 1)?;
    let _ = parse_index_block(&protected, vcn).map_err(|err| parse_err(&err))?;
    Ok(protected)
}

pub(super) fn build_empty_small_index_root(
    index_bytes: u32,
    cluster_bytes: u32,
) -> Result<Vec<u8>> {
    let vcn_bytes = if index_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let units = u8::try_from(index_bytes / vcn_bytes).map_err(|_| corrupt(0, "index units"))?;
    let mut root = vec![0_u8; 48];
    root[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root[4..8].copy_from_slice(&1_u32.to_le_bytes()); // COLLATION_FILE_NAME
    root[8..12].copy_from_slice(&index_bytes.to_le_bytes());
    root[12] = units;
    // INDEX_HDR at offset 16: entries_off=16, used=32, allocated=32, flags=0.
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&32_u32.to_le_bytes());
    root[24..28].copy_from_slice(&32_u32.to_le_bytes());
    root[28..32].copy_from_slice(&0_u32.to_le_bytes());
    // Terminal entry at offset 32: length=16, flags=2.
    root[32 + 8..32 + 10].copy_from_slice(&16_u16.to_le_bytes());
    root[32 + 12..32 + 14].copy_from_slice(&2_u16.to_le_bytes());
    let _ = NtfsIndexRoot::parse(&root, cluster_bytes).map_err(|err| parse_err(&err))?;
    Ok(root)
}

fn build_large_index_root_pointing_to_zero(
    index_bytes: u32,
    cluster_bytes: u32,
) -> Result<Vec<u8>> {
    let vcn_bytes = if index_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let units = u8::try_from(index_bytes / vcn_bytes).map_err(|_| corrupt(0, "index units"))?;
    // 16-byte root header + 16-byte INDEX_HDR + 24-byte internal terminal entry (child_vcn = 0).
    let mut root = vec![0_u8; 56];
    root[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root[4..8].copy_from_slice(&1_u32.to_le_bytes());
    root[8..12].copy_from_slice(&index_bytes.to_le_bytes());
    root[12] = units;
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&40_u32.to_le_bytes());
    root[24..28].copy_from_slice(&40_u32.to_le_bytes());
    root[28..32].copy_from_slice(&1_u32.to_le_bytes()); // LARGE_INDEX (flags = 1)
    // Internal terminal entry at offset 32: length = 24, flags = 3 (HAS_CHILD | END), child_vcn = 0.
    root[32 + 8..32 + 10].copy_from_slice(&24_u16.to_le_bytes());
    root[32 + 12..32 + 14].copy_from_slice(&3_u16.to_le_bytes());
    root[32 + 16..32 + 24].copy_from_slice(&0_u64.to_le_bytes());
    let _ = NtfsIndexRoot::parse(&root, cluster_bytes).map_err(|err| parse_err(&err))?;
    Ok(root)
}

pub(super) fn parse_node_spans(
    node_bytes: &[u8],
    header_at: usize,
) -> Result<Vec<RawIndexEntrySpan>> {
    let rel_off = u32::from_le_bytes(
        node_bytes
            .get(header_at..header_at + 4)
            .ok_or_else(|| corrupt(0, "short index header"))?
            .try_into()
            .map_err(|_| corrupt(0, "slice"))?,
    ) as usize;
    let used = u32::from_le_bytes(
        node_bytes
            .get(header_at + 4..header_at + 8)
            .ok_or_else(|| corrupt(0, "short index header"))?
            .try_into()
            .map_err(|_| corrupt(0, "slice"))?,
    ) as usize;
    let end = header_at + used;
    let mut pos = header_at + rel_off;
    let mut spans = Vec::new();
    while pos + 16 <= end && end <= node_bytes.len() {
        let length = u16::from_le_bytes([node_bytes[pos + 8], node_bytes[pos + 9]]) as usize;
        let key_len = u16::from_le_bytes([node_bytes[pos + 10], node_bytes[pos + 11]]) as usize;
        let flags = u16::from_le_bytes([node_bytes[pos + 12], node_bytes[pos + 13]]);
        if length < 16 || pos + length > end {
            return Err(corrupt(0, "invalid index entry span"));
        }
        let child_vcn = if flags & 1 != 0 {
            let c_off = pos + length - 8;
            let raw = u64::from_le_bytes(
                node_bytes[c_off..c_off + 8]
                    .try_into()
                    .map_err(|_| corrupt(0, "child_vcn"))?,
            );
            Some(raw)
        } else {
            None
        };
        let key = if flags & 2 != 0 {
            None
        } else {
            let fref = NtfsReference::decode(u64::from_le_bytes(
                node_bytes[pos..pos + 8]
                    .try_into()
                    .map_err(|_| corrupt(0, "fref"))?,
            ));
            let key_raw = node_bytes[pos + 16..pos + 16 + key_len].to_vec();
            let parsed = NtfsFileName::parse(&key_raw).map_err(|err| parse_err(&err))?;
            Some((fref, parsed, key_raw))
        };
        spans.push(RawIndexEntrySpan {
            offset_in_node: pos,
            length,
            child_vcn,
            key,
        });
        if flags & 2 != 0 {
            return Ok(spans);
        }
        pos += length;
    }
    Err(corrupt(0, "missing terminal index entry"))
}

pub(super) fn find_attr_offset_in_restored(
    restored_file: &[u8],
    kind: u32,
    name: &[u16],
) -> Result<Option<(usize, usize)>> {
    let mut at = usize::from(u16::from_le_bytes([restored_file[20], restored_file[21]]));
    let used = u32::from_le_bytes([
        restored_file[24],
        restored_file[25],
        restored_file[26],
        restored_file[27],
    ]) as usize;
    while at + 4 <= used && used <= restored_file.len() {
        let k = u32::from_le_bytes([
            restored_file[at],
            restored_file[at + 1],
            restored_file[at + 2],
            restored_file[at + 3],
        ]);
        if k == u32::MAX {
            return Ok(None);
        }
        let sz = u32::from_le_bytes([
            restored_file[at + 4],
            restored_file[at + 5],
            restored_file[at + 6],
            restored_file[at + 7],
        ]) as usize;
        if sz < 24 || at + sz > used {
            return Err(corrupt(0, "corrupt attribute header in restored FILE"));
        }
        let name_len = usize::from(restored_file[at + 9]);
        let name_off = usize::from(u16::from_le_bytes([
            restored_file[at + 10],
            restored_file[at + 11],
        ]));
        let mut attr_name = Vec::with_capacity(name_len);
        for idx in 0..name_len {
            let off = at + name_off + idx * 2;
            attr_name.push(u16::from_le_bytes([
                restored_file[off],
                restored_file[off + 1],
            ]));
        }
        if k == kind && attr_name.as_slice() == name {
            return Ok(Some((at, sz)));
        }
        at += sz;
    }
    Ok(None)
}

pub(super) fn encode_resident_attribute(
    kind: u32,
    id: u16,
    name: &[u16],
    indexed: bool,
    value: &[u8],
) -> Result<Vec<u8>> {
    let name_bytes = name.len() * 2;
    let value_off = (24 + name_bytes + 7) & !7;
    let total_len = (value_off + value.len() + 7) & !7;
    let mut out = vec![0_u8; total_len];
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
    out[8] = 0; // resident
    out[9] = u8::try_from(name.len()).map_err(|_| corrupt(0, "attr name too long"))?;
    out[10..12].copy_from_slice(&24_u16.to_le_bytes());
    out[12..14].copy_from_slice(&0_u16.to_le_bytes());
    out[14..16].copy_from_slice(&id.to_le_bytes());
    out[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    out[20..22].copy_from_slice(&(value_off as u16).to_le_bytes());
    out[22..24].copy_from_slice(&u16::from(indexed).to_le_bytes());
    for (i, &unit) in name.iter().enumerate() {
        out[24 + i * 2..26 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    out[value_off..value_off + value.len()].copy_from_slice(value);
    Ok(out)
}

pub(super) fn encode_nonresident_attribute(
    kind: u32,
    id: u16,
    name: &[u16],
    runs: &[NtfsRun],
    allocated_bytes: u64,
    data_bytes: u64,
    initialized_bytes: u64,
) -> Result<Vec<u8>> {
    let (pairs, last_vcn) =
        encode_mapping_pairs(runs, 0, i64::MAX as u64).map_err(|err| parse_err(&err))?;
    let name_bytes = name.len() * 2;
    let mapping_off = (64 + name_bytes + 7) & !7;
    let total_len = (mapping_off + pairs.len() + 7) & !7;
    let mut out = vec![0_u8; total_len];
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
    out[8] = 1; // nonresident
    out[9] = u8::try_from(name.len()).map_err(|_| corrupt(0, "attr name too long"))?;
    out[10..12].copy_from_slice(&64_u16.to_le_bytes());
    out[12..14].copy_from_slice(&0_u16.to_le_bytes());
    out[14..16].copy_from_slice(&id.to_le_bytes());
    out[16..24].copy_from_slice(&0_u64.to_le_bytes()); // first_vcn
    out[24..32].copy_from_slice(&last_vcn.to_le_bytes());
    out[32..34].copy_from_slice(&(mapping_off as u16).to_le_bytes());
    out[40..48].copy_from_slice(&allocated_bytes.to_le_bytes());
    out[48..56].copy_from_slice(&data_bytes.to_le_bytes());
    out[56..64].copy_from_slice(&initialized_bytes.to_le_bytes());
    for (i, &unit) in name.iter().enumerate() {
        out[64 + i * 2..66 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    out[mapping_off..mapping_off + pairs.len()].copy_from_slice(&pairs);
    Ok(out)
}

impl NtfsTransactionEngine {
    pub(super) fn fold_upcase(&self, name: &[u16]) -> Vec<u16> {
        name.iter().map(|&u| self.upcase[usize::from(u)]).collect()
    }

    pub(super) fn cmp_ntfs_names(&self, left: &[u16], right: &[u16]) -> Ordering {
        self.fold_upcase(left).cmp(&self.fold_upcase(right))
    }

    /// Look up `target_upper` (already folded through `$UpCase`) inside `dir_rec`'s `$I30` index.
    pub(super) fn lookup_in_directory_raw(
        &self,
        cx: &Cx,
        mft_runs: &[NtfsRun],
        dir_rec: &NtfsFileRecord,
        target_upper: &[u16],
    ) -> Result<Option<NtfsReference>> {
        self.lookup_in_directory_raw_with_overrides(cx, mft_runs, dir_rec, target_upper, &[])
    }

    pub(super) fn lookup_in_directory_raw_with_overrides(
        &self,
        cx: &Cx,
        _mft_runs: &[NtfsRun],
        dir_rec: &NtfsFileRecord,
        target_upper: &[u16],
        indx_overrides: &[(u64, Vec<u8>)],
    ) -> Result<Option<NtfsReference>> {
        checkpoint(cx)?;
        if !dir_rec.is_directory() {
            return Err(FfsError::NotDirectory);
        }
        let root_bytes = extract_resident_attr(dir_rec, ATTR_INDEX_ROOT, &I30_NAME)?;
        let root = NtfsIndexRoot::parse(&root_bytes, self.geometry.cluster_bytes())
            .map_err(|err| parse_err(&err))?;
        let has_external = root.entries.iter().any(|e| e.child_vcn.is_some());
        let alloc_runs = if has_external {
            Some(extract_plain_nonresident_stream(
                &self.geometry,
                dir_rec,
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
            )?)
        } else {
            None
        };

        let mut entries: Vec<NtfsIndexEntry> = root.entries;
        for _depth in 0..=32 {
            checkpoint(cx)?;
            let mut next_child: Option<u64> = None;
            for entry in entries {
                if let Some((fref, fname)) = entry.key {
                    match self.fold_upcase(&fname.name).as_slice().cmp(target_upper) {
                        Ordering::Equal => return Ok(Some(fref)),
                        Ordering::Greater => {
                            next_child = entry.child_vcn;
                            break;
                        }
                        Ordering::Less => {}
                    }
                } else {
                    next_child = entry.child_vcn;
                    break;
                }
            }
            let Some(vcn) = next_child else {
                return Ok(None);
            };
            let (runs, alloc_size, _) = alloc_runs
                .as_ref()
                .ok_or_else(|| corrupt(0, "missing INDEX_ALLOCATION for child_vcn"))?;
            let byte_off = vcn * u64::from(root.vcn_bytes);
            if byte_off + u64::from(root.block_bytes) > *alloc_size {
                return Err(corrupt(byte_off, "child_vcn exceeds INDEX_ALLOCATION"));
            }
            let block_raw = if let Some((_, overridden)) =
                indx_overrides.iter().find(|(off, _)| *off == byte_off)
            {
                overridden.clone()
            } else {
                read_mapped_runs(
                    &self.device,
                    cx,
                    &self.geometry,
                    runs,
                    byte_off,
                    root.block_bytes as usize,
                )?
            };
            entries = parse_index_block(&block_raw, vcn).map_err(|err| parse_err(&err))?;
        }
        Err(corrupt(0, "NTFS directory B-tree depth exceeded 32"))
    }

    pub(super) fn resolve_path_raw(
        &self,
        cx: &Cx,
        mft_runs: &[NtfsRun],
        path: &str,
    ) -> Result<(u32, NtfsFileRecord)> {
        let components = parse_path_components(path)?;
        let mut cur_no = 5_u32;
        let mut cur_rec = read_mft_record_via_runs(&self.device, cx, &self.geometry, mft_runs, 5)?;
        for (idx, comp) in components.iter().enumerate() {
            if !cur_rec.is_directory() {
                return Err(FfsError::NotDirectory);
            }
            let upper = self.fold_upcase(comp);
            let Some(next_ref) = self.lookup_in_directory_raw(cx, mft_runs, &cur_rec, &upper)?
            else {
                return Err(FfsError::NotFound(format!("NTFS path '{path}' not found")));
            };
            let next_no = u32::try_from(next_ref.record)
                .map_err(|_| corrupt(0, "MFT record number overflow"))?;
            let child_record =
                read_mft_record_via_runs(&self.device, cx, &self.geometry, mft_runs, next_no)?;
            if child_record.sequence != next_ref.sequence {
                return Err(corrupt(0, "NTFS directory entry sequence mismatch"));
            }
            if idx + 1 < components.len() && !child_record.is_directory() {
                return Err(FfsError::NotDirectory);
            }
            cur_no = next_no;
            cur_rec = child_record;
        }
        Ok((cur_no, cur_rec))
    }

    pub(super) fn directory_is_empty(&self, cx: &Cx, dir_rec: &NtfsFileRecord) -> Result<bool> {
        let root_bytes = extract_resident_attr(dir_rec, ATTR_INDEX_ROOT, &I30_NAME)?;
        let root = NtfsIndexRoot::parse(&root_bytes, self.geometry.cluster_bytes())
            .map_err(|err| parse_err(&err))?;
        if root.entries.iter().any(|e| e.key.is_some()) {
            return Ok(false);
        }
        let has_ext = root.entries.iter().any(|e| e.child_vcn.is_some());
        if !has_ext {
            return Ok(true);
        }
        let (runs, alloc_size, _) = extract_plain_nonresident_stream(
            &self.geometry,
            dir_rec,
            ATTR_INDEX_ALLOCATION,
            &I30_NAME,
        )?;
        let mut stack: Vec<u64> = root.entries.iter().filter_map(|e| e.child_vcn).collect();
        let mut visited = 0_usize;
        while let Some(vcn) = stack.pop() {
            checkpoint(cx)?;
            visited += 1;
            if visited > 16_384 {
                return Err(corrupt(0, "directory traversal exceeded 16384 blocks"));
            }
            let off = vcn * u64::from(root.vcn_bytes);
            if off + u64::from(root.block_bytes) > alloc_size {
                return Err(corrupt(off, "INDX child out of bounds"));
            }
            let raw = read_mapped_runs(
                &self.device,
                cx,
                &self.geometry,
                &runs,
                off,
                root.block_bytes as usize,
            )?;
            let children = parse_index_block(&raw, vcn).map_err(|err| parse_err(&err))?;
            for ent in children {
                if ent.key.is_some() {
                    return Ok(false);
                }
                if let Some(c) = ent.child_vcn {
                    stack.push(c);
                }
            }
        }
        Ok(true)
    }

    pub(super) fn locate_directory_entry(
        &self,
        cx: &Cx,
        dir_raw: &[u8],
        dir_rec: &NtfsFileRecord,
        exact_name: &[u16],
    ) -> Result<LocatedDirectoryEntry> {
        let restored = restore_record(dir_raw, b"FILE").map_err(|err| parse_err(&err))?;
        let (root_at, root_sz) =
            find_attr_offset_in_restored(&restored, ATTR_INDEX_ROOT, &I30_NAME)?
                .ok_or_else(|| corrupt(0, "directory missing $I30 INDEX_ROOT"))?;
        let val_off = usize::from(u16::from_le_bytes([
            restored[root_at + 20],
            restored[root_at + 21],
        ]));
        let val_len = u32::from_le_bytes([
            restored[root_at + 16],
            restored[root_at + 17],
            restored[root_at + 18],
            restored[root_at + 19],
        ]) as usize;
        if root_at + val_off + val_len > root_at + root_sz {
            return Err(corrupt(0, "corrupt INDEX_ROOT bounds"));
        }
        let root_val = &restored[root_at + val_off..root_at + val_off + val_len];
        let root_parsed = NtfsIndexRoot::parse(root_val, self.geometry.cluster_bytes())
            .map_err(|err| parse_err(&err))?;
        let target_upper = self.fold_upcase(exact_name);

        let root_spans = parse_node_spans(root_val, 16)?;
        let mut descend_vcn: Option<u64> = None;
        for span in root_spans {
            if let Some((_, ref fname, _)) = span.key {
                match self.fold_upcase(&fname.name).cmp(&target_upper) {
                    Ordering::Equal if fname.name == exact_name => {
                        return Ok(LocatedDirectoryEntry {
                            external_vcn: None,
                            span,
                            root_attr_offset: u16::try_from(root_at)
                                .map_err(|_| corrupt(0, "root_at"))?,
                            root_value_offset: u16::try_from(val_off)
                                .map_err(|_| corrupt(0, "val_off"))?,
                        });
                    }
                    Ordering::Greater => {
                        descend_vcn = span.child_vcn;
                        break;
                    }
                    _ => {}
                }
            } else {
                descend_vcn = span.child_vcn;
                break;
            }
        }

        let (runs, alloc_size, _) = extract_plain_nonresident_stream(
            &self.geometry,
            dir_rec,
            ATTR_INDEX_ALLOCATION,
            &I30_NAME,
        )?;
        let mut cur_vcn =
            descend_vcn.ok_or_else(|| FfsError::NotFound("entry not in $I30".into()))?;
        for _ in 0..32 {
            checkpoint(cx)?;
            let byte_off = cur_vcn * u64::from(root_parsed.vcn_bytes);
            if byte_off + u64::from(root_parsed.block_bytes) > alloc_size {
                return Err(corrupt(byte_off, "INDX child exceeds stream"));
            }
            let block_idx = byte_off / u64::from(root_parsed.block_bytes);
            let block_raw = read_mapped_runs(
                &self.device,
                cx,
                &self.geometry,
                &runs,
                byte_off,
                root_parsed.block_bytes as usize,
            )?;
            let block_restored =
                restore_record(&block_raw, b"INDX").map_err(|err| parse_err(&err))?;
            let spans = parse_node_spans(&block_restored, 24)?;
            let mut next_vcn = None;
            for span in spans {
                if let Some((_, ref fname, _)) = span.key {
                    match self.fold_upcase(&fname.name).cmp(&target_upper) {
                        Ordering::Equal if fname.name == exact_name => {
                            return Ok(LocatedDirectoryEntry {
                                external_vcn: Some((cur_vcn, block_idx)),
                                span,
                                root_attr_offset: u16::try_from(root_at)
                                    .map_err(|_| corrupt(0, "root_at"))?,
                                root_value_offset: u16::try_from(val_off)
                                    .map_err(|_| corrupt(0, "val_off"))?,
                            });
                        }
                        Ordering::Greater => {
                            next_vcn = span.child_vcn;
                            break;
                        }
                        _ => {}
                    }
                } else {
                    next_vcn = span.child_vcn;
                    break;
                }
            }
            cur_vcn = next_vcn.ok_or_else(|| FfsError::NotFound("entry not in $I30".into()))?;
        }
        Err(corrupt(0, "INDX depth exceeded 32"))
    }

    /// Plan an `$I30` directory insertion (supporting resident `INDEX_ROOT`,
    /// automatic promotion from `SMALL_INDEX` to `LARGE_INDEX` when `INDEX_ROOT` fills,
    /// external `INDX` leaf insertion, and external `INDX` leaf splits).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn plan_directory_insert(
        &self,
        cx: &Cx,
        dir_no: u32,
        dir_raw: &[u8],
        dir_rec: &NtfsFileRecord,
        mft_slot_attr_id: u16,
        dir_mft_vcn: u64,
        dir_mft_cbo: u16,
        dir_mft_lcns: &[u64],
        indx_attr_slot_if_open: Option<u16>,
        child_ref: NtfsReference,
        child_file_name_bytes: &[u8],
        free_cluster_finder: &mut dyn FnMut(u64) -> Result<u64>,
    ) -> Result<PlannedDirMutation> {
        self.plan_directory_insert_with_overrides(
            cx,
            dir_no,
            dir_raw,
            dir_rec,
            mft_slot_attr_id,
            dir_mft_vcn,
            dir_mft_cbo,
            dir_mft_lcns,
            indx_attr_slot_if_open,
            child_ref,
            child_file_name_bytes,
            &[],
            free_cluster_finder,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) fn plan_directory_insert_with_overrides(
        &self,
        cx: &Cx,
        dir_no: u32,
        dir_raw: &[u8],
        dir_rec: &NtfsFileRecord,
        mft_slot_attr_id: u16,
        dir_mft_vcn: u64,
        dir_mft_cbo: u16,
        dir_mft_lcns: &[u64],
        indx_attr_slot_if_open: Option<u16>,
        child_ref: NtfsReference,
        child_file_name_bytes: &[u8],
        indx_overrides: &[(u64, Vec<u8>)],
        free_cluster_finder: &mut dyn FnMut(u64) -> Result<u64>,
    ) -> Result<PlannedDirMutation> {
        let child_fn = NtfsFileName::parse(child_file_name_bytes).map_err(|err| parse_err(&err))?;
        let child_upper = self.fold_upcase(&child_fn.name);
        if self
            .lookup_in_directory_raw_with_overrides(cx, &[], dir_rec, &child_upper, indx_overrides)?
            .is_some()
        {
            return Err(FfsError::Exists);
        }

        let restored = restore_record(dir_raw, b"FILE").map_err(|err| parse_err(&err))?;
        let (root_at, root_sz) =
            find_attr_offset_in_restored(&restored, ATTR_INDEX_ROOT, &I30_NAME)?
                .ok_or_else(|| corrupt(0, "directory missing $I30 INDEX_ROOT"))?;
        let val_off = usize::from(u16::from_le_bytes([
            restored[root_at + 20],
            restored[root_at + 21],
        ]));
        let val_len = u32::from_le_bytes([
            restored[root_at + 16],
            restored[root_at + 17],
            restored[root_at + 18],
            restored[root_at + 19],
        ]) as usize;
        let root_val = &restored[root_at + val_off..root_at + val_off + val_len];
        let root_parsed = NtfsIndexRoot::parse(root_val, self.geometry.cluster_bytes())
            .map_err(|err| parse_err(&err))?;
        let root_flags =
            u32::from_le_bytes([root_val[28], root_val[29], root_val[30], root_val[31]]);
        let leaf_entry_bytes = encode_index_entry(child_ref, child_file_name_bytes, None)
            .map_err(|err| parse_err(&err))?;

        if root_flags == 0 {
            // Resident SMALL_INDEX: try in-place AddIndexEntryRoot first.
            let spans = parse_node_spans(root_val, 16)?;
            let mut insert_off_in_val = spans
                .last()
                .ok_or_else(|| corrupt(0, "empty spans"))?
                .offset_in_node;
            for sp in &spans {
                if let Some((_, ref fn_existing, _)) = sp.key
                    && self.cmp_ntfs_names(&fn_existing.name, &child_fn.name) == Ordering::Greater
                {
                    insert_off_in_val = sp.offset_in_node;
                    break;
                }
            }
            let attr_rel_off = u16::try_from(val_off + insert_off_in_val)
                .map_err(|_| corrupt(0, "attr_rel_off"))?;
            let try_edit = apply_file_edit(
                dir_raw,
                dir_no,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::IndexRoot(IndexOperation::AddEntry),
                    record_offset: u16::try_from(root_at).map_err(|_| corrupt(0, "root_at"))?,
                    attribute_offset: attr_rel_off,
                    data: &leaf_entry_bytes,
                },
            );
            if let Ok(FileEditResult::Applied(updated_dir)) = try_edit {
                let spec = NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::AddIndexEntryRoot,
                    undo_op: NtfsLogOp::DeleteIndexEntryRoot,
                    target_attribute: mft_slot_attr_id,
                    record_offset: u16::try_from(root_at).map_err(|_| corrupt(0, "root_at"))?,
                    attribute_offset: attr_rel_off,
                    cluster_block_offset: dir_mft_cbo,
                    target_vcn: dir_mft_vcn,
                    target_lcns: dir_mft_lcns.to_vec(),
                    redo_data: leaf_entry_bytes,
                    undo_data: Vec::new(),
                };
                return Ok(PlannedDirMutation {
                    pre_payload_writes: Vec::new(),
                    allocated_clusters: None,
                    log_specs: vec![spec],
                    updated_dir_raw: updated_dir,
                    updated_indx_blocks: Vec::new(),
                });
            }

            // Resident INDEX_ROOT is full -> promote to LARGE_INDEX with 1 external INDX block!
            let block_bytes = root_parsed.block_bytes;
            let cluster_bytes = self.geometry.cluster_bytes();
            let block_clusters = u64::from(block_bytes.max(cluster_bytes) / cluster_bytes);
            let alloc_lcn = free_cluster_finder(block_clusters)?;
            let alloc_phys = self
                .geometry
                .cluster_offset(alloc_lcn)
                .map_err(|err| parse_err(&err))?;

            let mut all_leaf_entries: Vec<(Vec<u16>, Vec<u8>)> = Vec::new();
            for sp in &spans {
                if let Some((fref, ref fn_existing, ref raw_fn)) = sp.key {
                    let ent =
                        encode_index_entry(fref, raw_fn, None).map_err(|err| parse_err(&err))?;
                    all_leaf_entries.push((self.fold_upcase(&fn_existing.name), ent));
                }
            }
            all_leaf_entries.push((child_upper, leaf_entry_bytes));
            all_leaf_entries.sort_by(|a, b| a.0.cmp(&b.0));
            let sorted_bytes: Vec<Vec<u8>> = all_leaf_entries.into_iter().map(|(_, b)| b).collect();
            let indx0 = build_fresh_leaf_indx_block(block_bytes, 0, &sorted_bytes)?;
            let mut pre_buf = vec![0_u8; (block_clusters * u64::from(cluster_bytes)) as usize];
            pre_buf[..indx0.len()].copy_from_slice(&indx0);

            // Rewrite attributes from root_at..used in sorted order: 0x90, 0xA0, 0xB0, plus any >0xB0 attributes.
            let used = u32::from_le_bytes([restored[24], restored[25], restored[26], restored[27]])
                as usize;
            let mut next_id = u16::from_le_bytes([restored[40], restored[41]]);
            let root_attr_id = u16::from_le_bytes([restored[root_at + 14], restored[root_at + 15]]);
            let mut preserved_after_root: Vec<(u32, Vec<u8>)> = Vec::new();
            let mut scan = root_at + root_sz;
            while scan + 4 <= used {
                let k = u32::from_le_bytes([
                    restored[scan],
                    restored[scan + 1],
                    restored[scan + 2],
                    restored[scan + 3],
                ]);
                if k == u32::MAX {
                    break;
                }
                let sz = u32::from_le_bytes([
                    restored[scan + 4],
                    restored[scan + 5],
                    restored[scan + 6],
                    restored[scan + 7],
                ]) as usize;
                preserved_after_root.push((k, restored[scan..scan + sz].to_vec()));
                scan += sz;
            }

            let new_root_val = build_large_index_root_pointing_to_zero(block_bytes, cluster_bytes)?;
            let new_root_attr = encode_resident_attribute(
                ATTR_INDEX_ROOT,
                root_attr_id,
                &I30_NAME,
                false,
                &new_root_val,
            )?;
            let a0_id = next_id;
            next_id = next_id
                .checked_add(1)
                .ok_or_else(|| corrupt(0, "attr id overflow"))?;
            let b0_id = next_id;
            let run0 = NtfsRun {
                vcn: 0,
                clusters: block_clusters,
                lcn: Some(alloc_lcn),
            };
            let alloc_bytes = block_clusters * u64::from(cluster_bytes);
            let alloc_stream_attr = encode_nonresident_attribute(
                ATTR_INDEX_ALLOCATION,
                a0_id,
                &I30_NAME,
                &[run0],
                alloc_bytes,
                u64::from(block_bytes),
                u64::from(block_bytes),
            )?;
            let bitmap_attr = encode_resident_attribute(
                ATTR_BITMAP,
                b0_id,
                &I30_NAME,
                false,
                &[0x01, 0, 0, 0, 0, 0, 0, 0],
            )?;

            let mut to_insert: Vec<(u32, Vec<u8>)> = vec![
                (ATTR_INDEX_ROOT, new_root_attr),
                (ATTR_INDEX_ALLOCATION, alloc_stream_attr),
                (ATTR_BITMAP, bitmap_attr),
            ];
            to_insert.extend(preserved_after_root);
            to_insert.sort_by_key(|(k, _)| *k);

            // Build sequential DeleteAttribute (from root_at) + CreateAttribute log specs!
            let mut cur_dir = dir_raw.to_vec();
            let mut specs = Vec::new();
            loop {
                let cur_rest = restore_record(&cur_dir, b"FILE").map_err(|err| parse_err(&err))?;
                let k = u32::from_le_bytes([
                    cur_rest[root_at],
                    cur_rest[root_at + 1],
                    cur_rest[root_at + 2],
                    cur_rest[root_at + 3],
                ]);
                if k == u32::MAX {
                    break;
                }
                let sz = u32::from_le_bytes([
                    cur_rest[root_at + 4],
                    cur_rest[root_at + 5],
                    cur_rest[root_at + 6],
                    cur_rest[root_at + 7],
                ]) as usize;
                let old_attr = cur_rest[root_at..root_at + sz].to_vec();
                let FileEditResult::Applied(next_dir) = apply_file_edit(
                    &cur_dir,
                    dir_no,
                    RecoveryPass::Undo,
                    &FileEdit {
                        operation: FileOperation::DeleteAttribute,
                        record_offset: u16::try_from(root_at).map_err(|_| corrupt(0, "off"))?,
                        attribute_offset: 0,
                        data: &[],
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "unexpected AlreadyApplied"));
                };
                specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::DeleteAttribute,
                    undo_op: NtfsLogOp::CreateAttribute,
                    target_attribute: mft_slot_attr_id,
                    record_offset: u16::try_from(root_at).map_err(|_| corrupt(0, "off"))?,
                    attribute_offset: 0,
                    cluster_block_offset: dir_mft_cbo,
                    target_vcn: dir_mft_vcn,
                    target_lcns: dir_mft_lcns.to_vec(),
                    redo_data: Vec::new(),
                    undo_data: old_attr,
                });
                cur_dir = next_dir;
            }

            let mut ins_off = root_at;
            for (_, attr_bytes) in to_insert {
                let FileEditResult::Applied(next_dir) = apply_file_edit(
                    &cur_dir,
                    dir_no,
                    RecoveryPass::Undo,
                    &FileEdit {
                        operation: FileOperation::CreateAttribute,
                        record_offset: u16::try_from(ins_off).map_err(|_| corrupt(0, "ins_off"))?,
                        attribute_offset: 0,
                        data: &attr_bytes,
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "unexpected AlreadyApplied"));
                };
                specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::CreateAttribute,
                    undo_op: NtfsLogOp::DeleteAttribute,
                    target_attribute: mft_slot_attr_id,
                    record_offset: u16::try_from(ins_off).map_err(|_| corrupt(0, "ins_off"))?,
                    attribute_offset: 0,
                    cluster_block_offset: dir_mft_cbo,
                    target_vcn: dir_mft_vcn,
                    target_lcns: dir_mft_lcns.to_vec(),
                    redo_data: attr_bytes.clone(),
                    undo_data: Vec::new(),
                });
                ins_off += attr_bytes.len();
                cur_dir = next_dir;
            }

            return Ok(PlannedDirMutation {
                pre_payload_writes: vec![DirPrePayloadWrite {
                    phys_offset: alloc_phys,
                    bytes: pre_buf,
                }],
                allocated_clusters: Some((alloc_lcn, block_clusters)),
                log_specs: specs,
                updated_dir_raw: cur_dir,
                updated_indx_blocks: Vec::new(),
            });
        }

        // External LARGE_INDEX: descend to leaf INDX block.
        let indx_slot = indx_attr_slot_if_open
            .ok_or_else(|| corrupt(0, "missing open-attribute slot for $I30 INDEX_ALLOCATION"))?;
        let (mut a0_runs, a0_size, _) = extract_plain_nonresident_stream(
            &self.geometry,
            dir_rec,
            ATTR_INDEX_ALLOCATION,
            &I30_NAME,
        )?;
        let root_spans = parse_node_spans(root_val, 16)?;
        let mut parent_span_idx = root_spans.len() - 1;
        for (idx, sp) in root_spans.iter().enumerate() {
            if let Some((_, ref fn_existing, _)) = sp.key
                && self.cmp_ntfs_names(&fn_existing.name, &child_fn.name) == Ordering::Greater
            {
                parent_span_idx = idx;
                break;
            }
        }
        let mut leaf_vcn = root_spans[parent_span_idx]
            .child_vcn
            .ok_or_else(|| corrupt(0, "LARGE_INDEX root entry lacks child_vcn"))?;
        let mut depth = 0_usize;
        let mut leaf_raw;
        loop {
            checkpoint(cx)?;
            depth += 1;
            if depth > 32 {
                return Err(corrupt(0, "INDX depth > 32"));
            }
            let byte_off = leaf_vcn * u64::from(root_parsed.vcn_bytes);
            leaf_raw = if let Some((_, overridden)) =
                indx_overrides.iter().find(|(off, _)| *off == byte_off)
            {
                overridden.clone()
            } else {
                read_mapped_runs(
                    &self.device,
                    cx,
                    &self.geometry,
                    &a0_runs,
                    byte_off,
                    root_parsed.block_bytes as usize,
                )?
            };
            let leaf_rest = restore_record(&leaf_raw, b"INDX").map_err(|err| parse_err(&err))?;
            let flags =
                u32::from_le_bytes([leaf_rest[36], leaf_rest[37], leaf_rest[38], leaf_rest[39]]);
            if flags == 0 {
                break;
            }
            let spans = parse_node_spans(&leaf_rest, 24)?;
            let mut next_c = spans.last().and_then(|s| s.child_vcn);
            for sp in &spans {
                if let Some((_, ref fn_ex, _)) = sp.key
                    && self.cmp_ntfs_names(&fn_ex.name, &child_fn.name) == Ordering::Greater
                {
                    next_c = sp.child_vcn;
                    break;
                }
            }
            leaf_vcn = next_c.ok_or_else(|| corrupt(0, "internal INDX missing child_vcn"))?;
        }

        let leaf_byte_off = leaf_vcn * u64::from(root_parsed.vcn_bytes);
        let (target_vcn, cbo, rec_off, target_lcns) = map_indx_transfer(
            &self.geometry,
            &a0_runs,
            leaf_byte_off,
            root_parsed.block_bytes,
        )?;
        let leaf_rest = restore_record(&leaf_raw, b"INDX").map_err(|err| parse_err(&err))?;
        let leaf_spans = parse_node_spans(&leaf_rest, 24)?;
        let mut ins_in_block = leaf_spans
            .last()
            .ok_or_else(|| corrupt(0, "empty leaf spans"))?
            .offset_in_node;
        for sp in &leaf_spans {
            if let Some((_, ref fn_ex, _)) = sp.key
                && self.cmp_ntfs_names(&fn_ex.name, &child_fn.name) == Ordering::Greater
            {
                ins_in_block = sp.offset_in_node;
                break;
            }
        }

        if let Ok(FileEditResult::Applied(updated_leaf)) = apply_index_edit(
            &leaf_raw,
            leaf_vcn,
            RecoveryPass::Undo,
            &IndexEdit {
                operation: IndexOperation::AddEntry,
                entry_offset: u16::try_from(ins_in_block).map_err(|_| corrupt(0, "ins"))?,
                data: &leaf_entry_bytes,
            },
        ) {
            let spec = NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::AddIndexEntryAllocation,
                undo_op: NtfsLogOp::DeleteIndexEntryAllocation,
                target_attribute: indx_slot,
                record_offset: rec_off,
                attribute_offset: u16::try_from(ins_in_block).map_err(|_| corrupt(0, "ins"))?,
                cluster_block_offset: cbo,
                target_vcn,
                target_lcns,
                redo_data: leaf_entry_bytes,
                undo_data: Vec::new(),
            };
            return Ok(PlannedDirMutation {
                pre_payload_writes: Vec::new(),
                allocated_clusters: None,
                log_specs: vec![spec],
                updated_dir_raw: dir_raw.to_vec(),
                updated_indx_blocks: vec![(leaf_byte_off, updated_leaf)],
            });
        }

        // Leaf INDX block is full and depth == 1 -> split leaf INDX block!
        if depth != 1 {
            return Err(unsupported(
                "multi-level NTFS INDX internal-node split exceeds single-root-level profile",
            ));
        }
        let block_bytes = root_parsed.block_bytes;
        let cluster_bytes = self.geometry.cluster_bytes();
        let new_block_idx = a0_size / u64::from(block_bytes);
        let new_byte_off = new_block_idx * u64::from(block_bytes);
        let new_vcn = new_byte_off / u64::from(root_parsed.vcn_bytes);

        // Allocate clusters for the new INDX block if new_byte_off + block_bytes exceeds current allocated clusters.
        let total_a0_clusters: u64 = a0_runs.iter().map(|r| r.clusters).sum();
        let cur_a0_alloc = total_a0_clusters * u64::from(cluster_bytes);
        let mut allocated_clusters = None;
        let mut pre_payload_writes = Vec::new();
        if new_byte_off + u64::from(block_bytes) > cur_a0_alloc {
            let add_clusters = u64::from(block_bytes.max(cluster_bytes) / cluster_bytes);
            let alloc_lcn = free_cluster_finder(add_clusters)?;
            allocated_clusters = Some((alloc_lcn, add_clusters));
            a0_runs.push(NtfsRun {
                vcn: total_a0_clusters,
                clusters: add_clusters,
                lcn: Some(alloc_lcn),
            });
        }

        let mut combined: Vec<SplitCandidateEntry> = Vec::new();
        for sp in &leaf_spans {
            if let Some((fref, ref fn_ex, ref raw_fn)) = sp.key {
                let ent = encode_index_entry(fref, raw_fn, None).map_err(|err| parse_err(&err))?;
                combined.push((self.fold_upcase(&fn_ex.name), fref, raw_fn.clone(), ent));
            }
        }
        combined.push((
            child_upper,
            child_ref,
            child_file_name_bytes.to_vec(),
            leaf_entry_bytes,
        ));
        combined.sort_by(|a, b| a.0.cmp(&b.0));

        let mid = combined.len() / 2;
        let left_entries: Vec<Vec<u8>> = combined[..mid]
            .iter()
            .map(|(_, _, _, e)| e.clone())
            .collect();
        let (_, median_ref, ref median_fn_raw, _) = combined[mid];

        // Left leaf goes into new_vcn (pre-flushed before commit!); Right leaf stays in leaf_vcn
        // by deleting the moved prefix entries individually (each <= ~630B, well within single-page
        // RCRD capacity) and inserting `child` into Right if `child` sorted after `median`!
        let left_block = build_fresh_leaf_indx_block(block_bytes, new_vcn, &left_entries)?;
        let (new_phys, avail, _) = map_logical_offset(&self.geometry, &a0_runs, new_byte_off)?;
        if avail < u64::from(block_bytes) {
            return Err(unsupported("fragmented sub-block INDX allocation"));
        }
        pre_payload_writes.push(DirPrePayloadWrite {
            phys_offset: new_phys,
            bytes: left_block,
        });

        let first_ent_off = leaf_spans[0].offset_in_node;
        let median_upper = &combined[mid].0;
        let child_in_right = self.fold_upcase(&child_fn.name) > *median_upper;
        let prefix_delete_count = if child_in_right { mid + 1 } else { mid };

        let mut specs = Vec::new();
        let mut cur_right_leaf = leaf_raw;
        for _ in 0..prefix_delete_count {
            let cur_rest =
                restore_record(&cur_right_leaf, b"INDX").map_err(|err| parse_err(&err))?;
            let cur_spans = parse_node_spans(&cur_rest, 24)?;
            let victim = cur_spans
                .first()
                .filter(|sp| sp.key.is_some())
                .ok_or_else(|| corrupt(0, "missing prefix entry during INDX split"))?;
            let undo_entry =
                cur_rest[victim.offset_in_node..victim.offset_in_node + victim.length].to_vec();
            let FileEditResult::Applied(next_leaf) = apply_index_edit(
                &cur_right_leaf,
                leaf_vcn,
                RecoveryPass::Undo,
                &IndexEdit {
                    operation: IndexOperation::DeleteEntry,
                    entry_offset: u16::try_from(first_ent_off).map_err(|_| corrupt(0, "off"))?,
                    data: &[],
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "unexpected AlreadyApplied on INDX split delete"));
            };
            specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::DeleteIndexEntryAllocation,
                undo_op: NtfsLogOp::AddIndexEntryAllocation,
                target_attribute: indx_slot,
                record_offset: rec_off,
                attribute_offset: u16::try_from(first_ent_off).map_err(|_| corrupt(0, "off"))?,
                cluster_block_offset: cbo,
                target_vcn,
                target_lcns: target_lcns.clone(),
                redo_data: Vec::new(),
                undo_data: undo_entry,
            });
            cur_right_leaf = next_leaf;
        }

        if child_in_right {
            let cur_rest =
                restore_record(&cur_right_leaf, b"INDX").map_err(|err| parse_err(&err))?;
            let cur_spans = parse_node_spans(&cur_rest, 24)?;
            let mut ins_right_off = cur_spans
                .last()
                .ok_or_else(|| corrupt(0, "empty right leaf spans"))?
                .offset_in_node;
            for sp in &cur_spans {
                if let Some((_, ref fn_ex, _)) = sp.key
                    && self.cmp_ntfs_names(&fn_ex.name, &child_fn.name) == Ordering::Greater
                {
                    ins_right_off = sp.offset_in_node;
                    break;
                }
            }
            let FileEditResult::Applied(next_leaf) = apply_index_edit(
                &cur_right_leaf,
                leaf_vcn,
                RecoveryPass::Undo,
                &IndexEdit {
                    operation: IndexOperation::AddEntry,
                    entry_offset: u16::try_from(ins_right_off).map_err(|_| corrupt(0, "ins"))?,
                    data: &combined
                        .iter()
                        .find(|(_, r, _, _)| *r == child_ref)
                        .ok_or_else(|| corrupt(0, "missing child in combined"))?
                        .3,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "unexpected AlreadyApplied on INDX split insert"));
            };
            let ins_bytes = combined
                .iter()
                .find(|(_, r, _, _)| *r == child_ref)
                .ok_or_else(|| corrupt(0, "missing child in combined"))?
                .3
                .clone();
            specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::AddIndexEntryAllocation,
                undo_op: NtfsLogOp::DeleteIndexEntryAllocation,
                target_attribute: indx_slot,
                record_offset: rec_off,
                attribute_offset: u16::try_from(ins_right_off).map_err(|_| corrupt(0, "ins"))?,
                cluster_block_offset: cbo,
                target_vcn,
                target_lcns,
                redo_data: ins_bytes,
                undo_data: Vec::new(),
            });
            cur_right_leaf = next_leaf;
        }
        let updated_right_leaf = cur_right_leaf;

        // Update directory FILE record: grow 0xA0 if needed, set bit new_block_idx in 0xB0, and insert separator in 0x90!
        let mut cur_dir = dir_raw.to_vec();
        if allocated_clusters.is_some() || new_byte_off + u64::from(block_bytes) > a0_size {
            let cur_rest = restore_record(&cur_dir, b"FILE").map_err(|err| parse_err(&err))?;
            let (a0_at, a0_sz) =
                find_attr_offset_in_restored(&cur_rest, ATTR_INDEX_ALLOCATION, &I30_NAME)?
                    .ok_or_else(|| corrupt(0, "missing 0xA0"))?;
            let map_off = usize::from(u16::from_le_bytes([
                cur_rest[a0_at + 32],
                cur_rest[a0_at + 33],
            ]));
            let old_pairs = cur_rest[a0_at + map_off..a0_at + a0_sz].to_vec();
            let (new_pairs, _) = encode_mapping_pairs(&a0_runs, 0, self.geometry.cluster_count())
                .map_err(|err| parse_err(&err))?;
            if new_pairs != old_pairs {
                let FileEditResult::Applied(next_dir) = apply_file_edit(
                    &cur_dir,
                    dir_no,
                    RecoveryPass::Undo,
                    &FileEdit {
                        operation: FileOperation::UpdateMappingPairs {
                            volume_clusters: self.geometry.cluster_count(),
                        },
                        record_offset: u16::try_from(a0_at).map_err(|_| corrupt(0, "a0_at"))?,
                        attribute_offset: u16::try_from(map_off).map_err(|_| corrupt(0, "map"))?,
                        data: &new_pairs,
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "AlreadyApplied"));
                };
                specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::UpdateMappingPairs,
                    undo_op: NtfsLogOp::UpdateMappingPairs,
                    target_attribute: mft_slot_attr_id,
                    record_offset: u16::try_from(a0_at).map_err(|_| corrupt(0, "a0_at"))?,
                    attribute_offset: u16::try_from(map_off).map_err(|_| corrupt(0, "map"))?,
                    cluster_block_offset: dir_mft_cbo,
                    target_vcn: dir_mft_vcn,
                    target_lcns: dir_mft_lcns.to_vec(),
                    redo_data: new_pairs,
                    undo_data: old_pairs,
                });
                cur_dir = next_dir;
            }

            let cur_rest2 = restore_record(&cur_dir, b"FILE").map_err(|err| parse_err(&err))?;
            let (a0_at2, _) =
                find_attr_offset_in_restored(&cur_rest2, ATTR_INDEX_ALLOCATION, &I30_NAME)?
                    .ok_or_else(|| corrupt(0, "missing 0xA0"))?;
            let old_alloc = u64::from_le_bytes(
                cur_rest2[a0_at2 + 40..a0_at2 + 48]
                    .try_into()
                    .map_err(|_| corrupt(0, "alloc"))?,
            );
            let old_data = u64::from_le_bytes(
                cur_rest2[a0_at2 + 48..a0_at2 + 56]
                    .try_into()
                    .map_err(|_| corrupt(0, "data"))?,
            );
            let old_init = u64::from_le_bytes(
                cur_rest2[a0_at2 + 56..a0_at2 + 64]
                    .try_into()
                    .map_err(|_| corrupt(0, "init"))?,
            );
            let new_total_clusters: u64 = a0_runs.iter().map(|r| r.clusters).sum();
            let new_alloc = new_total_clusters * u64::from(cluster_bytes);
            let new_data = new_byte_off + u64::from(block_bytes);
            let mut redo_sz = Vec::with_capacity(24);
            redo_sz.extend_from_slice(&new_alloc.to_le_bytes());
            redo_sz.extend_from_slice(&new_data.to_le_bytes());
            redo_sz.extend_from_slice(&new_data.to_le_bytes());
            let mut undo_sz = Vec::with_capacity(24);
            undo_sz.extend_from_slice(&old_alloc.to_le_bytes());
            undo_sz.extend_from_slice(&old_init.to_le_bytes());
            undo_sz.extend_from_slice(&old_data.to_le_bytes());
            let FileEditResult::Applied(next_dir2) = apply_file_edit(
                &cur_dir,
                dir_no,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::SetSizes,
                    record_offset: u16::try_from(a0_at2).map_err(|_| corrupt(0, "a0"))?,
                    attribute_offset: 0,
                    data: &redo_sz,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::SetNewAttributeSizes,
                undo_op: NtfsLogOp::SetNewAttributeSizes,
                target_attribute: mft_slot_attr_id,
                record_offset: u16::try_from(a0_at2).map_err(|_| corrupt(0, "a0"))?,
                attribute_offset: 0,
                cluster_block_offset: dir_mft_cbo,
                target_vcn: dir_mft_vcn,
                target_lcns: dir_mft_lcns.to_vec(),
                redo_data: redo_sz,
                undo_data: undo_sz,
            });
            cur_dir = next_dir2;
        }

        // Set bit new_block_idx in resident 0xB0 $I30 BITMAP (extending by 8 bytes if needed).
        {
            let cur_rest = restore_record(&cur_dir, b"FILE").map_err(|err| parse_err(&err))?;
            let (b0_at, _) = find_attr_offset_in_restored(&cur_rest, ATTR_BITMAP, &I30_NAME)?
                .ok_or_else(|| corrupt(0, "missing resident 0xB0 $I30 BITMAP"))?;
            if cur_rest[b0_at + 8] != 0 {
                return Err(unsupported("nonresident $I30 BITMAP split"));
            }
            let b0_val_off = usize::from(u16::from_le_bytes([
                cur_rest[b0_at + 20],
                cur_rest[b0_at + 21],
            ]));
            let b0_val_len = u32::from_le_bytes([
                cur_rest[b0_at + 16],
                cur_rest[b0_at + 17],
                cur_rest[b0_at + 18],
                cur_rest[b0_at + 19],
            ]) as usize;
            let old_bm = cur_rest[b0_at + b0_val_off..b0_at + b0_val_off + b0_val_len].to_vec();
            let req_len = ((new_block_idx as usize / 8) + 1 + 7) & !7;
            let mut new_bm = old_bm.clone();
            if new_bm.len() < req_len {
                new_bm.resize(req_len, 0);
            }
            new_bm[new_block_idx as usize / 8] |= 1_u8 << (new_block_idx % 8);
            let resize = new_bm.len() != old_bm.len();
            let FileEditResult::Applied(next_dir) = apply_file_edit(
                &cur_dir,
                dir_no,
                RecoveryPass::Undo,
                &FileEdit {
                    operation: FileOperation::UpdateResident { resize },
                    record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0_at"))?,
                    attribute_offset: u16::try_from(b0_val_off).map_err(|_| corrupt(0, "off"))?,
                    data: &new_bm,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            specs.push(NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::UpdateResidentValue,
                undo_op: NtfsLogOp::UpdateResidentValue,
                target_attribute: mft_slot_attr_id,
                record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0_at"))?,
                attribute_offset: u16::try_from(b0_val_off).map_err(|_| corrupt(0, "off"))?,
                cluster_block_offset: dir_mft_cbo,
                target_vcn: dir_mft_vcn,
                target_lcns: dir_mft_lcns.to_vec(),
                redo_data: new_bm,
                undo_data: old_bm,
            });
            cur_dir = next_dir;
        }

        // Finally insert separator (median_ref, median_fn_raw, child_vcn = new_vcn) into 0x90 INDEX_ROOT!
        let sep_entry = encode_index_entry(median_ref, median_fn_raw, Some(new_vcn))
            .map_err(|err| parse_err(&err))?;
        let cur_rest = restore_record(&cur_dir, b"FILE").map_err(|err| parse_err(&err))?;
        let (r90_at, _) = find_attr_offset_in_restored(&cur_rest, ATTR_INDEX_ROOT, &I30_NAME)?
            .ok_or_else(|| corrupt(0, "missing 0x90"))?;
        let r90_val_off = usize::from(u16::from_le_bytes([
            cur_rest[r90_at + 20],
            cur_rest[r90_at + 21],
        ]));
        let ins_root_off = r90_val_off + root_spans[parent_span_idx].offset_in_node;
        let FileEditResult::Applied(final_dir) = apply_file_edit(
            &cur_dir,
            dir_no,
            RecoveryPass::Undo,
            &FileEdit {
                operation: FileOperation::IndexRoot(IndexOperation::AddEntry),
                record_offset: u16::try_from(r90_at).map_err(|_| corrupt(0, "r90"))?,
                attribute_offset: u16::try_from(ins_root_off).map_err(|_| corrupt(0, "off"))?,
                data: &sep_entry,
            },
        )
        .map_err(|_| FfsError::NoSpace)?
        else {
            return Err(corrupt(0, "AlreadyApplied"));
        };
        specs.push(NtfsClientUpdateSpec {
            redo_op: NtfsLogOp::AddIndexEntryRoot,
            undo_op: NtfsLogOp::DeleteIndexEntryRoot,
            target_attribute: mft_slot_attr_id,
            record_offset: u16::try_from(r90_at).map_err(|_| corrupt(0, "r90"))?,
            attribute_offset: u16::try_from(ins_root_off).map_err(|_| corrupt(0, "off"))?,
            cluster_block_offset: dir_mft_cbo,
            target_vcn: dir_mft_vcn,
            target_lcns: dir_mft_lcns.to_vec(),
            redo_data: sep_entry,
            undo_data: Vec::new(),
        });

        Ok(PlannedDirMutation {
            pre_payload_writes,
            allocated_clusters,
            log_specs: specs,
            updated_dir_raw: final_dir,
            updated_indx_blocks: vec![(leaf_byte_off, updated_right_leaf)],
        })
    }

    /// Plan an `$I30` directory deletion for `exact_name`.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) fn plan_directory_delete(
        &self,
        cx: &Cx,
        dir_no: u32,
        dir_raw: &[u8],
        dir_rec: &NtfsFileRecord,
        mft_slot_attr_id: u16,
        dir_mft_vcn: u64,
        dir_mft_cbo: u16,
        dir_mft_lcns: &[u64],
        indx_attr_slot_if_open: Option<u16>,
        exact_name: &[u16],
    ) -> Result<PlannedDirMutation> {
        let located = self.locate_directory_entry(cx, dir_raw, dir_rec, exact_name)?;
        let restored = restore_record(dir_raw, b"FILE").map_err(|err| parse_err(&err))?;
        let root_at = usize::from(located.root_attr_offset);
        let val_off = usize::from(located.root_value_offset);

        if let Some((leaf_vcn, _)) = located.external_vcn {
            if located.span.child_vcn.is_some() {
                return Err(unsupported(
                    "deleting internal external INDX separator node exceeds single-level profile",
                ));
            }
            let indx_slot = indx_attr_slot_if_open
                .ok_or_else(|| corrupt(0, "missing open-attribute slot for $I30"))?;
            let root_bytes = extract_resident_attr(dir_rec, ATTR_INDEX_ROOT, &I30_NAME)?;
            let root_parsed = NtfsIndexRoot::parse(&root_bytes, self.geometry.cluster_bytes())
                .map_err(|err| parse_err(&err))?;
            let (a0_runs, _, _) = extract_plain_nonresident_stream(
                &self.geometry,
                dir_rec,
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
            )?;
            let byte_off = leaf_vcn * u64::from(root_parsed.vcn_bytes);
            let leaf_raw = read_mapped_runs(
                &self.device,
                cx,
                &self.geometry,
                &a0_runs,
                byte_off,
                root_parsed.block_bytes as usize,
            )?;
            let leaf_rest = restore_record(&leaf_raw, b"INDX").map_err(|err| parse_err(&err))?;
            let old_entry = leaf_rest
                [located.span.offset_in_node..located.span.offset_in_node + located.span.length]
                .to_vec();
            let (target_vcn, cbo, rec_off, target_lcns) =
                map_indx_transfer(&self.geometry, &a0_runs, byte_off, root_parsed.block_bytes)?;
            let FileEditResult::Applied(updated_leaf) = apply_index_edit(
                &leaf_raw,
                leaf_vcn,
                RecoveryPass::Undo,
                &IndexEdit {
                    operation: IndexOperation::DeleteEntry,
                    entry_offset: u16::try_from(located.span.offset_in_node)
                        .map_err(|_| corrupt(0, "off"))?,
                    data: &[],
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            return Ok(PlannedDirMutation {
                pre_payload_writes: Vec::new(),
                allocated_clusters: None,
                log_specs: vec![NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::DeleteIndexEntryAllocation,
                    undo_op: NtfsLogOp::AddIndexEntryAllocation,
                    target_attribute: indx_slot,
                    record_offset: rec_off,
                    attribute_offset: u16::try_from(located.span.offset_in_node)
                        .map_err(|_| corrupt(0, "off"))?,
                    cluster_block_offset: cbo,
                    target_vcn,
                    target_lcns,
                    redo_data: Vec::new(),
                    undo_data: old_entry,
                }],
                updated_dir_raw: dir_raw.to_vec(),
                updated_indx_blocks: vec![(byte_off, updated_leaf)],
            });
        }

        // Entry is in INDEX_ROOT.
        if let Some(left_vcn) = located.span.child_vcn {
            // Internal separator key in INDEX_ROOT (LARGE_INDEX): replace with predecessor from left leaf or drop empty left leaf!
            let indx_slot = indx_attr_slot_if_open
                .ok_or_else(|| corrupt(0, "missing open-attribute slot for $I30"))?;
            let root_bytes = extract_resident_attr(dir_rec, ATTR_INDEX_ROOT, &I30_NAME)?;
            let root_parsed = NtfsIndexRoot::parse(&root_bytes, self.geometry.cluster_bytes())
                .map_err(|err| parse_err(&err))?;
            let (a0_runs, _, _) = extract_plain_nonresident_stream(
                &self.geometry,
                dir_rec,
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
            )?;
            let left_byte_off = left_vcn * u64::from(root_parsed.vcn_bytes);
            let left_block_idx = left_byte_off / u64::from(root_parsed.block_bytes);
            let left_raw = read_mapped_runs(
                &self.device,
                cx,
                &self.geometry,
                &a0_runs,
                left_byte_off,
                root_parsed.block_bytes as usize,
            )?;
            let left_rest = restore_record(&left_raw, b"INDX").map_err(|err| parse_err(&err))?;
            let left_spans = parse_node_spans(&left_rest, 24)?;
            let mut specs = Vec::new();
            let mut updated_indx_blocks = Vec::new();
            let mut cur_dir = dir_raw.to_vec();

            if left_spans.len() >= 2 {
                // Predecessor is left_spans[left_spans.len() - 2].
                let pred = &left_spans[left_spans.len() - 2];
                let (pred_ref, _, pred_fn_raw) = pred
                    .key
                    .as_ref()
                    .ok_or_else(|| corrupt(0, "missing pred key"))?;
                let old_pred_leaf =
                    left_rest[pred.offset_in_node..pred.offset_in_node + pred.length].to_vec();
                let (tv, cbo, ro, tlcns) = map_indx_transfer(
                    &self.geometry,
                    &a0_runs,
                    left_byte_off,
                    root_parsed.block_bytes,
                )?;
                let FileEditResult::Applied(upd_left) = apply_index_edit(
                    &left_raw,
                    left_vcn,
                    RecoveryPass::Undo,
                    &IndexEdit {
                        operation: IndexOperation::DeleteEntry,
                        entry_offset: u16::try_from(pred.offset_in_node)
                            .map_err(|_| corrupt(0, "off"))?,
                        data: &[],
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "AlreadyApplied"));
                };
                specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::DeleteIndexEntryAllocation,
                    undo_op: NtfsLogOp::AddIndexEntryAllocation,
                    target_attribute: indx_slot,
                    record_offset: ro,
                    attribute_offset: u16::try_from(pred.offset_in_node)
                        .map_err(|_| corrupt(0, "off"))?,
                    cluster_block_offset: cbo,
                    target_vcn: tv,
                    target_lcns: tlcns,
                    redo_data: Vec::new(),
                    undo_data: old_pred_leaf,
                });
                updated_indx_blocks.push((left_byte_off, upd_left));

                let old_sep = restored[root_at + val_off + located.span.offset_in_node
                    ..root_at + val_off + located.span.offset_in_node + located.span.length]
                    .to_vec();
                let new_sep = encode_index_entry(*pred_ref, pred_fn_raw, Some(left_vcn))
                    .map_err(|err| parse_err(&err))?;
                let attr_off = u16::try_from(val_off + located.span.offset_in_node)
                    .map_err(|_| corrupt(0, "off"))?;
                let FileEditResult::Applied(dir1) = apply_file_edit(
                    &cur_dir,
                    dir_no,
                    RecoveryPass::Undo,
                    &FileEdit {
                        operation: FileOperation::IndexRoot(IndexOperation::DeleteEntry),
                        record_offset: located.root_attr_offset,
                        attribute_offset: attr_off,
                        data: &[],
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "AlreadyApplied"));
                };
                specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::DeleteIndexEntryRoot,
                    undo_op: NtfsLogOp::AddIndexEntryRoot,
                    target_attribute: mft_slot_attr_id,
                    record_offset: located.root_attr_offset,
                    attribute_offset: attr_off,
                    cluster_block_offset: dir_mft_cbo,
                    target_vcn: dir_mft_vcn,
                    target_lcns: dir_mft_lcns.to_vec(),
                    redo_data: Vec::new(),
                    undo_data: old_sep,
                });
                let FileEditResult::Applied(dir2) = apply_file_edit(
                    &dir1,
                    dir_no,
                    RecoveryPass::Undo,
                    &FileEdit {
                        operation: FileOperation::IndexRoot(IndexOperation::AddEntry),
                        record_offset: located.root_attr_offset,
                        attribute_offset: attr_off,
                        data: &new_sep,
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "AlreadyApplied"));
                };
                specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::AddIndexEntryRoot,
                    undo_op: NtfsLogOp::DeleteIndexEntryRoot,
                    target_attribute: mft_slot_attr_id,
                    record_offset: located.root_attr_offset,
                    attribute_offset: attr_off,
                    cluster_block_offset: dir_mft_cbo,
                    target_vcn: dir_mft_vcn,
                    target_lcns: dir_mft_lcns.to_vec(),
                    redo_data: new_sep,
                    undo_data: Vec::new(),
                });
                cur_dir = dir2;
            } else {
                // Left leaf is empty: clear bit left_block_idx in resident 0xB0 BITMAP and delete separator from INDEX_ROOT!
                let old_sep = restored[root_at + val_off + located.span.offset_in_node
                    ..root_at + val_off + located.span.offset_in_node + located.span.length]
                    .to_vec();
                let attr_off = u16::try_from(val_off + located.span.offset_in_node)
                    .map_err(|_| corrupt(0, "off"))?;
                let FileEditResult::Applied(dir1) = apply_file_edit(
                    &cur_dir,
                    dir_no,
                    RecoveryPass::Undo,
                    &FileEdit {
                        operation: FileOperation::IndexRoot(IndexOperation::DeleteEntry),
                        record_offset: located.root_attr_offset,
                        attribute_offset: attr_off,
                        data: &[],
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "AlreadyApplied"));
                };
                specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::DeleteIndexEntryRoot,
                    undo_op: NtfsLogOp::AddIndexEntryRoot,
                    target_attribute: mft_slot_attr_id,
                    record_offset: located.root_attr_offset,
                    attribute_offset: attr_off,
                    cluster_block_offset: dir_mft_cbo,
                    target_vcn: dir_mft_vcn,
                    target_lcns: dir_mft_lcns.to_vec(),
                    redo_data: Vec::new(),
                    undo_data: old_sep,
                });
                let rest1 = restore_record(&dir1, b"FILE").map_err(|err| parse_err(&err))?;
                let (b0_at, _) = find_attr_offset_in_restored(&rest1, ATTR_BITMAP, &I30_NAME)?
                    .ok_or_else(|| corrupt(0, "missing 0xB0"))?;
                let b0_voff =
                    usize::from(u16::from_le_bytes([rest1[b0_at + 20], rest1[b0_at + 21]]));
                let byte_pos = left_block_idx as usize / 8;
                let old_b = rest1[b0_at + b0_voff + byte_pos];
                let new_b = old_b & !(1_u8 << (left_block_idx % 8));
                let FileEditResult::Applied(dir2) = apply_file_edit(
                    &dir1,
                    dir_no,
                    RecoveryPass::Undo,
                    &FileEdit {
                        operation: FileOperation::UpdateResident { resize: false },
                        record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0"))?,
                        attribute_offset: u16::try_from(b0_voff + byte_pos)
                            .map_err(|_| corrupt(0, "off"))?,
                        data: &[new_b],
                    },
                )
                .map_err(|err| parse_err(&err))?
                else {
                    return Err(corrupt(0, "AlreadyApplied"));
                };
                specs.push(NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::UpdateResidentValue,
                    undo_op: NtfsLogOp::UpdateResidentValue,
                    target_attribute: mft_slot_attr_id,
                    record_offset: u16::try_from(b0_at).map_err(|_| corrupt(0, "b0"))?,
                    attribute_offset: u16::try_from(b0_voff + byte_pos)
                        .map_err(|_| corrupt(0, "off"))?,
                    cluster_block_offset: dir_mft_cbo,
                    target_vcn: dir_mft_vcn,
                    target_lcns: dir_mft_lcns.to_vec(),
                    redo_data: vec![new_b],
                    undo_data: vec![old_b],
                });
                cur_dir = dir2;
            }
            return Ok(PlannedDirMutation {
                pre_payload_writes: Vec::new(),
                allocated_clusters: None,
                log_specs: specs,
                updated_dir_raw: cur_dir,
                updated_indx_blocks,
            });
        }

        // Leaf entry in resident INDEX_ROOT.
        let old_entry = restored[root_at + val_off + located.span.offset_in_node
            ..root_at + val_off + located.span.offset_in_node + located.span.length]
            .to_vec();
        let attr_off = u16::try_from(val_off + located.span.offset_in_node)
            .map_err(|_| corrupt(0, "attr_off"))?;
        let FileEditResult::Applied(updated_dir) = apply_file_edit(
            dir_raw,
            dir_no,
            RecoveryPass::Undo,
            &FileEdit {
                operation: FileOperation::IndexRoot(IndexOperation::DeleteEntry),
                record_offset: located.root_attr_offset,
                attribute_offset: attr_off,
                data: &[],
            },
        )
        .map_err(|err| parse_err(&err))?
        else {
            return Err(corrupt(0, "AlreadyApplied"));
        };
        Ok(PlannedDirMutation {
            pre_payload_writes: Vec::new(),
            allocated_clusters: None,
            log_specs: vec![NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::DeleteIndexEntryRoot,
                undo_op: NtfsLogOp::AddIndexEntryRoot,
                target_attribute: mft_slot_attr_id,
                record_offset: located.root_attr_offset,
                attribute_offset: attr_off,
                cluster_block_offset: dir_mft_cbo,
                target_vcn: dir_mft_vcn,
                target_lcns: dir_mft_lcns.to_vec(),
                redo_data: Vec::new(),
                undo_data: old_entry,
            }],
            updated_dir_raw: updated_dir,
            updated_indx_blocks: Vec::new(),
        })
    }

    /// Plan an in-place `$I30` `FILE_NAME::dup` 56-byte update (`0x10` or `0x19`).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn plan_directory_update_dup(
        &self,
        cx: &Cx,
        dir_no: u32,
        dir_raw: &[u8],
        dir_rec: &NtfsFileRecord,
        mft_slot_attr_id: u16,
        dir_mft_vcn: u64,
        dir_mft_cbo: u16,
        dir_mft_lcns: &[u64],
        indx_attr_slot_if_open: Option<u16>,
        exact_name: &[u16],
        new_dup_56: &[u8],
    ) -> Result<PlannedDirMutation> {
        if new_dup_56.len() != DUPLICATED_INFO_BYTES {
            return Err(corrupt(0, "FILE_NAME dup update must be 56 bytes"));
        }
        let located = self.locate_directory_entry(cx, dir_raw, dir_rec, exact_name)?;
        let (_, _, key_raw) = located
            .span
            .key
            .as_ref()
            .ok_or_else(|| corrupt(0, "terminal entry has no FILE_NAME"))?;
        let old_dup = key_raw[8..64].to_vec();

        if let Some((leaf_vcn, _)) = located.external_vcn {
            let indx_slot = indx_attr_slot_if_open
                .ok_or_else(|| corrupt(0, "missing open-attribute slot for $I30"))?;
            let root_bytes = extract_resident_attr(dir_rec, ATTR_INDEX_ROOT, &I30_NAME)?;
            let root_parsed = NtfsIndexRoot::parse(&root_bytes, self.geometry.cluster_bytes())
                .map_err(|err| parse_err(&err))?;
            let (a0_runs, _, _) = extract_plain_nonresident_stream(
                &self.geometry,
                dir_rec,
                ATTR_INDEX_ALLOCATION,
                &I30_NAME,
            )?;
            let byte_off = leaf_vcn * u64::from(root_parsed.vcn_bytes);
            let leaf_raw = read_mapped_runs(
                &self.device,
                cx,
                &self.geometry,
                &a0_runs,
                byte_off,
                root_parsed.block_bytes as usize,
            )?;
            let (target_vcn, cbo, rec_off, target_lcns) =
                map_indx_transfer(&self.geometry, &a0_runs, byte_off, root_parsed.block_bytes)?;
            let FileEditResult::Applied(updated_leaf) = apply_index_edit(
                &leaf_raw,
                leaf_vcn,
                RecoveryPass::Undo,
                &IndexEdit {
                    operation: IndexOperation::UpdateFileName,
                    entry_offset: u16::try_from(located.span.offset_in_node)
                        .map_err(|_| corrupt(0, "off"))?,
                    data: new_dup_56,
                },
            )
            .map_err(|err| parse_err(&err))?
            else {
                return Err(corrupt(0, "AlreadyApplied"));
            };
            return Ok(PlannedDirMutation {
                pre_payload_writes: Vec::new(),
                allocated_clusters: None,
                log_specs: vec![NtfsClientUpdateSpec {
                    redo_op: NtfsLogOp::UpdateFileNameAllocation,
                    undo_op: NtfsLogOp::UpdateFileNameAllocation,
                    target_attribute: indx_slot,
                    record_offset: rec_off,
                    attribute_offset: u16::try_from(located.span.offset_in_node)
                        .map_err(|_| corrupt(0, "off"))?,
                    cluster_block_offset: cbo,
                    target_vcn,
                    target_lcns,
                    redo_data: new_dup_56.to_vec(),
                    undo_data: old_dup,
                }],
                updated_dir_raw: dir_raw.to_vec(),
                updated_indx_blocks: vec![(byte_off, updated_leaf)],
            });
        }

        let attr_off =
            u16::try_from(usize::from(located.root_value_offset) + located.span.offset_in_node)
                .map_err(|_| corrupt(0, "attr_off"))?;
        let FileEditResult::Applied(updated_dir) = apply_file_edit(
            dir_raw,
            dir_no,
            RecoveryPass::Undo,
            &FileEdit {
                operation: FileOperation::IndexRoot(IndexOperation::UpdateFileName),
                record_offset: located.root_attr_offset,
                attribute_offset: attr_off,
                data: new_dup_56,
            },
        )
        .map_err(|err| parse_err(&err))?
        else {
            return Err(corrupt(0, "AlreadyApplied"));
        };
        Ok(PlannedDirMutation {
            pre_payload_writes: Vec::new(),
            allocated_clusters: None,
            log_specs: vec![NtfsClientUpdateSpec {
                redo_op: NtfsLogOp::UpdateFileNameRoot,
                undo_op: NtfsLogOp::UpdateFileNameRoot,
                target_attribute: mft_slot_attr_id,
                record_offset: located.root_attr_offset,
                attribute_offset: attr_off,
                cluster_block_offset: dir_mft_cbo,
                target_vcn: dir_mft_vcn,
                target_lcns: dir_mft_lcns.to_vec(),
                redo_data: new_dup_56.to_vec(),
                undo_data: old_dup,
            }],
            updated_dir_raw: updated_dir,
            updated_indx_blocks: Vec::new(),
        })
    }
}

pub(super) fn map_indx_transfer(
    geometry: &NtfsGeometry,
    a0_runs: &[NtfsRun],
    byte_off: u64,
    block_bytes: u32,
) -> Result<(u64, u16, u16, Vec<u64>)> {
    let cluster_bytes = u64::from(geometry.cluster_bytes());
    let target_vcn = byte_off / cluster_bytes;
    let within_cluster = (byte_off % cluster_bytes) as usize;
    let cbo = u16::try_from(within_cluster / SECTOR_BYTES).map_err(|_| corrupt(0, "cbo"))?;
    let rec_off = u16::try_from(within_cluster % SECTOR_BYTES).map_err(|_| corrupt(0, "rec"))?;
    let num_clusters = (within_cluster as u64 + u64::from(block_bytes)).div_ceil(cluster_bytes);
    let mut lcns = Vec::with_capacity(num_clusters as usize);
    for c in 0..num_clusters {
        let (_, _, lcn) = map_logical_offset(geometry, a0_runs, (target_vcn + c) * cluster_bytes)?;
        lcns.push(lcn);
    }
    Ok((target_vcn, cbo, rec_off, lcns))
}

pub(super) fn directory_has_external_indx(dir_rec: &NtfsFileRecord) -> Result<Option<u32>> {
    for attr in dir_rec.attributes().map_err(|err| parse_err(&err))? {
        if attr.kind == ATTR_INDEX_ALLOCATION && attr.name == I30_NAME {
            let root_bytes = extract_resident_attr(dir_rec, ATTR_INDEX_ROOT, &I30_NAME)?;
            let block_bytes =
                u32::from_le_bytes([root_bytes[8], root_bytes[9], root_bytes[10], root_bytes[11]]);
            return Ok(Some(block_bytes));
        }
    }
    Ok(None)
}

#[allow(dead_code)]
fn _keep_usa_helper_linked() {
    let _ = next_usa_token(1);
    let _ = DATA;
    let _ = NtfsValue::Resident(&[]);
    let _ = decode_mapping_pairs;
}
