//! Deterministic NTFS 3.1 / 3.0 system-file and metadata-stream builder for
//! [`crate::formatter`].

use std::cmp::Ordering;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::index::{NtfsFileName, NtfsIndexRoot, encode_index_entry, parse_index_block};
use ffs_ondisk::ntfs::logfile_writer::{
    LFS_RECORD_CLIENT_RESTART, NtfsCheckpointPayload, NtfsLogRingWriter,
};
use ffs_ondisk::ntfs::{
    DATA, NtfsBootSectorSpec, NtfsFileRecord, NtfsReference, NtfsRun, SPARSE, VOLUME_INFORMATION,
    encode_mapping_pairs, encode_ntfs_boot_sector, encode_standard_ntfs_attr_def_table,
    protect_record,
};
use ffs_ondisk::ntfs_security::{
    NtfsSecurityIndexKind, build_default_ntfs_security_descriptor, encode_sds_stream,
    encode_security_index_root,
};

use super::NtfsFormatLayout;
use super::upcase::{canonical_ntfs_upcase_bytes, canonical_ntfs_upcase_u16, compare_utf16_upcase};

const SECTOR_BYTES: usize = 512;
const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_VOLUME_NAME: u32 = 0x60;
const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const ATTR_BITMAP: u32 = 0xB0;

const FILE_ATTR_HIDDEN_SYSTEM: u32 = 0x0006;
const FILE_ATTR_DUP_INDEX: u32 = 0x1000_0000;

const I30_NAME: [u16; 4] = [b'$' as u16, b'I' as u16, b'3' as u16, b'0' as u16];
const BAD_NAME: [u16; 4] = [b'$' as u16, b'B' as u16, b'a' as u16, b'd' as u16];
const SDS_NAME: [u16; 4] = [b'$' as u16, b'S' as u16, b'D' as u16, b'S' as u16];
const SII_NAME: [u16; 4] = [b'$' as u16, b'S' as u16, b'I' as u16, b'I' as u16];
const SDH_NAME: [u16; 4] = [b'$' as u16, b'S' as u16, b'D' as u16, b'H' as u16];
const DOLLAR_O_NAME: [u16; 2] = [b'$' as u16, b'O' as u16];
const DOLLAR_Q_NAME: [u16; 2] = [b'$' as u16, b'Q' as u16];
const DOLLAR_R_NAME: [u16; 2] = [b'$' as u16, b'R' as u16];

/// Complete serialized bootstrap artifacts produced for a planned NTFS volume.
#[derive(Debug)]
pub struct BuiltBootstrapVolume {
    pub vbr_sector: Vec<u8>,
    pub boot_stream: Vec<u8>,
    pub attrdef_bytes: Vec<u8>,
    pub bitmap_bytes: Vec<u8>,
    pub upcase_bytes: Vec<u8>,
    pub sds_bytes: Vec<u8>,
    pub root_indx_block: Vec<u8>,
    pub logfile_bytes: Vec<u8>,
    pub mft_bytes: Vec<u8>,
    pub mirror_bytes: Vec<u8>,
}

fn format_err(detail: impl Into<String>) -> FfsError {
    FfsError::Format(detail.into())
}

fn parse_err(err: &ffs_types::ParseError) -> FfsError {
    FfsError::Format(err.to_string())
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn encode_standard_info(filetime: u64, file_attributes: u32, security_id: u32) -> [u8; 72] {
    let mut out = [0_u8; 72];
    out[0..8].copy_from_slice(&filetime.to_le_bytes());
    out[8..16].copy_from_slice(&filetime.to_le_bytes());
    out[16..24].copy_from_slice(&filetime.to_le_bytes());
    out[24..32].copy_from_slice(&filetime.to_le_bytes());
    out[32..36].copy_from_slice(&file_attributes.to_le_bytes());
    out[52..56].copy_from_slice(&security_id.to_le_bytes());
    out
}

fn encode_resident_attr(
    kind: u32,
    id: u16,
    name: &[u16],
    indexed: bool,
    value: &[u8],
) -> Result<Vec<u8>> {
    let name_bytes = name.len() * 2;
    let value_off = (24 + name_bytes).next_multiple_of(8);
    let total_len = (value_off + value.len()).next_multiple_of(8);
    let len_u32 =
        u32::try_from(total_len).map_err(|_| format_err("resident attr length overflow"))?;
    let val_len_u32 =
        u32::try_from(value.len()).map_err(|_| format_err("resident attr value overflow"))?;
    let val_off_u16 =
        u16::try_from(value_off).map_err(|_| format_err("resident attr value offset overflow"))?;
    let name_len_u8 = u8::try_from(name.len()).map_err(|_| format_err("attr name too long"))?;

    let mut out = vec![0_u8; total_len];
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&len_u32.to_le_bytes());
    out[8] = 0; // resident
    out[9] = name_len_u8;
    out[10..12].copy_from_slice(&24_u16.to_le_bytes());
    out[12..14].copy_from_slice(&0_u16.to_le_bytes());
    out[14..16].copy_from_slice(&id.to_le_bytes());
    out[16..20].copy_from_slice(&val_len_u32.to_le_bytes());
    out[20..22].copy_from_slice(&val_off_u16.to_le_bytes());
    out[22..24].copy_from_slice(&u16::from(indexed).to_le_bytes());
    for (i, &u) in name.iter().enumerate() {
        out[24 + i * 2..26 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    out[value_off..value_off + value.len()].copy_from_slice(value);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn encode_nonresident_attr(
    kind: u32,
    id: u16,
    name: &[u16],
    flags: u16,
    runs: &[NtfsRun],
    allocated_bytes: u64,
    data_bytes: u64,
    initialized_bytes: u64,
    vol_clusters: u64,
) -> Result<Vec<u8>> {
    let (pairs, last_vcn) =
        encode_mapping_pairs(runs, 0, vol_clusters).map_err(|e| parse_err(&e))?;
    let base_hdr: usize = if flags & (SPARSE | ffs_ondisk::ntfs::COMPRESSED) != 0 {
        72
    } else {
        64
    };
    let name_bytes = name.len() * 2;
    let mapping_off = (base_hdr + name_bytes).next_multiple_of(8);
    let total_len = (mapping_off + pairs.len()).next_multiple_of(8);
    let len_u32 =
        u32::try_from(total_len).map_err(|_| format_err("nonresident attr length overflow"))?;
    let map_off_u16 = u16::try_from(mapping_off)
        .map_err(|_| format_err("nonresident mapping offset overflow"))?;
    let name_off_u16 =
        u16::try_from(base_hdr).map_err(|_| format_err("nonresident name offset overflow"))?;
    let name_len_u8 = u8::try_from(name.len()).map_err(|_| format_err("attr name too long"))?;

    let mut out = vec![0_u8; total_len];
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out[4..8].copy_from_slice(&len_u32.to_le_bytes());
    out[8] = 1; // nonresident
    out[9] = name_len_u8;
    out[10..12].copy_from_slice(&name_off_u16.to_le_bytes());
    out[12..14].copy_from_slice(&flags.to_le_bytes());
    out[14..16].copy_from_slice(&id.to_le_bytes());
    out[16..24].copy_from_slice(&0_u64.to_le_bytes()); // first_vcn
    out[24..32].copy_from_slice(&last_vcn.to_le_bytes());
    out[32..34].copy_from_slice(&map_off_u16.to_le_bytes());
    out[40..48].copy_from_slice(&allocated_bytes.to_le_bytes());
    out[48..56].copy_from_slice(&data_bytes.to_le_bytes());
    out[56..64].copy_from_slice(&initialized_bytes.to_le_bytes());
    if base_hdr == 72 {
        // Sparse/compressed allocated physical size (bytes on disk).
        let phys_clusters: u64 = runs.iter().filter_map(|r| r.lcn.map(|_| r.clusters)).sum();
        let phys_bytes = phys_clusters
            .checked_mul(
                allocated_bytes
                    .checked_div(runs.iter().map(|r| r.clusters).sum::<u64>().max(1))
                    .unwrap_or(0),
            )
            .unwrap_or(0);
        out[64..72].copy_from_slice(&phys_bytes.to_le_bytes());
    }
    for (i, &u) in name.iter().enumerate() {
        out[base_hdr + i * 2..base_hdr + 2 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    out[mapping_off..mapping_off + pairs.len()].copy_from_slice(&pairs);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn encode_file_record(
    version: [u8; 2],
    record_bytes: u32,
    record_no: u32,
    sequence: u16,
    flags: u16,
    hard_links: u16,
    attrs: &[Vec<u8>],
    next_attr_id: u16,
) -> Result<Vec<u8>> {
    let len = usize::try_from(record_bytes).map_err(|_| format_err("record_bytes overflow"))?;
    let usa_offset: u16 = if version == [3, 0] { 42 } else { 48 };
    let usa_count = u16::try_from(len / SECTOR_BYTES + 1).map_err(|_| format_err("usa_count"))?;
    let first_attr = (usize::from(usa_offset) + usize::from(usa_count) * 2).next_multiple_of(8);
    let attrs_bytes: usize = attrs.iter().map(Vec::len).sum();
    let used = first_attr + attrs_bytes + 8;
    if used > len {
        return Err(format_err(format!(
            "system FILE record {record_no} overflows record_bytes ({used} > {len})"
        )));
    }

    let mut buf = vec![0_u8; len];
    buf[0..4].copy_from_slice(b"FILE");
    buf[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    buf[6..8].copy_from_slice(&usa_count.to_le_bytes());
    buf[16..18].copy_from_slice(&sequence.to_le_bytes());
    buf[18..20].copy_from_slice(&hard_links.to_le_bytes());
    let first_attr_u16 =
        u16::try_from(first_attr).map_err(|_| format_err("first_attr overflow"))?;
    buf[20..22].copy_from_slice(&first_attr_u16.to_le_bytes());
    buf[22..24].copy_from_slice(&flags.to_le_bytes());
    let used_u32 = u32::try_from(used).map_err(|_| format_err("used overflow"))?;
    buf[24..28].copy_from_slice(&used_u32.to_le_bytes());
    buf[28..32].copy_from_slice(&record_bytes.to_le_bytes());
    buf[40..42].copy_from_slice(&next_attr_id.to_le_bytes());
    if usa_offset >= 48 {
        buf[44..48].copy_from_slice(&record_no.to_le_bytes());
    }

    let mut pos = first_attr;
    for attr in attrs {
        buf[pos..pos + attr.len()].copy_from_slice(attr);
        pos += attr.len();
    }
    buf[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    // Seed initial non-zero USA token before calling protect_record.
    let usa_off = usize::from(usa_offset);
    buf[usa_off..usa_off + 2].copy_from_slice(&1_u16.to_le_bytes());
    let protected = protect_record(&buf).map_err(|e| parse_err(&e))?;
    let parsed = NtfsFileRecord::parse(&protected).map_err(|e| parse_err(&e))?;
    if version == [3, 1] && parsed.self_number != Some(record_no) {
        return Err(format_err(
            "encoded NTFS 3.1 FILE record round-trip mismatch",
        ));
    }
    Ok(protected)
}

fn build_empty_view_index_root(
    collation: u32,
    index_bytes: u32,
    cluster_bytes: u32,
) -> Result<Vec<u8>> {
    let vcn_bytes = if index_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let units = u8::try_from(index_bytes / vcn_bytes).map_err(|_| format_err("index units"))?;
    let mut root = vec![0_u8; 48];
    root[0..4].copy_from_slice(&0_u32.to_le_bytes()); // attr_type = 0 (view index)
    root[4..8].copy_from_slice(&collation.to_le_bytes());
    root[8..12].copy_from_slice(&index_bytes.to_le_bytes());
    root[12] = units;
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&32_u32.to_le_bytes());
    root[24..28].copy_from_slice(&32_u32.to_le_bytes());
    root[28..32].copy_from_slice(&0_u32.to_le_bytes());
    root[32 + 8..32 + 10].copy_from_slice(&16_u16.to_le_bytes());
    root[32 + 12..32 + 14].copy_from_slice(&2_u16.to_le_bytes());
    Ok(root)
}

/// Build the exact inactive `$Quota::$Q` view-index root matching `mkntfs` and
/// `NtfsTransactionEngine::validate_inactive_quota_record`.
fn build_inactive_quota_q_index_root(index_bytes: u32, cluster_bytes: u32) -> Result<Vec<u8>> {
    const ADMINISTRATORS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];

    let vcn_bytes = if index_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let units = u8::try_from(index_bytes / vcn_bytes).map_err(|_| format_err("index units"))?;

    let mut entries = Vec::new();
    // Entry 1: owner = 1 (default inactive quota record, 48B payload, entry_len = 72B).
    let mut e1 = vec![0_u8; 72];
    e1[0..2].copy_from_slice(&24_u16.to_le_bytes()); // data_off = 24
    e1[2..4].copy_from_slice(&48_u16.to_le_bytes()); // data_len = 48
    e1[8..10].copy_from_slice(&72_u16.to_le_bytes()); // entry_len = 72
    e1[10..12].copy_from_slice(&4_u16.to_le_bytes()); // key_len = 4
    e1[16..20].copy_from_slice(&1_u32.to_le_bytes()); // owner = 1
    e1[24..28].copy_from_slice(&2_u32.to_le_bytes()); // version = 2
    e1[28..32].copy_from_slice(&0_u32.to_le_bytes()); // flags = 0 (inactive)
    e1[48..64].fill(0xFF); // threshold & limit = u64::MAX (unlimited)
    entries.extend_from_slice(&e1);

    // Entry 2: owner = 0x100 (bootstrap Administrators SID, 64B payload, entry_len = 88B).
    let mut e2 = vec![0_u8; 88];
    e2[0..2].copy_from_slice(&24_u16.to_le_bytes()); // data_off = 24
    e2[2..4].copy_from_slice(&64_u16.to_le_bytes()); // data_len = 64
    e2[8..10].copy_from_slice(&88_u16.to_le_bytes()); // entry_len = 88
    e2[10..12].copy_from_slice(&4_u16.to_le_bytes()); // key_len = 4
    e2[16..20].copy_from_slice(&0x100_u32.to_le_bytes()); // owner = 0x100
    e2[24..28].copy_from_slice(&2_u32.to_le_bytes()); // version = 2
    e2[28..32].copy_from_slice(&1_u32.to_le_bytes()); // flags = 1 (default limits)
    e2[48..64].fill(0xFF); // unlimited
    e2[72..88].copy_from_slice(&ADMINISTRATORS);
    entries.extend_from_slice(&e2);

    // Terminal END entry (16B).
    let mut term = [0_u8; 16];
    term[8..10].copy_from_slice(&16_u16.to_le_bytes());
    term[12..14].copy_from_slice(&2_u16.to_le_bytes());
    entries.extend_from_slice(&term);

    let used = u32::try_from(16 + entries.len()).map_err(|_| format_err("quota root size"))?;
    let mut root = Vec::with_capacity(16 + entries.len());
    root.extend_from_slice(&0_u32.to_le_bytes());
    root.extend_from_slice(&0x10_u32.to_le_bytes()); // COLLATION_ULONG
    root.extend_from_slice(&index_bytes.to_le_bytes());
    root.push(units);
    root.extend_from_slice(&[0_u8; 3]);
    root.extend_from_slice(&16_u32.to_le_bytes());
    root.extend_from_slice(&used.to_le_bytes());
    root.extend_from_slice(&used.to_le_bytes());
    root.extend_from_slice(&0_u32.to_le_bytes());
    root.extend_from_slice(&entries);
    Ok(root)
}

fn build_small_i30_root(
    index_bytes: u32,
    cluster_bytes: u32,
    leaf_entries: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let vcn_bytes = if index_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let units = u8::try_from(index_bytes / vcn_bytes).map_err(|_| format_err("index units"))?;
    let payload: usize = leaf_entries.iter().map(Vec::len).sum();
    let hdr_used = 16 + payload + 16;
    let used_u32 = u32::try_from(hdr_used).map_err(|_| format_err("small i30 root overflow"))?;
    let mut root = vec![0_u8; 16 + hdr_used];
    root[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root[4..8].copy_from_slice(&1_u32.to_le_bytes()); // COLLATION_FILE_NAME
    root[8..12].copy_from_slice(&index_bytes.to_le_bytes());
    root[12] = units;
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&used_u32.to_le_bytes());
    root[24..28].copy_from_slice(&used_u32.to_le_bytes());
    root[28..32].copy_from_slice(&0_u32.to_le_bytes()); // SMALL_INDEX
    let mut pos = 32;
    for ent in leaf_entries {
        root[pos..pos + ent.len()].copy_from_slice(ent);
        pos += ent.len();
    }
    root[pos + 8..pos + 10].copy_from_slice(&16_u16.to_le_bytes());
    root[pos + 12..pos + 14].copy_from_slice(&2_u16.to_le_bytes());
    let _ = NtfsIndexRoot::parse(&root, cluster_bytes).map_err(|e| parse_err(&e))?;
    Ok(root)
}

fn build_large_i30_root_pointing_zero(index_bytes: u32, cluster_bytes: u32) -> Result<Vec<u8>> {
    let vcn_bytes = if index_bytes < cluster_bytes {
        512
    } else {
        cluster_bytes
    };
    let units = u8::try_from(index_bytes / vcn_bytes).map_err(|_| format_err("index units"))?;
    let mut root = vec![0_u8; 56];
    root[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root[4..8].copy_from_slice(&1_u32.to_le_bytes());
    root[8..12].copy_from_slice(&index_bytes.to_le_bytes());
    root[12] = units;
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&40_u32.to_le_bytes());
    root[24..28].copy_from_slice(&40_u32.to_le_bytes());
    root[28..32].copy_from_slice(&1_u32.to_le_bytes()); // LARGE_INDEX
    // Terminal internal entry: len = 24, flags = 3 (HAS_SUBNODE | END), child_vcn = 0.
    root[32 + 8..32 + 10].copy_from_slice(&24_u16.to_le_bytes());
    root[32 + 12..32 + 14].copy_from_slice(&3_u16.to_le_bytes());
    root[32 + 16..32 + 24].copy_from_slice(&0_u64.to_le_bytes());
    let _ = NtfsIndexRoot::parse(&root, cluster_bytes).map_err(|e| parse_err(&e))?;
    Ok(root)
}

fn build_leaf_indx_block(index_bytes: u32, leaf_entries: &[Vec<u8>]) -> Result<Vec<u8>> {
    let len = usize::try_from(index_bytes).map_err(|_| format_err("index_bytes overflow"))?;
    let usa_offset: u16 = 40;
    let usa_count = u16::try_from(len / SECTOR_BYTES + 1).map_err(|_| format_err("usa_count"))?;
    let raw_entries_off =
        (usize::from(usa_offset) + usize::from(usa_count) * 2).next_multiple_of(8);
    let rel_entries_off = raw_entries_off - 24;
    let allocated = len - 24;
    let payload: usize = leaf_entries.iter().map(Vec::len).sum();
    let used = rel_entries_off + payload + 16;
    if used > allocated {
        return Err(format_err("root INDX block overflow"));
    }

    let mut buf = vec![0_u8; len];
    buf[0..4].copy_from_slice(b"INDX");
    buf[4..6].copy_from_slice(&usa_offset.to_le_bytes());
    buf[6..8].copy_from_slice(&usa_count.to_le_bytes());
    let rel_u32 = u32::try_from(rel_entries_off).map_err(|_| format_err("rel_off"))?;
    let used_u32 = u32::try_from(used).map_err(|_| format_err("used"))?;
    let alloc_u32 = u32::try_from(allocated).map_err(|_| format_err("alloc"))?;
    buf[24..28].copy_from_slice(&rel_u32.to_le_bytes());
    buf[28..32].copy_from_slice(&used_u32.to_le_bytes());
    buf[32..36].copy_from_slice(&alloc_u32.to_le_bytes());
    buf[36..40].copy_from_slice(&0_u32.to_le_bytes()); // leaf
    let mut pos = raw_entries_off;
    for ent in leaf_entries {
        buf[pos..pos + ent.len()].copy_from_slice(ent);
        pos += ent.len();
    }
    buf[pos + 8..pos + 10].copy_from_slice(&16_u16.to_le_bytes());
    buf[pos + 12..pos + 14].copy_from_slice(&2_u16.to_le_bytes());

    let usa_off = usize::from(usa_offset);
    buf[usa_off..usa_off + 2].copy_from_slice(&1_u16.to_le_bytes());
    let protected = protect_record(&buf).map_err(|e| parse_err(&e))?;
    let _ = parse_index_block(&protected, 0).map_err(|e| parse_err(&e))?;
    Ok(protected)
}

fn build_clean_logfile(cx: &Cx, logfile_bytes: u64) -> Result<Vec<u8>> {
    let total = usize::try_from(logfile_bytes).map_err(|_| format_err("logfile_bytes overflow"))?;
    let mut ring = NtfsLogRingWriter::new_fresh(4_096, (1, 1), logfile_bytes, 1, 1)
        .map_err(|e| parse_err(&e))?;
    let ckpt = NtfsCheckpointPayload::default()
        .encode()
        .map_err(|e| parse_err(&e))?;
    let appended = ring
        .append_raw_record(LFS_RECORD_CLIENT_RESTART, 0, 0, 0, &ckpt)
        .map_err(|e| parse_err(&e))?;
    let rstr0 = ring.build_next_rstr_page(true).map_err(|e| parse_err(&e))?;
    let rstr1 = ring.build_next_rstr_page(true).map_err(|e| parse_err(&e))?;

    let mut out = vec![0xFF_u8; total];
    let copy_page = |buf: &mut [u8], vbo: u64, page: &[u8]| -> Result<()> {
        let start = usize::try_from(vbo).map_err(|_| format_err("vbo overflow"))?;
        let end = start + page.len();
        if end > buf.len() {
            return Err(format_err("$LogFile staged page exceeds file_size"));
        }
        buf[start..end].copy_from_slice(page);
        Ok(())
    };
    copy_page(&mut out, rstr0.page_vbo, &rstr0.bytes)?;
    copy_page(&mut out, rstr1.page_vbo, &rstr1.bytes)?;
    copy_page(&mut out, appended.page_vbo, &appended.protected_page)?;

    let verified =
        crate::reader::filesystem::inspect_logfile(cx, logfile_bytes, |offset, size| {
            let start =
                usize::try_from(offset).map_err(|_| format_err("logfile offset overflow"))?;
            let end = start
                .checked_add(size)
                .filter(|end| *end <= out.len())
                .ok_or_else(|| format_err("logfile audit read exceeds serialized bytes"))?;
            Ok(out[start..end].to_vec())
        })?;
    if !verified.clean
        || verified.erased
        || verified.current_lsn != appended.lsn
        || verified.oldest_lsn != appended.lsn
        || verified.client_restart_lsn != appended.lsn
    {
        return Err(format_err(
            "freshly formatted $LogFile failed clean self-check",
        ));
    }
    Ok(out)
}

fn mark_bitmap_span(bitmap: &mut [u8], start: u64, count: u64) {
    for lcn in start..start + count {
        let idx = (lcn / 8) as usize;
        if idx < bitmap.len() {
            bitmap[idx] |= 1_u8 << (lcn % 8);
        }
    }
}

/// Build every system stream and MFT record (`0..32`) for the planned NTFS layout.
///
/// # Errors
/// Returns an error if any encoded boot sector, security index, `$LogFile`,
/// `$I30` index, or `FILE` record fails round-trip self-verification.
#[allow(clippy::too_many_lines)]
pub fn build_bootstrap_volume(
    cx: &Cx,
    layout: &NtfsFormatLayout,
    label: &str,
    filetime: u64,
) -> Result<BuiltBootstrapVolume> {
    let cb = u64::from(layout.cluster_bytes);
    let vol_clusters = layout.cluster_count;

    // 1. Primary VBR & 8 KiB $Boot stream.
    let vbr_spec = NtfsBootSectorSpec {
        sector_bytes: layout.sector_bytes,
        sectors_per_cluster: layout.sectors_per_cluster,
        total_sectors: layout.total_sectors,
        mft_cluster: layout.mft_cluster,
        mirror_cluster: layout.mirror_cluster,
        record_bytes: layout.record_bytes,
        index_bytes: layout.index_bytes,
        serial: layout.serial,
        hidden_sectors: 0,
    };
    let vbr_sector = encode_ntfs_boot_sector(&vbr_spec).map_err(|e| parse_err(&e))?;
    let mut boot_stream = vec![0_u8; 8_192];
    boot_stream[..vbr_sector.len()].copy_from_slice(&vbr_sector);

    // 2. $AttrDef, $UpCase, $Secure:$SDS + $SII + $SDH, $LogFile.
    let attrdef_bytes = encode_standard_ntfs_attr_def_table();
    let upcase_u16 = canonical_ntfs_upcase_u16();
    let upcase_bytes = canonical_ntfs_upcase_bytes();

    let default_sd = build_default_ntfs_security_descriptor();
    let (sds_bytes, sds_headers) =
        encode_sds_stream(&[(256, &default_sd), (257, &default_sd)]).map_err(|e| parse_err(&e))?;
    let sds_alloc_bytes = (sds_bytes.len() as u64).next_multiple_of(cb);
    if sds_alloc_bytes > layout.sds_clusters * cb {
        return Err(format_err("$Secure:$SDS exceeds planned cluster span"));
    }
    let sii_root = encode_security_index_root(
        NtfsSecurityIndexKind::SecurityId,
        &sds_headers,
        layout.index_bytes,
        layout.cluster_bytes,
    )
    .map_err(|e| parse_err(&e))?;
    let sdh_root = encode_security_index_root(
        NtfsSecurityIndexKind::SecurityHash,
        &sds_headers,
        layout.index_bytes,
        layout.cluster_bytes,
    )
    .map_err(|e| parse_err(&e))?;

    let logfile_bytes = build_clean_logfile(cx, layout.logfile_bytes)?;

    // 3. $Bitmap covering exact allocated bootstrap runs.
    let mut bitmap_bytes = vec![
        0_u8;
        usize::try_from(layout.bitmap_bytes)
            .map_err(|_| format_err("bitmap overflow"))?
    ];
    mark_bitmap_span(&mut bitmap_bytes, 0, layout.boot_clusters);
    mark_bitmap_span(&mut bitmap_bytes, layout.mft_cluster, layout.mft_clusters);
    mark_bitmap_span(
        &mut bitmap_bytes,
        layout.mirror_cluster,
        layout.mirror_clusters,
    );
    mark_bitmap_span(
        &mut bitmap_bytes,
        layout.attrdef_cluster,
        layout.attrdef_clusters,
    );
    mark_bitmap_span(
        &mut bitmap_bytes,
        layout.bitmap_cluster,
        layout.bitmap_clusters,
    );
    mark_bitmap_span(
        &mut bitmap_bytes,
        layout.upcase_cluster,
        layout.upcase_clusters,
    );
    mark_bitmap_span(&mut bitmap_bytes, layout.sds_cluster, layout.sds_clusters);
    mark_bitmap_span(
        &mut bitmap_bytes,
        layout.root_indx_cluster,
        layout.root_indx_clusters,
    );
    mark_bitmap_span(
        &mut bitmap_bytes,
        layout.logfile_cluster,
        layout.logfile_clusters,
    );

    let root_ref = NtfsReference {
        record: 5,
        sequence: 5,
    };
    let extend_ref = NtfsReference {
        record: 11,
        sequence: 11,
    };

    let make_fn_bytes = |parent: NtfsReference,
                         name: &str,
                         alloc: u64,
                         size: u64,
                         attrs: u32|
     -> Result<(Vec<u16>, Vec<u8>)> {
        let units = utf16(name);
        let fn_struct = NtfsFileName {
            parent,
            namespace: 3, // WIN32_AND_DOS
            name: units.clone(),
        };
        let encoded = fn_struct
            .encode(
                filetime, filetime, filetime, filetime, alloc, size, attrs, 0,
            )
            .map_err(|e| parse_err(&e))?;
        Ok((units, encoded))
    };

    // Collect root directory entries (system files 0..4, 6..11) and $Extend entries (24..26).
    let mut root_entries: Vec<(Vec<u16>, NtfsReference, Vec<u8>)> = Vec::new();
    let mut extend_entries: Vec<(Vec<u16>, NtfsReference, Vec<u8>)> = Vec::new();

    let rec_len = usize::try_from(layout.record_bytes).map_err(|_| format_err("rec_len"))?;
    let mft_total_bytes = usize::try_from(layout.mft_records * u64::from(layout.record_bytes))
        .map_err(|_| format_err("mft_bytes"))?;
    let mut mft_bytes = vec![0_u8; mft_total_bytes];

    let mut place_record = |slot: u32, raw: &[u8]| {
        let start = usize::try_from(slot).unwrap_or(0) * rec_len;
        mft_bytes[start..start + rec_len].copy_from_slice(raw);
    };

    // Record 0: $MFT
    {
        let mft_alloc = layout.mft_clusters * cb;
        let mft_size = layout.mft_records * u64::from(layout.record_bytes);
        let (u, fn_raw) = make_fn_bytes(
            root_ref,
            "$MFT",
            mft_alloc,
            mft_size,
            FILE_ATTR_HIDDEN_SYSTEM,
        )?;
        root_entries.push((
            u,
            NtfsReference {
                record: 0,
                sequence: 1,
            },
            fn_raw.clone(),
        ));
        // Bits 0..15 (system) and 24..26 ($ObjId, $Quota, $Reparse) set.
        let mft_bm_len = usize::try_from(layout.mft_records.div_ceil(8).next_multiple_of(8))
            .map_err(|_| format_err("mft_bm_len overflow"))?
            .max(8);
        let mut mft_bm = vec![0_u8; mft_bm_len];
        mft_bm[0] = 0xFF;
        mft_bm[1] = 0xFF;
        mft_bm[3] = 0x07;
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_nonresident_attr(
                DATA,
                2,
                &[],
                0,
                &[NtfsRun {
                    vcn: 0,
                    clusters: layout.mft_clusters,
                    lcn: Some(layout.mft_cluster),
                }],
                mft_alloc,
                mft_size,
                mft_size,
                vol_clusters,
            )?,
            encode_resident_attr(ATTR_BITMAP, 3, &[], false, &mft_bm)?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            0,
            1,
            0x0001,
            1,
            &attrs,
            4,
        )?;
        place_record(0, &raw);
    }

    // Record 1: $MFTMirr
    {
        let mirr_alloc = layout.mirror_clusters * cb;
        let mirr_size = layout.mirror_records * u64::from(layout.record_bytes);
        let (u, fn_raw) = make_fn_bytes(
            root_ref,
            "$MFTMirr",
            mirr_alloc,
            mirr_size,
            FILE_ATTR_HIDDEN_SYSTEM,
        )?;
        root_entries.push((
            u,
            NtfsReference {
                record: 1,
                sequence: 1,
            },
            fn_raw.clone(),
        ));
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_nonresident_attr(
                DATA,
                2,
                &[],
                0,
                &[NtfsRun {
                    vcn: 0,
                    clusters: layout.mirror_clusters,
                    lcn: Some(layout.mirror_cluster),
                }],
                mirr_alloc,
                mirr_size,
                mirr_size,
                vol_clusters,
            )?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            1,
            1,
            0x0001,
            1,
            &attrs,
            3,
        )?;
        place_record(1, &raw);
    }

    // Record 2: $LogFile
    {
        let log_alloc = layout.logfile_clusters * cb;
        let log_size = layout.logfile_bytes;
        let (u, fn_raw) = make_fn_bytes(
            root_ref,
            "$LogFile",
            log_alloc,
            log_size,
            FILE_ATTR_HIDDEN_SYSTEM,
        )?;
        root_entries.push((
            u,
            NtfsReference {
                record: 2,
                sequence: 2,
            },
            fn_raw.clone(),
        ));
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_nonresident_attr(
                DATA,
                2,
                &[],
                0,
                &[NtfsRun {
                    vcn: 0,
                    clusters: layout.logfile_clusters,
                    lcn: Some(layout.logfile_cluster),
                }],
                log_alloc,
                log_size,
                log_size,
                vol_clusters,
            )?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            2,
            2,
            0x0001,
            1,
            &attrs,
            3,
        )?;
        place_record(2, &raw);
    }

    // Record 3: $Volume
    {
        let (u, fn_raw) = make_fn_bytes(root_ref, "$Volume", 0, 0, FILE_ATTR_HIDDEN_SYSTEM)?;
        root_entries.push((
            u,
            NtfsReference {
                record: 3,
                sequence: 3,
            },
            fn_raw.clone(),
        ));
        let mut vol_name_bytes = Vec::new();
        for unit in label.encode_utf16() {
            vol_name_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let mut vol_info = [0_u8; 12];
        vol_info[8] = layout.version[0];
        vol_info[9] = layout.version[1];
        let mut attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
        ];
        let mut next_attr_id = 2_u16;
        if !vol_name_bytes.is_empty() {
            attrs.push(encode_resident_attr(
                ATTR_VOLUME_NAME,
                next_attr_id,
                &[],
                false,
                &vol_name_bytes,
            )?);
            next_attr_id += 1;
        }
        attrs.push(encode_resident_attr(
            VOLUME_INFORMATION,
            next_attr_id,
            &[],
            false,
            &vol_info,
        )?);
        next_attr_id += 1;
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            3,
            3,
            0x0001,
            1,
            &attrs,
            next_attr_id,
        )?;
        place_record(3, &raw);
    }

    // Record 4: $AttrDef
    {
        let ad_alloc = layout.attrdef_clusters * cb;
        let ad_size = attrdef_bytes.len() as u64;
        let (u, fn_raw) = make_fn_bytes(
            root_ref,
            "$AttrDef",
            ad_alloc,
            ad_size,
            FILE_ATTR_HIDDEN_SYSTEM,
        )?;
        root_entries.push((
            u,
            NtfsReference {
                record: 4,
                sequence: 4,
            },
            fn_raw.clone(),
        ));
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_nonresident_attr(
                DATA,
                2,
                &[],
                0,
                &[NtfsRun {
                    vcn: 0,
                    clusters: layout.attrdef_clusters,
                    lcn: Some(layout.attrdef_cluster),
                }],
                ad_alloc,
                ad_size,
                ad_size,
                vol_clusters,
            )?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            4,
            4,
            0x0001,
            1,
            &attrs,
            3,
        )?;
        place_record(4, &raw);
    }

    // Record 6: $Bitmap
    {
        let bm_alloc = layout.bitmap_clusters * cb;
        let bm_size = layout.bitmap_bytes;
        let (u, fn_raw) = make_fn_bytes(
            root_ref,
            "$Bitmap",
            bm_alloc,
            bm_size,
            FILE_ATTR_HIDDEN_SYSTEM,
        )?;
        root_entries.push((
            u,
            NtfsReference {
                record: 6,
                sequence: 6,
            },
            fn_raw.clone(),
        ));
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_nonresident_attr(
                DATA,
                2,
                &[],
                0,
                &[NtfsRun {
                    vcn: 0,
                    clusters: layout.bitmap_clusters,
                    lcn: Some(layout.bitmap_cluster),
                }],
                bm_alloc,
                bm_size,
                bm_size,
                vol_clusters,
            )?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            6,
            6,
            0x0001,
            1,
            &attrs,
            3,
        )?;
        place_record(6, &raw);
    }

    // Record 7: $Boot
    {
        let boot_alloc = layout.boot_clusters * cb;
        let boot_size = boot_stream.len() as u64;
        let (u, fn_raw) = make_fn_bytes(
            root_ref,
            "$Boot",
            boot_alloc,
            boot_size,
            FILE_ATTR_HIDDEN_SYSTEM,
        )?;
        root_entries.push((
            u,
            NtfsReference {
                record: 7,
                sequence: 7,
            },
            fn_raw.clone(),
        ));
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_nonresident_attr(
                DATA,
                2,
                &[],
                0,
                &[NtfsRun {
                    vcn: 0,
                    clusters: layout.boot_clusters,
                    lcn: Some(0),
                }],
                boot_alloc,
                boot_size,
                boot_size,
                vol_clusters,
            )?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            7,
            7,
            0x0001,
            1,
            &attrs,
            3,
        )?;
        place_record(7, &raw);
    }

    // Record 8: $BadClus
    {
        let bad_bytes = vol_clusters * cb;
        let (u, fn_raw) = make_fn_bytes(root_ref, "$BadClus", 0, 0, FILE_ATTR_HIDDEN_SYSTEM)?;
        root_entries.push((
            u,
            NtfsReference {
                record: 8,
                sequence: 8,
            },
            fn_raw.clone(),
        ));
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_resident_attr(DATA, 2, &[], false, &[])?,
            encode_nonresident_attr(
                DATA,
                3,
                &BAD_NAME,
                SPARSE,
                &[NtfsRun {
                    vcn: 0,
                    clusters: vol_clusters,
                    lcn: None,
                }],
                bad_bytes,
                bad_bytes,
                0,
                vol_clusters,
            )?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            8,
            8,
            0x0001,
            1,
            &attrs,
            4,
        )?;
        place_record(8, &raw);
    }

    // Record 9: $Secure
    {
        let sds_alloc = layout.sds_clusters * cb;
        let sds_size = sds_bytes.len() as u64;
        let (u, fn_raw) = make_fn_bytes(root_ref, "$Secure", 0, 0, FILE_ATTR_HIDDEN_SYSTEM)?;
        root_entries.push((
            u,
            NtfsReference {
                record: 9,
                sequence: 9,
            },
            fn_raw.clone(),
        ));
        // Attributes must be in ascending type order; within type 0x90 sort by name ($SDH < $SII).
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_nonresident_attr(
                DATA,
                2,
                &SDS_NAME,
                0,
                &[NtfsRun {
                    vcn: 0,
                    clusters: layout.sds_clusters,
                    lcn: Some(layout.sds_cluster),
                }],
                sds_alloc,
                sds_size,
                sds_size,
                vol_clusters,
            )?,
            encode_resident_attr(ATTR_INDEX_ROOT, 3, &SDH_NAME, false, &sdh_root)?,
            encode_resident_attr(ATTR_INDEX_ROOT, 4, &SII_NAME, false, &sii_root)?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            9,
            9,
            0x0001,
            1,
            &attrs,
            5,
        )?;
        place_record(9, &raw);
    }

    // Record 10: $UpCase
    {
        let up_alloc = layout.upcase_clusters * cb;
        let up_size = upcase_bytes.len() as u64;
        let (u, fn_raw) = make_fn_bytes(
            root_ref,
            "$UpCase",
            up_alloc,
            up_size,
            FILE_ATTR_HIDDEN_SYSTEM,
        )?;
        root_entries.push((
            u,
            NtfsReference {
                record: 10,
                sequence: 10,
            },
            fn_raw.clone(),
        ));
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_nonresident_attr(
                DATA,
                2,
                &[],
                0,
                &[NtfsRun {
                    vcn: 0,
                    clusters: layout.upcase_clusters,
                    lcn: Some(layout.upcase_cluster),
                }],
                up_alloc,
                up_size,
                up_size,
                vol_clusters,
            )?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            10,
            10,
            0x0001,
            1,
            &attrs,
            3,
        )?;
        place_record(10, &raw);
    }

    // Records 24..26: $Extend children ($ObjId, $Quota, $Reparse).
    {
        // Record 24: $ObjId
        let (u, fn_raw) = make_fn_bytes(extend_ref, "$ObjId", 0, 0, FILE_ATTR_HIDDEN_SYSTEM)?;
        extend_entries.push((
            u,
            NtfsReference {
                record: 24,
                sequence: 1,
            },
            fn_raw.clone(),
        ));
        let o_root = build_empty_view_index_root(0x11, layout.index_bytes, layout.cluster_bytes)?;
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_resident_attr(ATTR_INDEX_ROOT, 2, &DOLLAR_O_NAME, false, &o_root)?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            24,
            1,
            0x0009,
            1,
            &attrs,
            3,
        )?;
        place_record(24, &raw);
    }
    {
        // Record 25: $Quota
        let (u, fn_raw) = make_fn_bytes(extend_ref, "$Quota", 0, 0, FILE_ATTR_HIDDEN_SYSTEM)?;
        extend_entries.push((
            u,
            NtfsReference {
                record: 25,
                sequence: 1,
            },
            fn_raw.clone(),
        ));
        let o_root = build_empty_view_index_root(0x11, layout.index_bytes, layout.cluster_bytes)?;
        let q_root = build_inactive_quota_q_index_root(layout.index_bytes, layout.cluster_bytes)?;
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_resident_attr(ATTR_INDEX_ROOT, 2, &DOLLAR_O_NAME, false, &o_root)?,
            encode_resident_attr(ATTR_INDEX_ROOT, 3, &DOLLAR_Q_NAME, false, &q_root)?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            25,
            1,
            0x0009,
            1,
            &attrs,
            4,
        )?;
        place_record(25, &raw);
    }
    {
        // Record 26: $Reparse
        let (u, fn_raw) = make_fn_bytes(extend_ref, "$Reparse", 0, 0, FILE_ATTR_HIDDEN_SYSTEM)?;
        extend_entries.push((
            u,
            NtfsReference {
                record: 26,
                sequence: 1,
            },
            fn_raw.clone(),
        ));
        let r_root = build_empty_view_index_root(0x13, layout.index_bytes, layout.cluster_bytes)?;
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_resident_attr(ATTR_INDEX_ROOT, 2, &DOLLAR_R_NAME, false, &r_root)?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            26,
            1,
            0x0009,
            1,
            &attrs,
            3,
        )?;
        place_record(26, &raw);
    }

    // Record 11: $Extend directory (resident SMALL_INDEX $I30 with $ObjId, $Quota, $Reparse).
    {
        extend_entries.sort_by(|a, b| compare_utf16_upcase(&upcase_u16, &a.0, &b.0));
        let encoded_ext_entries: Vec<Vec<u8>> = extend_entries
            .iter()
            .map(|(_, r, fn_raw)| encode_index_entry(*r, fn_raw, None).map_err(|e| parse_err(&e)))
            .collect::<Result<_>>()?;
        let ext_i30_root = build_small_i30_root(
            layout.index_bytes,
            layout.cluster_bytes,
            &encoded_ext_entries,
        )?;
        let (u, fn_raw) = make_fn_bytes(
            root_ref,
            "$Extend",
            0,
            0,
            FILE_ATTR_HIDDEN_SYSTEM | FILE_ATTR_DUP_INDEX,
        )?;
        root_entries.push((u, extend_ref, fn_raw.clone()));
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &fn_raw)?,
            encode_resident_attr(ATTR_INDEX_ROOT, 2, &I30_NAME, false, &ext_i30_root)?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            11,
            11,
            0x0003,
            1,
            &attrs,
            3,
        )?;
        place_record(11, &raw);
    }

    // Records 12..15: Reserved system slots (allocated, IN_USE, unnamed, matching mkntfs).
    for slot in 12_u32..16 {
        let seq = u16::try_from(slot).unwrap_or(1);
        let attrs = vec![encode_resident_attr(
            ATTR_STANDARD_INFORMATION,
            0,
            &[],
            false,
            &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 256),
        )?];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            slot,
            seq,
            0x0001,
            0,
            &attrs,
            1,
        )?;
        place_record(slot, &raw);
    }

    // Record 5: Root directory `.` (LARGE_INDEX $I30 pointing to external INDX block at root_indx_cluster).
    root_entries.sort_by(|a, b| {
        let ord = compare_utf16_upcase(&upcase_u16, &a.0, &b.0);
        if ord == Ordering::Equal {
            a.0.cmp(&b.0)
        } else {
            ord
        }
    });
    let encoded_root_entries: Vec<Vec<u8>> = root_entries
        .iter()
        .map(|(_, r, fn_raw)| encode_index_entry(*r, fn_raw, None).map_err(|e| parse_err(&e)))
        .collect::<Result<_>>()?;
    let root_indx_block = build_leaf_indx_block(layout.index_bytes, &encoded_root_entries)?;
    {
        let (_, dot_fn_raw) = make_fn_bytes(
            root_ref,
            ".",
            0,
            0,
            FILE_ATTR_HIDDEN_SYSTEM | FILE_ATTR_DUP_INDEX,
        )?;
        let root_i30 =
            build_large_i30_root_pointing_zero(layout.index_bytes, layout.cluster_bytes)?;
        let root_alloc_bytes = layout.root_indx_clusters * cb;
        let root_indx_size = u64::from(layout.index_bytes);
        let root_bm = [0x01_u8, 0, 0, 0, 0, 0, 0, 0];
        let attrs = vec![
            encode_resident_attr(
                ATTR_STANDARD_INFORMATION,
                0,
                &[],
                false,
                &encode_standard_info(filetime, FILE_ATTR_HIDDEN_SYSTEM, 257),
            )?,
            encode_resident_attr(ATTR_FILE_NAME, 1, &[], true, &dot_fn_raw)?,
            encode_resident_attr(ATTR_INDEX_ROOT, 2, &I30_NAME, false, &root_i30)?,
            encode_nonresident_attr(
                ATTR_INDEX_ALLOCATION,
                3,
                &I30_NAME,
                0,
                &[NtfsRun {
                    vcn: 0,
                    clusters: layout.root_indx_clusters,
                    lcn: Some(layout.root_indx_cluster),
                }],
                root_alloc_bytes,
                root_indx_size,
                root_indx_size,
                vol_clusters,
            )?,
            encode_resident_attr(ATTR_BITMAP, 4, &I30_NAME, false, &root_bm)?,
        ];
        let raw = encode_file_record(
            layout.version,
            layout.record_bytes,
            5,
            5,
            0x0003,
            1,
            &attrs,
            5,
        )?;
        place_record(5, &raw);
    }

    // Mirror bytes: exact copy of the first `mirror_records` MFT records (0..4 minimum).
    let mirror_len = usize::try_from(layout.mirror_records * u64::from(layout.record_bytes))
        .map_err(|_| format_err("mirror_bytes overflow"))?;
    let mirror_bytes = mft_bytes[..mirror_len].to_vec();

    Ok(BuiltBootstrapVolume {
        vbr_sector,
        boot_stream,
        attrdef_bytes,
        bitmap_bytes,
        upcase_bytes,
        sds_bytes,
        root_indx_block,
        logfile_bytes,
        mft_bytes,
        mirror_bytes,
    })
}
