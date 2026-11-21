//! Deep read-only audit of NTFS system metadata records (`0..15`), unallocated
//! MFT slots, stream/attribute bounds, DOS/Win32 alias pairing, EA/reparse
//! consistency, `$Extend` secondary indexes, `hiberfil.sys`, and `$LogFile`.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::Cx;
use ffs_error::Result;
use ffs_ondisk::ntfs::ea::{NtfsEaInformation, parse_extended_attributes};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::{
    ATTRIBUTE_LIST, COMPRESSED, DATA, EA, EA_INFORMATION, NtfsAttrDef, NtfsFileRecord, NtfsValue,
    REPARSE_POINT, SPARSE, VOLUME_INFORMATION, decode_mapping_pairs, parse_attr_def_table,
    parse_ntfs_logfile, restore_record, validate_ntfs31_attr_def_table,
};

use super::{NtfsCheckCategory, NtfsCheckLimits, NtfsCheckReport};
use crate::reader::allocation::{bit, read_bitmap};
use crate::reader::namespace::parse_file_name;
use crate::reader::{NtfsVolume, Storage, checkpoint, standard_flags};
use crate::transaction::NtfsLogStateSummary;

const BAD_NAME: [u16; 4] = [b'$' as u16, b'B' as u16, b'a' as u16, b'd' as u16];
const HIBERFIL_UPPER: [u16; 12] = [
    b'H' as u16,
    b'I' as u16,
    b'B' as u16,
    b'E' as u16,
    b'R' as u16,
    b'F' as u16,
    b'I' as u16,
    b'L' as u16,
    b'.' as u16,
    b'S' as u16,
    b'Y' as u16,
    b'S' as u16,
];
const USNJRNL_UPPER: [u16; 8] = [
    b'$' as u16,
    b'U' as u16,
    b'S' as u16,
    b'N' as u16,
    b'J' as u16,
    b'R' as u16,
    b'N' as u16,
    b'L' as u16,
];
const QUOTA_UPPER: [u16; 6] = [
    b'$' as u16,
    b'Q' as u16,
    b'U' as u16,
    b'O' as u16,
    b'T' as u16,
    b'A' as u16,
];
const OBJID_UPPER: [u16; 6] = [
    b'$' as u16,
    b'O' as u16,
    b'B' as u16,
    b'J' as u16,
    b'I' as u16,
    b'D' as u16,
];
const REPARSE_UPPER: [u16; 8] = [
    b'$' as u16,
    b'R' as u16,
    b'E' as u16,
    b'P' as u16,
    b'A' as u16,
    b'R' as u16,
    b'S' as u16,
    b'E' as u16,
];
const DOLLAR_O_NAME: [u16; 2] = [b'$' as u16, b'O' as u16];
const DOLLAR_Q_NAME: [u16; 2] = [b'$' as u16, b'Q' as u16];
const DOLLAR_R_NAME: [u16; 2] = [b'$' as u16, b'R' as u16];
const UPCASE_BYTES: u64 = 131_072;
const BOOT_STREAM_BYTES: u64 = 8_192;
const LOG_PAGE_BYTES: usize = 4_096;

#[derive(Debug, Default)]
pub(super) struct DeepAuditOutput {
    pub(super) hibernated: bool,
    pub(super) journal: Option<NtfsLogStateSummary>,
    pub(super) free_slots_examined: u64,
    pub(super) free_slots_marked_in_use: u64,
}

pub(super) fn audit_system_and_records(
    cx: &Cx,
    volume: &NtfsVolume,
    vbr_sector: &[u8],
    limits: NtfsCheckLimits,
    report: &mut NtfsCheckReport,
) -> Result<DeepAuditOutput> {
    checkpoint(cx)?;
    let mut out = DeepAuditOutput::default();
    let record_bytes = u64::from(volume.geometry.record_bytes());
    let logical_records = volume.mft_stream().size / record_bytes;
    let init_records = volume.record_count();
    if logical_records > limits.records {
        report.complete = false;
        report.push_issue(
            NtfsCheckCategory::UnsupportedFeature,
            "mft_record_limit",
            None,
            None,
            format!(
                "logical MFT records ({logical_records}) exceed check limit ({})",
                limits.records
            ),
        );
        return Ok(out);
    }

    let mft_rec = match volume.record(cx, 0, None) {
        Ok(rec) => rec,
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::SystemMetadata,
                "mft_record_unreadable",
                Some(0),
                None,
                format!("cannot read $MFT record 0: {err}"),
            );
            return Ok(out);
        }
    };
    let mft_bm_stream = match volume.select_stream(cx, &mft_rec, 0xB0, &[]) {
        Ok(s) => s,
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::SystemMetadata,
                "mft_bitmap_missing",
                Some(0),
                None,
                format!("$MFT::$BITMAP unreadable: {err}"),
            );
            return Ok(out);
        }
    };
    let mft_bitmap = match read_bitmap(cx, volume, &mft_bm_stream, logical_records) {
        Ok(bm) => bm,
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::SystemMetadata,
                "mft_bitmap_corrupt",
                Some(0),
                None,
                format!("$MFT::$BITMAP invalid: {err}"),
            );
            return Ok(out);
        }
    };

    // 1. Audit reserved system metadata slots 0..15.
    let attr_defs =
        audit_system_slots(cx, volume, vbr_sector, &mft_bitmap, logical_records, report)?;

    // 2. Audit $LogFile (record 2) non-mutatingly.
    out.journal = inspect_logfile_readonly(cx, volume, report)?;

    // 3. Audit root directory for `hiberfil.sys` presence.
    out.hibernated = detect_hiberfil(cx, volume)?;
    if out.hibernated {
        report.push_issue(
            NtfsCheckCategory::Journal,
            "hiberfil_present",
            Some(5),
            None,
            "hiberfil.sys detected in root directory; volume may hold Windows hibernation/Fast Startup state".into(),
        );
    }

    // 4. Audit unallocated MFT slots and per-record stream/DOS-pair/EA/reparse invariants.
    let attr_def_map: BTreeMap<u32, NtfsAttrDef> =
        attr_defs.into_iter().map(|d| (d.type_code, d)).collect();
    let cluster_bytes = u64::from(volume.geometry.cluster_bytes());
    let cluster_count = volume.geometry.cluster_count();

    for slot in 0..logical_records {
        checkpoint(cx)?;
        let allocated = bit(&mft_bitmap, slot);
        if !allocated {
            if slot < init_records {
                out.free_slots_examined += 1;
                if let Ok(raw) = volume.read_mft_record_raw(cx, slot)
                    && raw.len() >= 24
                    && &raw[0..4] == b"FILE"
                {
                    let flags = u16::from_le_bytes([raw[22], raw[23]]);
                    if flags & 0x0001 != 0 {
                        out.free_slots_marked_in_use += 1;
                        report.push_issue(
                            NtfsCheckCategory::MftSlot,
                            "free_slot_marked_in_use",
                            Some(slot),
                            None,
                            format!("MFT slot {slot} is free in $MFT::$BITMAP but on-disk FILE header has IN_USE flag set ({flags:#06x})"),
                        );
                    }
                }
            }
            continue;
        }
        if slot >= init_records {
            continue;
        }
        let Ok(record) = volume.record(cx, slot, None) else {
            continue;
        };
        audit_single_record_attributes(
            cx,
            volume,
            slot,
            &record,
            cluster_bytes,
            cluster_count,
            &attr_def_map,
            report,
        )?;
    }

    Ok(out)
}

#[allow(clippy::too_many_lines)]
fn audit_system_slots(
    cx: &Cx,
    volume: &NtfsVolume,
    vbr_sector: &[u8],
    mft_bitmap: &[u8],
    logical_records: u64,
    report: &mut NtfsCheckReport,
) -> Result<Vec<NtfsAttrDef>> {
    let mut parsed_attr_defs = Vec::new();
    let mandatory_slots: [u64; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    for slot in mandatory_slots {
        checkpoint(cx)?;
        if slot >= logical_records || !bit(mft_bitmap, slot) {
            report.push_issue(
                NtfsCheckCategory::SystemMetadata,
                "system_slot_unallocated",
                Some(slot),
                None,
                format!(
                    "mandatory NTFS system metadata slot {slot} is not allocated in $MFT::$BITMAP"
                ),
            );
        }
    }
    // Slots 12..15 are reserved system metadata slots on standard NTFS 3.x volumes.
    for slot in 12_u64..16 {
        if slot < logical_records && !bit(mft_bitmap, slot) {
            report.push_issue(
                NtfsCheckCategory::SystemMetadata,
                "reserved_system_slot_free",
                Some(slot),
                None,
                format!(
                    "reserved NTFS system slot {slot} is not marked allocated in $MFT::$BITMAP"
                ),
            );
        }
    }

    // Record 3: $Volume
    if let Ok(vol_rec) = volume.record(cx, 3, None) {
        if let Ok(stream) = volume.select_stream(cx, &vol_rec, VOLUME_INFORMATION, &[]) {
            if !stream.resident() || stream.size < 12 {
                report.push_issue(
                    NtfsCheckCategory::SystemMetadata,
                    "volume_info_invalid",
                    Some(3),
                    None,
                    "$Volume::$VOLUME_INFORMATION must be resident and at least 12 bytes".into(),
                );
            }
        } else {
            report.push_issue(
                NtfsCheckCategory::SystemMetadata,
                "volume_info_missing",
                Some(3),
                None,
                "$Volume is missing $VOLUME_INFORMATION (0x70)".into(),
            );
        }
    }

    // Record 4: $AttrDef
    if logical_records > 4 && bit(mft_bitmap, 4) {
        match volume.record(cx, 4, None) {
            Ok(rec) => match volume.select_stream(cx, &rec, DATA, &[]) {
                Ok(stream) => {
                    if stream.size == 0 || stream.size > 65_536 || stream.initialized != stream.size
                    {
                        report.push_issue(
                            NtfsCheckCategory::SystemMetadata,
                            "attrdef_size_invalid",
                            Some(4),
                            None,
                            format!(
                                "$AttrDef::$DATA has invalid size/initialized ({}/{})",
                                stream.size, stream.initialized
                            ),
                        );
                    } else if let Ok(bytes) = volume.read(cx, &stream, 0, stream.size as usize) {
                        match parse_attr_def_table(&bytes) {
                            Ok(defs) => {
                                if let Err(err) = validate_ntfs31_attr_def_table(&defs) {
                                    report.push_issue(
                                        NtfsCheckCategory::SystemMetadata,
                                        "attrdef_schema_invalid",
                                        Some(4),
                                        None,
                                        format!(
                                            "$AttrDef failed NTFS 3.x schema validation: {err}"
                                        ),
                                    );
                                }
                                parsed_attr_defs = defs;
                            }
                            Err(err) => {
                                report.push_issue(
                                    NtfsCheckCategory::SystemMetadata,
                                    "attrdef_parse_failed",
                                    Some(4),
                                    None,
                                    format!("$AttrDef parse error: {err}"),
                                );
                            }
                        }
                    }
                }
                Err(err) => {
                    report.push_issue(
                        NtfsCheckCategory::SystemMetadata,
                        "attrdef_data_missing",
                        Some(4),
                        None,
                        format!("$AttrDef::$DATA missing or unreadable: {err}"),
                    );
                }
            },
            Err(err) => {
                report.push_issue(
                    NtfsCheckCategory::SystemMetadata,
                    "attrdef_unreadable",
                    Some(4),
                    None,
                    format!("$AttrDef record 4 unreadable: {err}"),
                );
            }
        }
    }

    // Record 5: Root directory `.`
    if let Ok(root_rec) = volume.record(cx, 5, None) {
        if !root_rec.is_directory() {
            report.push_issue(
                NtfsCheckCategory::SystemMetadata,
                "root_not_directory",
                Some(5),
                None,
                "MFT record 5 (root) is not marked IS_DIRECTORY".into(),
            );
        }
        if let Ok(attrs) = root_rec.attributes() {
            let has_dot_self = attrs.iter().filter(|a| a.kind == 0x30).any(|a| {
                parse_file_name(a).is_ok_and(|f| {
                    f.name == [u16::from(b'.')]
                        && f.parent.record == 5
                        && f.parent.sequence == root_rec.sequence
                })
            });
            if !has_dot_self {
                report.push_issue(
                    NtfsCheckCategory::SystemMetadata,
                    "root_missing_self_dot",
                    Some(5),
                    None,
                    "MFT record 5 is missing self-referencing '.' FILE_NAME attribute".into(),
                );
            }
        }
    }

    // Record 6: $Bitmap
    if let Ok(bm_rec) = volume.record(cx, 6, None) {
        let min_bytes = volume.geometry.cluster_count().div_ceil(8);
        match volume.select_stream(cx, &bm_rec, DATA, &[]) {
            Ok(stream) => {
                if stream.size < min_bytes || stream.initialized != stream.size {
                    report.push_issue(
                        NtfsCheckCategory::SystemMetadata,
                        "bitmap_short_or_uninitialized",
                        Some(6),
                        None,
                        format!(
                            "$Bitmap size={} initialized={} is shorter than required {min_bytes} bytes for {} clusters",
                            stream.size,
                            stream.initialized,
                            volume.geometry.cluster_count()
                        ),
                    );
                }
            }
            Err(err) => {
                report.push_issue(
                    NtfsCheckCategory::SystemMetadata,
                    "bitmap_missing",
                    Some(6),
                    None,
                    format!("$Bitmap::$DATA unreadable: {err}"),
                );
            }
        }
    }

    // Record 7: $Boot (non-resident at LCN 0, 8192 bytes, sector 0 matches VBR)
    if logical_records > 7 && bit(mft_bitmap, 7) {
        match volume.record(cx, 7, None) {
            Ok(boot_rec) => match volume.select_stream(cx, &boot_rec, DATA, &[]) {
                Ok(stream) => {
                    let boot_ok_runs = match &stream.storage {
                        Storage::Mapped(runs) => {
                            runs.first().is_some_and(|r| r.lcn == Some(0))
                                && runs.iter().all(|r| r.lcn.is_some())
                        }
                        _ => false,
                    };
                    if !boot_ok_runs || stream.size < BOOT_STREAM_BYTES {
                        report.push_issue(
                            NtfsCheckCategory::SystemMetadata,
                            "boot_stream_invalid",
                            Some(7),
                            Some(0),
                            format!(
                                "$Boot::$DATA must be non-resident starting at LCN 0 with size >= {BOOT_STREAM_BYTES} (got size={})",
                                stream.size
                            ),
                        );
                    } else if let Ok(first_sector) = volume.read(cx, &stream, 0, vbr_sector.len())
                        && first_sector.as_slice() != vbr_sector
                    {
                        report.push_issue(
                            NtfsCheckCategory::Boot,
                            "boot_stream_vbr_mismatch",
                            Some(7),
                            Some(0),
                            "$Boot::$DATA sector 0 disagrees with primary VBR".into(),
                        );
                    }
                }
                Err(err) => {
                    report.push_issue(
                        NtfsCheckCategory::SystemMetadata,
                        "boot_stream_missing",
                        Some(7),
                        None,
                        format!("$Boot::$DATA missing or unreadable: {err}"),
                    );
                }
            },
            Err(err) => {
                report.push_issue(
                    NtfsCheckCategory::SystemMetadata,
                    "boot_record_unreadable",
                    Some(7),
                    None,
                    format!("$Boot record 7 unreadable: {err}"),
                );
            }
        }
    }

    // Record 8: $BadClus (unnamed resident empty $DATA + named $Bad covering volume clusters)
    if logical_records > 8 && bit(mft_bitmap, 8) {
        match volume.record(cx, 8, None) {
            Ok(bad_rec) => {
                if let Ok(catalog) = volume.attributes(cx, &bad_rec)
                    && let Ok(all) = catalog.all()
                {
                    let mut saw_bad_stream = false;
                    let vol_clusters = volume.geometry.cluster_count();
                    let cluster_bytes = u64::from(volume.geometry.cluster_bytes());
                    let expected_bytes = vol_clusters.saturating_mul(cluster_bytes);
                    for attr in &all {
                        if attr.kind == DATA && attr.name == BAD_NAME {
                            saw_bad_stream = true;
                            if let NtfsValue::NonResident(ref nr) = attr.value {
                                if nr.data_bytes != expected_bytes {
                                    report.push_issue(
                                        NtfsCheckCategory::SystemMetadata,
                                        "badclus_size_mismatch",
                                        Some(8),
                                        None,
                                        format!(
                                            "$BadClus:$Bad data_bytes ({}) != volume cluster span ({expected_bytes})",
                                            nr.data_bytes
                                        ),
                                    );
                                }
                                if let Err(err) = decode_mapping_pairs(
                                    nr.mapping_pairs,
                                    nr.first_vcn,
                                    nr.last_vcn,
                                    vol_clusters,
                                ) {
                                    report.push_issue(
                                        NtfsCheckCategory::SystemMetadata,
                                        "badclus_mapping_corrupt",
                                        Some(8),
                                        None,
                                        format!("$BadClus:$Bad mapping pairs invalid: {err}"),
                                    );
                                }
                            } else {
                                report.push_issue(
                                    NtfsCheckCategory::SystemMetadata,
                                    "badclus_bad_resident",
                                    Some(8),
                                    None,
                                    "$BadClus:$Bad stream must be non-resident".into(),
                                );
                            }
                        }
                    }
                    if !saw_bad_stream {
                        report.push_issue(
                            NtfsCheckCategory::SystemMetadata,
                            "badclus_bad_missing",
                            Some(8),
                            None,
                            "$BadClus record 8 is missing named '$Bad' $DATA stream".into(),
                        );
                    }
                }
            }
            Err(err) => {
                report.push_issue(
                    NtfsCheckCategory::SystemMetadata,
                    "badclus_unreadable",
                    Some(8),
                    None,
                    format!("$BadClus record 8 unreadable: {err}"),
                );
            }
        }
    }

    // Record 10: $UpCase (131,072 bytes, ASCII a..z -> A..Z, idempotent)
    if logical_records > 10
        && bit(mft_bitmap, 10)
        && let Ok(up_rec) = volume.record(cx, 10, None)
    {
        match volume.select_stream(cx, &up_rec, DATA, &[]) {
            Ok(stream) => {
                if stream.size != UPCASE_BYTES || stream.initialized != UPCASE_BYTES {
                    report.push_issue(
                        NtfsCheckCategory::SystemMetadata,
                        "upcase_size_invalid",
                        Some(10),
                        None,
                        format!(
                            "$UpCase::$DATA must be {UPCASE_BYTES} initialized bytes (got {}/{})",
                            stream.size, stream.initialized
                        ),
                    );
                } else if let Ok(raw) = volume.read(cx, &stream, 0, UPCASE_BYTES as usize) {
                    let mut table = vec![0_u16; 65_536];
                    for (i, &[lo, hi]) in raw.as_chunks::<2>().0.iter().enumerate() {
                        table[i] = u16::from_le_bytes([lo, hi]);
                    }
                    let mut bad_idemp = false;
                    for (i, &mapped) in table.iter().enumerate() {
                        if table[usize::from(mapped)] != mapped {
                            bad_idemp = true;
                            break;
                        }
                        if (usize::from(b'a')..=usize::from(b'z')).contains(&i)
                            && mapped != u16::try_from(i - 32).unwrap_or(0)
                        {
                            bad_idemp = true;
                            break;
                        }
                    }
                    if bad_idemp {
                        report.push_issue(
                            NtfsCheckCategory::SystemMetadata,
                            "upcase_non_idempotent",
                            Some(10),
                            None,
                            "$UpCase table failed idempotence or ASCII uppercase invariant".into(),
                        );
                    }
                }
            }
            Err(err) => {
                report.push_issue(
                    NtfsCheckCategory::SystemMetadata,
                    "upcase_missing",
                    Some(10),
                    None,
                    format!("$UpCase::$DATA unreadable: {err}"),
                );
            }
        }
    }

    // Record 11: $Extend secondary indexes ($ObjId, $Quota, $Reparse, $UsnJrnl)
    if logical_records > 11 && bit(mft_bitmap, 11) {
        audit_extend_directory(cx, volume, report)?;
    }

    Ok(parsed_attr_defs)
}

fn audit_extend_directory(
    cx: &Cx,
    volume: &NtfsVolume,
    report: &mut NtfsCheckReport,
) -> Result<()> {
    let extend_rec = match volume.record(cx, 11, None) {
        Ok(r) => r,
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::SecondaryIndex,
                "extend_unreadable",
                Some(11),
                None,
                format!("$Extend record 11 unreadable: {err}"),
            );
            return Ok(());
        }
    };
    if !extend_rec.is_directory() {
        report.push_issue(
            NtfsCheckCategory::SecondaryIndex,
            "extend_not_directory",
            Some(11),
            None,
            "$Extend record 11 is not marked IS_DIRECTORY".into(),
        );
        return Ok(());
    }
    let entries = match volume.list_directory(cx, &extend_rec) {
        Ok(e) => e,
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::SecondaryIndex,
                "extend_index_corrupt",
                Some(11),
                None,
                format!("$Extend::$I30 unreadable: {err}"),
            );
            return Ok(());
        }
    };
    for entry in entries {
        checkpoint(cx)?;
        let upper: Vec<u16> = entry
            .filename
            .name
            .iter()
            .map(|&u| {
                if (u16::from(b'a')..=u16::from(b'z')).contains(&u) {
                    u - 32
                } else {
                    u
                }
            })
            .collect();
        let child_rec =
            match volume.record(cx, entry.reference.record, Some(entry.reference.sequence)) {
                Ok(r) => r,
                Err(err) => {
                    report.push_issue(
                        NtfsCheckCategory::SecondaryIndex,
                        "extend_child_unreadable",
                        Some(entry.reference.record),
                        None,
                        format!("$Extend child unreadable: {err}"),
                    );
                    continue;
                }
            };
        if upper.as_slice() == OBJID_UPPER {
            validate_view_index_root_attr(
                cx,
                volume,
                &child_rec,
                &DOLLAR_O_NAME,
                0x11,
                "$Extend/$ObjId::$O",
                report,
            )?;
        } else if upper.as_slice() == REPARSE_UPPER {
            validate_view_index_root_attr(
                cx,
                volume,
                &child_rec,
                &DOLLAR_R_NAME,
                0x13,
                "$Extend/$Reparse::$R",
                report,
            )?;
        } else if upper.as_slice() == QUOTA_UPPER {
            validate_view_index_root_attr(
                cx,
                volume,
                &child_rec,
                &DOLLAR_Q_NAME,
                0x10,
                "$Extend/$Quota::$Q",
                report,
            )?;
            validate_view_index_root_attr(
                cx,
                volume,
                &child_rec,
                &DOLLAR_O_NAME,
                0x11,
                "$Extend/$Quota::$O",
                report,
            )?;
        } else if upper.as_slice() == USNJRNL_UPPER {
            // Note active $UsnJrnl honestly without falsely declaring corruption.
            if let Ok(attrs) = child_rec.attributes()
                && attrs.iter().any(|a| a.kind == DATA)
            {
                report.push_issue(
                    NtfsCheckCategory::UnsupportedFeature,
                    "usnjrnl_present",
                    Some(entry.reference.record),
                    None,
                    "$Extend/$UsnJrnl change journal is present; journal record payload validation is not implemented".into(),
                );
            }
        }
    }
    Ok(())
}

fn validate_view_index_root_attr(
    cx: &Cx,
    volume: &NtfsVolume,
    record: &NtfsFileRecord,
    index_name: &[u16],
    expected_collation: u32,
    label: &str,
    report: &mut NtfsCheckReport,
) -> Result<()> {
    checkpoint(cx)?;
    let Ok(catalog) = volume.attributes(cx, record) else {
        report.push_issue(
            NtfsCheckCategory::SecondaryIndex,
            "secondary_index_catalog_corrupt",
            Some(u64::from(record.number)),
            None,
            format!("{label}: failed to resolve attribute catalog"),
        );
        return Ok(());
    };
    let Ok(stream) = catalog.select(&volume.geometry, 0x90, index_name) else {
        report.push_issue(
            NtfsCheckCategory::SecondaryIndex,
            "secondary_index_root_missing",
            Some(u64::from(record.number)),
            None,
            format!("{label}: missing resident INDEX_ROOT"),
        );
        return Ok(());
    };
    if !stream.resident() || stream.size < 48 || stream.size > 65_536 {
        report.push_issue(
            NtfsCheckCategory::SecondaryIndex,
            "secondary_index_root_invalid",
            Some(u64::from(record.number)),
            None,
            format!(
                "{label}: invalid INDEX_ROOT residency or size ({})",
                stream.size
            ),
        );
        return Ok(());
    }
    let bytes = volume.read(cx, &stream, 0, stream.size as usize)?;
    let attr_type = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let collation = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let entries_off = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
    let used = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) as usize;
    let allocated = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;
    if attr_type != 0
        || collation != expected_collation
        || entries_off < 16
        || !entries_off.is_multiple_of(8)
        || entries_off > used
        || used > allocated
        || 16 + allocated > bytes.len()
    {
        report.push_issue(
            NtfsCheckCategory::SecondaryIndex,
            "secondary_index_header_corrupt",
            Some(u64::from(record.number)),
            None,
            format!(
                "{label}: malformed view INDEX_ROOT header (attr_type={attr_type:#x}, collation={collation:#x}, used={used}, alloc={allocated})"
            ),
        );
        return Ok(());
    }
    // Walk entries until terminal END entry (flag 2).
    let mut pos = 16 + entries_off;
    let end = 16 + used;
    let mut found_end = false;
    while pos + 16 <= end {
        let len = usize::from(u16::from_le_bytes([bytes[pos + 8], bytes[pos + 9]]));
        let flags = u16::from_le_bytes([bytes[pos + 12], bytes[pos + 13]]);
        if len < 16 || !len.is_multiple_of(8) || pos + len > end {
            report.push_issue(
                NtfsCheckCategory::SecondaryIndex,
                "secondary_index_entry_corrupt",
                Some(u64::from(record.number)),
                None,
                format!("{label}: malformed index entry length {len} at offset {pos}"),
            );
            return Ok(());
        }
        if flags & 2 != 0 {
            found_end = true;
            break;
        }
        pos += len;
    }
    if !found_end {
        report.push_issue(
            NtfsCheckCategory::SecondaryIndex,
            "secondary_index_missing_end",
            Some(u64::from(record.number)),
            None,
            format!("{label}: INDEX_ROOT missing terminal END entry"),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn audit_single_record_attributes(
    cx: &Cx,
    volume: &NtfsVolume,
    slot: u64,
    record: &NtfsFileRecord,
    cluster_bytes: u64,
    cluster_count: u64,
    attr_defs: &BTreeMap<u32, NtfsAttrDef>,
    report: &mut NtfsCheckReport,
) -> Result<()> {
    let attrs = match record.attributes() {
        Ok(a) => a,
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::StreamBounds,
                "record_attributes_unreadable",
                Some(slot),
                None,
                format!("MFT record {slot} attributes invalid: {err}"),
            );
            return Ok(());
        }
    };

    let is_base = record.base.record == 0 && record.base.sequence == 0;
    let mut has_ea_info = false;
    let mut has_ea = false;
    let mut has_reparse_attr = false;
    let mut has_attr_list = false;
    let mut file_names: Vec<NtfsFileName> = Vec::new();

    for attr in &attrs {
        checkpoint(cx)?;
        if attr.kind == ATTRIBUTE_LIST {
            has_attr_list = true;
        }
        if attr.kind == EA_INFORMATION {
            has_ea_info = true;
        }
        if attr.kind == EA {
            has_ea = true;
        }
        if attr.kind == REPARSE_POINT {
            has_reparse_attr = true;
        }
        if attr.kind == 0x30
            && let Ok(parsed) = parse_file_name(attr)
        {
            file_names.push(parsed);
        }

        // Check against $AttrDef schema if loaded.
        if let Some(def) = attr_defs.get(&attr.kind) {
            match attr.value {
                NtfsValue::Resident(val) => {
                    if !def.allows_resident() {
                        report.push_issue(
                            NtfsCheckCategory::StreamBounds,
                            "attrdef_residency_violation",
                            Some(slot),
                            None,
                            format!(
                                "record {slot} attribute {:#x} is resident but $AttrDef forbids resident form",
                                attr.kind
                            ),
                        );
                    }
                    if def.validate_value_size(val.len() as u64).is_err() {
                        report.push_issue(
                            NtfsCheckCategory::StreamBounds,
                            "attrdef_size_violation",
                            Some(slot),
                            None,
                            format!(
                                "record {slot} resident attribute {:#x} length {} violates $AttrDef bounds",
                                attr.kind,
                                val.len()
                            ),
                        );
                    }
                }
                NtfsValue::NonResident(ref nr) => {
                    if !def.allows_non_resident() {
                        report.push_issue(
                            NtfsCheckCategory::StreamBounds,
                            "attrdef_nonresident_violation",
                            Some(slot),
                            None,
                            format!(
                                "record {slot} attribute {:#x} is non-resident but $AttrDef requires resident",
                                attr.kind
                            ),
                        );
                    }
                    if nr.first_vcn == 0 && def.validate_value_size(nr.data_bytes).is_err() {
                        report.push_issue(
                            NtfsCheckCategory::StreamBounds,
                            "attrdef_size_violation",
                            Some(slot),
                            None,
                            format!(
                                "record {slot} non-resident attribute {:#x} data_bytes {} violates $AttrDef bounds",
                                attr.kind, nr.data_bytes
                            ),
                        );
                    }
                }
            }
        }

        // Non-resident stream size / VCN / cluster-multiple bounds.
        if let NtfsValue::NonResident(ref nr) = attr.value {
            let is_compressed = attr.flags & COMPRESSED != 0 || nr.compression_unit != 0;
            let is_sparse = attr.flags & SPARSE != 0;
            if nr.first_vcn == 0 {
                if nr.initialized_bytes > nr.data_bytes {
                    report.push_issue(
                        NtfsCheckCategory::StreamBounds,
                        "initialized_exceeds_data",
                        Some(slot),
                        None,
                        format!(
                            "record {slot} attr {:#x}: initialized_bytes ({}) > data_bytes ({})",
                            attr.kind, nr.initialized_bytes, nr.data_bytes
                        ),
                    );
                }
                if nr.data_bytes > nr.allocated_bytes {
                    report.push_issue(
                        NtfsCheckCategory::StreamBounds,
                        "data_exceeds_allocated",
                        Some(slot),
                        None,
                        format!(
                            "record {slot} attr {:#x}: data_bytes ({}) > allocated_bytes ({})",
                            attr.kind, nr.data_bytes, nr.allocated_bytes
                        ),
                    );
                }
                if !nr.allocated_bytes.is_multiple_of(cluster_bytes) {
                    report.push_issue(
                        NtfsCheckCategory::StreamBounds,
                        "allocated_not_cluster_aligned",
                        Some(slot),
                        None,
                        format!(
                            "record {slot} attr {:#x}: allocated_bytes ({}) is not a multiple of cluster_bytes ({cluster_bytes})",
                            attr.kind, nr.allocated_bytes
                        ),
                    );
                }
                if !is_compressed && !is_sparse && !has_attr_list {
                    let expected_vcn_clusters = nr.allocated_bytes / cluster_bytes;
                    let declared_vcn_clusters = if nr.allocated_bytes == 0 {
                        0
                    } else {
                        nr.last_vcn.saturating_sub(nr.first_vcn).saturating_add(1)
                    };
                    if declared_vcn_clusters != expected_vcn_clusters {
                        report.push_issue(
                            NtfsCheckCategory::StreamBounds,
                            "vcn_span_mismatch",
                            Some(slot),
                            None,
                            format!(
                                "record {slot} attr {:#x}: VCN span ({declared_vcn_clusters}) != allocated clusters ({expected_vcn_clusters})",
                                attr.kind
                            ),
                        );
                    }
                }
            }
            if let Err(err) =
                decode_mapping_pairs(nr.mapping_pairs, nr.first_vcn, nr.last_vcn, cluster_count)
            {
                report.push_issue(
                    NtfsCheckCategory::StreamBounds,
                    "mapping_pairs_corrupt",
                    Some(slot),
                    None,
                    format!(
                        "record {slot} attr {:#x} mapping pairs invalid: {err}",
                        attr.kind
                    ),
                );
            }
        }
    }

    // For base records without extension splitting, validate cross-attribute consistency.
    if is_base && !has_attr_list {
        // DOS (namespace 2) <-> Win32 (namespace 1) pairing per parent directory.
        let mut dos_parents: BTreeSet<(u64, u16)> = BTreeSet::new();
        let mut win32_parents: BTreeSet<(u64, u16)> = BTreeSet::new();
        for f in &file_names {
            let parent_key = (f.parent.record, f.parent.sequence);
            match f.namespace {
                1 => {
                    win32_parents.insert(parent_key);
                }
                2 => {
                    dos_parents.insert(parent_key);
                }
                _ => {}
            }
        }
        for dos_parent in &dos_parents {
            if !win32_parents.contains(dos_parent) {
                report.push_issue(
                    NtfsCheckCategory::Namespace,
                    "unpaired_dos_file_name",
                    Some(slot),
                    None,
                    format!(
                        "record {slot} has DOS (0x02) FILE_NAME in parent {}:{} without paired Win32 (0x01) FILE_NAME",
                        dos_parent.0, dos_parent.1
                    ),
                );
            }
        }

        // REPARSE_POINT flag agreement.
        if let Ok(Some(std_flags)) = standard_flags(&attrs) {
            let flag_set = std_flags & 0x0400 != 0;
            if flag_set != has_reparse_attr {
                report.push_issue(
                    NtfsCheckCategory::StreamBounds,
                    "reparse_flag_mismatch",
                    Some(slot),
                    None,
                    format!(
                        "record {slot} FILE_ATTRIBUTE_REPARSE_POINT ({flag_set}) disagrees with $REPARSE_POINT attribute ({has_reparse_attr})"
                    ),
                );
            }
        }

        // EA_INFORMATION (0xD0) <-> EA (0xE0) agreement.
        if has_ea_info != has_ea {
            report.push_issue(
                NtfsCheckCategory::StreamBounds,
                "ea_attribute_mismatch",
                Some(slot),
                None,
                format!(
                    "record {slot} EA_INFORMATION ({has_ea_info}) and EA ({has_ea}) must both be present or both absent"
                ),
            );
        } else if has_ea_info
            && has_ea
            && let Ok(info_stream) = volume.select_stream(cx, record, EA_INFORMATION, &[])
            && let Ok(ea_stream) = volume.select_stream(cx, record, EA, &[])
            && info_stream.size == 8
            && ea_stream.size <= 65_536
            && let Ok(info_bytes) = volume.read(cx, &info_stream, 0, 8)
            && let Ok(ea_bytes) = volume.read(cx, &ea_stream, 0, ea_stream.size as usize)
        {
            let parsed_ok = NtfsEaInformation::parse(&info_bytes)
                .and_then(|info| parse_extended_attributes(&info, &ea_bytes));
            if let Err(err) = parsed_ok {
                report.push_issue(
                    NtfsCheckCategory::StreamBounds,
                    "ea_payload_corrupt",
                    Some(slot),
                    None,
                    format!("record {slot} EA payload failed validation: {err}"),
                );
            }
        }
    }

    Ok(())
}

fn detect_hiberfil(cx: &Cx, volume: &NtfsVolume) -> Result<bool> {
    checkpoint(cx)?;
    let Ok(root) = volume.record(cx, 5, None) else {
        return Ok(false);
    };
    let Ok(entries) = volume.list_directory(cx, &root) else {
        return Ok(false);
    };
    for entry in entries {
        let upper: Vec<u16> = entry
            .filename
            .name
            .iter()
            .map(|&u| {
                if (u16::from(b'a')..=u16::from(b'z')).contains(&u) {
                    u - 32
                } else {
                    u
                }
            })
            .collect();
        if upper.as_slice() == HIBERFIL_UPPER {
            return Ok(true);
        }
    }
    Ok(false)
}

fn inspect_logfile_readonly(
    cx: &Cx,
    volume: &NtfsVolume,
    report: &mut NtfsCheckReport,
) -> Result<Option<NtfsLogStateSummary>> {
    checkpoint(cx)?;
    let log_rec = match volume.record(cx, 2, None) {
        Ok(r) => r,
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::Journal,
                "logfile_record_unreadable",
                Some(2),
                None,
                format!("$LogFile record 2 unreadable: {err}"),
            );
            return Ok(None);
        }
    };
    let stream = match volume.select_stream(cx, &log_rec, DATA, &[]) {
        Ok(s) => s,
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::Journal,
                "logfile_data_missing",
                Some(2),
                None,
                format!("$LogFile::$DATA unreadable: {err}"),
            );
            return Ok(None);
        }
    };
    let min_bytes = (50 * LOG_PAGE_BYTES) as u64;
    if stream.resident()
        || stream.initialized != stream.size
        || stream.size < min_bytes
        || !stream.size.is_multiple_of(LOG_PAGE_BYTES as u64)
    {
        report.push_issue(
            NtfsCheckCategory::Journal,
            "logfile_geometry_invalid",
            Some(2),
            None,
            format!(
                "$LogFile::$DATA has invalid geometry (size={}, init={})",
                stream.size, stream.initialized
            ),
        );
        return Ok(None);
    }

    // Check first two RSTR pages (8 KiB) first.
    let head = volume.read(cx, &stream, 0, LOG_PAGE_BYTES * 2)?;
    if head.iter().all(|&b| b == 0xFF) {
        return Ok(Some(NtfsLogStateSummary {
            erased: true,
            clean: true,
            version: (0, 0),
            page_size: LOG_PAGE_BYTES as u32,
            file_size: stream.size,
            oldest_lsn: 0,
            current_lsn: 0,
            client_restart_lsn: 0,
            torn_rstr_slot: None,
        }));
    }

    let rstr0_ok = restore_record(&head[0..LOG_PAGE_BYTES], b"RSTR").is_ok();
    let rstr1_ok = restore_record(&head[LOG_PAGE_BYTES..LOG_PAGE_BYTES * 2], b"RSTR").is_ok();
    let torn_rstr_slot = match (rstr0_ok, rstr1_ok) {
        (true, true) => None,
        (false, true) => Some(0),
        (true, false) => Some(1),
        (false, false) => {
            report.push_issue(
                NtfsCheckCategory::Journal,
                "logfile_both_rstr_corrupt",
                Some(2),
                None,
                "both $LogFile RSTR restart pages (0 and 1) are corrupt".into(),
            );
            return Ok(None);
        }
    };
    if let Some(slot) = torn_rstr_slot {
        report.push_issue(
            NtfsCheckCategory::Journal,
            "logfile_torn_rstr",
            Some(2),
            None,
            format!("$LogFile RSTR restart slot {slot} is torn/corrupt"),
        );
    }

    // Parse complete $LogFile up to 64 MiB cap (standard Windows max default).
    if stream.size > 64 * 1024 * 1024 {
        report.complete = false;
        report.push_issue(
            NtfsCheckCategory::UnsupportedFeature,
            "logfile_exceeds_check_cap",
            Some(2),
            None,
            format!(
                "$LogFile size ({}) exceeds 64 MiB read-only audit cap",
                stream.size
            ),
        );
        return Ok(None);
    }

    let mut full = Vec::new();
    full.try_reserve_exact(stream.size as usize)
        .map_err(|e| ffs_error::FfsError::Io(std::io::Error::other(e)))?;
    let mut offset = 0_u64;
    while offset < stream.size {
        checkpoint(cx)?;
        let chunk_len = ((stream.size - offset).min(1024 * 1024)) as usize;
        let part = volume.read(cx, &stream, offset, chunk_len)?;
        full.extend_from_slice(&part);
        offset += chunk_len as u64;
    }

    match parse_ntfs_logfile(&full) {
        Ok(plan) => {
            let redo = plan.redo_actions.len();
            let undo = plan.undo_actions.len();
            let restart_clean = plan.restart.flags & 0x0002 != 0;
            let clean = restart_clean && redo == 0 && undo == 0 && torn_rstr_slot.is_none();
            if !clean {
                report.push_issue(
                    NtfsCheckCategory::Journal,
                    "logfile_dirty",
                    Some(2),
                    None,
                    format!(
                        "$LogFile is dirty (lsn={}, redo_actions={redo}, undo_actions={undo}, flags={:#06x})",
                        plan.restart.current_lsn, plan.restart.flags
                    ),
                );
            }
            Ok(Some(NtfsLogStateSummary {
                erased: false,
                clean,
                version: (
                    u16::try_from(plan.restart.major_version).unwrap_or(0),
                    u16::try_from(plan.restart.minor_version).unwrap_or(0),
                ),
                page_size: plan.restart.log_page_size,
                file_size: plan.restart.file_size,
                oldest_lsn: plan.restart.oldest_lsn,
                current_lsn: plan.restart.current_lsn,
                client_restart_lsn: plan.restart.client_restart_lsn,
                torn_rstr_slot,
            }))
        }
        Err(err) => {
            report.push_issue(
                NtfsCheckCategory::Journal,
                "logfile_parse_failed",
                Some(2),
                None,
                format!("$LogFile failed ARIES parse: {err}"),
            );
            Ok(None)
        }
    }
}
