//! Bounded NTFS 3.1 boot, multi-sector record, attribute and mapping-pair parsing.
//!
//! No I/O, decompression or backing-store mutation. Sources: Microsoft's
//! ATTRIBUTE_RECORD_HEADER, FILE_RECORD_SEGMENT_HEADER and MULTI_SECTOR_HEADER
//! documentation. Update-sequence protection uses 512-byte strides even when
//! the BPB advertises larger sectors. Names remain native UTF-16 code units.

pub mod attribute_list;
pub mod ea;
pub mod index;
pub mod recovery;
pub mod reparse;

use ffs_types::ParseError;

pub const ATTRIBUTE_LIST: u32 = 0x20;
pub const DATA: u32 = 0x80;
pub const VOLUME_INFORMATION: u32 = 0x70;
pub const REPARSE_POINT: u32 = 0xC0;
pub const EA_INFORMATION: u32 = 0xD0;
pub const EA: u32 = 0xE0;
pub const COMPRESSED: u16 = 0x0001;
pub const ENCRYPTED: u16 = 0x4000;
pub const SPARSE: u16 = 0x8000;
const MAX_RECORD_BYTES: usize = 65_536;

fn invalid(field: &'static str, reason: &'static str) -> ParseError {
    ParseError::InvalidField { field, reason }
}

fn bytes<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], ParseError> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| invalid("ntfs.offset", "overflow"))?;
    input
        .get(offset..end)
        .ok_or_else(|| invalid("ntfs.record", "truncated field"))?
        .try_into()
        .map_err(|_| invalid("ntfs.record", "truncated field"))
}

fn le16(input: &[u8], at: usize) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(bytes(input, at)?))
}
fn le32(input: &[u8], at: usize) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(bytes(input, at)?))
}
fn le64(input: &[u8], at: usize) -> Result<u64, ParseError> {
    Ok(u64::from_le_bytes(bytes(input, at)?))
}

/// Validated geometry of an already selected volume. Hidden sectors are never
/// added again. Bytes after the BPB's addressable region are not file data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsGeometry {
    sector_bytes: u32,
    cluster_bytes: u32,
    volume_bytes: u64,
    cluster_count: u64,
    mft_cluster: u64,
    mirror_cluster: u64,
    record_bytes: u32,
    index_bytes: u32,
    serial: u64,
}

impl NtfsGeometry {
    pub fn parse(boot: &[u8], backing_bytes: u64) -> Result<Self, ParseError> {
        if boot.len() < 512 || &boot[3..11] != b"NTFS    " || le16(boot, 510)? != 0xAA55 {
            return Err(invalid(
                "ntfs.boot",
                "missing NTFS OEM identifier or boot signature",
            ));
        }
        let sector_bytes = u32::from(le16(boot, 11)?);
        if !matches!(sector_bytes, 512 | 1024 | 2048 | 4096) {
            return Err(invalid("ntfs.sector_bytes", "unsupported sector size"));
        }
        let sectors_per_cluster = u32::from(boot[13]);
        if !sectors_per_cluster.is_power_of_two() || sectors_per_cluster > 128 {
            return Err(invalid("ntfs.cluster", "unsupported cluster encoding"));
        }
        let cluster_bytes = sector_bytes * sectors_per_cluster;
        if cluster_bytes > 65_536 {
            return Err(invalid(
                "ntfs.cluster",
                "read profile supports at most 64 KiB clusters",
            ));
        }
        // 0x24 is the BIOS drive and 0x26 the extended boot signature;
        // these are not the legacy FAT sector-count field at 0x20.
        if boot[14..21]
            .iter()
            .chain(&boot[22..24])
            .chain(&boot[32..36])
            .any(|b| *b != 0)
        {
            return Err(invalid("ntfs.bpb", "legacy FAT fields must be zero"));
        }
        let volume_bytes = le64(boot, 40)?
            .checked_mul(u64::from(sector_bytes))
            .ok_or_else(|| invalid("ntfs.volume", "byte length overflow"))?;
        if volume_bytes < u64::from(cluster_bytes) || volume_bytes > backing_bytes {
            return Err(invalid(
                "ntfs.volume",
                "zero or truncated addressable volume",
            ));
        }
        let record_size = |encoded: u8| -> Result<u32, ParseError> {
            let signed = i8::from_ne_bytes([encoded]);
            let size = if signed < 0 {
                1_u32.checked_shl(u32::from(signed.unsigned_abs()))
            } else {
                u32::from(encoded).checked_mul(cluster_bytes)
            }
            .ok_or_else(|| invalid("ntfs.record_size", "size encoding overflow"))?;
            if !(512..=65_536).contains(&size) || !size.is_power_of_two() {
                return Err(invalid("ntfs.record_size", "unsupported record size"));
            }
            Ok(size)
        };
        let geometry = Self {
            sector_bytes,
            cluster_bytes,
            volume_bytes,
            cluster_count: volume_bytes / u64::from(cluster_bytes),
            mft_cluster: le64(boot, 48)?,
            mirror_cluster: le64(boot, 56)?,
            record_bytes: record_size(boot[64])?,
            index_bytes: record_size(boot[68])?,
            serial: le64(boot, 72)?,
        };
        if geometry.mft_cluster == 0 || geometry.mft_cluster == geometry.mirror_cluster {
            return Err(invalid(
                "ntfs.mft",
                "invalid or aliased MFT bootstrap locations",
            ));
        }
        for cluster in [geometry.mft_cluster, geometry.mirror_cluster] {
            let start = geometry.cluster_offset(cluster)?;
            if cluster == 0
                || start
                    .checked_add(u64::from(geometry.record_bytes))
                    .is_none_or(|end| end > geometry.volume_bytes)
            {
                return Err(invalid("ntfs.mft", "bootstrap record outside volume"));
            }
        }
        Ok(geometry)
    }

    #[must_use]
    pub const fn sector_bytes(&self) -> u32 {
        self.sector_bytes
    }
    #[must_use]
    pub const fn cluster_bytes(&self) -> u32 {
        self.cluster_bytes
    }
    #[must_use]
    pub const fn volume_bytes(&self) -> u64 {
        self.volume_bytes
    }
    #[must_use]
    pub const fn cluster_count(&self) -> u64 {
        self.cluster_count
    }
    #[must_use]
    pub const fn mft_cluster(&self) -> u64 {
        self.mft_cluster
    }
    #[must_use]
    pub const fn mirror_cluster(&self) -> u64 {
        self.mirror_cluster
    }
    #[must_use]
    pub const fn record_bytes(&self) -> u32 {
        self.record_bytes
    }
    #[must_use]
    pub const fn index_bytes(&self) -> u32 {
        self.index_bytes
    }
    #[must_use]
    pub const fn serial(&self) -> u64 {
        self.serial
    }

    pub fn cluster_offset(&self, cluster: u64) -> Result<u64, ParseError> {
        if cluster >= self.cluster_count {
            return Err(invalid("ntfs.lcn", "cluster outside addressable volume"));
        }
        Ok(cluster * u64::from(self.cluster_bytes))
    }
}

/// Validate every protected trailer before copying or restoring any byte.
/// The input is never modified, including on a late torn-sector failure.
pub fn restore_record(raw: &[u8], signature: &[u8; 4]) -> Result<Vec<u8>, ParseError> {
    if raw.len() < 512
        || raw.len() > MAX_RECORD_BYTES
        || !raw.len().is_multiple_of(512)
        || raw.get(..4) != Some(signature.as_slice())
    {
        return Err(invalid(
            "ntfs.multi_sector",
            "wrong signature or protected record length",
        ));
    }
    let offset = usize::from(le16(raw, 4)?);
    let count = usize::from(le16(raw, 6)?);
    let end = offset
        .checked_add(count * 2)
        .ok_or_else(|| invalid("ntfs.usa", "overflow"))?;
    if offset < 8 || !offset.is_multiple_of(2) || count != raw.len() / 512 + 1 || end > 510 {
        return Err(invalid("ntfs.usa", "invalid update sequence array bounds"));
    }
    let token = le16(raw, offset)?;
    for part in 1..count {
        if le16(raw, part * 512 - 2)? != token {
            return Err(invalid("ntfs.usa", "torn multi-sector record"));
        }
    }
    let mut restored = raw.to_vec();
    for part in 1..count {
        restored[part * 512 - 2..part * 512]
            .copy_from_slice(&raw[offset + part * 2..offset + part * 2 + 2]);
    }
    Ok(restored)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsReference {
    pub record: u64,
    pub sequence: u16,
}
impl NtfsReference {
    #[must_use]
    pub const fn decode(raw: u64) -> Self {
        Self {
            record: raw & 0x0000_FFFF_FFFF_FFFF,
            sequence: (raw >> 48) as u16,
        }
    }
}

#[derive(Debug)]
pub struct NtfsFileRecord {
    data: Vec<u8>,
    first_attribute: usize,
    pub sequence: u16,
    pub flags: u16,
    pub hard_links: u16,
    pub base: NtfsReference,
    pub number: u32,
}

impl NtfsFileRecord {
    pub fn parse(raw: &[u8]) -> Result<Self, ParseError> {
        let mut data = restore_record(raw, b"FILE")?;
        let used = usize::try_from(le32(&data, 24)?)
            .map_err(|_| invalid("ntfs.file_record", "used length overflow"))?;
        let allocated = u64::from(le32(&data, 28)?);
        let first_attribute = usize::from(le16(&data, 20)?);
        let usa = usize::from(le16(&data, 4)?);
        let usa_end = usa + usize::from(le16(&data, 6)?) * 2;
        if usa < 48
            || first_attribute < usa_end
            || !first_attribute.is_multiple_of(8)
            || used > data.len()
            || first_attribute + 4 > used
            || allocated != data.len() as u64
        {
            return Err(invalid(
                "ntfs.file_record",
                "invalid header, attribute or used-byte bounds",
            ));
        }
        let sequence = le16(&data, 16)?;
        let hard_links = le16(&data, 18)?;
        let flags = le16(&data, 22)?;
        if flags & !3 != 0 {
            return Err(invalid("ntfs.file_record", "unknown record flags"));
        }
        let base = NtfsReference::decode(le64(&data, 32)?);
        let number = le32(&data, 44)?;
        data.truncate(used);
        let record = Self {
            data,
            first_attribute,
            sequence,
            flags,
            hard_links,
            base,
            number,
        };
        record.attributes()?;
        Ok(record)
    }

    #[must_use]
    pub const fn in_use(&self) -> bool {
        self.flags & 1 != 0
    }
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.flags & 2 != 0
    }

    /// Parsed, used bytes including the restored sector trailers. Suitable for
    /// comparing immutable primary/mirror records without their unused slack.
    #[must_use]
    pub fn used_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn attributes(&self) -> Result<Vec<NtfsAttribute<'_>>, ParseError> {
        let mut position = self.first_attribute;
        let mut attributes = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        loop {
            let kind = le32(&self.data, position)?;
            if kind == u32::MAX {
                return Ok(attributes);
            }
            if kind == 0 || kind & 0xF != 0 {
                return Err(invalid("ntfs.attribute", "invalid attribute type"));
            }
            let length = usize::try_from(le32(&self.data, position + 4)?)
                .map_err(|_| invalid("ntfs.attribute", "length overflow"))?;
            let end = position
                .checked_add(length)
                .ok_or_else(|| invalid("ntfs.attribute", "overflow"))?;
            if length < 24 || !length.is_multiple_of(8) || end > self.data.len() {
                return Err(invalid(
                    "ntfs.attribute",
                    "record length outside used bytes",
                ));
            }
            let attr = NtfsAttribute::parse(&self.data[position..end], kind)?;
            if !ids.insert(attr.id) {
                return Err(invalid("ntfs.attribute", "duplicate attribute instance"));
            }
            attributes.push(attr);
            position = end;
        }
    }
}

#[derive(Debug)]
pub struct NtfsAttribute<'a> {
    pub kind: u32,
    pub id: u16,
    pub flags: u16,
    pub name: Vec<u16>,
    pub value: NtfsValue<'a>,
}
#[derive(Debug)]
pub enum NtfsValue<'a> {
    Resident(&'a [u8]),
    NonResident(NtfsNonResident<'a>),
}
#[derive(Debug)]
pub struct NtfsNonResident<'a> {
    pub first_vcn: u64,
    pub last_vcn: u64,
    pub compression_unit: u16,
    pub allocated_bytes: u64,
    pub data_bytes: u64,
    pub initialized_bytes: u64,
    pub mapping_pairs: &'a [u8],
}

impl<'a> NtfsAttribute<'a> {
    fn parse(raw: &'a [u8], kind: u32) -> Result<Self, ParseError> {
        let flags = le16(raw, 12)?;
        let id = le16(raw, 14)?;
        let (header, body_start, value) = match raw[8] {
            0 => {
                let start = usize::from(le16(raw, 20)?);
                let len = usize::try_from(le32(raw, 16)?)
                    .map_err(|_| invalid("ntfs.resident", "length overflow"))?;
                let end = start
                    .checked_add(len)
                    .ok_or_else(|| invalid("ntfs.resident", "overflow"))?;
                if start < 24 || end > raw.len() {
                    return Err(invalid("ntfs.resident", "value outside attribute"));
                }
                (24, start, NtfsValue::Resident(&raw[start..end]))
            }
            1 => {
                let header = if flags & (SPARSE | COMPRESSED) != 0 {
                    72
                } else {
                    64
                };
                let start = usize::from(le16(raw, 32)?);
                if start < header || start >= raw.len() {
                    return Err(invalid(
                        "ntfs.nonresident",
                        "mapping pairs overlap header or are absent",
                    ));
                }
                let value = NtfsNonResident {
                    first_vcn: le64(raw, 16)?,
                    last_vcn: le64(raw, 24)?,
                    compression_unit: le16(raw, 34)?,
                    allocated_bytes: le64(raw, 40)?,
                    data_bytes: le64(raw, 48)?,
                    initialized_bytes: le64(raw, 56)?,
                    mapping_pairs: &raw[start..],
                };
                if value.first_vcn == 0 && value.initialized_bytes > value.data_bytes {
                    return Err(invalid(
                        "ntfs.nonresident",
                        "initialized data exceeds logical size",
                    ));
                }
                (header, start, NtfsValue::NonResident(value))
            }
            _ => return Err(invalid("ntfs.attribute", "invalid resident discriminator")),
        };
        let name_len = usize::from(raw[9]);
        let name_start = usize::from(le16(raw, 10)?);
        let name_end = name_start + name_len * 2;
        if name_len != 0
            && (name_start < header || !name_start.is_multiple_of(2) || name_end > body_start)
        {
            return Err(invalid(
                "ntfs.attribute_name",
                "name overlaps header or value",
            ));
        }
        let mut name = Vec::with_capacity(name_len);
        if name_len != 0 {
            for at in (name_start..name_end).step_by(2) {
                name.push(le16(raw, at)?);
            }
        }
        Ok(Self {
            kind,
            id,
            flags,
            name,
            value,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsRun {
    pub vcn: u64,
    pub clusters: u64,
    /// None denotes a sparse run; it does not reset the relative LCN base.
    pub lcn: Option<u64>,
}

/// Decode an entire attribute extent, requiring its terminating zero and exact
/// VCN coverage. Signed LCN deltas are accumulated without wrapping. This does
/// not assemble ATTRIBUTE_LIST extension records or decompress compressed runs.
pub fn decode_mapping_pairs(
    pairs: &[u8],
    first_vcn: u64,
    last_vcn: u64,
    volume_clusters: u64,
) -> Result<Vec<NtfsRun>, ParseError> {
    let end_vcn = if first_vcn == 0 && last_vcn == u64::MAX {
        0
    } else {
        last_vcn
            .checked_add(1)
            .filter(|end| *end > first_vcn)
            .ok_or_else(|| invalid("ntfs.runlist", "invalid VCN interval"))?
    };
    let mut vcn = first_vcn;
    let mut lcn = 0_i128;
    let mut position = 0_usize;
    let mut runs = Vec::new();
    loop {
        let header = *pairs
            .get(position)
            .ok_or_else(|| invalid("ntfs.runlist", "missing terminator"))?;
        position += 1;
        if header == 0 {
            if vcn != end_vcn {
                return Err(invalid(
                    "ntfs.runlist",
                    "mapping does not cover VCN interval",
                ));
            }
            return Ok(runs);
        }
        if runs.len() >= 65_536 {
            return Err(invalid("ntfs.runlist", "run budget exceeded"));
        }
        let len_width = usize::from(header & 15);
        let off_width = usize::from(header >> 4);
        if !(1..=8).contains(&len_width) || off_width > 8 {
            return Err(invalid("ntfs.runlist", "invalid mapping-pair widths"));
        }
        let end = position
            .checked_add(len_width + off_width)
            .ok_or_else(|| invalid("ntfs.runlist", "offset overflow"))?;
        let payload = pairs
            .get(position..end)
            .ok_or_else(|| invalid("ntfs.runlist", "truncated mapping pair"))?;
        let mut length_bytes = [0_u8; 8];
        length_bytes[..len_width].copy_from_slice(&payload[..len_width]);
        let clusters = u64::from_le_bytes(length_bytes);
        let next_vcn = vcn
            .checked_add(clusters)
            .filter(|end| clusters != 0 && *end <= end_vcn)
            .ok_or_else(|| invalid("ntfs.runlist", "zero, overflowing or excessive run length"))?;
        let physical = if off_width == 0 {
            None
        } else {
            let delta = &payload[len_width..];
            let mut delta_bytes = if delta[off_width - 1] & 0x80 == 0 {
                [0; 8]
            } else {
                [0xFF; 8]
            };
            delta_bytes[..off_width].copy_from_slice(delta);
            lcn += i128::from(i64::from_le_bytes(delta_bytes));
            let physical = u64::try_from(lcn)
                .map_err(|_| invalid("ntfs.runlist", "negative or overflowing LCN"))?;
            if physical
                .checked_add(clusters)
                .is_none_or(|end| end > volume_clusters)
            {
                return Err(invalid("ntfs.runlist", "physical run outside volume"));
            }
            Some(physical)
        };
        runs.push(NtfsRun {
            vcn,
            clusters,
            lcn: physical,
        });
        vcn = next_vcn;
        position = end;
    }
}

/// Re-apply update-sequence protection (`USA`) to an unpacked multi-sector record
/// (`FILE`, `INDX`, `RSTR`, `RCRD`) so its 512-byte sector trailers carry the USA token
/// and the USA array stores the actual trailer bytes.
pub fn protect_record(restored: &[u8]) -> Result<Vec<u8>, ParseError> {
    if restored.len() < 512 || restored.len() > MAX_RECORD_BYTES || !restored.len().is_multiple_of(512) {
        return Err(invalid("ntfs.multi_sector", "invalid record length for USA protection"));
    }
    let offset = usize::from(le16(restored, 4)?);
    let count = usize::from(le16(restored, 6)?);
    let end = offset
        .checked_add(count * 2)
        .ok_or_else(|| invalid("ntfs.usa", "overflow"))?;
    if offset < 8 || !offset.is_multiple_of(2) || count != restored.len() / 512 + 1 || end > 510 {
        return Err(invalid("ntfs.usa", "invalid update sequence array bounds"));
    }
    let token_bytes = [restored[offset], restored[offset + 1]];
    let mut raw = restored.to_vec();
    for part in 1..count {
        let trailer_at = part * 512 - 2;
        let usa_slot = offset + part * 2;
        raw[usa_slot..usa_slot + 2].copy_from_slice(&restored[trailer_at..trailer_at + 2]);
        raw[trailer_at..trailer_at + 2].copy_from_slice(&token_bytes);
    }
    Ok(raw)
}

/// NTFS `$LogFile` operation codes (`NTFS_LOG_OPERATION`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsLogOp {
    Noop,
    CompensationLogRecord,
    InitializeFileRecordSegment,
    DeallocateFileRecordSegment,
    WriteEndOfFileRecordSegment,
    CreateAttribute,
    DeleteAttribute,
    UpdateResidentValue,
    UpdateNonresidentValue,
    UpdateMappingPairs,
    SetNewAttributeSizes,
    AddIndexEntryRoot,
    DeleteIndexEntryRoot,
    AddIndexEntryAllocation,
    DeleteIndexEntryAllocation,
    WriteEndOfIndexBuffer,
    SetIndexEntryVcnRoot,
    SetIndexEntryVcnAllocation,
    UpdateFileNameRoot,
    UpdateFileNameAllocation,
    SetBitsInNonresidentBitMap,
    ClearBitsInNonresidentBitMap,
    CommitTransaction,
    ForgetTransaction,
    OpenNonresidentAttribute,
    Unknown(u16),
}

impl NtfsLogOp {
    #[must_use]
    pub const fn from_raw(code: u16) -> Self {
        match code {
            0x00 => Self::Noop,
            0x01 => Self::CompensationLogRecord,
            0x02 => Self::InitializeFileRecordSegment,
            0x03 => Self::DeallocateFileRecordSegment,
            0x04 => Self::WriteEndOfFileRecordSegment,
            0x05 => Self::CreateAttribute,
            0x06 => Self::DeleteAttribute,
            0x07 => Self::UpdateResidentValue,
            0x08 => Self::UpdateNonresidentValue,
            0x09 => Self::UpdateMappingPairs,
            0x0B => Self::SetNewAttributeSizes,
            0x0C => Self::AddIndexEntryRoot,
            0x0D => Self::DeleteIndexEntryRoot,
            0x0E => Self::AddIndexEntryAllocation,
            0x0F => Self::DeleteIndexEntryAllocation,
            0x10 | 0x19 => Self::WriteEndOfIndexBuffer,
            0x12 => Self::SetIndexEntryVcnRoot,
            0x13 => Self::SetIndexEntryVcnAllocation,
            0x14 => Self::UpdateFileNameRoot,
            0x15 => Self::UpdateFileNameAllocation,
            0x16 => Self::SetBitsInNonresidentBitMap,
            0x17 => Self::ClearBitsInNonresidentBitMap,
            0x1B => Self::CommitTransaction,
            0x1C => Self::ForgetTransaction,
            0x1D => Self::OpenNonresidentAttribute,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn patches_bytes(self) -> bool {
        matches!(
            self,
            Self::InitializeFileRecordSegment
                | Self::DeallocateFileRecordSegment
                | Self::WriteEndOfFileRecordSegment
                | Self::CreateAttribute
                | Self::DeleteAttribute
                | Self::UpdateResidentValue
                | Self::UpdateNonresidentValue
                | Self::UpdateMappingPairs
                | Self::SetNewAttributeSizes
                | Self::AddIndexEntryRoot
                | Self::DeleteIndexEntryRoot
                | Self::AddIndexEntryAllocation
                | Self::DeleteIndexEntryAllocation
                | Self::WriteEndOfIndexBuffer
                | Self::SetIndexEntryVcnRoot
                | Self::SetIndexEntryVcnAllocation
                | Self::UpdateFileNameRoot
                | Self::UpdateFileNameAllocation
        )
    }
}

/// Validated NTFS `$LogFile` restart area (`RSTR` page + `LFS_RESTART_AREA` + `LFS_CLIENT_RECORD`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsLogRestartArea {
    pub chkdsk_lsn: u64,
    pub system_page_size: u32,
    pub log_page_size: u32,
    pub major_version: i16,
    pub minor_version: i16,
    pub current_lsn: u64,
    pub oldest_lsn: u64,
    pub client_restart_lsn: u64,
    pub flags: u16,
    pub file_size: u64,
    pub record_header_length: u16,
    pub log_page_data_offset: u16,
}

impl NtfsLogRestartArea {
    pub fn parse_page(raw_page: &[u8]) -> Result<Self, ParseError> {
        let restored = restore_record(raw_page, b"RSTR")?;
        if restored.len() < 64 {
            return Err(invalid("ntfs.rstr", "restart page too short"));
        }
        let chkdsk_lsn = le64(&restored, 8)?;
        let system_page_size = le32(&restored, 16)?;
        let log_page_size = le32(&restored, 20)?;
        let restart_offset = usize::from(le16(&restored, 24)?);
        let minor_version = i16::from_le_bytes(bytes(&restored, 26)?);
        let major_version = i16::from_le_bytes(bytes(&restored, 28)?);
        if !matches!(system_page_size, 512 | 1024 | 2048 | 4096)
            || !matches!(log_page_size, 512 | 1024 | 2048 | 4096)
            || !matches!(major_version, 1 | 2)
        {
            return Err(invalid("ntfs.rstr", "unsupported page size or LFS version"));
        }
        if restart_offset < 30 || restart_offset + 40 > restored.len() {
            return Err(invalid("ntfs.rstr", "restart area offset out of bounds"));
        }
        let area = &restored[restart_offset..];
        let current_lsn = le64(area, 0)?;
        let log_clients = le16(area, 8)?;
        let flags = le16(area, 14)?;
        let restart_area_len = usize::from(le16(area, 20)?);
        let client_array_offset = usize::from(le16(area, 22)?);
        let file_size = le64(area, 24)?;
        let record_header_length = le16(area, 36)?;
        let log_page_data_offset = le16(area, 38)?;
        if log_clients == 0
            || restart_offset + restart_area_len > restored.len()
            || client_array_offset + 16 > restart_area_len
            || record_header_length < 48
            || usize::from(log_page_data_offset) >= log_page_size as usize
        {
            return Err(invalid("ntfs.rstr", "invalid LFS_RESTART_AREA client bounds"));
        }
        let client = &area[client_array_offset..];
        let oldest_lsn = le64(client, 0)?;
        let client_restart_lsn = le64(client, 8)?;
        Ok(Self {
            chkdsk_lsn,
            system_page_size,
            log_page_size,
            major_version,
            minor_version,
            current_lsn,
            oldest_lsn,
            client_restart_lsn,
            flags,
            file_size,
            record_header_length,
            log_page_data_offset,
        })
    }

    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.flags & 0x0002 != 0
    }
}

/// One parsed NTFS client log record inside an `RCRD` page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsLogRecord {
    pub this_lsn: u64,
    pub client_previous_lsn: u64,
    pub client_undo_next_lsn: u64,
    pub transaction_id: u32,
    pub record_type: u32,
    pub redo_op: NtfsLogOp,
    pub undo_op: NtfsLogOp,
    pub target_attribute: u16,
    pub record_offset: u16,
    pub attribute_offset: u16,
    pub cluster_block_offset: u16,
    pub target_vcn: u64,
    pub target_lcn: u64,
    pub redo_data: Vec<u8>,
    pub undo_data: Vec<u8>,
}

/// One concrete byte-patch action produced by ARIES Redo or Undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsRecoveryAction {
    pub lsn: u64,
    pub transaction_id: u32,
    pub is_undo: bool,
    pub op: NtfsLogOp,
    pub target_lcn: u64,
    pub cluster_block_offset: u16,
    pub record_offset: u16,
    pub attribute_offset: u16,
    pub data: Vec<u8>,
}

/// Complete 3-pass ARIES recovery plan extracted from `$LogFile` (`NTFS-07`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsLogFilePlan {
    pub restart: NtfsLogRestartArea,
    pub records_parsed: usize,
    pub committed_transactions: Vec<u32>,
    pub aborted_transactions: Vec<u32>,
    pub dirty_lcns: Vec<u64>,
    pub redo_actions: Vec<NtfsRecoveryAction>,
    pub undo_actions: Vec<NtfsRecoveryAction>,
}

/// Parse `$LogFile` (`RSTR` + `RCRD` pages) and execute 3-pass ARIES
/// (Analysis -> Redo -> Undo) to produce deterministic overlay actions (`NTFS-07`).
pub fn parse_ntfs_logfile(raw_logfile: &[u8]) -> Result<NtfsLogFilePlan, ParseError> {
    if raw_logfile.len() < 8192 {
        return Err(invalid("ntfs.logfile", "$LogFile stream smaller than 8 KiB"));
    }
    // Probe page size from the first RSTR header (bytes 16..20 = system_page_size).
    let probe_size = usize::try_from(le32(raw_logfile, 16).unwrap_or(4096))
        .unwrap_or(4096)
        .clamp(512, 4096);
    let rstr0 = raw_logfile
        .get(..probe_size)
        .and_then(|page| NtfsLogRestartArea::parse_page(page).ok());
    let rstr1 = raw_logfile
        .get(probe_size..probe_size * 2)
        .and_then(|page| NtfsLogRestartArea::parse_page(page).ok());
    let restart = match (rstr0, rstr1) {
        (Some(a), Some(b)) => {
            if b.current_lsn > a.current_lsn {
                b
            } else {
                a
            }
        }
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => {
            return Err(invalid(
                "ntfs.logfile",
                "neither primary nor backup RSTR page is valid",
            ))
        }
    };

    let page_bytes = restart.log_page_size as usize;
    let data_start = usize::from(restart.log_page_data_offset).max(40);
    let hdr_len = usize::from(restart.record_header_length).max(48);
    let mut records = Vec::new();

    for page_at in (probe_size * 2..raw_logfile.len()).step_by(page_bytes) {
        let Some(raw_page) = raw_logfile.get(page_at..page_at + page_bytes) else {
            break;
        };
        if raw_page.get(..4) != Some(b"RCRD".as_slice()) {
            continue;
        }
        let Ok(page) = restore_record(raw_page, b"RCRD") else {
            continue;
        };
        let end_off = usize::from(le16(&page, 24).unwrap_or(0)).min(page.len());
        let mut pos = data_start;
        while pos + hdr_len <= end_off {
            let this_lsn = le64(&page, pos)?;
            if this_lsn == 0 {
                break;
            }
            let client_previous_lsn = le64(&page, pos + 8)?;
            let client_undo_next_lsn = le64(&page, pos + 16)?;
            let client_data_len = usize::try_from(le32(&page, pos + 24)?)
                .map_err(|_| invalid("ntfs.rcrd", "client data length overflow"))?;
            let record_type = le32(&page, pos + 32)?;
            let transaction_id = le32(&page, pos + 36)?;
            let payload_start = pos + hdr_len;
            let Some(payload) = page.get(payload_start..payload_start + client_data_len) else {
                break;
            };
            if record_type == 1 && payload.len() >= 40 {
                let redo_op = NtfsLogOp::from_raw(le16(payload, 0)?);
                let undo_op = NtfsLogOp::from_raw(le16(payload, 2)?);
                let redo_offset = usize::from(le16(payload, 4)?);
                let redo_length = usize::from(le16(payload, 6)?);
                let undo_offset = usize::from(le16(payload, 8)?);
                let undo_length = usize::from(le16(payload, 10)?);
                let target_attribute = le16(payload, 12)?;
                let lcns_to_follow = le16(payload, 14)?;
                let record_offset = le16(payload, 16)?;
                let attribute_offset = le16(payload, 18)?;
                let cluster_block_offset = le16(payload, 20)?;
                let target_vcn = le64(payload, 24)?;
                let target_lcn = if lcns_to_follow > 0 {
                    le64(payload, 32)?
                } else {
                    0
                };
                let redo_data = if redo_length > 0 {
                    payload
                        .get(redo_offset..redo_offset + redo_length)
                        .ok_or_else(|| invalid("ntfs.rcrd", "redo slice out of bounds"))?
                        .to_vec()
                } else {
                    Vec::new()
                };
                let undo_data = if undo_length > 0 {
                    payload
                        .get(undo_offset..undo_offset + undo_length)
                        .ok_or_else(|| invalid("ntfs.rcrd", "undo slice out of bounds"))?
                        .to_vec()
                } else {
                    Vec::new()
                };
                if this_lsn >= restart.oldest_lsn
                    && (restart.current_lsn == 0 || this_lsn <= restart.current_lsn)
                {
                    records.push(NtfsLogRecord {
                        this_lsn,
                        client_previous_lsn,
                        client_undo_next_lsn,
                        transaction_id,
                        record_type,
                        redo_op,
                        undo_op,
                        target_attribute,
                        record_offset,
                        attribute_offset,
                        cluster_block_offset,
                        target_vcn,
                        target_lcn,
                        redo_data,
                        undo_data,
                    });
                }
            }
            let aligned = (hdr_len + client_data_len + 7) & !7;
            pos += aligned.max(hdr_len);
        }
    }

    records.sort_by_key(|r| r.this_lsn);
    records.dedup_by_key(|r| r.this_lsn);

    // Pass 1: Analysis
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum TxStatus {
        Active,
        Committed,
    }
    let mut tx_table: std::collections::BTreeMap<u32, (TxStatus, u64, u64)> =
        std::collections::BTreeMap::new();
    let mut dirty_pages: std::collections::BTreeMap<u64, u64> =
        std::collections::BTreeMap::new();
    let mut committed_set = std::collections::BTreeSet::new();

    for rec in &records {
        if rec.target_lcn != 0 && rec.redo_op.patches_bytes() {
            dirty_pages.entry(rec.target_lcn).or_insert(rec.this_lsn);
        }
        match rec.redo_op {
            NtfsLogOp::CommitTransaction => {
                tx_table.insert(
                    rec.transaction_id,
                    (TxStatus::Committed, rec.this_lsn, rec.client_undo_next_lsn),
                );
                committed_set.insert(rec.transaction_id);
            }
            NtfsLogOp::ForgetTransaction => {
                tx_table.remove(&rec.transaction_id);
                committed_set.insert(rec.transaction_id);
            }
            _ => {
                let status = tx_table
                    .get(&rec.transaction_id)
                    .map_or(TxStatus::Active, |entry| entry.0);
                tx_table.insert(
                    rec.transaction_id,
                    (status, rec.this_lsn, rec.client_undo_next_lsn),
                );
            }
        }
    }

    let min_rec_lsn = dirty_pages
        .values()
        .copied()
        .min()
        .unwrap_or(restart.oldest_lsn);

    // Pass 2: Redo (repeating history in ascending LSN order)
    let mut redo_actions = Vec::new();
    for rec in &records {
        if rec.this_lsn >= min_rec_lsn && rec.target_lcn != 0 && rec.redo_op.patches_bytes() {
            redo_actions.push(NtfsRecoveryAction {
                lsn: rec.this_lsn,
                transaction_id: rec.transaction_id,
                is_undo: false,
                op: rec.redo_op,
                target_lcn: rec.target_lcn,
                cluster_block_offset: rec.cluster_block_offset,
                record_offset: rec.record_offset,
                attribute_offset: rec.attribute_offset,
                data: rec.redo_data.clone(),
            });
        }
    }

    // Pass 3: Undo (loser transactions in descending LSN order)
    let active_txs: std::collections::BTreeSet<u32> = tx_table
        .iter()
        .filter_map(|(&tx_id, &(status, _, _))| (status == TxStatus::Active).then_some(tx_id))
        .collect();
    let mut undo_actions = Vec::new();
    for rec in records.iter().rev() {
        if active_txs.contains(&rec.transaction_id)
            && rec.target_lcn != 0
            && rec.undo_op.patches_bytes()
        {
            undo_actions.push(NtfsRecoveryAction {
                lsn: rec.this_lsn,
                transaction_id: rec.transaction_id,
                is_undo: true,
                op: rec.undo_op,
                target_lcn: rec.target_lcn,
                cluster_block_offset: rec.cluster_block_offset,
                record_offset: rec.record_offset,
                attribute_offset: rec.attribute_offset,
                data: rec.undo_data.clone(),
            });
        }
    }

    Ok(NtfsLogFilePlan {
        restart,
        records_parsed: records.len(),
        committed_transactions: committed_set.into_iter().collect(),
        aborted_transactions: active_txs.into_iter().collect(),
        dirty_lcns: dirty_pages.keys().copied().collect(),
        redo_actions,
        undo_actions,
    })
}

#[cfg(test)]
mod tests;
