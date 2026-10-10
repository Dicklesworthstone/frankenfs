//! Bounded NTFS 3.1 boot, multi-sector record, attribute and mapping-pair parsing.
//!
//! No I/O, replay, decompression or mutation. Sources: Microsoft's
//! ATTRIBUTE_RECORD_HEADER, FILE_RECORD_SEGMENT_HEADER and MULTI_SECTOR_HEADER
//! documentation. Update-sequence protection uses 512-byte strides even when
//! the BPB advertises larger sectors. Names remain native UTF-16 code units.

pub mod index;

use ffs_types::ParseError;

pub const ATTRIBUTE_LIST: u32 = 0x20;
pub const DATA: u32 = 0x80;
pub const VOLUME_INFORMATION: u32 = 0x70;
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

#[cfg(test)]
mod tests;
