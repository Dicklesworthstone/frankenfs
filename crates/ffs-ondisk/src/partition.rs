//! Bounded MBR and GPT partition-table discovery and validation.
//!
//! Pure byte-slice / callback parser — no ambient I/O, no `unsafe`, bounded
//! allocation. Validates protective and legacy MBR (`0x55AA`), primary and
//! backup GPT headers (`"EFI PART"`, IEEE 802.3 CRC32), GPT entry arrays
//! (IEEE 802.3 CRC32, `first_usable_lba <= start <= end <= last_usable_lba`),
//! image byte bounds, pairwise interval non-overlap, VBR disambiguation
//! (so FAT16/FAT32/NTFS boot sectors are never misclassified as MBR tables),
//! and nested partition-table bomb rejection.

use crate::fat::FatGeometry;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Standard logical block size for MBR and 512e/512n GPT disks.
pub const DEFAULT_LOGICAL_BLOCK_BYTES: u32 = 512;

/// Native 4Kn logical block size supported for GPT disks.
pub const NATIVE_4K_LOGICAL_BLOCK_BYTES: u32 = 4096;

/// Hard upper bound on GPT partition entry count to prevent allocation bombs.
/// UEFI 2.10 requires a minimum array of 128 entries; 1024 generously covers
/// enterprise layouts while capping array reads to at most 4 MiB.
pub const MAX_GPT_PARTITIONS: u32 = 1024;

/// Minimum GPT header size per UEFI specification (92 bytes).
pub const MIN_GPT_HEADER_BYTES: u32 = 92;

/// Minimum GPT partition entry size per UEFI specification (128 bytes).
pub const MIN_GPT_ENTRY_BYTES: u32 = 128;

/// Maximum GPT partition entry size accepted (4096 bytes, power-of-two multiple of 8).
pub const MAX_GPT_ENTRY_BYTES: u32 = 4096;

/// MBR boot signature at bytes `510..512` (`0x55`, `0xAA`).
pub const MBR_SIGNATURE_LE: u16 = 0xAA55;

/// Protective GPT MBR partition type (`0xEE`).
pub const MBR_TYPE_PROTECTIVE_GPT: u8 = 0xEE;

/// GPT header signature (`"EFI PART"`).
pub const GPT_HEADER_SIGNATURE: &[u8; 8] = b"EFI PART";

const fn build_crc32_ieee_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut i = 0_usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const CRC32_IEEE_TABLE: [u32; 256] = build_crc32_ieee_table();

/// Compute standard IEEE 802.3 CRC32 (reflected polynomial `0xEDB88320`),
/// as required by UEFI GPT headers and partition entry arrays.
#[must_use]
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in bytes {
        let idx = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_IEEE_TABLE[idx];
    }
    !crc
}

/// UEFI mixed-endian GUID (`u32_le-u16_le-u16_le-be2-be6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartUuid([u8; 16]);

impl PartUuid {
    /// Construct from raw on-disk mixed-endian UEFI GUID bytes.
    #[must_use]
    pub const fn from_raw_le(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return raw on-disk mixed-endian UEFI GUID bytes.
    #[must_use]
    pub const fn to_raw_le(self) -> [u8; 16] {
        self.0
    }

    /// Return `true` when all 16 bytes are zero (unused GPT entry).
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0_u8; 16]
    }
}

impl fmt::Display for PartUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let d2 = u16::from_le_bytes([b[4], b[5]]);
        let d3 = u16::from_le_bytes([b[6], b[7]]);
        write!(
            f,
            "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl Serialize for PartUuid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PartUuid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_str(&text).map_err(serde::de::Error::custom)
    }
}

impl FromStr for PartUuid {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 36 {
            return Err(format!(
                "invalid GUID length {} (expected 36-char xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
                value.len()
            ));
        }
        let bytes = value.as_bytes();
        for &hyphen_idx in &[8_usize, 13, 18, 23] {
            if bytes[hyphen_idx] != b'-' {
                return Err(format!("expected '-' at GUID byte {hyphen_idx}"));
            }
        }
        let d1 = u32::from_str_radix(&value[0..8], 16)
            .map_err(|_| "invalid hex in GUID field 1".to_owned())?;
        let d2 = u16::from_str_radix(&value[9..13], 16)
            .map_err(|_| "invalid hex in GUID field 2".to_owned())?;
        let d3 = u16::from_str_radix(&value[14..18], 16)
            .map_err(|_| "invalid hex in GUID field 3".to_owned())?;
        let mut raw = [0_u8; 16];
        raw[0..4].copy_from_slice(&d1.to_le_bytes());
        raw[4..6].copy_from_slice(&d2.to_le_bytes());
        raw[6..8].copy_from_slice(&d3.to_le_bytes());
        raw[8] = u8::from_str_radix(&value[19..21], 16)
            .map_err(|_| "invalid hex in GUID field 4".to_owned())?;
        raw[9] = u8::from_str_radix(&value[21..23], 16)
            .map_err(|_| "invalid hex in GUID field 4".to_owned())?;
        for i in 0..6_usize {
            let start = 24 + i * 2;
            raw[10 + i] = u8::from_str_radix(&value[start..start + 2], 16)
                .map_err(|_| "invalid hex in GUID field 5".to_owned())?;
        }
        Ok(Self(raw))
    }
}

/// Partition-table scheme discovered at the outer disk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PartitionScheme {
    Mbr,
    Gpt,
}

impl fmt::Display for PartitionScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mbr => f.write_str("mbr"),
            Self::Gpt => f.write_str("gpt"),
        }
    }
}

/// Validated, non-overlapping partition slice entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionEntry {
    /// 1-based partition number (`1..=4` for MBR, `1..=N` for GPT).
    pub index: u32,
    /// Table scheme (`mbr` or `gpt`).
    pub scheme: PartitionScheme,
    /// Inclusive starting LBA in `logical_block_bytes` units.
    pub start_lba: u64,
    /// Inclusive ending LBA in `logical_block_bytes` units.
    pub end_lba_inclusive: u64,
    /// Exact byte offset from the start of the disk image.
    pub start_byte: u64,
    /// Exact byte length of this partition (`(end_lba_inclusive - start_lba + 1) * lba_bytes`).
    pub byte_len: u64,
    /// MBR partition type byte (`Some` for MBR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbr_type: Option<u8>,
    /// MBR active/bootable indicator (`0x80`).
    pub mbr_bootable: bool,
    /// GPT partition type GUID (`Some` for GPT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_guid: Option<PartUuid>,
    /// GPT unique partition GUID / `PARTUUID` (`Some` for GPT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part_uuid: Option<PartUuid>,
    /// Decoded UTF-16LE GPT partition name (`PARTLABEL`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// GPT attribute flags (`0` for MBR).
    pub attributes: u64,
}

impl PartitionEntry {
    /// Exclusive ending byte offset (`start_byte + byte_len`).
    #[must_use]
    pub const fn end_byte(&self) -> u64 {
        self.start_byte.saturating_add(self.byte_len)
    }

    /// Canonical identifier string for structured logs (`gpt:1:<uuid>` or `mbr:1`).
    #[must_use]
    pub fn canonical_id(&self) -> String {
        match (&self.scheme, &self.part_uuid) {
            (PartitionScheme::Gpt, Some(uuid)) => format!("gpt:{}:{uuid}", self.index),
            (scheme, _) => format!("{scheme}:{}", self.index),
        }
    }
}

/// Caller selector for `--partition <index|partuuid|label>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionSelector {
    /// 1-based partition slot index (`1`, `2`, `index:1`).
    Index(u32),
    /// UEFI partition GUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` or `partuuid:...`).
    PartUuid(PartUuid),
    /// Exact GPT partition label (`DATA` or `label:DATA`).
    Label(String),
}

impl fmt::Display for PartitionSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Index(idx) => write!(f, "index:{idx}"),
            Self::PartUuid(uuid) => write!(f, "partuuid:{uuid}"),
            Self::Label(label) => write!(f, "label:{label}"),
        }
    }
}

impl FromStr for PartitionSelector {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.is_empty() || raw.len() > 256 {
            return Err("partition selector must be 1..=256 bytes".to_owned());
        }
        if let Some(rest) = raw.strip_prefix("index:") {
            let idx = parse_nonzero_index(rest)?;
            return Ok(Self::Index(idx));
        }
        if let Some(rest) = raw
            .strip_prefix("partuuid:")
            .or_else(|| raw.strip_prefix("guid:"))
        {
            return PartUuid::from_str(rest).map(Self::PartUuid);
        }
        if let Some(rest) = raw.strip_prefix("label:") {
            if rest.is_empty() {
                return Err("partition label selector must not be empty".to_owned());
            }
            return Ok(Self::Label(rest.to_owned()));
        }
        if raw.bytes().all(|b| b.is_ascii_digit()) {
            return parse_nonzero_index(raw).map(Self::Index);
        }
        if raw.len() == 36 && PartUuid::from_str(raw).is_ok() {
            return PartUuid::from_str(raw).map(Self::PartUuid);
        }
        Ok(Self::Label(raw.to_owned()))
    }
}

fn parse_nonzero_index(text: &str) -> Result<u32, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "invalid 1-based partition index {text:?} (expected positive integer)"
        ));
    }
    let idx = text
        .parse::<u32>()
        .map_err(|_| format!("partition index {text:?} overflows u32"))?;
    if idx == 0 {
        return Err("partition indices are 1-based; 0 is invalid".to_owned());
    }
    Ok(idx)
}

/// Options controlling bounded MBR/GPT discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionParseOptions {
    /// Logical sector size in bytes (`512` or `4096`).
    pub logical_block_bytes: u32,
    /// Permit falling back to the backup GPT header at `last_lba` when the
    /// primary GPT header or its entry array fails validation.
    pub allow_backup_gpt_fallback: bool,
    /// Upper bound on GPT entry slots (capped at [`MAX_GPT_PARTITIONS`]).
    pub max_gpt_entries: u32,
}

impl Default for PartitionParseOptions {
    fn default() -> Self {
        Self {
            logical_block_bytes: DEFAULT_LOGICAL_BLOCK_BYTES,
            allow_backup_gpt_fallback: false,
            max_gpt_entries: MAX_GPT_PARTITIONS,
        }
    }
}

/// Structured error produced during MBR or GPT discovery and selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionParseError {
    Io(String),
    InvalidOptions(String),
    NotAPartitionTable(String),
    PrimaryGptCorrupt {
        detail: String,
    },
    BackupGptCorrupt {
        primary_detail: String,
        backup_detail: String,
    },
    InvalidGeometry(String),
    OverlappingPartitions {
        first_index: u32,
        second_index: u32,
        first_range: (u64, u64),
        second_range: (u64, u64),
    },
    NestedPartitionTable {
        partition_index: u32,
        inner_scheme: PartitionScheme,
    },
    PartitionNotFound(String),
    AmbiguousLabel(String),
}

impl fmt::Display for PartitionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "partition read I/O failed: {msg}"),
            Self::InvalidOptions(msg) => write!(f, "invalid partition parse options: {msg}"),
            Self::NotAPartitionTable(msg) => {
                write!(f, "no valid MBR or GPT partition table: {msg}")
            }
            Self::PrimaryGptCorrupt { detail } => write!(
                f,
                "primary GPT validation failed (backup GPT fallback disabled): {detail}"
            ),
            Self::BackupGptCorrupt {
                primary_detail,
                backup_detail,
            } => write!(
                f,
                "both primary and backup GPT headers failed validation: primary=({primary_detail}); backup=({backup_detail})"
            ),
            Self::InvalidGeometry(msg) => write!(f, "invalid partition geometry: {msg}"),
            Self::OverlappingPartitions {
                first_index,
                second_index,
                first_range,
                second_range,
            } => write!(
                f,
                "overlapping partitions #{first_index} [{}..{}) and #{second_index} [{}..{})",
                first_range.0, first_range.1, second_range.0, second_range.1
            ),
            Self::NestedPartitionTable {
                partition_index,
                inner_scheme,
            } => write!(
                f,
                "nested {inner_scheme} partition table inside partition #{partition_index} is refused"
            ),
            Self::PartitionNotFound(sel) => write!(f, "partition {sel} not found in table"),
            Self::AmbiguousLabel(label) => {
                write!(f, "partition label {label:?} matches multiple GPT entries")
            }
        }
    }
}

impl std::error::Error for PartitionParseError {}

/// Validated outer MBR or GPT partition table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionTable {
    pub scheme: PartitionScheme,
    pub logical_block_bytes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_guid: Option<PartUuid>,
    pub mbr_disk_signature: u32,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub used_backup_gpt_header: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_gpt_error: Option<String>,
    pub partitions: Vec<PartitionEntry>,
}

#[derive(Debug, Clone)]
struct ParsedGptHeader {
    disk_guid: PartUuid,
    alternate_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
}

impl PartitionTable {
    /// Parse an in-memory disk image slice.
    pub fn parse_bytes(
        image: &[u8],
        options: &PartitionParseOptions,
    ) -> Result<Self, PartitionParseError> {
        let len = image.len() as u64;
        Self::parse_with_reader(len, options, |offset, buf| {
            let start = usize::try_from(offset)
                .map_err(|_| "partition read offset overflows usize".to_owned())?;
            let end = start
                .checked_add(buf.len())
                .ok_or_else(|| "partition read range overflows usize".to_owned())?;
            let slice = image.get(start..end).ok_or_else(|| {
                format!(
                    "read [{offset}..{}) exceeds image length {len}",
                    offset.saturating_add(buf.len() as u64)
                )
            })?;
            buf.copy_from_slice(slice);
            Ok(())
        })
    }

    /// Parse a disk image of `image_len_bytes` using a bounded positional reader.
    ///
    /// Reads only LBA 0, GPT headers, and the bounded GPT entry array (`<= 4 MiB`),
    /// so multi-gigabyte or multi-terabyte disk images require only tens of KiB of I/O.
    pub fn parse_with_reader<F>(
        image_len_bytes: u64,
        options: &PartitionParseOptions,
        mut read_at: F,
    ) -> Result<Self, PartitionParseError>
    where
        F: FnMut(u64, &mut [u8]) -> Result<(), String>,
    {
        if !matches!(
            options.logical_block_bytes,
            DEFAULT_LOGICAL_BLOCK_BYTES | NATIVE_4K_LOGICAL_BLOCK_BYTES
        ) {
            return Err(PartitionParseError::InvalidOptions(format!(
                "logical_block_bytes must be 512 or 4096 (got {})",
                options.logical_block_bytes
            )));
        }
        let max_entries = options.max_gpt_entries.min(MAX_GPT_PARTITIONS);
        if max_entries == 0 {
            return Err(PartitionParseError::InvalidOptions(
                "max_gpt_entries must be >= 1".to_owned(),
            ));
        }

        let lba_bytes = u64::from(options.logical_block_bytes);
        if image_len_bytes < lba_bytes {
            return Err(PartitionParseError::NotAPartitionTable(format!(
                "image length {image_len_bytes} is smaller than one logical block ({lba_bytes})"
            )));
        }

        let mut lba0 = [0_u8; 512];
        read_at(0, &mut lba0).map_err(PartitionParseError::Io)?;

        // Disambiguate standalone filesystem Volume Boot Records (FAT16/FAT32/NTFS/exFAT)
        // before considering MBR signatures, because VBRs also end with 0x55AA at 510..512!
        if looks_like_filesystem_vbr(&lba0, image_len_bytes) {
            return Err(PartitionParseError::NotAPartitionTable(
                "LBA 0 is a filesystem volume boot record (VBR), not a partition table".to_owned(),
            ));
        }

        let mbr_sig = u16::from_le_bytes([lba0[510], lba0[511]]);
        let mbr_disk_signature = u32::from_le_bytes([lba0[440], lba0[441], lba0[442], lba0[443]]);

        // Probe LBA 1 for a GPT signature as well so a corrupted protective MBR still
        // surfaces an accurate GPT diagnostic when LBA 1 carries `"EFI PART"`.
        let mut lba1_sig = [0_u8; 8];
        let has_lba1_efi_sig = if image_len_bytes >= lba_bytes.saturating_mul(2) {
            read_at(lba_bytes, &mut lba1_sig)
                .map_err(PartitionParseError::Io)
                .map(|()| &lba1_sig == GPT_HEADER_SIGNATURE)?
        } else {
            false
        };

        let has_protective_mbr = mbr_sig == MBR_SIGNATURE_LE && mbr_has_protective_gpt(&lba0);

        if has_protective_mbr || has_lba1_efi_sig {
            if mbr_sig != MBR_SIGNATURE_LE {
                return Err(PartitionParseError::InvalidGeometry(
                    "GPT image is missing protective MBR 0x55AA signature at LBA 0".to_owned(),
                ));
            }
            if !mbr_protective_layout_valid(&lba0) {
                return Err(PartitionParseError::InvalidGeometry(
                    "hybrid or malformed protective MBR accompanying GPT is refused".to_owned(),
                ));
            }
            return Self::parse_gpt(
                image_len_bytes,
                lba_bytes,
                max_entries,
                options.allow_backup_gpt_fallback,
                mbr_disk_signature,
                &mut read_at,
            );
        }

        if mbr_sig != MBR_SIGNATURE_LE {
            return Err(PartitionParseError::NotAPartitionTable(
                "missing 0x55AA MBR signature at bytes 510..512".to_owned(),
            ));
        }

        Self::parse_legacy_mbr(&lba0, image_len_bytes, lba_bytes, mbr_disk_signature)
    }

    /// Select a single partition entry by 1-based index, `PARTUUID`, or GPT label.
    pub fn select(
        &self,
        selector: &PartitionSelector,
    ) -> Result<&PartitionEntry, PartitionParseError> {
        match selector {
            PartitionSelector::Index(idx) => self
                .partitions
                .iter()
                .find(|entry| entry.index == *idx)
                .ok_or_else(|| PartitionParseError::PartitionNotFound(selector.to_string())),
            PartitionSelector::PartUuid(uuid) => self
                .partitions
                .iter()
                .find(|entry| entry.part_uuid.as_ref() == Some(uuid))
                .ok_or_else(|| PartitionParseError::PartitionNotFound(selector.to_string())),
            PartitionSelector::Label(label) => {
                let mut matches = self
                    .partitions
                    .iter()
                    .filter(|entry| entry.label.as_deref() == Some(label.as_str()));
                let first = matches
                    .next()
                    .ok_or_else(|| PartitionParseError::PartitionNotFound(selector.to_string()))?;
                if matches.next().is_some() {
                    return Err(PartitionParseError::AmbiguousLabel(label.clone()));
                }
                Ok(first)
            }
        }
    }

    /// Verify that a selected partition slice does not itself contain a nested
    /// MBR or GPT partition table (partition-table bomb defense).
    pub fn ensure_slice_not_nested_partition_table<F>(
        partition_index: u32,
        slice_byte_len: u64,
        logical_block_bytes: u32,
        read_slice_at: F,
    ) -> Result<(), PartitionParseError>
    where
        F: FnMut(u64, &mut [u8]) -> Result<(), String>,
    {
        let probe_opts = PartitionParseOptions {
            logical_block_bytes,
            allow_backup_gpt_fallback: true,
            max_gpt_entries: MAX_GPT_PARTITIONS,
        };
        if let Ok(inner) = Self::parse_with_reader(slice_byte_len, &probe_opts, read_slice_at) {
            return Err(PartitionParseError::NestedPartitionTable {
                partition_index,
                inner_scheme: inner.scheme,
            });
        }
        Ok(())
    }

    fn parse_legacy_mbr(
        lba0: &[u8; 512],
        image_len_bytes: u64,
        lba_bytes: u64,
        mbr_disk_signature: u32,
    ) -> Result<Self, PartitionParseError> {
        let total_lbas = image_len_bytes / lba_bytes;
        let mut partitions = Vec::new();

        for slot in 0..4_usize {
            let off = 446 + slot * 16;
            let entry = &lba0[off..off + 16];
            let status = entry[0];
            if (status & !0x80) != 0 {
                return Err(PartitionParseError::NotAPartitionTable(format!(
                    "MBR slot {} has invalid status byte 0x{status:02x}",
                    slot + 1
                )));
            }
            let part_type = entry[4];
            let first_lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
            let sector_count = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);

            if part_type == 0 {
                if first_lba != 0 || sector_count != 0 {
                    return Err(PartitionParseError::InvalidGeometry(format!(
                        "empty MBR slot {} carries nonzero LBA geometry ({first_lba}, {sector_count})",
                        slot + 1
                    )));
                }
                continue;
            }
            if matches!(part_type, 0x05 | 0x0F | 0x85) {
                return Err(PartitionParseError::InvalidGeometry(format!(
                    "extended EBR chain in MBR slot {} (type 0x{part_type:02x}) is refused by bounded flat-table policy",
                    slot + 1
                )));
            }
            if first_lba == 0 || sector_count == 0 {
                return Err(PartitionParseError::InvalidGeometry(format!(
                    "MBR slot {} has zero start_lba ({first_lba}) or sector_count ({sector_count})",
                    slot + 1
                )));
            }
            let start_lba = u64::from(first_lba);
            let count_lba = u64::from(sector_count);
            let end_lba_inclusive = start_lba
                .checked_add(count_lba - 1)
                .ok_or_else(|| PartitionParseError::InvalidGeometry("MBR LBA overflow".into()))?;
            let start_byte = start_lba.checked_mul(lba_bytes).ok_or_else(|| {
                PartitionParseError::InvalidGeometry("MBR start_byte overflow".into())
            })?;
            let byte_len = count_lba.checked_mul(lba_bytes).ok_or_else(|| {
                PartitionParseError::InvalidGeometry("MBR byte_len overflow".into())
            })?;
            let end_byte = start_byte.checked_add(byte_len).ok_or_else(|| {
                PartitionParseError::InvalidGeometry("MBR end_byte overflow".into())
            })?;
            if end_byte > image_len_bytes {
                return Err(PartitionParseError::InvalidGeometry(format!(
                    "MBR slot {} end_byte {end_byte} exceeds image length {image_len_bytes}",
                    slot + 1
                )));
            }

            partitions.push(PartitionEntry {
                index: u32::try_from(slot + 1).expect("1..=4 fits u32"),
                scheme: PartitionScheme::Mbr,
                start_lba,
                end_lba_inclusive,
                start_byte,
                byte_len,
                mbr_type: Some(part_type),
                mbr_bootable: status == 0x80,
                type_guid: None,
                part_uuid: None,
                label: None,
                attributes: 0,
            });
        }

        if partitions.is_empty() {
            return Err(PartitionParseError::NotAPartitionTable(
                "MBR has 0x55AA signature but zero non-empty partition entries".to_owned(),
            ));
        }

        validate_pairwise_non_overlap(&partitions)?;

        Ok(Self {
            scheme: PartitionScheme::Mbr,
            logical_block_bytes: u32::try_from(lba_bytes).expect("validated 512 or 4096"),
            disk_guid: None,
            mbr_disk_signature,
            first_usable_lba: 1,
            last_usable_lba: total_lbas.saturating_sub(1),
            used_backup_gpt_header: false,
            primary_gpt_error: None,
            partitions,
        })
    }

    fn parse_gpt<F>(
        image_len_bytes: u64,
        lba_bytes: u64,
        max_entries: u32,
        allow_backup_gpt_fallback: bool,
        mbr_disk_signature: u32,
        read_at: &mut F,
    ) -> Result<Self, PartitionParseError>
    where
        F: FnMut(u64, &mut [u8]) -> Result<(), String>,
    {
        let total_lbas = image_len_bytes / lba_bytes;
        if total_lbas < 6 {
            return Err(PartitionParseError::InvalidGeometry(format!(
                "GPT image has only {total_lbas} LBAs (minimum 6 required)"
            )));
        }

        let primary_attempt = Self::read_and_validate_gpt_copy(
            image_len_bytes,
            lba_bytes,
            total_lbas,
            1,
            true,
            max_entries,
            read_at,
        );

        match primary_attempt {
            Ok((hdr, partitions)) => {
                // Also verify that backup header LBA is plausible within image bounds.
                if hdr.alternate_lba <= hdr.last_usable_lba || hdr.alternate_lba >= total_lbas {
                    return Err(PartitionParseError::InvalidGeometry(format!(
                        "primary GPT alternate_lba {} lies outside (last_usable_lba={}, total_lbas={total_lbas})",
                        hdr.alternate_lba, hdr.last_usable_lba
                    )));
                }
                Ok(Self {
                    scheme: PartitionScheme::Gpt,
                    logical_block_bytes: u32::try_from(lba_bytes).expect("512 or 4096"),
                    disk_guid: Some(hdr.disk_guid),
                    mbr_disk_signature,
                    first_usable_lba: hdr.first_usable_lba,
                    last_usable_lba: hdr.last_usable_lba,
                    used_backup_gpt_header: false,
                    primary_gpt_error: None,
                    partitions,
                })
            }
            Err(primary_err) => {
                // Structural geometry / overlap errors inside an otherwise CRC-valid
                // primary table remain hard errors even when backup GPT fallback is enabled;
                // fallback is strictly for primary header/entry CRC or signature corruption.
                if matches!(
                    primary_err,
                    PartitionParseError::OverlappingPartitions { .. }
                        | PartitionParseError::InvalidGeometry(_)
                ) {
                    return Err(primary_err);
                }
                let primary_detail = primary_err.to_string();
                if !allow_backup_gpt_fallback {
                    return Err(PartitionParseError::PrimaryGptCorrupt {
                        detail: primary_detail,
                    });
                }

                let backup_lba = total_lbas - 1;
                match Self::read_and_validate_gpt_copy(
                    image_len_bytes,
                    lba_bytes,
                    total_lbas,
                    backup_lba,
                    false,
                    max_entries,
                    read_at,
                ) {
                    Ok((hdr, partitions)) => Ok(Self {
                        scheme: PartitionScheme::Gpt,
                        logical_block_bytes: u32::try_from(lba_bytes).expect("512 or 4096"),
                        disk_guid: Some(hdr.disk_guid),
                        mbr_disk_signature,
                        first_usable_lba: hdr.first_usable_lba,
                        last_usable_lba: hdr.last_usable_lba,
                        used_backup_gpt_header: true,
                        primary_gpt_error: Some(primary_detail),
                        partitions,
                    }),
                    Err(backup_err) => Err(PartitionParseError::BackupGptCorrupt {
                        primary_detail,
                        backup_detail: backup_err.to_string(),
                    }),
                }
            }
        }
    }

    fn read_and_validate_gpt_copy<F>(
        image_len_bytes: u64,
        lba_bytes: u64,
        total_lbas: u64,
        expected_my_lba: u64,
        is_primary: bool,
        max_entries: u32,
        read_at: &mut F,
    ) -> Result<(ParsedGptHeader, Vec<PartitionEntry>), PartitionParseError>
    where
        F: FnMut(u64, &mut [u8]) -> Result<(), String>,
    {
        let header_offset = expected_my_lba.checked_mul(lba_bytes).ok_or_else(|| {
            PartitionParseError::InvalidGeometry("GPT header offset overflow".into())
        })?;
        let mut block = vec![0_u8; usize::try_from(lba_bytes).expect("512 or 4096")];
        read_at(header_offset, &mut block).map_err(PartitionParseError::Io)?;

        if &block[0..8] != GPT_HEADER_SIGNATURE {
            return Err(PartitionParseError::PrimaryGptCorrupt {
                detail: format!("missing 'EFI PART' signature at LBA {expected_my_lba}"),
            });
        }
        let revision = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        if revision == 0 {
            return Err(PartitionParseError::PrimaryGptCorrupt {
                detail: "GPT header revision is 0".to_owned(),
            });
        }
        let header_size = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);
        if header_size < MIN_GPT_HEADER_BYTES || u64::from(header_size) > lba_bytes {
            return Err(PartitionParseError::PrimaryGptCorrupt {
                detail: format!(
                    "GPT header_size {header_size} outside [{MIN_GPT_HEADER_BYTES}..={lba_bytes}]"
                ),
            });
        }
        let expected_hdr_crc = u32::from_le_bytes([block[16], block[17], block[18], block[19]]);
        let reserved = u32::from_le_bytes([block[20], block[21], block[22], block[23]]);
        if reserved != 0 {
            return Err(PartitionParseError::PrimaryGptCorrupt {
                detail: format!("GPT reserved field is nonzero (0x{reserved:08x})"),
            });
        }

        let mut hdr_for_crc = block[..header_size as usize].to_vec();
        hdr_for_crc[16..20].fill(0);
        let computed_hdr_crc = crc32_ieee(&hdr_for_crc);
        if computed_hdr_crc != expected_hdr_crc {
            return Err(PartitionParseError::PrimaryGptCorrupt {
                detail: format!(
                    "GPT header CRC32 mismatch at LBA {expected_my_lba}: stored=0x{expected_hdr_crc:08x}, computed=0x{computed_hdr_crc:08x}"
                ),
            });
        }

        let my_lba = u64::from_le_bytes(block[24..32].try_into().expect("8 bytes"));
        let alternate_lba = u64::from_le_bytes(block[32..40].try_into().expect("8 bytes"));
        let first_usable_lba = u64::from_le_bytes(block[40..48].try_into().expect("8 bytes"));
        let last_usable_lba = u64::from_le_bytes(block[48..56].try_into().expect("8 bytes"));
        let mut disk_guid_bytes = [0_u8; 16];
        disk_guid_bytes.copy_from_slice(&block[56..72]);
        let partition_entry_lba = u64::from_le_bytes(block[72..80].try_into().expect("8 bytes"));
        let num_partition_entries = u32::from_le_bytes(block[80..84].try_into().expect("4 bytes"));
        let partition_entry_size = u32::from_le_bytes(block[84..88].try_into().expect("4 bytes"));
        let partition_entry_array_crc32 =
            u32::from_le_bytes(block[88..92].try_into().expect("4 bytes"));

        if my_lba != expected_my_lba {
            return Err(PartitionParseError::PrimaryGptCorrupt {
                detail: format!(
                    "GPT my_lba={my_lba} does not match expected LBA {expected_my_lba}"
                ),
            });
        }
        if !is_primary && alternate_lba != 1 {
            return Err(PartitionParseError::PrimaryGptCorrupt {
                detail: format!("backup GPT alternate_lba={alternate_lba} must be 1"),
            });
        }
        if first_usable_lba < 2
            || first_usable_lba > last_usable_lba
            || last_usable_lba >= total_lbas
        {
            return Err(PartitionParseError::InvalidGeometry(format!(
                "invalid GPT usable LBA window [{first_usable_lba}..={last_usable_lba}] for total_lbas={total_lbas}"
            )));
        }
        if num_partition_entries == 0 || num_partition_entries > max_entries {
            return Err(PartitionParseError::InvalidGeometry(format!(
                "GPT num_partition_entries={num_partition_entries} outside [1..={max_entries}]"
            )));
        }
        if !(MIN_GPT_ENTRY_BYTES..=MAX_GPT_ENTRY_BYTES).contains(&partition_entry_size)
            || !partition_entry_size.is_power_of_two()
        {
            return Err(PartitionParseError::InvalidGeometry(format!(
                "GPT partition_entry_size={partition_entry_size} must be a power of two in [{MIN_GPT_ENTRY_BYTES}..={MAX_GPT_ENTRY_BYTES}]"
            )));
        }

        let array_bytes_u64 = u64::from(num_partition_entries)
            .checked_mul(u64::from(partition_entry_size))
            .ok_or_else(|| {
                PartitionParseError::InvalidGeometry("GPT entry array byte size overflow".into())
            })?;
        let array_offset = partition_entry_lba.checked_mul(lba_bytes).ok_or_else(|| {
            PartitionParseError::InvalidGeometry("GPT entry array offset overflow".into())
        })?;
        let array_end_byte = array_offset.checked_add(array_bytes_u64).ok_or_else(|| {
            PartitionParseError::InvalidGeometry("GPT entry array end offset overflow".into())
        })?;
        if array_end_byte > image_len_bytes {
            return Err(PartitionParseError::InvalidGeometry(format!(
                "GPT entry array [{array_offset}..{array_end_byte}) exceeds image length {image_len_bytes}"
            )));
        }

        let array_lbas = array_bytes_u64.div_ceil(lba_bytes);
        let array_end_lba_inclusive =
            partition_entry_lba.saturating_add(array_lbas.saturating_sub(1));
        if is_primary {
            if partition_entry_lba < 2 || array_end_lba_inclusive >= first_usable_lba {
                return Err(PartitionParseError::InvalidGeometry(format!(
                    "primary GPT entry array LBAs [{partition_entry_lba}..={array_end_lba_inclusive}] overlap header or first_usable_lba={first_usable_lba}"
                )));
            }
        } else if partition_entry_lba <= last_usable_lba
            || array_end_lba_inclusive >= expected_my_lba
        {
            return Err(PartitionParseError::InvalidGeometry(format!(
                "backup GPT entry array LBAs [{partition_entry_lba}..={array_end_lba_inclusive}] overlap usable LBAs (<= {last_usable_lba}) or backup header ({expected_my_lba})"
            )));
        }

        let array_len = usize::try_from(array_bytes_u64).map_err(|_| {
            PartitionParseError::InvalidGeometry("GPT entry array exceeds usize".to_owned())
        })?;
        let mut raw_entries = vec![0_u8; array_len];
        read_at(array_offset, &mut raw_entries).map_err(PartitionParseError::Io)?;

        let computed_entries_crc = crc32_ieee(&raw_entries);
        if computed_entries_crc != partition_entry_array_crc32 {
            return Err(PartitionParseError::PrimaryGptCorrupt {
                detail: format!(
                    "GPT entry array CRC32 mismatch at LBA {partition_entry_lba}: stored=0x{partition_entry_array_crc32:08x}, computed=0x{computed_entries_crc:08x}"
                ),
            });
        }

        let entry_stride = partition_entry_size as usize;
        let mut partitions = Vec::new();
        for slot in 0..num_partition_entries {
            let start = (slot as usize) * entry_stride;
            let raw = &raw_entries[start..start + entry_stride];
            let mut type_bytes = [0_u8; 16];
            type_bytes.copy_from_slice(&raw[0..16]);
            let type_guid = PartUuid::from_raw_le(type_bytes);
            if type_guid.is_zero() {
                continue;
            }

            let mut uniq_bytes = [0_u8; 16];
            uniq_bytes.copy_from_slice(&raw[16..32]);
            let part_uuid = PartUuid::from_raw_le(uniq_bytes);
            let starting_lba = u64::from_le_bytes(raw[32..40].try_into().expect("8 bytes"));
            let ending_lba = u64::from_le_bytes(raw[40..48].try_into().expect("8 bytes"));
            let attributes = u64::from_le_bytes(raw[48..56].try_into().expect("8 bytes"));

            if starting_lba < first_usable_lba
                || starting_lba > ending_lba
                || ending_lba > last_usable_lba
            {
                return Err(PartitionParseError::InvalidGeometry(format!(
                    "GPT slot {} LBA range [{starting_lba}..={ending_lba}] violates usable window [{first_usable_lba}..={last_usable_lba}]",
                    slot + 1
                )));
            }
            let lba_count = ending_lba
                .checked_sub(starting_lba)
                .and_then(|d| d.checked_add(1))
                .ok_or_else(|| {
                    PartitionParseError::InvalidGeometry("GPT partition LBA count overflow".into())
                })?;
            let start_byte = starting_lba.checked_mul(lba_bytes).ok_or_else(|| {
                PartitionParseError::InvalidGeometry("GPT partition start_byte overflow".into())
            })?;
            let byte_len = lba_count.checked_mul(lba_bytes).ok_or_else(|| {
                PartitionParseError::InvalidGeometry("GPT partition byte_len overflow".into())
            })?;
            let end_byte = start_byte.checked_add(byte_len).ok_or_else(|| {
                PartitionParseError::InvalidGeometry("GPT partition end_byte overflow".into())
            })?;
            if end_byte > image_len_bytes {
                return Err(PartitionParseError::InvalidGeometry(format!(
                    "GPT slot {} end_byte {end_byte} exceeds image length {image_len_bytes}",
                    slot + 1
                )));
            }

            let label = decode_gpt_utf16le_name(&raw[56..128], slot + 1)?;
            partitions.push(PartitionEntry {
                index: slot + 1,
                scheme: PartitionScheme::Gpt,
                start_lba: starting_lba,
                end_lba_inclusive: ending_lba,
                start_byte,
                byte_len,
                mbr_type: None,
                mbr_bootable: false,
                type_guid: Some(type_guid),
                part_uuid: Some(part_uuid),
                label,
                attributes,
            });
        }

        validate_pairwise_non_overlap(&partitions)?;

        Ok((
            ParsedGptHeader {
                disk_guid: PartUuid::from_raw_le(disk_guid_bytes),
                alternate_lba,
                first_usable_lba,
                last_usable_lba,
            },
            partitions,
        ))
    }
}

fn decode_gpt_utf16le_name(
    raw_72_bytes: &[u8],
    slot_one_based: u32,
) -> Result<Option<String>, PartitionParseError> {
    let mut units = Vec::with_capacity(36);
    for &pair in raw_72_bytes.as_chunks::<2>().0 {
        let unit = u16::from_le_bytes(pair);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    if units.is_empty() {
        return Ok(None);
    }
    let mut out = String::with_capacity(units.len());
    for decoded in char::decode_utf16(units) {
        let ch = decoded.map_err(|_| {
            PartitionParseError::InvalidGeometry(format!(
                "GPT slot {slot_one_based} name contains unpaired UTF-16 surrogate"
            ))
        })?;
        out.push(ch);
    }
    Ok(Some(out))
}

fn validate_pairwise_non_overlap(partitions: &[PartitionEntry]) -> Result<(), PartitionParseError> {
    if partitions.len() < 2 {
        return Ok(());
    }
    let mut sorted: Vec<&PartitionEntry> = partitions.iter().collect();
    sorted.sort_by_key(|entry| (entry.start_byte, entry.end_byte(), entry.index));
    for pair in sorted.windows(2) {
        let first = pair[0];
        let second = pair[1];
        if first.end_byte() > second.start_byte {
            return Err(PartitionParseError::OverlappingPartitions {
                first_index: first.index,
                second_index: second.index,
                first_range: (first.start_byte, first.end_byte()),
                second_range: (second.start_byte, second.end_byte()),
            });
        }
    }
    Ok(())
}

fn mbr_has_protective_gpt(lba0: &[u8; 512]) -> bool {
    (0..4_usize).any(|slot| lba0[446 + slot * 16 + 4] == MBR_TYPE_PROTECTIVE_GPT)
}

fn mbr_protective_layout_valid(lba0: &[u8; 512]) -> bool {
    let mut protective_count = 0_usize;
    let mut other_non_empty = 0_usize;
    for slot in 0..4_usize {
        let off = 446 + slot * 16;
        let part_type = lba0[off + 4];
        if part_type == MBR_TYPE_PROTECTIVE_GPT {
            let start_lba =
                u32::from_le_bytes([lba0[off + 8], lba0[off + 9], lba0[off + 10], lba0[off + 11]]);
            let count = u32::from_le_bytes([
                lba0[off + 12],
                lba0[off + 13],
                lba0[off + 14],
                lba0[off + 15],
            ]);
            if start_lba != 1 || count == 0 {
                return false;
            }
            protective_count += 1;
        } else if part_type != 0 {
            other_non_empty += 1;
        }
    }
    // Accept either pure protective MBR (exactly 1 0xEE entry, 0 hybrid entries)
    // or a raw LBA1 GPT with an empty MBR table when no hybrid entries exist.
    other_non_empty == 0 && protective_count <= 1
}

fn looks_like_filesystem_vbr(lba0: &[u8; 512], image_len_bytes: u64) -> bool {
    // NTFS / exFAT OEM signatures at bytes 3..11.
    if matches!(&lba0[3..11], b"NTFS    " | b"EXFAT   ") {
        return true;
    }
    // Valid FAT16/FAT32 BPB at LBA 0.
    if FatGeometry::parse(lba0, image_len_bytes).is_ok() {
        return true;
    }
    // Also recognize explicit FAT12/FAT16/FAT32 extended BPB type tags paired with x86 JMP.
    let valid_jmp = (lba0[0] == 0xEB && lba0[2] == 0x90) || lba0[0] == 0xE9;
    valid_jmp
        && (matches!(&lba0[54..62], b"FAT12   " | b"FAT16   " | b"FAT     ")
            || &lba0[82..90] == b"FAT32   ")
}

/// Specification of a single GPT partition for deterministic disk image synthesis.
#[derive(Debug, Clone)]
pub struct SyntheticGptPartitionSpec {
    pub type_guid: PartUuid,
    pub part_uuid: PartUuid,
    pub start_lba: u64,
    pub end_lba_inclusive: u64,
    pub label: String,
    pub attributes: u64,
}

/// Stamp a valid protective MBR + primary GPT + backup GPT onto `disk_bytes`
/// (`512`-byte logical sectors, 128-entry table). Useful for tests, fixtures,
/// and E2E multi-filesystem disk images.
pub fn write_gpt_partition_table(
    disk_bytes: &mut [u8],
    disk_guid: PartUuid,
    specs: &[SyntheticGptPartitionSpec],
) -> Result<(), PartitionParseError> {
    const LBA: usize = 512;
    const ENTRIES: u32 = 128;
    const ENTRY_SIZE: u32 = 128;
    const ENTRY_ARRAY_BYTES: usize = (ENTRIES as usize) * (ENTRY_SIZE as usize); // 16384 = 32 LBAs
    const ARRAY_LBAS: u64 = 32;

    if !disk_bytes.len().is_multiple_of(LBA) {
        return Err(PartitionParseError::InvalidGeometry(
            "disk_bytes length must be a multiple of 512".to_owned(),
        ));
    }
    let total_lbas = (disk_bytes.len() / LBA) as u64;
    // LBA 0 = protective MBR, LBA 1 = primary header, LBAs 2..=33 = primary entries,
    // LBAs (total-33)..=(total-2) = backup entries, LBA (total-1) = backup header.
    if total_lbas < 2 + ARRAY_LBAS * 2 + 2 {
        return Err(PartitionParseError::InvalidGeometry(format!(
            "disk image too small for 128-entry GPT ({total_lbas} LBAs)"
        )));
    }
    if specs.len() > ENTRIES as usize {
        return Err(PartitionParseError::InvalidGeometry(
            "too many partitions for 128-entry GPT".to_owned(),
        ));
    }

    let first_usable_lba = 2 + ARRAY_LBAS; // 34
    let backup_entries_lba = total_lbas - 1 - ARRAY_LBAS;
    let last_usable_lba = backup_entries_lba - 1;
    let backup_header_lba = total_lbas - 1;

    // 1. Protective MBR at LBA 0.
    disk_bytes[0..LBA].fill(0);
    let protective_sectors = u32::try_from(total_lbas.saturating_sub(1)).unwrap_or(u32::MAX);
    let p0 = &mut disk_bytes[446..462];
    p0[0] = 0x00;
    p0[4] = MBR_TYPE_PROTECTIVE_GPT;
    p0[8..12].copy_from_slice(&1_u32.to_le_bytes());
    p0[12..16].copy_from_slice(&protective_sectors.to_le_bytes());
    disk_bytes[510..512].copy_from_slice(&MBR_SIGNATURE_LE.to_le_bytes());

    // 2. Entry array bytes.
    let mut entry_array = vec![0_u8; ENTRY_ARRAY_BYTES];
    for (idx, spec) in specs.iter().enumerate() {
        let base = idx * (ENTRY_SIZE as usize);
        let slot = &mut entry_array[base..base + (ENTRY_SIZE as usize)];
        slot[0..16].copy_from_slice(&spec.type_guid.to_raw_le());
        slot[16..32].copy_from_slice(&spec.part_uuid.to_raw_le());
        slot[32..40].copy_from_slice(&spec.start_lba.to_le_bytes());
        slot[40..48].copy_from_slice(&spec.end_lba_inclusive.to_le_bytes());
        slot[48..56].copy_from_slice(&spec.attributes.to_le_bytes());
        let utf16: Vec<u16> = spec.label.encode_utf16().collect();
        if utf16.len() > 36 {
            return Err(PartitionParseError::InvalidGeometry(
                "GPT label exceeds 36 UTF-16 code units".to_owned(),
            ));
        }
        for (u_idx, unit) in utf16.into_iter().enumerate() {
            let off = 56 + u_idx * 2;
            slot[off..off + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    let entries_crc = crc32_ieee(&entry_array);

    let primary_entries_off = 2 * LBA;
    disk_bytes[primary_entries_off..primary_entries_off + ENTRY_ARRAY_BYTES]
        .copy_from_slice(&entry_array);

    let backup_entries_off = (backup_entries_lba as usize) * LBA;
    disk_bytes[backup_entries_off..backup_entries_off + ENTRY_ARRAY_BYTES]
        .copy_from_slice(&entry_array);

    // 3. Primary and backup headers.
    let stamp_header = |my_lba: u64, alt_lba: u64, entries_lba: u64| -> [u8; LBA] {
        let mut hdr = [0_u8; LBA];
        hdr[0..8].copy_from_slice(GPT_HEADER_SIGNATURE);
        hdr[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
        hdr[12..16].copy_from_slice(&MIN_GPT_HEADER_BYTES.to_le_bytes());
        hdr[24..32].copy_from_slice(&my_lba.to_le_bytes());
        hdr[32..40].copy_from_slice(&alt_lba.to_le_bytes());
        hdr[40..48].copy_from_slice(&first_usable_lba.to_le_bytes());
        hdr[48..56].copy_from_slice(&last_usable_lba.to_le_bytes());
        hdr[56..72].copy_from_slice(&disk_guid.to_raw_le());
        hdr[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        hdr[80..84].copy_from_slice(&ENTRIES.to_le_bytes());
        hdr[84..88].copy_from_slice(&ENTRY_SIZE.to_le_bytes());
        hdr[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let hdr_crc = crc32_ieee(&hdr[..MIN_GPT_HEADER_BYTES as usize]);
        hdr[16..20].copy_from_slice(&hdr_crc.to_le_bytes());
        hdr
    };

    let primary_hdr = stamp_header(1, backup_header_lba, 2);
    disk_bytes[LBA..2 * LBA].copy_from_slice(&primary_hdr);

    let backup_hdr = stamp_header(backup_header_lba, 1, backup_entries_lba);
    let backup_hdr_off = (backup_header_lba as usize) * LBA;
    disk_bytes[backup_hdr_off..backup_hdr_off + LBA].copy_from_slice(&backup_hdr);

    // Self-verify round-trip invariants before returning.
    PartitionTable::parse_bytes(disk_bytes, &PartitionParseOptions::default())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_linux_fs_guid() -> PartUuid {
        PartUuid::from_str("0fc63daf-8483-4772-8e79-3d69d8477de4").expect("linux fs type guid")
    }

    fn build_two_partition_gpt_disk() -> Vec<u8> {
        let mut disk = vec![0_u8; 256 * 512]; // 128 KiB (LBAs 0..=255, usable 34..=222)
        let disk_guid =
            PartUuid::from_str("11111111-2222-3333-4444-555555555555").expect("disk guid");
        let p1_uuid = PartUuid::from_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0001").expect("p1 uuid");
        let p2_uuid = PartUuid::from_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0002").expect("p2 uuid");
        write_gpt_partition_table(
            &mut disk,
            disk_guid,
            &[
                SyntheticGptPartitionSpec {
                    type_guid: sample_linux_fs_guid(),
                    part_uuid: p1_uuid,
                    start_lba: 40,
                    end_lba_inclusive: 119,
                    label: "ROOT_EXT4".to_owned(),
                    attributes: 0,
                },
                SyntheticGptPartitionSpec {
                    type_guid: sample_linux_fs_guid(),
                    part_uuid: p2_uuid,
                    start_lba: 120,
                    end_lba_inclusive: 200,
                    label: "DATA_FAT".to_owned(),
                    attributes: 0,
                },
            ],
        )
        .expect("build synthetic GPT disk");
        disk
    }

    #[test]
    fn crc32_ieee_matches_standard_check_vector_and_partuuid_roundtrips() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        let text = "0fc63daf-8483-4772-8e79-3d69d8477de4";
        let guid = PartUuid::from_str(text).expect("parse UEFI GUID");
        assert_eq!(guid.to_string(), text);
        // Verify mixed-endian layout of first three fields:
        assert_eq!(&guid.to_raw_le()[0..4], &0x0fc6_3daf_u32.to_le_bytes());
        assert_eq!(&guid.to_raw_le()[4..6], &0x8483_u16.to_le_bytes());
        assert_eq!(&guid.to_raw_le()[6..8], &0x4772_u16.to_le_bytes());
        assert_eq!(&guid.to_raw_le()[8..10], &[0x8e, 0x79]);
    }

    #[test]
    fn gpt_parses_and_selects_by_index_partuuid_and_label() {
        let disk = build_two_partition_gpt_disk();
        let table = PartitionTable::parse_bytes(&disk, &PartitionParseOptions::default())
            .expect("valid GPT");
        assert_eq!(table.scheme, PartitionScheme::Gpt);
        assert!(!table.used_backup_gpt_header);
        assert_eq!(table.partitions.len(), 2);

        let by_idx = table
            .select(&PartitionSelector::from_str("2").expect("index selector"))
            .expect("select p2");
        assert_eq!(by_idx.start_byte, 120 * 512);
        assert_eq!(by_idx.byte_len, 81 * 512);

        let by_uuid = table
            .select(
                &PartitionSelector::from_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0001")
                    .expect("uuid selector"),
            )
            .expect("select p1 by uuid");
        assert_eq!(by_uuid.index, 1);
        assert_eq!(by_uuid.label.as_deref(), Some("ROOT_EXT4"));

        let by_label = table
            .select(&PartitionSelector::from_str("label:DATA_FAT").expect("label selector"))
            .expect("select p2 by label");
        assert_eq!(by_label.index, 2);
    }

    #[test]
    fn corrupted_primary_gpt_fails_closed_by_default_and_recovers_only_when_explicitly_permitted() {
        let mut disk = build_two_partition_gpt_disk();
        // Corrupt one byte in the primary GPT header at LBA 1.
        disk[512 + 40] ^= 0xFF;

        let default_err = PartitionTable::parse_bytes(&disk, &PartitionParseOptions::default())
            .expect_err("corrupted primary GPT must fail closed when fallback is off");
        assert!(
            matches!(default_err, PartitionParseError::PrimaryGptCorrupt { .. }),
            "unexpected error: {default_err:?}"
        );

        let fallback_opts = PartitionParseOptions {
            allow_backup_gpt_fallback: true,
            ..PartitionParseOptions::default()
        };
        let recovered = PartitionTable::parse_bytes(&disk, &fallback_opts)
            .expect("backup GPT must recover when explicitly permitted");
        assert!(recovered.used_backup_gpt_header);
        assert!(recovered.primary_gpt_error.is_some());
        assert_eq!(recovered.partitions.len(), 2);
    }

    #[test]
    fn gpt_rejects_overlapping_entries_and_out_of_bounds_lbas() {
        let mut disk = build_two_partition_gpt_disk();
        // Mutate partition 2 start_lba from 120 -> 119 (overlapping partition 1's end_lba 119)
        // and re-stamp primary CRC32s so CRC passes and interval overlap logic is tested!
        let p2_off = 2 * 512 + 128;
        disk[p2_off + 32..p2_off + 40].copy_from_slice(&119_u64.to_le_bytes());
        let entries_crc = crc32_ieee(&disk[2 * 512..2 * 512 + 128 * 128]);
        disk[512 + 88..512 + 92].copy_from_slice(&entries_crc.to_le_bytes());
        disk[512 + 16..512 + 20].fill(0);
        let hdr_crc = crc32_ieee(&disk[512..512 + 92]);
        disk[512 + 16..512 + 20].copy_from_slice(&hdr_crc.to_le_bytes());

        let err = PartitionTable::parse_bytes(&disk, &PartitionParseOptions::default())
            .expect_err("overlapping GPT entries must be rejected");
        assert!(
            matches!(
                err,
                PartitionParseError::OverlappingPartitions {
                    first_index: 1,
                    second_index: 2,
                    ..
                }
            ),
            "expected OverlappingPartitions, got {err:?}"
        );

        // Even with backup fallback enabled, structural overlap in primary is a hard error!
        let err_with_fallback = PartitionTable::parse_bytes(
            &disk,
            &PartitionParseOptions {
                allow_backup_gpt_fallback: true,
                ..PartitionParseOptions::default()
            },
        )
        .expect_err("overlap must not silently mask behind backup GPT");
        assert!(matches!(
            err_with_fallback,
            PartitionParseError::OverlappingPartitions { .. }
        ));
    }

    #[test]
    fn legacy_mbr_parses_and_disambiguates_ntfs_and_fat_vbrs() {
        let mut mbr_disk = vec![0_u8; 64 * 512];
        // Slot 1: bootable Linux 0x83 [LBA 8..24)
        mbr_disk[446] = 0x80;
        mbr_disk[446 + 4] = 0x83;
        mbr_disk[446 + 8..446 + 12].copy_from_slice(&8_u32.to_le_bytes());
        mbr_disk[446 + 12..446 + 16].copy_from_slice(&16_u32.to_le_bytes());
        // Slot 2: FAT32 LBA 0x0C [LBA 24..64)
        mbr_disk[462 + 4] = 0x0C;
        mbr_disk[462 + 8..462 + 12].copy_from_slice(&24_u32.to_le_bytes());
        mbr_disk[462 + 12..462 + 16].copy_from_slice(&40_u32.to_le_bytes());
        mbr_disk[510..512].copy_from_slice(&MBR_SIGNATURE_LE.to_le_bytes());

        let parsed = PartitionTable::parse_bytes(&mbr_disk, &PartitionParseOptions::default())
            .expect("valid MBR");
        assert_eq!(parsed.scheme, PartitionScheme::Mbr);
        assert_eq!(parsed.partitions.len(), 2);
        assert!(parsed.partitions[0].mbr_bootable);
        assert_eq!(parsed.partitions[1].start_byte, 24 * 512);
        assert_eq!(parsed.partitions[1].byte_len, 40 * 512);

        // NTFS VBR with 0x55AA must NOT be misclassified as an MBR partition table!
        let mut ntfs_vbr = mbr_disk.clone();
        ntfs_vbr[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        ntfs_vbr[3..11].copy_from_slice(b"NTFS    ");
        let vbr_err = PartitionTable::parse_bytes(&ntfs_vbr, &PartitionParseOptions::default())
            .expect_err("NTFS VBR must not parse as MBR");
        assert!(matches!(
            vbr_err,
            PartitionParseError::NotAPartitionTable(_)
        ));
    }

    #[test]
    fn nested_partition_table_bomb_is_rejected() {
        let inner_gpt = build_two_partition_gpt_disk(); // 256 LBAs = 128 KiB
        let mut outer_disk = vec![0_u8; 512 * 512]; // 256 KiB
        let outer_guid =
            PartUuid::from_str("99999999-8888-7777-6666-555555555555").expect("outer guid");
        let p1_uuid = PartUuid::from_str("bbbbbbbb-cccc-dddd-eeee-ffffffff0001").expect("p1 uuid");
        write_gpt_partition_table(
            &mut outer_disk,
            outer_guid,
            &[SyntheticGptPartitionSpec {
                type_guid: sample_linux_fs_guid(),
                part_uuid: p1_uuid,
                start_lba: 40,
                end_lba_inclusive: 40 + 256 - 1,
                label: "NESTED_BOMB".to_owned(),
                attributes: 0,
            }],
        )
        .expect("write outer GPT");

        let start = 40 * 512;
        outer_disk[start..start + inner_gpt.len()].copy_from_slice(&inner_gpt);

        let outer_table =
            PartitionTable::parse_bytes(&outer_disk, &PartitionParseOptions::default())
                .expect("outer GPT parses");
        let p1 = &outer_table.partitions[0];
        let slice = &outer_disk[p1.start_byte as usize..p1.end_byte() as usize];
        let bomb_err = PartitionTable::ensure_slice_not_nested_partition_table(
            p1.index,
            p1.byte_len,
            outer_table.logical_block_bytes,
            |off, buf| {
                let s = off as usize;
                buf.copy_from_slice(&slice[s..s + buf.len()]);
                Ok(())
            },
        )
        .expect_err("nested GPT inside GPT partition must be refused");
        assert!(matches!(
            bomb_err,
            PartitionParseError::NestedPartitionTable {
                partition_index: 1,
                inner_scheme: PartitionScheme::Gpt
            }
        ));
    }

    proptest! {
        #[test]
        fn prop_arbitrary_corrupted_gpt_bytes_never_panic_or_violate_bounds(
            flip_offset in 0_usize..(256 * 512),
            flip_mask in 1_u8..=255_u8,
            allow_fallback in any::<bool>(),
        ) {
            let mut disk = build_two_partition_gpt_disk();
            disk[flip_offset] ^= flip_mask;
            let opts = PartitionParseOptions {
                allow_backup_gpt_fallback: allow_fallback,
                ..PartitionParseOptions::default()
            };
            if let Ok(table) = PartitionTable::parse_bytes(&disk, &opts) {
                for entry in &table.partitions {
                    prop_assert!(entry.start_lba >= table.first_usable_lba);
                    prop_assert!(entry.start_lba <= entry.end_lba_inclusive);
                    prop_assert!(entry.end_lba_inclusive <= table.last_usable_lba);
                    prop_assert!(entry.end_byte() <= disk.len() as u64);
                }
            }
        }
    }
}
