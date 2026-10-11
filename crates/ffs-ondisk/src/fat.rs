//! FAT16/FAT32 geometry and directory records. No I/O or native mutation.
//!
//! Layout follows the Microsoft FAT specification and Linux `msdos_fs.h`.
//! FAT type is derived from cluster count, never from the cosmetic type label.
//! This is a bounded read profile: 512..=4096-byte sectors, clusters up to
//! 64 KiB, and one or two FAT copies. FAT12 and exFAT are not admitted.

use ffs_types::{ParseError, ensure_slice, read_le_u16, read_le_u32};
use std::time::Duration;

fn invalid(field: &'static str, reason: &'static str) -> ParseError {
    ParseError::InvalidField { field, reason }
}

/// Width of the allocation entries, not the boot sector's type string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatKind {
    Fat16,
    Fat32,
}

impl FatKind {
    #[must_use]
    pub const fn entry_bytes(self) -> u32 {
        match self {
            Self::Fat16 => 2,
            Self::Fat32 => 4,
        }
    }

    const fn reserved_start(self) -> u32 {
        match self {
            Self::Fat16 => 0xFFF0,
            Self::Fat32 => 0x0FFF_FFF0,
        }
    }

    /// FAT32's upper four bits do not participate in chain interpretation.
    #[must_use]
    pub fn decode_entry(self, raw: u32) -> FatEntry {
        let value = raw
            & match self {
                Self::Fat16 => 0xFFFF,
                Self::Fat32 => 0x0FFF_FFFF,
            };
        let reserved = self.reserved_start();
        match value {
            0 => FatEntry::Free,
            1 => FatEntry::Reserved,
            n if n >= reserved + 8 => FatEntry::End,
            n if n == reserved + 7 => FatEntry::Bad,
            n if n >= reserved => FatEntry::Reserved,
            n => FatEntry::Next(n),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatEntry {
    Free,
    Reserved,
    Bad,
    End,
    Next(u32),
}

/// Validated volume-relative geometry. Fields are private so callers cannot
/// construct a geometry that bypasses the BPB and backing-length checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatGeometry {
    kind: FatKind,
    sector_bytes: u32,
    cluster_bytes: u32,
    fat_count: u8,
    fat_start: u64,
    fat_bytes: u64,
    root_start: u64,
    root_entries: u16,
    root_cluster: u32,
    data_start: u64,
    cluster_count: u32,
    volume_bytes: u64,
    active_fat: u8,
    mirrored: bool,
    fs_info_sector: Option<u16>,
    backup_boot_sector: Option<u16>,
}

impl FatGeometry {
    /// Parse a boot sector at the start of a selected volume, whose available
    /// byte length is `backing_bytes`. Trailing bytes outside the volume are
    /// never made part of its address space. The hidden-sector field is not
    /// added to offsets: partition selection belongs to the caller.
    pub fn parse(boot: &[u8], backing_bytes: u64) -> Result<Self, ParseError> {
        ensure_slice(boot, 0, 512)?;
        if read_le_u16(boot, 510)? != 0xAA55 {
            return Err(invalid("fat.boot_signature", "expected 55 AA at byte 510"));
        }
        if &boot[3..11] == b"EXFAT   " || &boot[3..11] == b"NTFS    " {
            return Err(invalid("fat.kind", "not a FAT16/FAT32 volume"));
        }
        let sector_bytes = u32::from(read_le_u16(boot, 11)?);
        if !matches!(sector_bytes, 512 | 1024 | 2048 | 4096) {
            return Err(invalid("fat.sector_bytes", "unsupported sector size"));
        }
        let sectors_per_cluster = u32::from(boot[13]);
        if !sectors_per_cluster.is_power_of_two() || sectors_per_cluster > 128 {
            return Err(invalid(
                "fat.sectors_per_cluster",
                "invalid cluster geometry",
            ));
        }
        let cluster_bytes = sector_bytes * sectors_per_cluster;
        if cluster_bytes > 65_536 {
            return Err(invalid(
                "fat.cluster_bytes",
                "read profile supports at most 64 KiB",
            ));
        }
        let reserved = read_le_u16(boot, 14)?;
        let fat_count = boot[16];
        if reserved == 0 || !(1..=2).contains(&fat_count) {
            return Err(invalid(
                "fat.reserved_or_copies",
                "need reserved sectors and one or two FATs",
            ));
        }
        let root_entries = read_le_u16(boot, 17)?;
        let small_total = u32::from(read_le_u16(boot, 19)?);
        let large_total = read_le_u32(boot, 32)?;
        if small_total != 0 && large_total != 0 && small_total != large_total {
            return Err(invalid("fat.total_sectors", "conflicting sector counts"));
        }
        let total = if small_total == 0 {
            large_total
        } else {
            small_total
        };
        let small_fat = u32::from(read_le_u16(boot, 22)?);
        let fat_sectors = if small_fat == 0 {
            read_le_u32(boot, 36)?
        } else {
            small_fat
        };
        if total == 0 || fat_sectors == 0 {
            return Err(invalid("fat.size", "zero volume or FAT size"));
        }
        let root_bytes = u64::from(root_entries) * 32;
        let root_sectors = root_bytes.div_ceil(u64::from(sector_bytes));
        let first_data =
            u64::from(reserved) + u64::from(fat_count) * u64::from(fat_sectors) + root_sectors;
        let data_sectors = u64::from(total)
            .checked_sub(first_data)
            .ok_or_else(|| invalid("fat.data_region", "metadata exceeds volume"))?;
        let cluster_count = u32::try_from(data_sectors / u64::from(sectors_per_cluster))
            .map_err(|_| invalid("fat.cluster_count", "overflow"))?;
        let kind = match cluster_count {
            0..=4084 => return Err(invalid("fat.kind", "FAT12 is not supported")),
            4085..=65_524 => FatKind::Fat16,
            _ => FatKind::Fat32,
        };
        // A count-derived dialect must also have that dialect's BPB layout.
        let (root_cluster, active_fat, mirrored, fs_info_sector, backup_boot_sector) = match kind {
            FatKind::Fat16 => {
                if small_fat == 0
                    || root_entries == 0
                    || !root_bytes.is_multiple_of(u64::from(sector_bytes))
                {
                    return Err(invalid("fat16.layout", "invalid fixed root or FAT16 size"));
                }
                (0, 0, true, None, None)
            }
            FatKind::Fat32 => {
                if small_fat != 0 || root_entries != 0 || small_total != 0 {
                    return Err(invalid("fat32.layout", "FAT16 fields in FAT32 BPB"));
                }
                if read_le_u16(boot, 42)? != 0 {
                    return Err(invalid("fat32.version", "unsupported filesystem version"));
                }
                if cluster_count >= 0x0FFF_FFF5 {
                    return Err(invalid(
                        "fat32.cluster_count",
                        "cluster namespace exhausted",
                    ));
                }
                let flags = read_le_u16(boot, 40)?;
                if flags & !0x008F != 0 {
                    return Err(invalid("fat32.flags", "reserved flag bits are set"));
                }
                let mirrored = flags & 0x80 == 0;
                let active = if mirrored { 0 } else { (flags & 0x0F) as u8 };
                if active >= fat_count {
                    return Err(invalid("fat32.active_fat", "active copy is absent"));
                }
                let pointer = |offset| -> Result<Option<u16>, ParseError> {
                    let value = read_le_u16(boot, offset)?;
                    match value {
                        0 | 0xFFFF => Ok(None),
                        n if n < reserved => Ok(Some(n)),
                        _ => Err(invalid("fat32.reserved_pointer", "outside reserved region")),
                    }
                };
                (
                    read_le_u32(boot, 44)?,
                    active,
                    mirrored,
                    pointer(48)?,
                    pointer(50)?,
                )
            }
        };
        let fat_bytes = u64::from(fat_sectors) * u64::from(sector_bytes);
        if (u64::from(cluster_count) + 2) * u64::from(kind.entry_bytes()) > fat_bytes {
            return Err(invalid("fat.capacity", "FAT does not cover data clusters"));
        }
        let volume_bytes = u64::from(total) * u64::from(sector_bytes);
        if volume_bytes > backing_bytes {
            return Err(invalid("fat.backing_bytes", "truncated volume"));
        }
        let geometry = Self {
            kind,
            sector_bytes,
            cluster_bytes,
            fat_count,
            fat_start: u64::from(reserved) * u64::from(sector_bytes),
            fat_bytes,
            root_start: (u64::from(reserved) + u64::from(fat_count) * u64::from(fat_sectors))
                * u64::from(sector_bytes),
            root_entries,
            root_cluster,
            data_start: first_data * u64::from(sector_bytes),
            cluster_count,
            volume_bytes,
            active_fat,
            mirrored,
            fs_info_sector,
            backup_boot_sector,
        };
        if kind == FatKind::Fat32 {
            geometry.cluster_offset(root_cluster)?;
        }
        Ok(geometry)
    }

    #[must_use]
    pub const fn kind(&self) -> FatKind {
        self.kind
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
    pub const fn cluster_count(&self) -> u32 {
        self.cluster_count
    }
    #[must_use]
    pub const fn volume_bytes(&self) -> u64 {
        self.volume_bytes
    }
    #[must_use]
    pub const fn fat_count(&self) -> u8 {
        self.fat_count
    }
    #[must_use]
    pub const fn active_fat(&self) -> u8 {
        self.active_fat
    }
    #[must_use]
    pub const fn mirrored(&self) -> bool {
        self.mirrored
    }
    #[must_use]
    pub const fn root_cluster(&self) -> u32 {
        self.root_cluster
    }
    #[must_use]
    pub const fn fs_info_sector(&self) -> Option<u16> {
        self.fs_info_sector
    }
    #[must_use]
    pub const fn backup_boot_sector(&self) -> Option<u16> {
        self.backup_boot_sector
    }

    #[must_use]
    pub fn fixed_root(&self) -> Option<(u64, u64)> {
        (self.kind == FatKind::Fat16)
            .then_some((self.root_start, u64::from(self.root_entries) * 32))
    }

    pub fn cluster_offset(&self, cluster: u32) -> Result<u64, ParseError> {
        if !(2..self.kind.reserved_start()).contains(&cluster)
            || u64::from(cluster) > u64::from(self.cluster_count) + 1
        {
            return Err(invalid("fat.cluster", "not an addressable data cluster"));
        }
        Ok(self.data_start + u64::from(cluster - 2) * u64::from(self.cluster_bytes))
    }

    pub fn entry_offset(&self, copy: u8, cluster: u32) -> Result<u64, ParseError> {
        self.cluster_offset(cluster)?;
        if copy >= self.fat_count {
            return Err(invalid("fat.copy", "copy index out of range"));
        }
        Ok(self.fat_start
            + u64::from(copy) * self.fat_bytes
            + u64::from(cluster) * u64::from(self.kind.entry_bytes()))
    }
}

/// Native fields retained without Unicode replacement or invented Unix metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatDirEntry {
    pub short_name: [u8; 11],
    pub long_name: Option<Vec<u16>>,
    pub attributes: u8,
    pub case_flags: u8,
    pub first_cluster: u32,
    pub size: u32,
    pub created_date: u16,
    pub created_time: u16,
    /// Creation-time increments of 10 ms, including the odd second (0..=199).
    pub created_centiseconds: u8,
    pub accessed_date: u16,
    pub modified_date: u16,
    pub modified_time: u16,
}

impl FatDirEntry {
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.attributes & 0x10 != 0
    }

    /// FAT has no creation date when this optional field is zero. Other raw
    /// creation fields are retained even when they cannot identify a date.
    pub fn created_timestamp(&self) -> Result<Option<FatTimestamp>, ParseError> {
        (self.created_date != 0)
            .then(|| {
                FatTimestamp::parse(
                    self.created_date,
                    self.created_time,
                    self.created_centiseconds,
                )
            })
            .transpose()
    }

    /// Last access has day precision; FAT stores no access-time-of-day field.
    pub fn accessed_timestamp(&self) -> Result<Option<FatTimestamp>, ParseError> {
        (self.accessed_date != 0)
            .then(|| FatTimestamp::parse(self.accessed_date, 0, 0))
            .transpose()
    }

    pub fn modified_timestamp(&self) -> Result<Option<FatTimestamp>, ParseError> {
        (self.modified_date != 0 || self.modified_time != 0)
            .then(|| FatTimestamp::parse(self.modified_date, self.modified_time, 0))
            .transpose()
    }

    /// ASCII short-name presentation. Non-ASCII OEM bytes are deliberately
    /// not decoded with the host's locale or with a lossy UTF-8 conversion.
    #[must_use]
    pub fn ascii_short_name(&self) -> Option<String> {
        if !self.short_name.is_ascii() || self.short_name[0] == 5 {
            return None;
        }
        let mut name = String::new();
        for (part, lower) in [(&self.short_name[..8], 0x08), (&self.short_name[8..], 0x10)] {
            let end = part.iter().rposition(|b| *b != b' ').map_or(0, |n| n + 1);
            if end == 0 {
                continue;
            }
            if !name.is_empty() {
                name.push('.');
            }
            for &byte in &part[..end] {
                if byte < 0x20 || matches!(byte, b'/' | b'\\' | b':' | 0x7F) {
                    return None;
                }
                name.push(char::from(if self.case_flags & lower != 0 {
                    byte.to_ascii_lowercase()
                } else {
                    byte
                }));
            }
        }
        (!name.is_empty()).then_some(name)
    }
}

/// A checked FAT wall-clock timestamp. The format carries no timezone or UTC
/// offset. `utc_projection` places its calendar fields on a UTC timeline as a
/// deterministic presentation policy; it does not recover the original instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatTimestamp {
    seconds: u64,
    nanoseconds: u32,
}

impl FatTimestamp {
    /// Decode a present native date/time. Creation's extra byte is in 10 ms
    /// units across the full two-second interval; use zero for modification
    /// times, and zero for both time fields when decoding an access date.
    pub fn parse(date: u16, time: u16, centiseconds: u8) -> Result<Self, ParseError> {
        let year = 1980 + u64::from(date >> 9);
        let month = usize::from((date >> 5) & 15);
        let day = u64::from(date & 31);
        let hour = u64::from(time >> 11);
        let minute = u64::from((time >> 5) & 63);
        let second = u64::from(time & 31) * 2;
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let months = [
            31_u64,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        if !(1..=12).contains(&month) || day == 0 || day > months[month - 1] {
            return Err(invalid("fat.timestamp_date", "invalid calendar date"));
        }
        if hour > 23 || minute > 59 || second > 58 || centiseconds > 199 {
            return Err(invalid(
                "fat.timestamp_time",
                "invalid time or 10 ms increment",
            ));
        }
        let before = |year: u64| {
            let last = year - 1;
            365 * last + last / 4 - last / 100 + last / 400
        };
        let days = before(year) - before(1970) + months[..month - 1].iter().sum::<u64>() + day - 1;
        Ok(Self {
            seconds: days * 86_400
                + hour * 3600
                + minute * 60
                + second
                + u64::from(centiseconds / 100),
            nanoseconds: u32::from(centiseconds % 100) * 10_000_000,
        })
    }

    #[must_use]
    pub const fn utc_projection(self) -> Duration {
        Duration::new(self.seconds, self.nanoseconds)
    }
}

#[must_use]
pub fn short_name_checksum(name: &[u8; 11]) -> u8 {
    name.iter()
        .fold(0_u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

#[derive(Debug)]
struct LongName {
    units: [u16; 260],
    slots: u8,
    next: u8,
    checksum: u8,
}

/// Streaming LFN decoder; state carries across directory-sector/cluster edges.
/// Invalid/orphan long-name records never attach to an unrelated short entry.
#[derive(Debug, Default)]
pub struct FatDirectoryDecoder {
    long: Option<LongName>,
    ended: bool,
    malformed_long_name: bool,
}

impl FatDirectoryDecoder {
    #[must_use]
    pub const fn ended(&self) -> bool {
        self.ended
    }

    /// The ordinary reader may use the short alias after a damaged LFN set.
    /// A checker must still report that damage instead of declaring it clean.
    #[must_use]
    pub const fn has_malformed_long_name(&self) -> bool {
        self.malformed_long_name
    }

    /// Finish a full directory without an end-marker slot. A pending LFN set
    /// at the allocation boundary is an orphan, even if its ordinals are valid.
    pub fn finish(&mut self) {
        self.malformed_long_name |= self.long.take().is_some();
        self.ended = true;
    }

    pub fn push(
        &mut self,
        slot: &[u8; 32],
        kind: FatKind,
    ) -> Result<Option<FatDirEntry>, ParseError> {
        if self.ended {
            return Ok(None);
        }
        if slot[0] == 0 {
            self.finish();
            return Ok(None);
        }
        if slot[0] == 0xE5 {
            self.malformed_long_name |= self.long.take().is_some();
            return Ok(None);
        }
        if slot[11] == 0x0F {
            self.push_long(slot);
            return Ok(None);
        }
        let pending = self.long.take();
        if slot[11] & 0xC0 != 0 || slot[11] & 0x18 == 0x18 {
            self.malformed_long_name |= pending.is_some();
            return Err(invalid(
                "fat.directory_attributes",
                "invalid attribute combination",
            ));
        }
        if slot[11] & 0x08 != 0 {
            self.malformed_long_name |= pending.is_some();
            return Ok(None); // Volume label, not a file.
        }
        let mut short_name = [0_u8; 11];
        short_name.copy_from_slice(&slot[..11]);
        let long_name = pending.and_then(|long| {
            if long.next != 0 || long.checksum != short_name_checksum(&short_name) {
                self.malformed_long_name = true;
                return None;
            }
            let units = &long.units[..usize::from(long.slots) * 13];
            let end = units.iter().position(|u| *u == 0).unwrap_or(units.len());
            if end == 0
                || end > 255
                || units[..end].contains(&0xFFFF)
                || (end < units.len() && units[end + 1..].iter().any(|u| *u != 0xFFFF))
            {
                self.malformed_long_name = true;
                return None;
            }
            Some(units[..end].to_vec())
        });
        let low = u32::from(read_le_u16(slot, 26)?);
        let first_cluster = match kind {
            FatKind::Fat16 => low,
            FatKind::Fat32 => low | (u32::from(read_le_u16(slot, 20)? & 0x0FFF) << 16),
        };
        Ok(Some(FatDirEntry {
            short_name,
            long_name,
            attributes: slot[11],
            case_flags: slot[12],
            first_cluster,
            size: read_le_u32(slot, 28)?,
            created_date: read_le_u16(slot, 16)?,
            created_time: read_le_u16(slot, 14)?,
            created_centiseconds: slot[13],
            accessed_date: read_le_u16(slot, 18)?,
            modified_date: read_le_u16(slot, 24)?,
            modified_time: read_le_u16(slot, 22)?,
        }))
    }

    fn push_long(&mut self, slot: &[u8; 32]) {
        let ordinal = slot[0] & 0x1F;
        if !(1..=20).contains(&ordinal)
            || slot[0] & 0xA0 != 0
            || slot[12] != 0
            || slot[26] != 0
            || slot[27] != 0
        {
            self.long = None;
            self.malformed_long_name = true;
            return;
        }
        if slot[0] & 0x40 != 0 {
            self.malformed_long_name |= self.long.is_some();
            self.long = Some(LongName {
                units: [0xFFFF; 260],
                slots: ordinal,
                next: ordinal,
                checksum: slot[13],
            });
        }
        let Some(long) = self.long.as_mut() else {
            self.malformed_long_name = true;
            return;
        };
        if ordinal != long.next || slot[13] != long.checksum {
            self.long = None;
            self.malformed_long_name = true;
            return;
        }
        let start = usize::from(ordinal - 1) * 13;
        for (index, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .enumerate()
        {
            long.units[start + index] = u16::from_le_bytes([slot[offset], slot[offset + 1]]);
        }
        long.next -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot(kind: FatKind) -> [u8; 512] {
        let mut b = [0_u8; 512];
        b[11..13].copy_from_slice(&512_u16.to_le_bytes());
        b[13] = 1;
        b[16] = 2;
        b[510..].copy_from_slice(&[0x55, 0xAA]);
        match kind {
            FatKind::Fat16 => {
                b[14..16].copy_from_slice(&1_u16.to_le_bytes());
                b[17..19].copy_from_slice(&32_u16.to_le_bytes());
                b[19..21].copy_from_slice(&5043_u16.to_le_bytes());
                b[22..24].copy_from_slice(&20_u16.to_le_bytes());
            }
            FatKind::Fat32 => {
                b[14..16].copy_from_slice(&32_u16.to_le_bytes());
                b[32..36].copy_from_slice(&71_232_u32.to_le_bytes());
                b[36..40].copy_from_slice(&600_u32.to_le_bytes());
                b[44..48].copy_from_slice(&2_u32.to_le_bytes());
                b[48..50].copy_from_slice(&1_u16.to_le_bytes());
                b[50..52].copy_from_slice(&6_u16.to_le_bytes());
            }
        }
        b
    }

    #[test]
    fn geometry_uses_cluster_count_and_volume_relative_offsets() {
        let mut b = boot(FatKind::Fat16);
        b[54..62].copy_from_slice(b"FAT32   "); // Not authoritative.
        b[28..32].copy_from_slice(&2048_u32.to_le_bytes()); // Already-selected volume.
        let g = FatGeometry::parse(&b, 5043 * 512).unwrap();
        assert_eq!(g.kind(), FatKind::Fat16);
        assert_eq!(g.cluster_count(), 5000);
        assert_eq!(g.fixed_root(), Some((41 * 512, 1024)));
        assert_eq!(g.cluster_offset(2).unwrap(), 43 * 512);
        assert_eq!(g.entry_offset(1, 2).unwrap(), 21 * 512 + 4);
        assert_eq!(g.volume_bytes(), 5043 * 512);
        for n in [0, 1, 5002, 0xFFF0, u32::MAX] {
            assert!(g.cluster_offset(n).is_err());
        }
        assert!(g.entry_offset(2, 2).is_err());
    }

    #[test]
    fn fat32_active_copy_and_root_are_validated() {
        let mut b = boot(FatKind::Fat32);
        b[40..42].copy_from_slice(&0x81_u16.to_le_bytes());
        let g = FatGeometry::parse(&b, u64::MAX).unwrap();
        assert_eq!(g.cluster_count(), 70_000);
        assert_eq!(g.active_fat(), 1);
        assert!(!g.mirrored());
        assert_eq!(g.cluster_offset(2).unwrap(), 1232 * 512);
        assert_eq!(g.fixed_root(), None);
        assert_eq!(g.backup_boot_sector(), Some(6));
        b[40] = 0x82;
        assert!(FatGeometry::parse(&b, u64::MAX).is_err());
        b[40] = 0;
        b[44..48].copy_from_slice(&1_u32.to_le_bytes());
        assert!(FatGeometry::parse(&b, u64::MAX).is_err());
    }

    #[test]
    fn geometry_rejects_truncation_zero_divisors_and_insufficient_fat() {
        let b = boot(FatKind::Fat16);
        for end in 0..512 {
            assert!(FatGeometry::parse(&b[..end], u64::MAX).is_err());
        }
        assert!(FatGeometry::parse(&b, 5043 * 512 - 1).is_err());
        for (offset, value) in [(13, 0), (13, 3), (14, 0), (16, 0), (16, 3), (510, 0)] {
            let mut bad = b;
            bad[offset] = value;
            assert!(
                FatGeometry::parse(&bad, u64::MAX).is_err(),
                "offset {offset}"
            );
        }
        let mut bad = b;
        bad[22..24].copy_from_slice(&1_u16.to_le_bytes());
        assert!(FatGeometry::parse(&bad, u64::MAX).is_err());
        let mut bad = boot(FatKind::Fat32);
        bad[50..52].copy_from_slice(&32_u16.to_le_bytes());
        assert!(FatGeometry::parse(&bad, u64::MAX).is_err());
    }

    #[test]
    fn dialect_boundaries_require_matching_layouts() {
        for count in [4084_u32, 4085, 65_524, 65_525] {
            let mut b = boot(FatKind::Fat16);
            b[19..21].fill(0);
            b[22..24].copy_from_slice(&256_u16.to_le_bytes());
            b[32..36].copy_from_slice(&(count + 515).to_le_bytes());
            let result = FatGeometry::parse(&b, u64::MAX);
            assert_eq!(result.is_ok(), (4085..65_525).contains(&count), "{count}");
        }
    }

    #[test]
    fn allocation_entry_classes_and_reserved_bits() {
        for kind in [FatKind::Fat16, FatKind::Fat32] {
            let base = kind.reserved_start();
            assert_eq!(kind.decode_entry(0), FatEntry::Free);
            assert_eq!(kind.decode_entry(1), FatEntry::Reserved);
            assert_eq!(kind.decode_entry(123), FatEntry::Next(123));
            assert_eq!(kind.decode_entry(base), FatEntry::Reserved);
            assert_eq!(kind.decode_entry(base + 6), FatEntry::Reserved);
            assert_eq!(kind.decode_entry(base + 7), FatEntry::Bad);
            for n in 8..=15 {
                assert_eq!(kind.decode_entry(base + n), FatEntry::End);
            }
        }
        assert_eq!(FatKind::Fat32.decode_entry(0xA000_0012), FatEntry::Next(18));
    }

    fn short() -> [u8; 32] {
        let mut slot = [0_u8; 32];
        slot[..11].copy_from_slice(b"LONGFI~1TXT");
        slot[11] = 0x20;
        slot[26..28].copy_from_slice(&7_u16.to_le_bytes());
        slot[28..32].copy_from_slice(&513_u32.to_le_bytes());
        slot
    }

    fn long(ordinal: u8, checksum: u8, text: &[u16]) -> [u8; 32] {
        let mut slot = [0_u8; 32];
        slot[0] = ordinal;
        slot[11] = 0x0F;
        slot[13] = checksum;
        for (i, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .enumerate()
        {
            let unit = text
                .get(i)
                .copied()
                .unwrap_or(if i == text.len() { 0 } else { 0xFFFF });
            slot[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        slot
    }

    #[test]
    fn long_name_is_bound_to_its_short_record() {
        let text: Vec<u16> = "Long File.txt".encode_utf16().collect();
        let s = short();
        let checksum = short_name_checksum(b"LONGFI~1TXT");
        let l = long(0x41, checksum, &text);
        let mut decoder = FatDirectoryDecoder::default();
        assert!(decoder.push(&l, FatKind::Fat16).unwrap().is_none());
        let entry = decoder.push(&s, FatKind::Fat16).unwrap().unwrap();
        assert_eq!(entry.long_name, Some(text));
        assert_eq!(entry.ascii_short_name().as_deref(), Some("LONGFI~1.TXT"));
        assert_eq!((entry.first_cluster, entry.size), (7, 513));
        for (offset, value) in [
            (0, 0x42),
            (0, 0x01),
            (12, 1),
            (13, checksum.wrapping_add(1)),
            (26, 1),
        ] {
            let mut bad = l;
            bad[offset] = value;
            let mut decoder = FatDirectoryDecoder::default();
            decoder.push(&bad, FatKind::Fat16).unwrap();
            assert!(
                decoder
                    .push(&s, FatKind::Fat16)
                    .unwrap()
                    .unwrap()
                    .long_name
                    .is_none()
            );
        }
    }

    #[test]
    fn multi_slot_names_deleted_entries_and_end_marker() {
        let text: Vec<u16> = "name crossing records.txt".encode_utf16().collect();
        let sum = short_name_checksum(b"LONGFI~1TXT");
        let mut decoder = FatDirectoryDecoder::default();
        decoder
            .push(&long(0x42, sum, &text[13..]), FatKind::Fat32)
            .unwrap();
        decoder
            .push(&long(1, sum, &text[..13]), FatKind::Fat32)
            .unwrap();
        assert_eq!(
            decoder
                .push(&short(), FatKind::Fat32)
                .unwrap()
                .unwrap()
                .long_name,
            Some(text)
        );
        decoder
            .push(&long(0x41, sum, &[65]), FatKind::Fat32)
            .unwrap();
        let mut deleted = short();
        deleted[0] = 0xE5;
        decoder.push(&deleted, FatKind::Fat32).unwrap();
        assert!(
            decoder
                .push(&short(), FatKind::Fat32)
                .unwrap()
                .unwrap()
                .long_name
                .is_none()
        );
        decoder.push(&[0; 32], FatKind::Fat32).unwrap();
        assert!(decoder.ended());
        assert!(decoder.push(&short(), FatKind::Fat32).unwrap().is_none());
    }

    #[test]
    fn native_timestamp_calendar_and_fraction_boundaries() {
        // Independently specified UTC projections of the native calendar fields:
        // 1980-01-01, 2000-02-29, 2024-02-29 12:34:56, 2100-03-01,
        // and the last representable FAT date at 23:59:59.99.
        for (date, time, fraction, seconds, nanos) in [
            (0x0021, 0, 0, 315_532_800_u64, 0),
            (0x285D, 0, 0, 951_782_400, 0),
            (0x585D, 0x645C, 0, 1_709_210_096, 0),
            (0xF061, 0, 0, 4_107_542_400, 0),
            (0xFF9F, 0xBF7D, 199, 4_354_819_199, 990_000_000),
        ] {
            let timestamp = FatTimestamp::parse(date, time, fraction)
                .unwrap()
                .utc_projection();
            assert_eq!(
                (timestamp.as_secs(), timestamp.subsec_nanos()),
                (seconds, nanos),
                "date={date:#06x}, time={time:#06x}, fraction={fraction}"
            );
        }
        for (fraction, seconds, nanos) in [
            (0, 315_532_800_u64, 0),
            (1, 315_532_800, 10_000_000),
            (99, 315_532_800, 990_000_000),
            (100, 315_532_801, 0),
            (199, 315_532_801, 990_000_000),
        ] {
            let timestamp = FatTimestamp::parse(0x0021, 0, fraction)
                .unwrap()
                .utc_projection();
            assert_eq!(
                (timestamp.as_secs(), timestamp.subsec_nanos()),
                (seconds, nanos)
            );
        }
        for (date, time, fraction) in [
            (0, 0, 0),
            (0x0001, 0, 0),      // Month zero.
            (0x0020, 0, 0),      // Day zero.
            (0x01A1, 0, 0),      // Month thirteen.
            (0x005E, 0, 0),      // February thirty.
            (0x565D, 0, 0),      // 2023 is not a leap year.
            (0xF05D, 0, 0),      // 2100 is not a leap year.
            (0x0021, 0xC000, 0), // Hour twenty-four.
            (0x0021, 0x0780, 0), // Minute sixty.
            (0x0021, 30, 0),     // Encoded second sixty.
            (0x0021, 31, 0),
            (0x0021, 0, 200),
            (0x0021, 0, 255),
        ] {
            assert!(
                FatTimestamp::parse(date, time, fraction).is_err(),
                "date={date:#06x}, time={time:#06x}, fraction={fraction}"
            );
        }
    }

    #[test]
    fn directory_timestamp_fields_are_lossless_in_both_dialects() {
        for kind in [FatKind::Fat16, FatKind::Fat32] {
            let mut slot = short();
            slot[13] = 157;
            slot[14..16].copy_from_slice(&0x645C_u16.to_le_bytes());
            slot[16..18].copy_from_slice(&0x585D_u16.to_le_bytes());
            slot[18..20].copy_from_slice(&0x5861_u16.to_le_bytes());
            slot[22..24].copy_from_slice(&0x1883_u16.to_le_bytes());
            slot[24..26].copy_from_slice(&0x5862_u16.to_le_bytes());
            let entry = FatDirectoryDecoder::default()
                .push(&slot, kind)
                .unwrap()
                .unwrap();
            assert_eq!(entry.created_date, 0x585D);
            assert_eq!(entry.created_time, 0x645C);
            assert_eq!(entry.created_centiseconds, 157);
            assert_eq!(entry.accessed_date, 0x5861);
            let created = entry.created_timestamp().unwrap().unwrap().utc_projection();
            assert_eq!(
                (created.as_secs(), created.subsec_nanos()),
                (1_709_210_097, 570_000_000)
            );
            assert_eq!(
                entry
                    .accessed_timestamp()
                    .unwrap()
                    .unwrap()
                    .utc_projection()
                    .as_secs(),
                1_709_251_200
            );
            assert_eq!(
                entry
                    .modified_timestamp()
                    .unwrap()
                    .unwrap()
                    .utc_projection()
                    .as_secs(),
                1_709_348_646
            );
        }
    }

    #[test]
    fn missing_optional_dates_remain_unknown_without_losing_raw_fields() {
        let mut slot = short();
        slot[13] = 255;
        slot[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
        let entry = FatDirectoryDecoder::default()
            .push(&slot, FatKind::Fat16)
            .unwrap()
            .unwrap();
        assert_eq!(
            (entry.created_time, entry.created_centiseconds),
            (u16::MAX, 255)
        );
        assert_eq!(entry.created_timestamp().unwrap(), None);
        assert_eq!(entry.accessed_timestamp().unwrap(), None);
        assert_eq!(entry.modified_timestamp().unwrap(), None);

        // A partially populated mandatory modification timestamp remains an
        // error rather than being silently presented as an absent timestamp.
        slot[22..24].copy_from_slice(&1_u16.to_le_bytes());
        let entry = FatDirectoryDecoder::default()
            .push(&slot, FatKind::Fat16)
            .unwrap()
            .unwrap();
        assert!(entry.modified_timestamp().is_err());
    }

    #[test]
    fn checker_retains_long_name_damage_without_breaking_short_alias_fallback() {
        let sum = short_name_checksum(b"LONGFI~1TXT");
        let valid = long(0x41, sum, &[65]);
        let mut decoder = FatDirectoryDecoder::default();
        decoder.push(&valid, FatKind::Fat16).unwrap();
        assert_eq!(
            decoder
                .push(&short(), FatKind::Fat16)
                .unwrap()
                .unwrap()
                .long_name,
            Some(vec![65])
        );
        decoder.finish();
        assert!(!decoder.has_malformed_long_name());

        for ending in 0..4 {
            let mut decoder = FatDirectoryDecoder::default();
            decoder.push(&valid, FatKind::Fat16).unwrap();
            match ending {
                0 => {
                    decoder.finish();
                }
                1 => {
                    decoder.push(&[0; 32], FatKind::Fat16).unwrap();
                }
                2 => {
                    let mut deleted = short();
                    deleted[0] = 0xE5;
                    decoder.push(&deleted, FatKind::Fat16).unwrap();
                }
                _ => {
                    let mut other = short();
                    other[..11].copy_from_slice(b"OTHER   TXT");
                    let entry = decoder.push(&other, FatKind::Fat16).unwrap().unwrap();
                    assert_eq!(entry.ascii_short_name().as_deref(), Some("OTHER.TXT"));
                    assert!(entry.long_name.is_none());
                }
            }
            assert!(decoder.has_malformed_long_name(), "ending {ending}");
        }
    }
}
