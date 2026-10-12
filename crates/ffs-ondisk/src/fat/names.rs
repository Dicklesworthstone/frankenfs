//! Explicit OEM short-name decoding and bounded, single-code-page case folding.
//!
//! Byte mappings: Unicode's Microsoft CP437/CP850 tables, version 2.00:
//! <https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP437.TXT>
//! <https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP850.TXT>
//! Representable case pairs agree with Linux v6.19 `fs/nls/nls_cp{437,850}.c`.
//! This does not implement Windows' full Unicode LFN collation or normalization.

/// FAT does not record its OEM code page in the BPB. Selection is a caller
/// policy, never a guess based on a volume label, host locale, or file contents.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FatOemCodePage {
    #[default]
    Ascii,
    Cp437,
    Cp850,
}

impl FatOemCodePage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Cp437 => "437",
            Self::Cp850 => "850",
        }
    }

    /// Decode one native byte without replacement characters or host locale.
    #[must_use]
    pub fn decode(self, byte: u8) -> Option<char> {
        self.decode_unit(byte)
            .and_then(|unit| char::from_u32(u32::from(unit)))
    }

    /// All characters in the admitted single-byte pages occupy one UTF-16 unit.
    #[must_use]
    pub fn decode_unit(self, byte: u8) -> Option<u16> {
        if byte.is_ascii() {
            return Some(u16::from(byte));
        }
        let table = match self {
            Self::Ascii => return None,
            Self::Cp437 => &CP437,
            Self::Cp850 => &CP850,
        };
        Some(table[usize::from(byte - 128)])
    }

    fn case_pairs(self) -> &'static [(u16, u16)] {
        match self {
            Self::Ascii => &[],
            Self::Cp437 => CP437_PAIRS,
            Self::Cp850 => CP850_PAIRS,
        }
    }

    /// Canonical uppercase key for a UTF-16 unit. Units outside the selected
    /// OEM repertoire, including unpaired surrogates, remain exact. In
    /// particular, sharp s never expands to SS and accented letters never lose
    /// their accents. CP850's dotless i has the native one-way mapping to I.
    #[must_use]
    pub fn fold_unit(self, unit: u16) -> u16 {
        if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
            return unit - 32;
        }
        if self == Self::Cp850 && unit == 0x0131 {
            return u16::from(b'I');
        }
        self.case_pairs()
            .iter()
            .find_map(|&(upper, lower)| (unit == lower).then_some(upper))
            .unwrap_or(unit)
    }

    #[must_use]
    pub fn name_key(self, name: &str) -> Vec<u16> {
        name.encode_utf16()
            .map(|unit| self.fold_unit(unit))
            .collect()
    }

    fn lowercase(self, character: char) -> char {
        if character.is_ascii() {
            return character.to_ascii_lowercase();
        }
        self.case_pairs()
            .iter()
            .find_map(|&(upper, lower)| {
                (u32::from(character) == u32::from(upper))
                    .then(|| char::from_u32(u32::from(lower)))
                    .flatten()
            })
            .unwrap_or(character)
    }

    /// Decode an 8.3 entry, honoring the native first-byte 0x05 escape and the
    /// independent base/extension lowercase flags. Invalid path bytes and an
    /// empty basename fail instead of becoming a different host path.
    #[must_use]
    pub fn short_name(self, bytes: &[u8; 11], case_flags: u8) -> Option<String> {
        let base_end = bytes[..8].iter().rposition(|&byte| byte != b' ')? + 1;
        let ext_end = bytes[8..]
            .iter()
            .rposition(|&byte| byte != b' ')
            .map_or(0, |i| i + 1);
        let mut name = String::new();
        for (start, end, lower_flag) in [(0, base_end, 0x08), (8, 8 + ext_end, 0x10)] {
            if start == end {
                continue;
            }
            if start == 8 {
                name.push('.');
            }
            for (index, &stored) in bytes[start..end].iter().enumerate() {
                let byte = if start + index == 0 && stored == 5 {
                    0xE5
                } else {
                    stored
                };
                if byte < 0x20 || matches!(byte, b'/' | b'\\' | b':' | 0x7F) {
                    return None;
                }
                let character = self.decode(byte)?;
                name.push(if case_flags & lower_flag != 0 {
                    self.lowercase(character)
                } else {
                    character
                });
            }
        }
        Some(name)
    }
}

impl std::str::FromStr for FatOemCodePage {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ascii" => Ok(Self::Ascii),
            "437" => Ok(Self::Cp437),
            "850" => Ok(Self::Cp850),
            _ => Err("expected an explicit OEM code page: ascii, 437, or 850"),
        }
    }
}

// (uppercase, lowercase), restricted to pairs representable in the code page.
const CP437_PAIRS: &[(u16, u16)] = &[
    (0x00C7, 0x00E7),
    (0x00DC, 0x00FC),
    (0x00C9, 0x00E9),
    (0x00C4, 0x00E4),
    (0x00C5, 0x00E5),
    (0x00C6, 0x00E6),
    (0x00D6, 0x00F6),
    (0x00D1, 0x00F1),
    (0x03A3, 0x03C3),
    (0x03A6, 0x03C6),
];

const CP850_PAIRS: &[(u16, u16)] = &[
    (0x00C7, 0x00E7),
    (0x00DC, 0x00FC),
    (0x00C9, 0x00E9),
    (0x00C2, 0x00E2),
    (0x00C4, 0x00E4),
    (0x00C0, 0x00E0),
    (0x00C5, 0x00E5),
    (0x00CA, 0x00EA),
    (0x00CB, 0x00EB),
    (0x00C8, 0x00E8),
    (0x00CF, 0x00EF),
    (0x00CE, 0x00EE),
    (0x00CC, 0x00EC),
    (0x00C6, 0x00E6),
    (0x00D4, 0x00F4),
    (0x00D6, 0x00F6),
    (0x00D2, 0x00F2),
    (0x00DB, 0x00FB),
    (0x00D9, 0x00F9),
    (0x00D8, 0x00F8),
    (0x00C1, 0x00E1),
    (0x00CD, 0x00ED),
    (0x00D3, 0x00F3),
    (0x00DA, 0x00FA),
    (0x00D1, 0x00F1),
    (0x00C3, 0x00E3),
    (0x00D0, 0x00F0),
    (0x00D5, 0x00F5),
    (0x00DE, 0x00FE),
    (0x00DD, 0x00FD),
];

const CP437: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF,
    0x00EE, 0x00EC, 0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA,
    0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
    0x255D, 0x255C, 0x255B, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4,
    0x221E, 0x03C6, 0x03B5, 0x2229, 0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
];

const CP850: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF,
    0x00EE, 0x00EC, 0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x00D7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA,
    0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00C1, 0x00C2, 0x00C0, 0x00A9, 0x2563, 0x2551, 0x2557,
    0x255D, 0x00A2, 0x00A5, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x00E3, 0x00C3,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4, 0x00F0, 0x00D0, 0x00CA, 0x00CB,
    0x00C8, 0x0131, 0x00CD, 0x00CE, 0x00CF, 0x2518, 0x250C, 0x2588, 0x2584, 0x00A6, 0x00CC, 0x2580,
    0x00D3, 0x00DF, 0x00D4, 0x00D2, 0x00F5, 0x00D5, 0x00B5, 0x00FE, 0x00DE, 0x00DA, 0x00DB, 0x00D9,
    0x00FD, 0x00DD, 0x00AF, 0x00B4, 0x00AD, 0x00B1, 0x2017, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x00B8,
    0x00B0, 0x00A8, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0,
];

#[cfg(test)]
mod tests {
    use super::FatOemCodePage::{Ascii, Cp437, Cp850};

    #[test]
    fn explicit_code_page_controls_native_bytes_and_part_flags() {
        let bytes = b"\x90T\x9b     TXT";
        assert_eq!(Ascii.short_name(bytes, 0), None);
        assert_eq!(Cp437.short_name(bytes, 0).as_deref(), Some("ÉT¢.TXT"));
        assert_eq!(Cp850.short_name(bytes, 0x18).as_deref(), Some("étø.txt"));
        assert_eq!(Cp850.short_name(bytes, 0x08).as_deref(), Some("étø.TXT"));
        assert_eq!(Cp850.short_name(bytes, 0x10).as_deref(), Some("ÉTø.txt"));
    }

    #[test]
    fn first_byte_escape_is_native_data_only_at_the_first_position() {
        let escaped = b"\x05       BIN";
        assert_eq!(Ascii.short_name(escaped, 0), None);
        assert_eq!(Cp437.short_name(escaped, 0).as_deref(), Some("σ.BIN"));
        assert_eq!(Cp850.short_name(escaped, 0).as_deref(), Some("Õ.BIN"));
        assert_eq!(Cp850.short_name(escaped, 0x18).as_deref(), Some("õ.bin"));
        for page in [Ascii, Cp437, Cp850] {
            assert_eq!(page.short_name(b"A\x05      BIN", 0), None);
            assert_eq!(page.short_name(b"        BIN", 0), None);
            for byte in [0, b'/', b'\\', b':', 0x7F] {
                let mut invalid = *b"NAME    TXT";
                invalid[1] = byte;
                assert_eq!(page.short_name(&invalid, 0), None);
            }
        }
    }

    #[test]
    fn folding_is_code_page_bounded_without_unicode_expansion_or_normalization() {
        assert_ne!(Ascii.name_key("É"), Ascii.name_key("é"));
        assert_eq!(Cp437.name_key("Éσφ"), Cp437.name_key("éΣΦ"));
        assert_eq!(Cp850.name_key("ÀØÞı"), Cp850.name_key("àøþI"));
        assert_ne!(Cp437.name_key("À"), Cp437.name_key("à"));
        assert_ne!(Cp850.name_key("Σ"), Cp850.name_key("σ"));
        for page in [Ascii, Cp437, Cp850] {
            assert_ne!(page.name_key("ß"), page.name_key("SS"));
            assert_ne!(page.name_key("É"), page.name_key("E\u{301}"));
            assert_eq!(page.fold_unit(0xD800), 0xD800);
            assert_eq!(
                page.fold_unit(page.fold_unit(0x0131)),
                page.fold_unit(0x0131)
            );
        }
    }
}
