//! Canonical 131,072-byte (65,536 UTF-16 code units) NTFS `$UpCase` table.
//!
//! Matches the standard Windows / NTFS-3G uppercase mapping (`ntfs_upcase_build_default`),
//! satisfying full idempotence (`upcase[upcase[c]] == upcase[c]` for every `c`)
//! and canonical ASCII `a..=z` -> `A..=Z` folding with zero external binary blobs.

/// Exact byte length of an NTFS `$UpCase` stream (`65_536 * 2`).
pub const UPCASE_TABLE_BYTES: usize = 131_072;

/// Generate the canonical 65,536-entry NTFS `$UpCase` table as `u16` code units.
#[must_use]
pub fn canonical_ntfs_upcase_u16() -> Box<[u16]> {
    let mut table: Vec<u16> = (0_u32..65_536)
        .map(|cp| u16::try_from(cp).unwrap_or(0))
        .collect();

    // Contiguous shift ranges: (first_inclusive, last_inclusive, delta)
    const RANGES: &[(u16, u16, i32)] = &[
        (0x0061, 0x007A, -32), // ASCII a..z
        (0x00E0, 0x00F6, -32), // Latin-1 à..ö
        (0x00F8, 0x00FE, -32), // Latin-1 ø..þ
        (0x0256, 0x0257, -205),
        (0x03AD, 0x03AF, -37), // Greek έ..ί
        (0x03B1, 0x03C1, -32), // Greek α..ρ
        (0x03C3, 0x03CB, -32), // Greek σ..ϋ
        (0x03CD, 0x03CE, -63), // Greek ύ..ώ
        (0x0430, 0x044F, -32), // Cyrillic а..я
        (0x0450, 0x045F, -80), // Cyrillic ѐ..џ
        (0x0561, 0x0586, -48), // Armenian ա..ֆ
        (0x1F00, 0x1F07, 8),   // Greek Extended
        (0x1F10, 0x1F15, 8),
        (0x1F20, 0x1F27, 8),
        (0x1F30, 0x1F37, 8),
        (0x1F40, 0x1F45, 8),
        (0x1F60, 0x1F67, 8),
        (0x1F70, 0x1F71, 74),
        (0x1F72, 0x1F75, 86),
        (0x1F76, 0x1F77, 100),
        (0x1F78, 0x1F79, 128),
        (0x1F7A, 0x1F7B, 112),
        (0x1F7C, 0x1F7D, 126),
        (0x1F80, 0x1F87, 8),
        (0x1F90, 0x1F97, 8),
        (0x1FA0, 0x1FA7, 8),
        (0x1FB0, 0x1FB1, 8),
        (0x1FD0, 0x1FD1, 8),
        (0x1FE0, 0x1FE1, 8),
        (0x2170, 0x217F, -16), // Small Roman numerals
        (0x24D0, 0x24E9, -26), // Circled Latin small letters
        (0xFF41, 0xFF5A, -32), // Fullwidth Latin small letters
    ];

    for &(start, end, delta) in RANGES {
        for cp in start..=end {
            let mapped = i32::from(cp) + delta;
            if let Ok(u) = u16::try_from(mapped) {
                table[usize::from(cp)] = u;
            }
        }
    }

    // Alternating lowercase/uppercase pairs (step = 2, delta = -1).
    const STEP2_MINUS1: &[(u16, u16)] = &[
        (0x0101, 0x012F),
        (0x0133, 0x0137),
        (0x013A, 0x0148),
        (0x014B, 0x0177),
        (0x017A, 0x017E),
        (0x01A1, 0x01A5),
        (0x01B4, 0x01B6),
        (0x01CE, 0x01DC),
        (0x01DF, 0x01EF),
        (0x01F5, 0x01F5),
        (0x01F9, 0x021F),
        (0x0223, 0x0233),
        (0x03D9, 0x03EF),
        (0x0461, 0x0481),
        (0x048B, 0x04BF),
        (0x04C2, 0x04CE),
        (0x04D1, 0x04F5),
        (0x04F9, 0x04F9),
        (0x1E01, 0x1E95),
        (0x1EA1, 0x1EF9),
    ];

    for &(start, end) in STEP2_MINUS1 {
        let mut cp = start;
        while cp <= end {
            table[usize::from(cp)] = cp - 1;
            match cp.checked_add(2) {
                Some(next) => cp = next,
                None => break,
            }
        }
    }

    // Isolated canonical mappings matching Windows NTFS $UpCase.
    const SINGLES: &[(u16, u16)] = &[
        (0x00FF, 0x0178),
        (0x0183, 0x0182),
        (0x0185, 0x0184),
        (0x0188, 0x0187),
        (0x018C, 0x018B),
        (0x0192, 0x0191),
        (0x0195, 0x01F6),
        (0x0199, 0x0198),
        (0x019E, 0x0220),
        (0x01A8, 0x01A7),
        (0x01AD, 0x01AC),
        (0x01B0, 0x01AF),
        (0x01B9, 0x01B8),
        (0x01BD, 0x01BC),
        (0x01BF, 0x01F7),
        (0x01C6, 0x01C4),
        (0x01C9, 0x01C7),
        (0x01CC, 0x01CA),
        (0x01DD, 0x018E),
        (0x01F3, 0x01F1),
        (0x0253, 0x0181),
        (0x0254, 0x0186),
        (0x0259, 0x018F),
        (0x025B, 0x0190),
        (0x0260, 0x0193),
        (0x0263, 0x0194),
        (0x0268, 0x0197),
        (0x0269, 0x0196),
        (0x026F, 0x019C),
        (0x0272, 0x019D),
        (0x0275, 0x019F),
        (0x0280, 0x01A6),
        (0x0283, 0x01A9),
        (0x0288, 0x01AE),
        (0x028A, 0x01B1),
        (0x028B, 0x01B2),
        (0x0292, 0x01B7),
        (0x03AC, 0x0386),
        (0x03CC, 0x038C),
        (0x1F51, 0x1F59),
        (0x1F53, 0x1F5B),
        (0x1F55, 0x1F5D),
        (0x1F57, 0x1F5F),
        (0x1FE5, 0x1FEC),
    ];

    for &(from, to) in SINGLES {
        table[usize::from(from)] = to;
    }

    // Enforce idempotence mathematically (upcase[upcase[c]] == upcase[c]).
    let snapshot = table.clone();
    for (slot, &first) in table.iter_mut().zip(snapshot.iter()) {
        let second = snapshot[usize::from(first)];
        if second != first {
            *slot = second;
        }
    }

    table.into_boxed_slice()
}

/// Serialize the canonical `$UpCase` table into 131,072 little-endian bytes.
#[must_use]
pub fn canonical_ntfs_upcase_bytes() -> Vec<u8> {
    let table = canonical_ntfs_upcase_u16();
    let mut out = Vec::with_capacity(UPCASE_TABLE_BYTES);
    for &unit in &table {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Compare two UTF-16 names under the given 65,536-entry `$UpCase` table.
#[must_use]
pub fn compare_utf16_upcase(upcase: &[u16], a: &[u16], b: &[u16]) -> std::cmp::Ordering {
    for (&ua, &ub) in a.iter().zip(b.iter()) {
        let fa = upcase[usize::from(ua)];
        let fb = upcase[usize::from(ub)];
        match fa.cmp(&fb) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_upcase_is_exact_size_idempotent_and_ascii_folding() {
        let table = canonical_ntfs_upcase_u16();
        assert_eq!(table.len(), 65_536);
        for (idx, &mapped) in table.iter().enumerate() {
            assert_eq!(
                table[usize::from(mapped)],
                mapped,
                "upcase entry {idx:#06x} -> {mapped:#06x} is not idempotent"
            );
            if (usize::from(b'a')..=usize::from(b'z')).contains(&idx) {
                assert_eq!(mapped, u16::try_from(idx - 32).unwrap());
            }
        }
        assert_eq!(table[usize::from(0x00E4_u16)], 0x00C4); // ä -> Ä
        assert_eq!(table[usize::from(0x03B1_u16)], 0x0391); // α -> Α
        assert_eq!(table[usize::from(0x0430_u16)], 0x0410); // а -> А
        assert_eq!(canonical_ntfs_upcase_bytes().len(), UPCASE_TABLE_BYTES);
    }
}
