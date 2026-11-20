//! Exact Linux `fs/unicode` (`mkutf8data.c` + `utf8-norm.c`) Unicode 12.1.0
//! `utf8nfdicf` normalization and casefolding for `EXT4_ENC_UTF8_12_1` (`bd-vsuni.3`).
//!
//! Verified with zero divergences across all 1,112,064 Unicode scalar values
//! against upstream Linux `fs/unicode/utf8data.c_shipped`.

use smallvec::SmallVec;

/// Error returned when strict-mode `EXT4_ENC_UTF8_12_1` rejects a filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext4CasefoldError {
    /// Byte sequence is not valid UTF-8.
    InvalidUtf8,
    /// Scalar value is unassigned in Unicode 12.1.0 (`DerivedAge.txt`).
    UnassignedCodepoint(char),
}

impl core::fmt::Display for Ext4CasefoldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("invalid UTF-8 filename"),
            Self::UnassignedCodepoint(ch) => {
                write!(
                    f,
                    "code point U+{:04X} is unassigned in Unicode 12.1.0",
                    u32::from(*ch)
                )
            }
        }
    }
}

impl std::error::Error for Ext4CasefoldError {}

/// Returns `true` iff `ch` is an assigned scalar value in Unicode 12.1.0.
#[must_use]
#[inline]
pub fn is_assigned_unicode_12_1(ch: char) -> bool {
    let cp = u32::from(ch);
    if cp < 0x0378 {
        return true;
    }
    UNICODE_12_1_ASSIGNED_RANGES
        .binary_search_by(|&(lo, hi)| {
            if cp < lo {
                core::cmp::Ordering::Greater
            } else if cp > hi {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Returns `true` iff `ch` has `Default_Ignorable_Code_Point` in Unicode 12.1.0.
#[must_use]
#[inline]
pub fn is_default_ignorable_12_1(ch: char) -> bool {
    let cp = u32::from(ch);
    if cp < 0x00AD {
        return false;
    }
    UNICODE_12_1_IGNORABLE_RANGES
        .binary_search_by(|&(lo, hi)| {
            if cp < lo {
                core::cmp::Ordering::Greater
            } else if cp > hi {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Returns the Unicode 12.1.0 Canonical Combining Class (`0..=254`) of `ch`.
#[must_use]
#[inline]
pub fn unicode_12_1_ccc(ch: char) -> u8 {
    let cp = u32::from(ch);
    if cp < 0x0300 {
        return 0;
    }
    UNICODE_12_1_CCC_RANGES
        .binary_search_by(|&(lo, hi, _)| {
            if cp < lo {
                core::cmp::Ordering::Greater
            } else if cp > hi {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .map_or(0, |idx| UNICODE_12_1_CCC_RANGES[idx].2)
}

#[inline]
fn lookup_nfdicf_12_1(ch: char) -> Option<&'static str> {
    let cp = u32::from(ch);
    if cp < 0x00B5 {
        return None;
    }
    let idx = UNICODE_12_1_NFDICF_MAP
        .binary_search_by_key(&cp, |&(k, _, _)| k)
        .ok()?;
    let (_, off, len) = UNICODE_12_1_NFDICF_MAP[idx];
    let start = usize::from(off);
    let end = start + usize::from(len);
    core::str::from_utf8(&UNICODE_12_1_NFDICF_POOL[start..end]).ok()
}

#[inline]
fn push_utf8(out: &mut Vec<u8>, ch: char) {
    let mut buf = [0_u8; 4];
    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
}

#[inline]
fn flush_combining_marks(out: &mut Vec<u8>, pending: &mut SmallVec<[(u8, char); 8]>) {
    if pending.is_empty() {
        return;
    }
    if pending.len() >= 2 && !pending.is_sorted_by_key(|&(ccc, _)| ccc) {
        pending.sort_by_key(|&(ccc, _)| ccc);
    }
    for (_, mark) in pending.drain(..) {
        push_utf8(out, mark);
    }
}

#[inline]
fn emit_terminal_char(ch: char, out: &mut Vec<u8>, pending: &mut SmallVec<[(u8, char); 8]>) {
    let ccc = unicode_12_1_ccc(ch);
    if ccc == 0 {
        flush_combining_marks(out, pending);
        push_utf8(out, ch);
    } else {
        pending.push((ccc, ch));
    }
}

/// Normalize and casefold `name` using exact Linux `EXT4_ENC_UTF8_12_1` (`utf8nfdicf`)
/// rules:
/// 1. Canonical NFD decomposition + Unicode 12.1.0 `C` + `F` casefolding (fixed point),
///    including algorithmic Hangul syllable decomposition (`U+AC00..=U+D7A3`).
/// 2. `Default_Ignorable_Code_Point` stripping, treating each ignorable as a `CCC=0`
///    stopper barrier (`fs/unicode/utf8-norm.c:520-525`).
/// 3. Stable ascending `CCC` reordering of combining marks between `CCC=0` stoppers.
/// 4. In `strict` mode (`EXT4_ENC_STRICT_MODE_FL`), rejects invalid UTF-8 and code
///    points unassigned in Unicode 12.1.0.
///
/// # Errors
/// Returns [`Ext4CasefoldError`] if `name` is invalid UTF-8 or (when `strict` is `true`)
/// contains a code point unassigned in Unicode 12.1.0.
pub fn utf8_nfdicf_12_1(name: &[u8], strict: bool) -> Result<Vec<u8>, Ext4CasefoldError> {
    if name.is_ascii() {
        let mut folded = name.to_vec();
        folded.make_ascii_lowercase();
        return Ok(folded);
    }
    let text = core::str::from_utf8(name).map_err(|_| Ext4CasefoldError::InvalidUtf8)?;
    let mut out = Vec::with_capacity(name.len());
    let mut pending: SmallVec<[(u8, char); 8]> = SmallVec::new();

    for ch in text.chars() {
        if strict && !is_assigned_unicode_12_1(ch) {
            return Err(Ext4CasefoldError::UnassignedCodepoint(ch));
        }
        if ch.is_ascii() {
            flush_combining_marks(&mut out, &mut pending);
            if let Ok(byte) = u8::try_from(u32::from(ch.to_ascii_lowercase())) {
                out.push(byte);
            }
            continue;
        }
        let cp = u32::from(ch);
        if (0xAC00..=0xD7A3).contains(&cp) {
            flush_combining_marks(&mut out, &mut pending);
            let si = cp - 0xAC00;
            if let Some(lead) = char::from_u32(0x1100 + si / 588) {
                push_utf8(&mut out, lead);
            }
            if let Some(vowel) = char::from_u32(0x1161 + (si % 588) / 28) {
                push_utf8(&mut out, vowel);
            }
            let tail_idx = si % 28;
            if tail_idx != 0
                && let Some(tail) = char::from_u32(0x11A7 + tail_idx)
            {
                push_utf8(&mut out, tail);
            }
            continue;
        }
        if is_default_ignorable_12_1(ch) {
            // Linux utf8-norm.c:520-525: empty decomposition acts as CCC=0 STOPPER!
            flush_combining_marks(&mut out, &mut pending);
            continue;
        }
        if let Some(expanded) = lookup_nfdicf_12_1(ch) {
            for mapped in expanded.chars() {
                emit_terminal_char(mapped, &mut out, &mut pending);
            }
        } else {
            emit_terminal_char(ch, &mut out, &mut pending);
        }
    }
    flush_combining_marks(&mut out, &mut pending);
    Ok(out)
}

include!("unicode_12_1_tables.rs");
