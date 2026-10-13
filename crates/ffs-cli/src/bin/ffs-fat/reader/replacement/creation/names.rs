//! Bounded native LFN encoding and collision-checked ASCII short aliases.
//!
//! This is a conservative creation policy, not Windows Unicode collation or
//! byte-identical Windows alias generation. Native slot layout follows FAT's
//! 13-unit records, reverse ordinals and checksum binding to the short alias.

use super::super::super::{Directory, FatVolume, MAX_DIRECTORY_SLOTS, checkpoint};
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_ondisk::fat::short_name_checksum;
use std::collections::BTreeSet;

#[derive(Debug)]
pub(super) struct NativeName {
    pub short: [u8; 11],
    pub flags: u8,
    pub long: Vec<u16>,
}

fn collision_key(value: &str) -> String {
    value.to_uppercase().to_lowercase()
}

fn validate(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 || name.encode_utf16().count() > 255 {
        bail!("creation names must fit 255 UTF-8 bytes and 255 UTF-16 units");
    }
    if matches!(name, "." | "..")
        || name.ends_with([' ', '.'])
        || name.chars().any(|ch| {
            ch.is_control()
                || matches!(ch, '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|' | '\u{FFFF}')
        })
    {
        bail!("name is outside the portable FAT creation profile: {name:?}");
    }
    let base = name.split('.').next().unwrap_or("").to_uppercase();
    let numbered = base.strip_prefix("COM").or_else(|| base.strip_prefix("LPT"));
    if matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || numbered.is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
        })
    {
        bail!("reserved DOS device name is not admitted for creation");
    }
    Ok(())
}

fn short_byte(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"$%'-_@~`!(){}^#&".contains(&byte)
}

fn display(short: &[u8; 11], flags: u8) -> String {
    let mut result = String::new();
    for (index, (part, flag)) in [(&short[..8], 8), (&short[8..], 16)].into_iter().enumerate() {
        let length = part.iter().rposition(|byte| *byte != b' ').map_or(0, |at| at + 1);
        if index == 1 && length != 0 {
            result.push('.');
        }
        for &byte in &part[..length] {
            result.push(char::from(if flags & flag != 0 { byte.to_ascii_lowercase() } else { byte }));
        }
    }
    result
}

fn natural(name: &str) -> Option<NativeName> {
    let (base, extension) = name.rsplit_once('.').unwrap_or((name, ""));
    if base.is_empty() || base.len() > 8 || extension.len() > 3
        || !base.bytes().chain(extension.bytes()).all(|byte| short_byte(byte.to_ascii_uppercase()))
    {
        return None;
    }
    let mut short = [b' '; 11];
    for (target, byte) in short[..8].iter_mut().zip(base.bytes()) {
        *target = byte.to_ascii_uppercase();
    }
    for (target, byte) in short[8..].iter_mut().zip(extension.bytes()) {
        *target = byte.to_ascii_uppercase();
    }
    let mut flags = 0;
    for (part, flag) in [(base, 8), (extension, 16)] {
        if part.bytes().any(|byte| byte.is_ascii_lowercase())
            && !part.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            flags |= flag;
        }
    }
    let long = if display(&short, flags) == name { Vec::new() } else { name.encode_utf16().collect() };
    Some(NativeName { short, flags, long })
}

impl NativeName {
    pub(super) fn plan(cx: &Cx, volume: &FatVolume, directory: Directory, name: &str) -> Result<Self> {
        validate(name)?;
        let requested = volume.oem_code_page.name_key(name);
        let folded = collision_key(name);
        let mut shorts = BTreeSet::new();
        let mut native_keys = BTreeSet::new();
        let mut folded_keys = BTreeSet::new();
        for entry in volume.list(cx, directory)? {
            checkpoint(cx)?;
            shorts.insert(entry.native.short_name);
            for value in [entry.name()?, entry.short_alias().context("creation requires representable native aliases")?] {
                let key = volume.oem_code_page.name_key(&value);
                let fold = collision_key(&value);
                if key == requested || fold == folded {
                    bail!("--create never replaces an existing native name or short alias: {name:?}");
                }
                native_keys.insert(key);
                folded_keys.insert(fold);
            }
        }
        let available = |short: &[u8; 11]| {
            let alias = display(short, 0);
            !shorts.contains(short)
                && !native_keys.contains(&volume.oem_code_page.name_key(&alias))
                && !folded_keys.contains(&collision_key(&alias))
        };
        if let Some(candidate) = natural(name)
            && available(&candidate.short)
        {
            return Ok(candidate);
        }
        let (base, extension) = name.rsplit_once('.').unwrap_or((name, ""));
        let clean = |part: &str| -> Vec<u8> {
            part.chars().filter(|ch| !matches!(ch, ' ' | '.')).map(|ch| {
                if ch.is_ascii() && short_byte((ch as u8).to_ascii_uppercase()) {
                    (ch as u8).to_ascii_uppercase()
                } else {
                    b'_'
                }
            }).collect()
        };
        let mut base = clean(base);
        if base.is_empty() {
            base.extend_from_slice(b"FILE");
        }
        let extension = clean(extension);
        // Each entry can reserve a displayed name and an alias. This search
        // is bounded independently of input strings and covers that whole set.
        for serial in 1..=2 * MAX_DIRECTORY_SLOTS + 1 {
            checkpoint(cx)?;
            let suffix = format!("~{serial}");
            let count = base.len().min(8 - suffix.len());
            let mut short = [b' '; 11];
            short[..count].copy_from_slice(&base[..count]);
            short[count..count + suffix.len()].copy_from_slice(suffix.as_bytes());
            let extension_length = extension.len().min(3);
            short[8..8 + extension_length].copy_from_slice(&extension[..extension_length]);
            if available(&short) {
                return Ok(Self { short, flags: 0, long: name.encode_utf16().collect() });
            }
        }
        bail!("no collision-free native short alias within the creation budget")
    }

    pub(super) fn long_slots(&self) -> usize {
        self.long.len().div_ceil(13)
    }

    /// `ordinal` is one-based from the short entry; on disk these run backwards.
    pub(super) fn slot(&self, ordinal: usize) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0] = ordinal as u8 | if ordinal == self.long_slots() { 0x40 } else { 0 };
        bytes[11] = 0x0F;
        bytes[13] = short_name_checksum(&self.short);
        for (index, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30].into_iter().enumerate() {
            let position = (ordinal - 1) * 13 + index;
            let unit = self.long.get(position).copied().unwrap_or(if position == self.long.len() { 0 } else { 0xFFFF });
            bytes[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::fat::{FatDirectoryDecoder, FatKind};

    #[test]
    fn creation_name_limits_and_exact_short_case_are_preserved() {
        for value in ["", ".", "..", "bad.", "bad ", "a/b", "a\\b", "a:b", "a\0b", "NUL.txt", "COM¹.log"] {
            assert!(validate(value).is_err(), "{value:?}");
        }
        assert!(validate(&"a".repeat(256)).is_err());
        assert!(validate(&"é".repeat(128)).is_err());
        for value in ["Mixed.txt", "long name.txt", "é.txt", "a.b.c", "notes 🦀.txt"] {
            validate(value).unwrap();
        }
        let short = natural("lower.TXT").unwrap();
        assert_eq!(short.short, *b"LOWER   TXT");
        assert_eq!(short.flags, 8);
        assert!(short.long.is_empty());
        let mixed = natural("Mixed.txt").unwrap();
        assert_eq!(mixed.flags, 16);
        assert_eq!(mixed.long, "Mixed.txt".encode_utf16().collect::<Vec<_>>());
    }

    #[test]
    fn creation_lfn_slots_have_native_ordinals_terminators_and_lossless_utf16() {
        for text in ["A".repeat(13), "B".repeat(14), "C".repeat(26), "D".repeat(255), "notes 🦀.txt".to_owned()] {
            let name = NativeName { short: *b"LONGNA~1TXT", flags: 0, long: text.encode_utf16().collect() };
            let mut decoder = FatDirectoryDecoder::default();
            for ordinal in (1..=name.long_slots()).rev() {
                let slot = name.slot(ordinal);
                assert_eq!(slot[0], ordinal as u8 | if ordinal == name.long_slots() { 0x40 } else { 0 });
                assert_eq!(slot[11], 0x0F);
                assert_eq!(slot[12], 0);
                assert_eq!(&slot[26..28], &[0, 0]);
                assert!(decoder.push(&slot, FatKind::Fat32).unwrap().is_none());
            }
            let mut short = [0; 32];
            short[..11].copy_from_slice(&name.short);
            short[11] = 0x20;
            let entry = decoder.push(&short, FatKind::Fat32).unwrap().unwrap();
            assert_eq!(entry.long_name.as_deref(), Some(name.long.as_slice()));
            assert!(!decoder.has_malformed_long_name());
        }
        let name = NativeName { short: *b"LONGNA~1TXT", flags: 0, long: vec![65; 14] };
        let last = name.slot(2);
        assert_eq!(&last[1..7], &[65, 0, 0, 0, 255, 255]);
        let exact = NativeName { short: name.short, flags: 0, long: vec![65; 13] };
        assert_eq!(exact.long_slots(), 1);
        assert_eq!(&exact.slot(1)[28..32], &[65, 0, 65, 0]);
    }
}
