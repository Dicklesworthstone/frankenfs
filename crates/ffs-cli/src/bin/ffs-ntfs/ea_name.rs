//! Exact selectors for eight-bit native EA names; no implicit OEM conversion.

use ffs_ondisk::ntfs::ea::MAX_EA_NAME_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EaName(Vec<u8>);

impl EaName {
    pub fn parse_text(text: &str) -> Result<Self, String> {
        if text.len() > MAX_EA_NAME_BYTES {
            return Err("native EA names cannot exceed 255 bytes".into());
        }
        Self::checked(text.as_bytes().to_vec())
    }

    pub fn parse_hex(text: &str) -> Result<Self, String> {
        if text.is_empty()
            || text.len() > MAX_EA_NAME_BYTES * 2
            || !text.len().is_multiple_of(2)
            || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("use 1 to 255 native bytes as consecutive two-digit hex pairs".into());
        }
        let mut bytes = Vec::with_capacity(text.len() / 2);
        for offset in (0..text.len()).step_by(2) {
            bytes.push(
                u8::from_str_radix(&text[offset..offset + 2], 16)
                    .map_err(|_| "invalid EA name hex byte")?,
            );
        }
        Self::checked(bytes)
    }

    fn checked(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_EA_NAME_BYTES || bytes.contains(&0) {
            return Err("native EA names must contain 1 to 255 non-NUL bytes".into());
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_text_and_raw_selectors_do_not_case_fold_or_replace_native_bytes() {
        assert_eq!(
            EaName::parse_text("user.é").unwrap().as_bytes(),
            b"user.\xC3\xA9"
        );
        assert_eq!(
            EaName::parse_hex("757365722e8241").unwrap().as_bytes(),
            b"user.\x82A"
        );
        assert_eq!(EaName::parse_hex("fFaB").unwrap().as_bytes(), [0xFF, 0xAB]);
        assert_ne!(
            EaName::parse_text("Name").unwrap(),
            EaName::parse_text("name").unwrap()
        );
        assert_eq!(
            EaName::parse_hex(&"41".repeat(255)).unwrap().as_bytes(),
            vec![b'A'; 255]
        );
    }

    #[test]
    fn invalid_or_ambiguous_selectors_fail_before_opening_the_image() {
        for text in ["", "0", "0001", "4100", "4g", "41,42", "41 42", "0x41", "é"] {
            assert!(EaName::parse_hex(text).is_err(), "{text:?}");
        }
        assert!(EaName::parse_hex(&"41".repeat(256)).is_err());
        assert!(EaName::parse_text("").is_err());
        assert!(EaName::parse_text("a\0b").is_err());
        assert!(EaName::parse_text(&"é".repeat(128)).is_err());
    }
}
