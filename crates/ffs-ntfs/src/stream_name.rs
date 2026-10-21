//! Lossless selectors for native NTFS DATA names.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamName(Vec<u16>);

impl StreamName {
    /// Parse one comma-separated argument of four-digit hexadecimal code units.
    /// Keep unpaired surrogates intact; an empty argument selects unnamed DATA.
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.is_empty() {
            return Ok(Self(Vec::new()));
        }
        if value.len() > 255 * 5 - 1 {
            return Err("NTFS stream names cannot exceed 255 UTF-16 code units".into());
        }
        let mut units = Vec::new();
        for word in value.split(',') {
            if word.len() != 4 || !word.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(
                    "expected comma-separated four-digit UTF-16 hexadecimal units, such as 006e,006f,0074,0065"
                        .into(),
                );
            }
            let unit = u16::from_str_radix(word, 16)
                .map_err(|_| "invalid UTF-16 hexadecimal code unit".to_owned())?;
            if unit == 0 {
                return Err("NTFS stream names cannot contain NUL".into());
            }
            units.push(unit);
        }
        Ok(Self(units))
    }

    pub fn select(text: Option<&str>, native: Option<Self>) -> Result<Self, String> {
        match (text, native) {
            (Some(_), Some(_)) => Err("select either --stream or --stream-utf16".into()),
            (_, Some(native)) => Ok(native),
            (text, None) => {
                let units: Vec<_> = text.unwrap_or("").encode_utf16().take(256).collect();
                if units.len() > 255 || units.contains(&0) {
                    return Err("invalid NTFS stream name: at most 255 non-NUL UTF-16 units".into());
                }
                Ok(Self(units))
            }
        }
    }

    pub fn as_units(&self) -> &[u16] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_selector_preserves_exact_case_surrogates_and_unnamed_data() {
        let name = StreamName::parse("0046,006f,006F,D800,dc00").unwrap();
        assert_eq!(name.as_units(), [0x46, 0x6F, 0x6F, 0xD800, 0xDC00]);
        assert_eq!(StreamName::parse("d800").unwrap().as_units(), [0xD800]);
        assert!(String::from_utf16(StreamName::parse("d800").unwrap().as_units()).is_err());
        assert_eq!(StreamName::parse("").unwrap().as_units(), [] as [u16; 0]);
        assert_eq!(
            StreamName::select(None, None).unwrap().as_units(),
            [] as [u16; 0]
        );
        assert_eq!(
            StreamName::select(Some("Foo😀"), None).unwrap().as_units(),
            [0x46, 0x6F, 0x6F, 0xD83D, 0xDE00]
        );
        assert!(StreamName::select(Some("Foo"), Some(StreamName::parse("0046").unwrap())).is_err());
    }

    #[test]
    fn selectors_reject_invalid_units_nuls_and_names_beyond_native_bounds() {
        for text in [
            "0000",
            "0061,0000",
            "61",
            "00061",
            "0x61",
            "0x0061",
            "gggg",
            "0061,",
            ",0061",
            "0061,,0062",
            "0061 0062",
            " 0061",
            "0061 ",
        ] {
            assert!(StreamName::parse(text).is_err(), "{text:?}");
        }
        let limit = vec!["0061"; 255].join(",");
        assert_eq!(StreamName::parse(&limit).unwrap().as_units().len(), 255);
        assert!(StreamName::parse(&vec!["0061"; 256].join(",")).is_err());
        assert!(StreamName::select(Some("\0"), None).is_err());
        assert_eq!(
            StreamName::select(Some(&"a".repeat(255)), None)
                .unwrap()
                .as_units()
                .len(),
            255
        );
        assert!(StreamName::select(Some(&"a".repeat(256)), None).is_err());
        assert!(StreamName::select(Some(&"😀".repeat(128)), None).is_err());
    }
}
