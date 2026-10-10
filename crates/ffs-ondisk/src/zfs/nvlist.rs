//! Bounded XDR nvlist decoding for native vdev label configurations.
//! OpenZFS module/nvpair/nvpair.c defines the wire representation. Encoded and
//! decoded sizes are not trusted allocation requests. Unknown scalar/array
//! types remain opaque; a consumer must require the type of every used field.

use super::{LABEL_CONFIG_BYTES, ParseError, invalid};
use std::collections::BTreeMap;

const MAX_ITEMS: usize = 8192;
const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Boolean(bool),
    Unsigned(u64),
    String(String),
    List(NvList),
    Lists(Vec<NvList>),
    UnsignedArray(Vec<u64>),
    Opaque {
        kind: u32,
        elements: u32,
        bytes: Vec<u8>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvList {
    pub fields: BTreeMap<String, Value>,
}

impl NvList {
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() > LABEL_CONFIG_BYTES
            || input.len() < 20
            || input[0] != 1
            || input[1] > 1
            || input[2..4] != [0, 0]
        {
            return Err(invalid("invalid XDR nvlist envelope or byte budget"));
        }
        let mut cursor = Cursor {
            bytes: &input[4..],
            at: 0,
        };
        let mut budget = MAX_ITEMS;
        // Bytes following the outer terminator are label allocation padding.
        cursor.list(0, &mut budget)
    }
    #[must_use]
    pub fn unsigned(&self, name: &str) -> Option<u64> {
        match self.fields.get(name) {
            Some(Value::Unsigned(value)) => Some(*value),
            _ => None,
        }
    }
    #[must_use]
    pub fn text(&self, name: &str) -> Option<&str> {
        match self.fields.get(name) {
            Some(Value::String(value)) => Some(value.as_str()),
            _ => None,
        }
    }
    #[must_use]
    pub fn list(&self, name: &str) -> Option<&Self> {
        match self.fields.get(name) {
            Some(Value::List(value)) => Some(value),
            _ => None,
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .at
            .checked_add(length)
            .ok_or_else(|| invalid("XDR span overflow"))?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| invalid("truncated XDR field"))?;
        self.at = end;
        Ok(bytes)
    }
    fn word(&mut self) -> Result<u32, ParseError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    fn wide(&mut self) -> Result<u64, ParseError> {
        Ok((u64::from(self.word()?) << 32) | u64::from(self.word()?))
    }
    fn string(&mut self) -> Result<String, ParseError> {
        let length =
            usize::try_from(self.word()?).map_err(|_| invalid("XDR string length overflow"))?;
        if length > 4096 {
            return Err(invalid("XDR string exceeds read profile"));
        }
        let bytes = self.take(length)?;
        if bytes.contains(&0) {
            return Err(invalid("NUL inside XDR string"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| invalid("XDR config string is not UTF-8"))?
            .to_owned();
        if self
            .take((4 - length % 4) % 4)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(invalid("nonzero XDR string padding"));
        }
        Ok(text)
    }
    fn list(&mut self, depth: usize, budget: &mut usize) -> Result<NvList, ParseError> {
        if depth > MAX_DEPTH || self.word()? != 0 || self.word()? & !3 != 0 {
            return Err(invalid("unsupported nvlist version, flags or nesting"));
        }
        let mut fields = BTreeMap::new();
        loop {
            let length =
                usize::try_from(self.word()?).map_err(|_| invalid("nvpair length overflow"))?;
            let decoded = self.word()?;
            if length == 0 && decoded == 0 {
                return Ok(NvList { fields });
            }
            if length < 24
                || !length.is_multiple_of(4)
                || !(16..=8 * 1024 * 1024).contains(&decoded)
            {
                return Err(invalid("invalid nvpair encoded or decoded size"));
            }
            *budget = budget
                .checked_sub(1)
                .ok_or_else(|| invalid("nvlist item budget exceeded"))?;
            let bytes = self.take(length - 8)?;
            let mut pair = Cursor { bytes, at: 0 };
            let name = pair.string()?;
            if name.is_empty() {
                return Err(invalid("empty nvpair name"));
            }
            let kind = pair.word()?;
            let elements = pair.word()?;
            if elements as usize > MAX_ITEMS {
                return Err(invalid("nvpair element budget exceeded"));
            }
            let value = match (kind, elements) {
                (1, 0) => Value::Boolean(true),
                (21, 1) => {
                    let value = pair.word()?;
                    if value > 1 {
                        return Err(invalid("invalid nvpair boolean"));
                    }
                    Value::Boolean(value == 1)
                }
                (6, 1) => Value::Unsigned(u64::from(pair.word()?)),
                (8, 1) => Value::Unsigned(pair.wide()?),
                (9, 1) => Value::String(pair.string()?),
                (19, 1) => Value::List(pair.list(depth + 1, budget)?),
                (20, count) => {
                    if count as usize > *budget {
                        return Err(invalid("nvlist array exceeds remaining work budget"));
                    }
                    *budget -= count as usize;
                    let mut lists = Vec::new();
                    for _ in 0..count {
                        lists.push(pair.list(depth + 1, budget)?);
                    }
                    Value::Lists(lists)
                }
                (14 | 16, count) => {
                    if count != 0 && pair.word()? != count {
                        return Err(invalid("XDR array counts disagree"));
                    }
                    let mut values = Vec::new();
                    for _ in 0..count {
                        values.push(if kind == 16 {
                            pair.wide()?
                        } else {
                            u64::from(pair.word()?)
                        });
                    }
                    Value::UnsignedArray(values)
                }
                (1 | 6 | 8 | 9 | 19 | 21, _) => {
                    return Err(invalid("scalar nvpair has invalid element count"));
                }
                _ => {
                    let bytes = pair.take(pair.bytes.len() - pair.at)?.to_vec();
                    Value::Opaque {
                        kind,
                        elements,
                        bytes,
                    }
                }
            };
            if pair.at != pair.bytes.len() || fields.insert(name, value).is_some() {
                return Err(invalid("nvpair span mismatch or duplicate name"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn string(value: &str) -> Vec<u8> {
        let mut out = (value.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(value.as_bytes());
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }
    fn pair(name: &str, kind: u32, count: u32, value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(&string(name));
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(value);
        let length = bytes.len() as u32;
        bytes[..4].copy_from_slice(&length.to_be_bytes());
        bytes[4..8].copy_from_slice(&64_u32.to_be_bytes());
        bytes
    }
    fn nested(pairs: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 0, 0, 0, 0, 1];
        for pair in pairs {
            bytes.extend_from_slice(pair);
        }
        bytes.extend_from_slice(&[0; 8]);
        bytes
    }
    fn packed(pairs: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![1, 1, 0, 0];
        bytes.extend_from_slice(&nested(pairs));
        bytes
    }
    #[test]
    fn native_scalar_nested_and_array_fields() {
        let tree = nested(&[
            pair("type", 9, 1, &string("file")),
            pair("ashift", 8, 1, &12_u64.to_be_bytes()),
        ]);
        let mut array = 2_u32.to_be_bytes().to_vec();
        array.extend_from_slice(&42_u64.to_be_bytes());
        array.extend_from_slice(&99_u64.to_be_bytes());
        let raw = packed(&[
            pair("pool_guid", 8, 1, &123_u64.to_be_bytes()),
            pair("vdev_tree", 19, 1, &tree),
            pair("children", 20, 1, &tree),
            pair("stats", 16, 2, &array),
        ]);
        let list = NvList::parse(&raw).unwrap();
        assert_eq!(list.unsigned("pool_guid"), Some(123));
        assert_eq!(list.list("vdev_tree").unwrap().text("type"), Some("file"));
        assert_eq!(list.list("vdev_tree").unwrap().unsigned("ashift"), Some(12));
        assert_eq!(list.fields["stats"], Value::UnsignedArray(vec![42, 99]));
        let mut wrong_endian = raw;
        wrong_endian[1] = 0;
        assert_eq!(NvList::parse(&wrong_endian).unwrap(), list); // XDR remains big-endian.
    }
    #[test]
    fn truncation_counts_lengths_and_duplicate_keys_fail() {
        let value = pair("guid", 8, 1, &123_u64.to_be_bytes());
        let raw = packed(std::slice::from_ref(&value));
        for end in 0..raw.len() {
            assert!(NvList::parse(&raw[..end]).is_err(), "{end}");
        }
        assert!(NvList::parse(&packed(&[value.clone(), value])).is_err());
        assert!(NvList::parse(&packed(&[pair("guid", 8, 2, &[0; 8])])).is_err());
        for offset in [12, 16, 20] {
            let mut bad = raw.clone();
            bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(NvList::parse(&bad).is_err());
        }
        let mut bad = raw.clone();
        bad[0] = 0;
        assert!(NvList::parse(&bad).is_err());
        let mut bad = raw;
        bad[4] = 1;
        assert!(NvList::parse(&bad).is_err());
    }
    #[test]
    fn nested_lists_cannot_escape_pair_spans_or_depth_budget() {
        let mut child = nested(&[]);
        for _ in 0..18 {
            child = nested(&[pair("child", 19, 1, &child)]);
        }
        assert!(NvList::parse(&packed(&[pair("tree", 19, 1, &child)])).is_err());
        let truncated = nested(&[])[..8].to_vec();
        assert!(
            NvList::parse(&packed(&[
                pair("tree", 19, 1, &truncated),
                pair("guid", 8, 1, &[0; 8])
            ]))
            .is_err()
        );
        assert!(NvList::parse(&packed(&[pair("flag", 21, 1, &2_u32.to_be_bytes())])).is_err());
    }
}
