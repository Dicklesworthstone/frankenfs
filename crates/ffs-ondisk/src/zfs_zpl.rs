//! Native ZPL metadata and dataset-specific system attributes.
//!
//! Read contracts extracted from OpenZFS zfs-2.3.0 sa_impl.h, sa.c and zfs_sa.c:
//! legacy znodes have a 264-byte fixed layout; SA buffers describe their own
//! byte order and layout. Registrations bind names to IDs, lengths and swap
//! classes. Layouts order IDs, variable lengths occupy the header, and each
//! value starts on an eight-byte boundary. Bonus and spill are separate buffers.
//! This parser neither authenticates storage nor implements ACL enforcement.

use crate::zfs::Endian;
use crate::zfs::nvlist::{NvList, Value};
use crate::zfs_zap::Entry;
use ffs_types::ParseError;
use std::collections::{BTreeMap, BTreeSet};

pub const LEGACY_BYTES: usize = 264;
pub const SA_BYTES: usize = 128 * 1024;
pub const XATTR_BYTES: usize = 65_536;
pub const XATTR_NAME_BYTES: usize = 255;
pub const XATTR_COUNT: usize = 4096;
const MAX_ATTRIBUTES: usize = 4096;
const MAX_LAYOUT_ITEMS: usize = 65_536;
const OBJECT_LIMIT: u64 = 1 << 48;

fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField {
        field: "zfs.zpl",
        reason,
    }
}
fn word16(raw: &[u8], at: usize, order: Endian) -> Result<u16, ParseError> {
    let bytes: [u8; 2] = raw
        .get(at..at + 2)
        .ok_or_else(|| invalid("truncated SA word"))?
        .try_into()
        .map_err(|_| invalid("truncated SA word"))?;
    Ok(match order {
        Endian::Little => u16::from_le_bytes(bytes),
        Endian::Big => u16::from_be_bytes(bytes),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Fifo,
    CharDevice,
    Directory,
    BlockDevice,
    Regular,
    Symlink,
    Socket,
}
impl Kind {
    fn from_tag(tag: u64) -> Result<Self, ParseError> {
        match tag {
            1 => Ok(Self::Fifo),
            2 => Ok(Self::CharDevice),
            4 => Ok(Self::Directory),
            6 => Ok(Self::BlockDevice),
            8 => Ok(Self::Regular),
            10 => Ok(Self::Symlink),
            12 => Ok(Self::Socket),
            _ => Err(invalid("unknown ZPL file type")),
        }
    }
}

/// The middle twelve bits are not part of either native field. A zero type is
/// permitted for older directory records, but a zero object is never a child.
pub fn directory_reference(value: u64) -> Result<(u64, Option<Kind>), ParseError> {
    let object = value & (OBJECT_LIMIT - 1);
    if object == 0 || value & 0x0fff_0000_0000_0000 != 0 {
        return Err(invalid("invalid ZPL directory object reference"));
    }
    let tag = value >> 60;
    Ok((
        object,
        if tag == 0 {
            None
        } else {
            Some(Kind::from_tag(tag)?)
        },
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}
fn timestamp(raw: &[u8], order: Endian) -> Result<Timestamp, ParseError> {
    if raw.len() != 16 {
        return Err(invalid("ZPL timestamp is not two uint64s"));
    }
    let seconds = i64::from_le_bytes(order.u64(raw, 0)?.to_le_bytes());
    let nanos =
        u32::try_from(order.u64(raw, 8)?).map_err(|_| invalid("ZPL nanoseconds overflow"))?;
    if nanos >= 1_000_000_000 {
        return Err(invalid("invalid ZPL nanoseconds"));
    }
    Ok(Timestamp { seconds, nanos })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub kind: Kind,
    pub mode: u64,
    pub size: u64,
    pub parent: u64,
    pub links: u64,
    pub generation: u64,
    pub flags: u64,
    /// Native IDs are retained, not silently converted to host UID/GID values.
    pub uid: u64,
    pub gid: u64,
    pub times: [Timestamp; 4], // access, modification, change, creation
    pub inline_symlink: Option<Vec<u8>>,
}
impl Metadata {
    fn validate(mut self) -> Result<Self, ParseError> {
        if self.mode & !0xffff != 0
            || self.generation == 0
            || self.parent == 0
            || self.parent >= OBJECT_LIMIT
        {
            return Err(invalid("invalid ZPL mode, generation or parent"));
        }
        self.kind = Kind::from_tag((self.mode >> 12) & 15)?;
        if let Some(target) = &self.inline_symlink
            && (self.kind != Kind::Symlink
                || target.len() as u64 != self.size
                || target.contains(&0))
        {
            return Err(invalid("inline symlink disagrees with ZPL type or length"));
        }
        Ok(self)
    }

    pub fn legacy(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if !(LEGACY_BYTES..=16_384).contains(&raw.len()) {
            return Err(invalid("truncated or oversized legacy znode"));
        }
        let mode = order.u64(raw, 72)?;
        let size = order.u64(raw, 80)?;
        let kind = Kind::from_tag((mode >> 12) & 15)?;
        let inline_symlink = if kind == Kind::Symlink && size <= (raw.len() - LEGACY_BYTES) as u64 {
            Some(raw[LEGACY_BYTES..LEGACY_BYTES + size as usize].to_vec())
        } else {
            None
        };
        Self {
            kind,
            mode,
            size,
            generation: order.u64(raw, 64)?,
            parent: order.u64(raw, 88)?,
            links: order.u64(raw, 96)?,
            flags: order.u64(raw, 120)?,
            uid: order.u64(raw, 128)?,
            gid: order.u64(raw, 136)?,
            times: [
                timestamp(&raw[0..16], order)?,
                timestamp(&raw[16..32], order)?,
                timestamp(&raw[32..48], order)?,
                timestamp(&raw[48..64], order)?,
            ],
            inline_symlink,
        }
        .validate()
    }
}

/// Native storage references, before any host namespace projection. A zero
/// directory means absent; inline names and values come from ZPL_DXATTR's XDR
/// nvlist. Decoding these is independent of ordinary stat/file data access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrSources {
    pub directory: u64,
    pub inline: BTreeMap<String, Vec<u8>>,
}
impl XattrSources {
    fn validate(self) -> Result<Self, ParseError> {
        if self.directory >= OBJECT_LIMIT {
            return Err(invalid(
                "xattr directory reference exceeds the object namespace",
            ));
        }
        Ok(self)
    }

    pub fn legacy(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if !(LEGACY_BYTES..=16_384).contains(&raw.len()) {
            return Err(invalid("truncated or oversized legacy xattr owner"));
        }
        Self {
            directory: order.u64(raw, 104)?,
            inline: BTreeMap::new(),
        }
        .validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Registration {
    name: Vec<u8>,
    length: u16,
    swap: u8,
}

/// These sixteen legacy names/IDs are fixed by the ZPL format, including in an
/// SA-capable dataset. New registrations are dataset-specific, not array indices
/// from a source-code enum. The registry may redundantly store the fixed entries.
const LEGACY: [(&str, u16, u8); 16] = [
    ("ZPL_ATIME", 16, 0),
    ("ZPL_MTIME", 16, 0),
    ("ZPL_CTIME", 16, 0),
    ("ZPL_CRTIME", 16, 0),
    ("ZPL_GEN", 8, 0),
    ("ZPL_MODE", 8, 0),
    ("ZPL_SIZE", 8, 0),
    ("ZPL_PARENT", 8, 0),
    ("ZPL_LINKS", 8, 0),
    ("ZPL_XATTR", 8, 0),
    ("ZPL_RDEV", 8, 0),
    ("ZPL_FLAGS", 8, 0),
    ("ZPL_UID", 8, 0),
    ("ZPL_GID", 8, 0),
    ("ZPL_PAD", 32, 0),
    ("ZPL_ZNODE_ACL", 88, 3),
];

#[derive(Debug)]
pub struct SaRegistry {
    attributes: BTreeMap<u16, Registration>,
    layouts: BTreeMap<u16, Vec<u16>>,
}
impl SaRegistry {
    pub fn from_zaps(registry: &[Entry], layouts: &[Entry]) -> Result<Self, ParseError> {
        if registry.len() > MAX_ATTRIBUTES || layouts.len() > 1022 {
            return Err(invalid("SA registry or layout budget exceeded"));
        }
        let mut attributes = BTreeMap::new();
        let mut names = BTreeMap::new();
        for (id, (name, length, swap)) in LEGACY.iter().enumerate() {
            let id = u16::try_from(id).map_err(|_| invalid("legacy attribute ID overflow"))?;
            names.insert(name.as_bytes().to_vec(), id);
            attributes.insert(
                id,
                Registration {
                    name: name.as_bytes().to_vec(),
                    length: *length,
                    swap: *swap,
                },
            );
        }
        let mut stored_ids = BTreeSet::new();
        for entry in registry {
            let value = entry.scalar()?;
            let id = (value & 0xffff) as u16;
            let swap = ((value >> 16) & 0xff) as u8;
            let length = ((value >> 24) & 0xffff) as u16;
            if value >> 40 != 0
                || swap > 4
                || entry.name.is_empty()
                || entry.name.len() > 256
                || entry.name.contains(&0)
                || !stored_ids.insert(id)
            {
                return Err(invalid("invalid or duplicate SA registration"));
            }
            let registration = Registration {
                name: entry.name.clone(),
                length,
                swap,
            };
            if attributes.get(&id).is_some_and(|old| old != &registration)
                || names.get(&entry.name).is_some_and(|old| *old != id)
            {
                return Err(invalid(
                    "SA registration conflicts with another name or legacy ID",
                ));
            }
            names.insert(entry.name.clone(), id);
            attributes.insert(id, registration);
        }
        let mut result = Self {
            attributes,
            layouts: BTreeMap::new(),
        };
        result.layouts.insert(1, Vec::new()); // Native empty-buffer layout.
        let mut total = 0_usize;
        for entry in layouts {
            let text = std::str::from_utf8(&entry.name)
                .map_err(|_| invalid("nondecimal SA layout name"))?;
            let id: u16 = text
                .parse()
                .map_err(|_| invalid("nondecimal SA layout name"))?;
            if !(2..=1023).contains(&id)
                || text != id.to_string()
                || entry.integer_bytes != 2
                || entry.values.len() > MAX_ATTRIBUTES
            {
                return Err(invalid("invalid SA layout ID or attribute array"));
            }
            total += entry.values.len();
            if total > MAX_LAYOUT_ITEMS {
                return Err(invalid("SA layout item budget exceeded"));
            }
            let mut used = BTreeSet::new();
            let mut ids = Vec::new();
            for &value in &entry.values {
                let attr = u16::try_from(value).map_err(|_| invalid("SA attribute ID overflow"))?;
                if !result.attributes.contains_key(&attr) || !used.insert(attr) {
                    return Err(invalid(
                        "SA layout references an unknown or duplicate attribute",
                    ));
                }
                ids.push(attr);
            }
            if result.layouts.insert(id, ids).is_some() {
                return Err(invalid("duplicate SA layout"));
            }
        }
        Ok(result)
    }

    /// Decode all attributes before publishing any of them. SA magic, not the
    /// dnode container, identifies value byte order. No ignored attribute can
    /// evade length/bounds checks merely because the ZPL does not consume it.
    fn decode_into(&self, raw: &[u8], output: &mut Attributes) -> Result<(), ParseError> {
        if raw.is_empty() {
            return Ok(());
        }
        if !(8..=SA_BYTES).contains(&raw.len()) {
            return Err(invalid("invalid SA buffer length"));
        }
        let order = match &raw[..4] {
            [0x5a, 0x50, 0x2f, 0] => Endian::Little,
            [0, 0x2f, 0x50, 0x5a] => Endian::Big,
            _ => return Err(invalid("invalid SA buffer magic")),
        };
        let info = word16(raw, 4, order)?;
        let layout = match info & 1023 {
            0 => 1,
            id => id,
        };
        let ids = self
            .layouts
            .get(&layout)
            .ok_or_else(|| invalid("unknown SA layout"))?;
        let variable = ids
            .iter()
            .filter(|id| self.attributes[*id].length == 0)
            .count();
        let header = (6 + variable * 2).next_multiple_of(8);
        if header != usize::from(info >> 10) * 8 || header > raw.len() {
            return Err(invalid("SA header length disagrees with its layout"));
        }
        let mut offset = header;
        let mut length_index = 0;
        for id in ids {
            let attr = &self.attributes[id];
            let length = if attr.length == 0 {
                let length = usize::from(word16(raw, 6 + length_index * 2, order)?);
                length_index += 1;
                length
            } else {
                usize::from(attr.length)
            };
            let width = match attr.swap {
                0 => 8,
                1 => 4,
                2 => 2,
                _ => 1,
            };
            if !length.is_multiple_of(width) {
                return Err(invalid("misaligned SA integer array"));
            }
            let bytes = raw
                .get(offset..offset + length)
                .ok_or_else(|| invalid("SA value extends beyond its buffer"))?;
            if output
                .values
                .insert(
                    attr.name.clone(),
                    Attribute {
                        bytes: bytes.to_vec(),
                        order,
                        swap: attr.swap,
                    },
                )
                .is_some()
            {
                return Err(invalid("attribute repeated across SA bonus and spill"));
            }
            offset = (offset + length).next_multiple_of(8);
        }
        Ok(())
    }

    pub fn decode(&self, bonus: &[u8], spill: Option<&[u8]>) -> Result<Attributes, ParseError> {
        let mut result = Attributes {
            values: BTreeMap::new(),
        };
        self.decode_into(bonus, &mut result)?;
        if let Some(spill) = spill {
            self.decode_into(spill, &mut result)?;
        }
        Ok(result)
    }
}

#[derive(Debug)]
struct Attribute {
    bytes: Vec<u8>,
    order: Endian,
    swap: u8,
}
#[derive(Debug)]
pub struct Attributes {
    values: BTreeMap<Vec<u8>, Attribute>,
}
impl Attributes {
    fn required(&self, name: &str, len: usize) -> Result<&Attribute, ParseError> {
        let attr = self
            .values
            .get(name.as_bytes())
            .ok_or_else(|| invalid("missing required ZPL system attribute"))?;
        if attr.swap != 0 || attr.bytes.len() != len {
            return Err(invalid("mistyped ZPL system attribute"));
        }
        Ok(attr)
    }
    fn integer(&self, name: &str) -> Result<u64, ParseError> {
        let attr = self.required(name, 8)?;
        attr.order.u64(&attr.bytes, 0)
    }
    fn time(&self, name: &str) -> Result<Timestamp, ParseError> {
        let attr = self.required(name, 16)?;
        timestamp(&attr.bytes, attr.order)
    }
    pub fn xattrs(&self) -> Result<XattrSources, ParseError> {
        let directory = if self.values.contains_key(b"ZPL_XATTR".as_slice()) {
            self.integer("ZPL_XATTR")?
        } else {
            0
        };
        let mut inline = BTreeMap::new();
        if let Some(attr) = self.values.get(b"ZPL_DXATTR".as_slice()) {
            if attr.swap != 3 {
                return Err(invalid("inline xattr system attribute is not bytes"));
            }
            let packed = NvList::parse_exact(&attr.bytes)?;
            if packed.fields.len() > XATTR_COUNT {
                return Err(invalid("inline xattr count exceeds the read profile"));
            }
            for (name, value) in packed.fields {
                if name.len() > XATTR_NAME_BYTES {
                    return Err(invalid("inline xattr name exceeds the native limit"));
                }
                let Value::Bytes(bytes) = value else {
                    return Err(invalid("inline xattr nvpair is not a byte array"));
                };
                if bytes.len() > XATTR_BYTES {
                    return Err(invalid("inline xattr value exceeds the read profile"));
                }
                inline.insert(name, bytes);
            }
        }
        XattrSources { directory, inline }.validate()
    }

    pub fn metadata(&self) -> Result<Metadata, ParseError> {
        let inline_symlink = self
            .values
            .get(b"ZPL_SYMLINK".as_slice())
            .map(|attr| {
                if attr.swap != 3 {
                    return Err(invalid("symlink system attribute is not bytes"));
                }
                Ok(attr.bytes.clone())
            })
            .transpose()?;
        Metadata {
            kind: Kind::Regular,
            mode: self.integer("ZPL_MODE")?,
            size: self.integer("ZPL_SIZE")?,
            parent: self.integer("ZPL_PARENT")?,
            links: self.integer("ZPL_LINKS")?,
            generation: self.integer("ZPL_GEN")?,
            flags: self.integer("ZPL_FLAGS")?,
            uid: self.integer("ZPL_UID")?,
            gid: self.integer("ZPL_GID")?,
            times: [
                self.time("ZPL_ATIME")?,
                self.time("ZPL_MTIME")?,
                self.time("ZPL_CTIME")?,
                self.time("ZPL_CRTIME")?,
            ],
            inline_symlink,
        }
        .validate()
    }
}

#[cfg(test)]
mod tests;
