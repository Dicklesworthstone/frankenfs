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

    #[must_use]
    pub const fn to_tag(self) -> u64 {
        match self {
            Self::Fifo => 1,
            Self::CharDevice => 2,
            Self::Directory => 4,
            Self::BlockDevice => 6,
            Self::Regular => 8,
            Self::Symlink => 10,
            Self::Socket => 12,
        }
    }
}

/// Encode a ZPL directory ZAP scalar entry (`(type_tag << 60) | object_id`).
pub fn encode_directory_reference(object: u64, kind: Kind) -> Result<u64, ParseError> {
    if object == 0 || object >= OBJECT_LIMIT {
        return Err(invalid("invalid ZPL directory object reference"));
    }
    let encoded = (kind.to_tag() << 60) | object;
    let _ = directory_reference(encoded)?;
    Ok(encoded)
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

    /// Encode a legacy ZPL v4 `znode_phys_t` (`264` bytes + optional inline symlink),
    /// preserving unedited fields (`zp_xattr`, `zp_rdev`, `zp_pad`, `zp_acl`) when
    /// `existing_bonus` is provided.
    pub fn encode_legacy(
        &self,
        existing_bonus: Option<&[u8]>,
        order: Endian,
    ) -> Result<Vec<u8>, ParseError> {
        self.encode_legacy_with_options(existing_bonus, order, None, false)
    }

    /// Encode a legacy ZPL v4 `znode_phys_t` with optional `zp_xattr` directory
    /// override and optional trivial NFSv4 `zp_acl` rebuild (clearing any external ACL object).
    pub fn encode_legacy_with_options(
        &self,
        existing_bonus: Option<&[u8]>,
        order: Endian,
        xattr_dir_override: Option<u64>,
        rebuild_trivial_acl: bool,
    ) -> Result<Vec<u8>, ParseError> {
        if let Some(xdir) = xattr_dir_override
            && xdir >= OBJECT_LIMIT
        {
            return Err(invalid(
                "xattr directory reference exceeds the object namespace",
            ));
        }
        let checked = self.clone().validate()?;
        for ts in &checked.times {
            if ts.nanos >= 1_000_000_000 {
                return Err(invalid("invalid ZPL nanoseconds"));
            }
        }
        let extra_len = checked.inline_symlink.as_ref().map_or(0, Vec::len);
        if LEGACY_BYTES + extra_len > 16_384 {
            return Err(invalid("oversized legacy znode bonus"));
        }
        let mut raw = vec![0_u8; LEGACY_BYTES + extra_len];
        if let Some(prev) = existing_bonus {
            if prev.len() < LEGACY_BYTES {
                return Err(invalid("truncated existing legacy znode bonus"));
            }
            raw[..LEGACY_BYTES].copy_from_slice(&prev[..LEGACY_BYTES]);
        }
        for (idx, ts) in checked.times.iter().enumerate() {
            let at = idx * 16;
            raw[at..at + 8].copy_from_slice(&order.encode(ts.seconds.cast_unsigned()));
            raw[at + 8..at + 16].copy_from_slice(&order.encode(u64::from(ts.nanos)));
        }
        raw[64..72].copy_from_slice(&order.encode(checked.generation));
        raw[72..80].copy_from_slice(&order.encode(checked.mode));
        raw[80..88].copy_from_slice(&order.encode(checked.size));
        raw[88..96].copy_from_slice(&order.encode(checked.parent));
        raw[96..104].copy_from_slice(&order.encode(checked.links));
        if let Some(xdir) = xattr_dir_override {
            raw[104..112].copy_from_slice(&order.encode(xdir));
        }
        raw[120..128].copy_from_slice(&order.encode(checked.flags));
        raw[128..136].copy_from_slice(&order.encode(checked.uid));
        raw[136..144].copy_from_slice(&order.encode(checked.gid));
        if rebuild_trivial_acl {
            raw[176..264].fill(0);
            let aces =
                encode_trivial_nfsv4_aces(checked.mode, checked.kind == Kind::Directory, order);
            let size = aces.len() as u32;
            let count = (aces.len() / 8) as u16;
            let (size_b, ver_b, cnt_b) = match order {
                Endian::Little => (size.to_le_bytes(), 1_u16.to_le_bytes(), count.to_le_bytes()),
                Endian::Big => (size.to_be_bytes(), 1_u16.to_be_bytes(), count.to_be_bytes()),
            };
            raw[184..188].copy_from_slice(&size_b);
            raw[188..190].copy_from_slice(&ver_b);
            raw[190..192].copy_from_slice(&cnt_b);
            raw[192..264]
                .get_mut(..aces.len())
                .ok_or_else(|| invalid("trivial ACL exceeds legacy inline payload"))?
                .copy_from_slice(&aces);
        }
        if let Some(target) = &checked.inline_symlink {
            raw[LEGACY_BYTES..LEGACY_BYTES + target.len()].copy_from_slice(target);
        }
        let _ = Self::legacy(&raw, order)?;
        Ok(raw)
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

/// Native ownership that must be handled before reclaiming a ZPL object.
/// External ACL objects and xattr directories are separate DMU objects, not
/// children of the file's data or SA-spill block tree. Project IDs identify the
/// quota account to debit when the object is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReclamationOwnership {
    pub xattr_directory: u64,
    pub external_acl_object: u64,
    pub project_id: u64,
}

impl ReclamationOwnership {
    fn validate(self) -> Result<Self, ParseError> {
        if self.xattr_directory >= OBJECT_LIMIT || self.external_acl_object >= OBJECT_LIMIT {
            return Err(invalid(
                "ZPL reclamation reference exceeds the object namespace",
            ));
        }
        Ok(self)
    }

    /// Read the external ACL pointer from `zp_acl.z_acl_extern_obj`, at byte
    /// 176 of a legacy znode. Legacy znodes have no project-ID system attribute.
    pub fn legacy(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        let xattrs = XattrSources::legacy(raw, order)?;
        Self {
            xattr_directory: xattrs.directory,
            external_acl_object: order.u64(raw, 176)?,
            project_id: 0,
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

#[derive(Debug, Clone)]
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

    fn parse_buffer_header(&self, raw: &[u8]) -> Result<(Endian, u16), ParseError> {
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
        if !self.layouts.contains_key(&layout) {
            return Err(invalid("unknown SA layout"));
        }
        Ok((order, layout))
    }

    fn pack_layout(
        &self,
        layout_id: u16,
        values_by_name: &BTreeMap<Vec<u8>, Vec<u8>>,
        order: Endian,
    ) -> Result<Vec<u8>, ParseError> {
        if !(2..=1023).contains(&layout_id) {
            return Err(invalid("invalid SA layout ID for non-empty buffer"));
        }
        let ids = self
            .layouts
            .get(&layout_id)
            .ok_or_else(|| invalid("unknown SA layout"))?;
        let mut var_lengths = Vec::new();
        let mut payload_chunks = Vec::with_capacity(ids.len());
        for id in ids {
            let reg = self
                .attributes
                .get(id)
                .ok_or_else(|| invalid("SA layout references unregistered attribute"))?;
            let bytes = values_by_name
                .get(&reg.name)
                .ok_or_else(|| invalid("missing value for SA layout attribute"))?;
            if reg.length == 0 {
                let len_u16 = u16::try_from(bytes.len())
                    .map_err(|_| invalid("variable SA attribute exceeds u16 length"))?;
                var_lengths.push(len_u16);
            } else if bytes.len() != usize::from(reg.length) {
                return Err(invalid("fixed SA attribute value has wrong byte length"));
            }
            let width = match reg.swap {
                0 => 8,
                1 => 4,
                2 => 2,
                _ => 1,
            };
            if !bytes.len().is_multiple_of(width) {
                return Err(invalid("misaligned SA integer array"));
            }
            payload_chunks.push(bytes.as_slice());
        }

        let header_bytes = (6 + var_lengths.len() * 2).next_multiple_of(8);
        let header_words = header_bytes / 8;
        if header_words > 63 {
            return Err(invalid("SA header exceeds 6-bit word-count field"));
        }
        let mut raw = vec![0_u8; header_bytes];
        raw[..4].copy_from_slice(match order {
            Endian::Little => &[0x5a, 0x50, 0x2f, 0],
            Endian::Big => &[0, 0x2f, 0x50, 0x5a],
        });
        let info = layout_id | ((header_words as u16) << 10);
        raw[4..6].copy_from_slice(&match order {
            Endian::Little => info.to_le_bytes(),
            Endian::Big => info.to_be_bytes(),
        });
        for (idx, len) in var_lengths.iter().enumerate() {
            let at = 6 + idx * 2;
            raw[at..at + 2].copy_from_slice(&match order {
                Endian::Little => len.to_le_bytes(),
                Endian::Big => len.to_be_bytes(),
            });
        }
        for chunk in payload_chunks {
            raw.extend_from_slice(chunk);
            let padded = raw.len().next_multiple_of(8);
            raw.resize(padded, 0);
        }
        if raw.len() > SA_BYTES {
            return Err(invalid("encoded SA buffer exceeds maximum size"));
        }
        let mut check = Attributes {
            values: BTreeMap::new(),
        };
        self.decode_into(&raw, &mut check)?;
        Ok(raw)
    }

    fn apply_metadata_to_map(
        map: &mut BTreeMap<Vec<u8>, Vec<u8>>,
        metadata: &Metadata,
        order: Endian,
        update_trivial_dacl: bool,
    ) -> Result<(), ParseError> {
        let checked = metadata.clone().validate()?;
        let enc_ts = |ts: Timestamp| -> Result<Vec<u8>, ParseError> {
            if ts.nanos >= 1_000_000_000 {
                return Err(invalid("invalid ZPL nanoseconds"));
            }
            let mut b = Vec::with_capacity(16);
            b.extend_from_slice(&order.encode(ts.seconds.cast_unsigned()));
            b.extend_from_slice(&order.encode(u64::from(ts.nanos)));
            Ok(b)
        };
        let core: [(&[u8], Vec<u8>); 12] = [
            (b"ZPL_ATIME", enc_ts(checked.times[0])?),
            (b"ZPL_MTIME", enc_ts(checked.times[1])?),
            (b"ZPL_CTIME", enc_ts(checked.times[2])?),
            (b"ZPL_CRTIME", enc_ts(checked.times[3])?),
            (b"ZPL_GEN", order.encode(checked.generation).to_vec()),
            (b"ZPL_MODE", order.encode(checked.mode).to_vec()),
            (b"ZPL_SIZE", order.encode(checked.size).to_vec()),
            (b"ZPL_PARENT", order.encode(checked.parent).to_vec()),
            (b"ZPL_LINKS", order.encode(checked.links).to_vec()),
            (b"ZPL_FLAGS", order.encode(checked.flags).to_vec()),
            (b"ZPL_UID", order.encode(checked.uid).to_vec()),
            (b"ZPL_GID", order.encode(checked.gid).to_vec()),
        ];
        for (name, val) in core {
            map.insert(name.to_vec(), val);
        }
        if let Some(target) = &checked.inline_symlink {
            map.insert(b"ZPL_SYMLINK".to_vec(), target.clone());
        }
        if update_trivial_dacl {
            let aces =
                encode_trivial_nfsv4_aces(checked.mode, checked.kind == Kind::Directory, order);
            map.insert(
                b"ZPL_DACL_COUNT".to_vec(),
                order.encode((aces.len() / 8) as u64).to_vec(),
            );
            map.insert(b"ZPL_DACL_ACES".to_vec(), aces);
        }
        Ok(())
    }

    /// Update core ZPL `Metadata` inside an existing SA bonus (and optional spill),
    /// preserving its registered layout ID, byte order, and all non-core attributes
    /// (ACLs, project IDs, xattrs, rdev, etc.).
    pub fn encode_updated_bonus_and_spill(
        &self,
        existing_bonus: &[u8],
        existing_spill: Option<&[u8]>,
        metadata: &Metadata,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), ParseError> {
        let (bonus_order, bonus_layout) = self.parse_buffer_header(existing_bonus)?;
        let mut bonus_decoded = Attributes {
            values: BTreeMap::new(),
        };
        self.decode_into(existing_bonus, &mut bonus_decoded)?;
        let mut bonus_map: BTreeMap<Vec<u8>, Vec<u8>> = bonus_decoded
            .values
            .into_iter()
            .map(|(k, v)| (k, v.bytes))
            .collect();
        Self::apply_metadata_to_map(&mut bonus_map, metadata, bonus_order, false)?;
        let new_bonus = self.pack_layout(bonus_layout, &bonus_map, bonus_order)?;

        let new_spill = if let Some(spill_raw) = existing_spill {
            let (spill_order, spill_layout) = self.parse_buffer_header(spill_raw)?;
            let mut spill_decoded = Attributes {
                values: BTreeMap::new(),
            };
            self.decode_into(spill_raw, &mut spill_decoded)?;
            let mut spill_map: BTreeMap<Vec<u8>, Vec<u8>> = spill_decoded
                .values
                .into_iter()
                .map(|(k, v)| (k, v.bytes))
                .collect();
            Self::apply_metadata_to_map(&mut spill_map, metadata, spill_order, false)?;
            Some(self.pack_layout(spill_layout, &spill_map, spill_order)?)
        } else {
            None
        };

        let verified = self.decode(&new_bonus, new_spill.as_deref())?;
        let _ = verified.metadata()?;
        Ok((new_bonus, new_spill))
    }

    /// Encode a fresh SA bonus for a newly created regular file or directory by
    /// selecting a registered SA layout compatible with `template_bonus` (e.g.
    /// the parent directory's SA bonus) without requiring new SA layout creation.
    pub fn encode_new_from_template(
        &self,
        template_bonus: &[u8],
        metadata: &Metadata,
    ) -> Result<Vec<u8>, ParseError> {
        if metadata.inline_symlink.is_some() {
            return Err(invalid(
                "inline symlink creation requires a symlink SA layout",
            ));
        }
        let (order, template_layout) = self.parse_buffer_header(template_bonus)?;
        let mut template_decoded = Attributes {
            values: BTreeMap::new(),
        };
        self.decode_into(template_bonus, &mut template_decoded)?;

        let required_core: [&[u8]; 12] = [
            b"ZPL_ATIME",
            b"ZPL_MTIME",
            b"ZPL_CTIME",
            b"ZPL_CRTIME",
            b"ZPL_GEN",
            b"ZPL_MODE",
            b"ZPL_SIZE",
            b"ZPL_PARENT",
            b"ZPL_LINKS",
            b"ZPL_FLAGS",
            b"ZPL_UID",
            b"ZPL_GID",
        ];
        let allowed_optional: [&[u8]; 6] = [
            b"ZPL_PROJID",
            b"ZPL_DACL_COUNT",
            b"ZPL_DACL_ACES",
            b"ZPL_ZNODE_ACL",
            b"ZPL_RDEV",
            b"ZPL_PAD",
        ];

        let layout_admissible = |layout_id: u16| -> bool {
            let Some(ids) = self.layouts.get(&layout_id) else {
                return false;
            };
            let names: BTreeSet<&[u8]> = ids
                .iter()
                .filter_map(|id| self.attributes.get(id).map(|r| r.name.as_slice()))
                .collect();
            required_core.iter().all(|req| names.contains(req))
                && names
                    .iter()
                    .all(|name| required_core.contains(name) || allowed_optional.contains(name))
        };

        let chosen_layout = if layout_admissible(template_layout) {
            template_layout
        } else {
            self.layouts
                .keys()
                .copied()
                .find(|&id| id >= 2 && layout_admissible(id))
                .ok_or_else(|| invalid("dataset has no registered base ZPL SA layout"))?
        };

        let mut map = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        // Native children inherit a project only when the parent explicitly
        // enables ZFS_PROJINHERIT, not merely because its SA layout has an ID.
        let project_id = if template_decoded
            .values
            .contains_key(b"ZPL_FLAGS".as_slice())
            && template_decoded.integer("ZPL_FLAGS")? & 0x0000_4000_0000_0000 != 0
        {
            template_decoded.project_id()?
        } else {
            0
        };
        map.insert(b"ZPL_PROJID".to_vec(), order.encode(project_id).to_vec());
        map.insert(b"ZPL_RDEV".to_vec(), order.encode(0).to_vec());
        map.insert(b"ZPL_PAD".to_vec(), vec![0_u8; 32]);
        let znode_acl = template_decoded
            .values
            .get(b"ZPL_ZNODE_ACL".as_slice())
            .filter(|a| a.bytes.len() == 88)
            .map_or_else(|| vec![0_u8; 88], |a| a.bytes.clone());
        map.insert(b"ZPL_ZNODE_ACL".to_vec(), znode_acl);

        Self::apply_metadata_to_map(&mut map, metadata, order, true)?;
        let encoded = self.pack_layout(chosen_layout, &map, order)?;
        let verified = self.decode(&encoded, None)?;
        let _ = verified.metadata()?;
        Ok(encoded)
    }

    pub fn attr_id_by_name(&self, name: &[u8]) -> Option<u16> {
        self.attributes
            .iter()
            .find_map(|(&id, reg)| (reg.name.as_slice() == name).then_some(id))
    }

    /// Ensure an SA attribute registration exists in `self` (and append to `reg_entries`
    /// if newly registered), returning its 16-bit attribute ID.
    pub fn ensure_attribute(
        &mut self,
        reg_entries: &mut Vec<Entry>,
        name: &[u8],
        length: u16,
        swap: u8,
    ) -> Result<u16, ParseError> {
        if let Some(id) = self.attr_id_by_name(name) {
            let existing = &self.attributes[&id];
            if existing.length != length || existing.swap != swap {
                return Err(invalid(
                    "SA attribute registration disagrees with existing length/swap",
                ));
            }
            return Ok(id);
        }
        if swap > 4 || name.is_empty() || name.len() > 256 || name.contains(&0) {
            return Err(invalid("invalid new SA registration"));
        }
        let next_id = self
            .attributes
            .keys()
            .copied()
            .max()
            .unwrap_or(15)
            .max(15)
            .checked_add(1)
            .ok_or_else(|| invalid("SA attribute ID overflow"))?;
        if self.attributes.len() >= MAX_ATTRIBUTES {
            return Err(invalid("SA registry budget exceeded"));
        }
        self.attributes.insert(
            next_id,
            Registration {
                name: name.to_vec(),
                length,
                swap,
            },
        );
        let value = u64::from(next_id) | (u64::from(swap) << 16) | (u64::from(length) << 24);
        reg_entries.push(Entry {
            name: name.to_vec(),
            integer_bytes: 8,
            values: vec![value],
            collision: 0,
        });
        Ok(next_id)
    }

    /// Ensure an SA layout (`2..=1023`) matching `attr_ids` exists in `self`
    /// (and append to `layout_entries` if newly created), returning its layout ID.
    pub fn ensure_layout(
        &mut self,
        layout_entries: &mut Vec<Entry>,
        attr_ids: &[u16],
    ) -> Result<u16, ParseError> {
        if attr_ids.is_empty() {
            return Err(invalid("empty non-default SA layout"));
        }
        let mut seen = BTreeSet::new();
        for &aid in attr_ids {
            if !self.attributes.contains_key(&aid) || !seen.insert(aid) {
                return Err(invalid(
                    "SA layout references unknown or duplicate attribute ID",
                ));
            }
        }
        if let Some((&id, _)) = self
            .layouts
            .iter()
            .find(|&(&id, ids)| id >= 2 && ids.as_slice() == attr_ids)
        {
            return Ok(id);
        }
        let next_layout = (2_u16..=1023)
            .find(|id| !self.layouts.contains_key(id))
            .ok_or_else(|| invalid("SA layout table full"))?;
        self.layouts.insert(next_layout, attr_ids.to_vec());
        layout_entries.push(Entry {
            name: next_layout.to_string().into_bytes(),
            integer_bytes: 2,
            values: attr_ids.iter().map(|&v| u64::from(v)).collect(),
            collision: 0,
        });
        Ok(next_layout)
    }

    fn ordered_ids_for_map(
        &self,
        preferred_layout: Option<u16>,
        map: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u16>, ParseError> {
        let mut ids = Vec::with_capacity(map.len());
        let mut included = BTreeSet::new();
        if let Some(lid) = preferred_layout
            && let Some(existing_ids) = self.layouts.get(&lid)
        {
            for &aid in existing_ids {
                if let Some(reg) = self.attributes.get(&aid)
                    && map.contains_key(&reg.name)
                    && included.insert(aid)
                {
                    ids.push(aid);
                }
            }
        }
        for key in map.keys() {
            let aid = self
                .attr_id_by_name(key)
                .ok_or_else(|| invalid("missing SA attribute registration for map key"))?;
            if included.insert(aid) {
                ids.push(aid);
            }
        }
        Ok(ids)
    }

    /// Encode a fresh regular-file or directory SA bonus with an explicit
    /// project owner. Register the complete core/ACL/project layout as needed;
    /// a parent's split bonus/spill layout is not a complete child template.
    ///
    /// Only byte order comes from `template_bonus`. Fresh fields follow native
    /// `zfs_mknode` order, including the fixed offsets used by quota accounting.
    /// Native xattr/ACL ownership references and unrelated parent attributes
    /// never belong to the new object. The caller persists changed registration
    /// and layout ZAPs in the same TXG as the child's dnode.
    pub fn encode_new_with_project(
        &mut self,
        reg_entries: &mut Vec<Entry>,
        layout_entries: &mut Vec<Entry>,
        template_bonus: &[u8],
        metadata: &Metadata,
        inherited_project_id: Option<u64>,
    ) -> Result<Vec<u8>, ParseError> {
        let Some(proj_id) = inherited_project_id else {
            return self.encode_new_from_template(template_bonus, metadata);
        };
        if !matches!(metadata.kind, Kind::Regular | Kind::Directory)
            || metadata.inline_symlink.is_some()
        {
            return Err(invalid(
                "project ownership on creation requires a regular file or directory",
            ));
        }
        let (order, _) = self.parse_buffer_header(template_bonus)?;
        let mut metadata = metadata.clone();
        // The presence bit and attribute must agree so initial accounting and
        // subsequent mutations/reopen all resolve exactly the same owner.
        metadata.flags |= 0x0000_8000_0000_0000;
        let mut map = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        Self::apply_metadata_to_map(&mut map, &metadata, order, true)?;
        map.insert(b"ZPL_PROJID".to_vec(), order.encode(proj_id).to_vec());
        // OpenZFS zpl_get_file_info reads quota owners at fixed offsets after
        // the SA header. A valid registered layout alone does not establish
        // native interoperability: even a split parent's order cannot be copied.
        let native_order: [&[u8]; 15] = [
            b"ZPL_MODE",
            b"ZPL_SIZE",
            b"ZPL_GEN",
            b"ZPL_UID",
            b"ZPL_GID",
            b"ZPL_PARENT",
            b"ZPL_FLAGS",
            b"ZPL_ATIME",
            b"ZPL_MTIME",
            b"ZPL_CTIME",
            b"ZPL_CRTIME",
            b"ZPL_LINKS",
            b"ZPL_PROJID",
            b"ZPL_DACL_COUNT",
            b"ZPL_DACL_ACES",
        ];
        let mut ids = Vec::with_capacity(native_order.len());
        for name in native_order {
            let value = map
                .get(name)
                .ok_or_else(|| invalid("new ZPL SA attribute is missing"))?;
            let (length, swap) = if name == b"ZPL_DACL_ACES" {
                (0, 4)
            } else {
                (
                    u16::try_from(value.len())
                        .map_err(|_| invalid("new ZPL SA attribute exceeds u16 length"))?,
                    0,
                )
            };
            ids.push(self.ensure_attribute(reg_entries, name, length, swap)?);
        }
        let chosen_layout = self.ensure_layout(layout_entries, &ids)?;
        let encoded = self.pack_layout(chosen_layout, &map, order)?;
        let verified = self.decode(&encoded, None)?;
        if verified.metadata()? != metadata || verified.project_id()? != proj_id {
            return Err(invalid("new ZPL project metadata did not round-trip"));
        }
        Ok(encoded)
    }

    /// Update an SA node's bonus + optional `DMU_OT_SA` spill block with optional
    /// trivial DACL rebuild (`chmod`), inline/spill `ZPL_DXATTR` xattr map update,
    /// and/or `ZPL_XATTR` directory pointer override.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_updated_with_options(
        &mut self,
        reg_entries: &mut Vec<Entry>,
        layout_entries: &mut Vec<Entry>,
        existing_bonus: &[u8],
        existing_spill: Option<&[u8]>,
        metadata: &Metadata,
        rebuild_trivial_dacl: bool,
        inline_xattrs: Option<&BTreeMap<String, Vec<u8>>>,
        xattr_dir_override: Option<u64>,
        max_bonus_no_spill: usize,
        max_bonus_with_spill: usize,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), ParseError> {
        if !rebuild_trivial_dacl && inline_xattrs.is_none() && xattr_dir_override.is_none() {
            return self.encode_updated_bonus_and_spill(existing_bonus, existing_spill, metadata);
        }
        let (order, bonus_layout) = self.parse_buffer_header(existing_bonus)?;
        let mut bonus_decoded = Attributes {
            values: BTreeMap::new(),
        };
        self.decode_into(existing_bonus, &mut bonus_decoded)?;
        let mut bonus_map: BTreeMap<Vec<u8>, Vec<u8>> = bonus_decoded
            .values
            .into_iter()
            .map(|(k, v)| (k, v.bytes))
            .collect();

        let (spill_layout, mut spill_map) = if let Some(spill_raw) = existing_spill {
            let (s_ord, s_lay) = self.parse_buffer_header(spill_raw)?;
            if s_ord != order {
                return Err(invalid("SA spill byte order disagrees with bonus"));
            }
            let mut spill_decoded = Attributes {
                values: BTreeMap::new(),
            };
            self.decode_into(spill_raw, &mut spill_decoded)?;
            let map: BTreeMap<Vec<u8>, Vec<u8>> = spill_decoded
                .values
                .into_iter()
                .map(|(k, v)| (k, v.bytes))
                .collect();
            (Some(s_lay), map)
        } else {
            (None, BTreeMap::new())
        };

        // Update core metadata fields in whichever map currently holds them (defaulting to bonus_map).
        let mut core_updates = BTreeMap::new();
        Self::apply_metadata_to_map(&mut core_updates, metadata, order, false)?;
        for (k, v) in core_updates {
            match spill_map.get_mut(&k) {
                Some(slot) => *slot = v,
                None => {
                    bonus_map.insert(k, v);
                }
            }
        }

        if rebuild_trivial_dacl {
            let aces =
                encode_trivial_nfsv4_aces(metadata.mode, metadata.kind == Kind::Directory, order);
            let _ = self.ensure_attribute(reg_entries, b"ZPL_DACL_COUNT", 8, 0)?;
            // OpenZFS registers ZPL_DACL_ACES with variable length (0) and SA_ACL (swap == 4).
            let _ = self.ensure_attribute(reg_entries, b"ZPL_DACL_ACES", 0, 4)?;
            spill_map.remove(b"ZPL_DACL_COUNT".as_slice());
            spill_map.remove(b"ZPL_DACL_ACES".as_slice());
            bonus_map.insert(
                b"ZPL_DACL_COUNT".to_vec(),
                order.encode((aces.len() / 8) as u64).to_vec(),
            );
            bonus_map.insert(b"ZPL_DACL_ACES".to_vec(), aces);
            if let Some(zacl) = bonus_map
                .get_mut(b"ZPL_ZNODE_ACL".as_slice())
                .or_else(|| spill_map.get_mut(b"ZPL_ZNODE_ACL".as_slice()))
                && zacl.len() == 88
            {
                zacl[0..8].fill(0);
            }
        }

        if let Some(xdir) = xattr_dir_override {
            if xdir >= OBJECT_LIMIT {
                return Err(invalid(
                    "xattr directory reference exceeds the object namespace",
                ));
            }
            bonus_map.remove(b"ZPL_XATTR".as_slice());
            spill_map.remove(b"ZPL_XATTR".as_slice());
            if xdir != 0 {
                // ZPL_XATTR is fixed legacy attribute ID 9 (length 8, swap 0).
                bonus_map.insert(b"ZPL_XATTR".to_vec(), order.encode(xdir).to_vec());
            }
        }

        if let Some(xmap) = inline_xattrs {
            bonus_map.remove(b"ZPL_DXATTR".as_slice());
            spill_map.remove(b"ZPL_DXATTR".as_slice());
            if !xmap.is_empty() {
                let nv = NvList {
                    fields: xmap
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::Bytes(v.clone())))
                        .collect(),
                };
                let dx_bytes = nv.encode_xdr()?;
                if u16::try_from(dx_bytes.len()).is_err() {
                    return Err(invalid(
                        "packed ZPL_DXATTR nvlist exceeds u16 SA variable-attribute limit",
                    ));
                }
                let _ = self.ensure_attribute(reg_entries, b"ZPL_DXATTR", 0, 3)?;

                // Try inline bonus first if `spill_map` has no other attributes.
                if spill_map.is_empty() {
                    let mut inline_try = bonus_map.clone();
                    inline_try.insert(b"ZPL_DXATTR".to_vec(), dx_bytes.clone());
                    let mut tmp_layouts = layout_entries.clone();
                    let mut tmp_reg = self.clone();
                    let inline_ids =
                        tmp_reg.ordered_ids_for_map(Some(bonus_layout), &inline_try)?;
                    let inline_lid = tmp_reg.ensure_layout(&mut tmp_layouts, &inline_ids)?;
                    let candidate = tmp_reg.pack_layout(inline_lid, &inline_try, order)?;
                    if candidate.len() <= max_bonus_no_spill {
                        *self = tmp_reg;
                        *layout_entries = tmp_layouts;
                        let verified = self.decode(&candidate, None)?;
                        let _ = verified.metadata()?;
                        return Ok((candidate, None));
                    }
                }
                spill_map.insert(b"ZPL_DXATTR".to_vec(), dx_bytes);
            }
        }

        let bonus_ids = self.ordered_ids_for_map(Some(bonus_layout), &bonus_map)?;
        let new_bonus_lid = self.ensure_layout(layout_entries, &bonus_ids)?;
        let new_bonus = self.pack_layout(new_bonus_lid, &bonus_map, order)?;
        let max_allowed = if spill_map.is_empty() {
            max_bonus_no_spill
        } else {
            max_bonus_with_spill
        };
        if new_bonus.len() > max_allowed {
            return Err(invalid("updated SA bonus exceeds dnode bonus capacity"));
        }

        let new_spill = if spill_map.is_empty() {
            None
        } else {
            let spill_ids = self.ordered_ids_for_map(spill_layout, &spill_map)?;
            let new_spill_lid = self.ensure_layout(layout_entries, &spill_ids)?;
            Some(self.pack_layout(new_spill_lid, &spill_map, order)?)
        };

        let verified = self.decode(&new_bonus, new_spill.as_deref())?;
        let _ = verified.metadata()?;
        Ok((new_bonus, new_spill))
    }
}

fn encode_trivial_nfsv4_aces(mode: u64, is_dir: bool, order: Endian) -> Vec<u8> {
    const ACE_READ_DATA: u32 = 0x0000_0001;
    const ACE_WRITE_DATA: u32 = 0x0000_0002;
    const ACE_APPEND_DATA: u32 = 0x0000_0004;
    const ACE_READ_NAMED_ATTRS: u32 = 0x0000_0008;
    const ACE_WRITE_NAMED_ATTRS: u32 = 0x0000_0010;
    const ACE_EXECUTE: u32 = 0x0000_0020;
    const ACE_DELETE_CHILD: u32 = 0x0000_0040;
    const ACE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const ACE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    const ACE_READ_ACL: u32 = 0x0002_0000;
    const ACE_WRITE_ACL: u32 = 0x0004_0000;
    const ACE_WRITE_OWNER: u32 = 0x0008_0000;
    const ACE_SYNCHRONIZE: u32 = 0x0010_0000;

    let data_mask = |rwx: u64| -> u32 {
        let mut m = 0;
        if rwx & 0o4 != 0 {
            m |= ACE_READ_DATA;
        }
        if rwx & 0o2 != 0 {
            m |= ACE_WRITE_DATA | ACE_APPEND_DATA;
            if is_dir {
                m |= ACE_DELETE_CHILD;
            }
        }
        if rwx & 0o1 != 0 {
            m |= ACE_EXECUTE;
        }
        m
    };

    let owner = data_mask((mode >> 6) & 7);
    let group = data_mask((mode >> 3) & 7);
    let everyone = data_mask(mode & 7);
    let read_metadata = ACE_READ_ACL | ACE_READ_ATTRIBUTES | ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;
    let write_metadata =
        ACE_WRITE_ACL | ACE_WRITE_OWNER | ACE_WRITE_ATTRIBUTES | ACE_WRITE_NAMED_ATTRS;
    // OpenZFS zfs-2.3.0 acl_trivial_access_masks/zfs_acl_chmod: preserve
    // POSIX class precedence even when the owner also matches the group.
    // Sticky-directory ownership is checked separately from ACL grants.
    let aces: [(u16, u16, u32); 6] = [
        (0, 0x1000, owner & everyone & !group),
        (1, 0x1000, (group | everyone) & !owner),
        (1, 0x2040, everyone & !group),
        (0, 0x1000, owner | read_metadata | write_metadata),
        (0, 0x2040, group | read_metadata),
        (0, 0x4000, everyone | read_metadata),
    ];
    let mut out = Vec::with_capacity(aces.len() * 8);
    for (ace_type, flags, access_mask) in aces {
        if access_mask == 0 {
            continue;
        }
        match order {
            Endian::Little => {
                out.extend_from_slice(&ace_type.to_le_bytes());
                out.extend_from_slice(&flags.to_le_bytes());
                out.extend_from_slice(&access_mask.to_le_bytes());
            }
            Endian::Big => {
                out.extend_from_slice(&ace_type.to_be_bytes());
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(&access_mask.to_be_bytes());
            }
        }
    }
    out
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

    /// Native project accounting owner. Objects without `ZPL_PROJID` belong to
    /// the default project; a present attribute must be one native u64 scalar.
    pub fn project_id(&self) -> Result<u64, ParseError> {
        if self.values.contains_key(b"ZPL_PROJID".as_slice()) {
            self.integer("ZPL_PROJID")
        } else if self.values.contains_key(b"ZPL_FLAGS".as_slice())
            && self.integer("ZPL_FLAGS")? & 0x0000_8000_0000_0000 != 0
        {
            Err(invalid("ZFS_PROJID flag lacks its project ID attribute"))
        } else {
            Ok(0)
        }
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

    /// External object owned by a legacy `zfs_acl_phys_t` retained in SA.
    /// The ACL is a byte attribute, but its object reference follows the SA
    /// buffer's native byte order. A missing attribute owns no external ACL.
    pub fn external_acl_object(&self) -> Result<u64, ParseError> {
        let Some(attribute) = self.values.get(b"ZPL_ZNODE_ACL".as_slice()) else {
            return Ok(0);
        };
        if attribute.swap != 3 || attribute.bytes.len() != 88 {
            return Err(invalid("invalid legacy ACL system attribute"));
        }
        let object = attribute.order.u64(&attribute.bytes, 0)?;
        if object >= OBJECT_LIMIT {
            return Err(invalid(
                "external ACL reference exceeds the object namespace",
            ));
        }
        Ok(object)
    }

    /// Recover external ownership and quota identity without assuming that all
    /// attributes share the dnode's byte order or reside in its bonus buffer.
    pub fn reclamation_ownership(&self) -> Result<ReclamationOwnership, ParseError> {
        let xattrs = self.xattrs()?;
        ReclamationOwnership {
            xattr_directory: xattrs.directory,
            external_acl_object: self.external_acl_object()?,
            project_id: self.project_id()?,
        }
        .validate()
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
