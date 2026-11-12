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
        raw[120..128].copy_from_slice(&order.encode(checked.flags));
        raw[128..136].copy_from_slice(&order.encode(checked.uid));
        raw[136..144].copy_from_slice(&order.encode(checked.gid));
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
            let aces = encode_trivial_nfsv4_aces(checked.mode, checked.kind == Kind::Directory, order);
            map.insert(b"ZPL_DACL_COUNT".to_vec(), order.encode(3).to_vec());
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
            return Err(invalid("inline symlink creation requires a symlink SA layout"));
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
                && names.iter().all(|name| {
                    required_core.contains(name) || allowed_optional.contains(name)
                })
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
        // Seed optional defaults (and inherit ZPL_PROJID if present on template)
        let projid_bytes = template_decoded
            .values
            .get(b"ZPL_PROJID".as_slice())
            .filter(|a| a.bytes.len() == 8)
            .map_or_else(|| order.encode(0).to_vec(), |a| a.bytes.clone());
        map.insert(b"ZPL_PROJID".to_vec(), projid_bytes);
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

    let perm_mask = |rwx: u64, is_owner: bool| -> u32 {
        let mut m = ACE_READ_ACL | ACE_READ_ATTRIBUTES | ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;
        if is_owner {
            m |= ACE_WRITE_ACL | ACE_WRITE_OWNER | ACE_WRITE_ATTRIBUTES | ACE_WRITE_NAMED_ATTRS;
        }
        if rwx & 0o4 != 0 {
            m |= ACE_READ_DATA;
        }
        if rwx & 0o2 != 0 {
            m |= ACE_WRITE_DATA | ACE_APPEND_DATA;
            if is_dir && (mode & 0o1000 == 0 || is_owner) {
                m |= ACE_DELETE_CHILD;
            }
        }
        if rwx & 0o1 != 0 {
            m |= ACE_EXECUTE;
        }
        m
    };

    let aces: [(u16, u32); 3] = [
        (0x1000, perm_mask((mode >> 6) & 7, true)),
        (0x2040, perm_mask((mode >> 3) & 7, false)),
        (0x4000, perm_mask(mode & 7, false)),
    ];
    let mut out = Vec::with_capacity(24);
    for (flags, access_mask) in aces {
        match order {
            Endian::Little => {
                out.extend_from_slice(&0_u16.to_le_bytes());
                out.extend_from_slice(&flags.to_le_bytes());
                out.extend_from_slice(&access_mask.to_le_bytes());
            }
            Endian::Big => {
                out.extend_from_slice(&0_u16.to_be_bytes());
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
