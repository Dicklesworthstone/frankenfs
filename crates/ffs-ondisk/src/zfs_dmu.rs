//! Native ZFS DMU object-set, dnode and micro-ZAP parsing.
//!
//! Layout reference: OpenZFS zfs-2.3.0 dnode.h, dmu_objset.h and zap_impl.h.
//! Pure parsing only. A parsed dnode does not authorize a block read or import;
//! its owner must verify block checksums, types, levels, births and volume bounds.

pub mod space_map;

use crate::zfs::{BlockPointer, Endian, MAX_BLOCK_BYTES};
use ffs_types::ParseError;
use std::collections::BTreeSet;

pub const DNODE_BYTES: usize = 512;
pub const DNODE_BLOCK_BYTES: usize = 16 * 1024;
pub const DMU_OT_DNODE: u8 = 10;
pub const DMU_OT_OBJECT_DIRECTORY: u8 = 1;

fn invalid(reason: &'static str) -> ParseError {
    ParseError::InvalidField {
        field: "zfs.dmu",
        reason,
    }
}

fn u16_at(raw: &[u8], at: usize, order: Endian) -> Result<u16, ParseError> {
    let bytes: [u8; 2] = raw
        .get(at..at + 2)
        .ok_or_else(|| invalid("truncated 16-bit field"))?
        .try_into()
        .map_err(|_| invalid("truncated 16-bit field"))?;
    Ok(match order {
        Endian::Little => u16::from_le_bytes(bytes),
        Endian::Big => u16::from_be_bytes(bytes),
    })
}

/// An allocated native dnode, including its exact bonus bytes and optional spill.
/// Geometry fields are private: construction cannot bypass validation.
#[derive(Debug, Clone)]
pub struct Dnode {
    object_type: u8,
    bonus_type: u8,
    order: Endian,
    levels: u8,
    indirect_shift: u8,
    data_bytes: usize,
    max_block: u64,
    used_bytes: u64,
    slots: usize,
    pointers: Vec<BlockPointer>,
    bonus: Vec<u8>,
    spill: Option<BlockPointer>,
}

impl Dnode {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() < DNODE_BYTES || raw[0] == 0 {
            return Err(invalid("truncated or unallocated dnode"));
        }
        let slots = usize::from(raw[12]) + 1;
        let size = slots * DNODE_BYTES;
        if size > DNODE_BLOCK_BYTES || raw.len() != size {
            return Err(invalid("dnode size disagrees with its extra slots"));
        }
        let levels = raw[2];
        let count = usize::from(raw[3]);
        if !(1..=12).contains(&levels) || !(1..=3).contains(&count) {
            return Err(invalid("unsupported dnode level or root-pointer count"));
        }
        let indirect_shift = raw[1];
        if !((12..=17).contains(&indirect_shift) || levels == 1 && indirect_shift == 0) {
            return Err(invalid("unsupported indirect block shift"));
        }
        if raw[7] & !0x0F != 0 {
            return Err(invalid("unknown dnode flags"));
        }
        let data_bytes = usize::from(u16_at(raw, 8, order)?) * 512;
        let max_block = order.u64(raw, 16)?;
        if data_bytes == 0
            || data_bytes > MAX_BLOCK_BYTES
            || (max_block != 0 && !data_bytes.is_power_of_two())
        {
            return Err(invalid("invalid dnode data-block geometry"));
        }
        let bonus_start = 64 + count * 128;
        let bonus_end = size - if raw[7] & 4 != 0 { 128 } else { 0 };
        let bonus_len = usize::from(u16_at(raw, 10, order)?);
        if bonus_start > bonus_end || bonus_len > bonus_end - bonus_start {
            return Err(invalid("bonus data overlaps pointers or spill"));
        }
        let used = order.u64(raw, 24)?;
        let used_bytes = if raw[7] & 1 != 0 {
            used
        } else {
            used.checked_mul(512)
                .ok_or_else(|| invalid("dnode used-byte overflow"))?
        };
        let mut pointers = Vec::with_capacity(count);
        for at in (64..bonus_start).step_by(128) {
            pointers.push(BlockPointer::parse(&raw[at..at + 128], order)?);
        }
        let spill = if raw[7] & 4 != 0 {
            Some(BlockPointer::parse(&raw[size - 128..], order)?)
        } else {
            None
        };
        let dnode = Self {
            object_type: raw[0],
            bonus_type: raw[4],
            order,
            levels,
            indirect_shift,
            data_bytes,
            max_block,
            used_bytes,
            slots,
            pointers,
            bonus: raw[bonus_start..bonus_start + bonus_len].to_vec(),
            spill,
        };
        dnode.route(max_block)?;
        Ok(dnode)
    }

    #[must_use]
    pub const fn object_type(&self) -> u8 {
        self.object_type
    }
    #[must_use]
    pub const fn bonus_type(&self) -> u8 {
        self.bonus_type
    }
    #[must_use]
    pub const fn order(&self) -> Endian {
        self.order
    }
    #[must_use]
    pub const fn levels(&self) -> u8 {
        self.levels
    }
    #[must_use]
    pub const fn data_bytes(&self) -> usize {
        self.data_bytes
    }
    #[must_use]
    pub fn indirect_bytes(&self) -> usize {
        1_usize << self.indirect_shift
    }
    #[must_use]
    pub const fn max_block(&self) -> u64 {
        self.max_block
    }
    #[must_use]
    pub const fn used_bytes(&self) -> u64 {
        self.used_bytes
    }
    #[must_use]
    pub const fn slots(&self) -> usize {
        self.slots
    }
    #[must_use]
    pub fn pointers(&self) -> &[BlockPointer] {
        &self.pointers
    }
    #[must_use]
    pub fn bonus(&self) -> &[u8] {
        &self.bonus
    }
    #[must_use]
    pub const fn spill(&self) -> Option<&BlockPointer> {
        self.spill.as_ref()
    }

    /// Root slot followed by indirect slots. u128 arithmetic avoids wrapping
    /// on legal trees whose addressable capacity is greater than u64::MAX.
    /// This is allocated-block addressing, NOT a ZPL file's logical EOF.
    pub fn route(&self, block: u64) -> Result<Vec<usize>, ParseError> {
        if block > self.max_block {
            return Err(invalid("block exceeds dn_maxblkid"));
        }
        let bits = if self.levels > 1 {
            u32::from(self.indirect_shift - 7)
        } else {
            0
        };
        let shift = u32::from(self.levels - 1) * bits;
        let block = u128::from(block);
        let root = block >> shift;
        if root >= self.pointers.len() as u128 {
            return Err(invalid("dnode maximum block exceeds pointer-tree capacity"));
        }
        let mut route = Vec::with_capacity(usize::from(self.levels));
        route.push(root as usize);
        for level in (0..self.levels - 1).rev() {
            route.push(((block >> (u32::from(level) * bits)) & ((1_u128 << bits) - 1)) as usize);
        }
        Ok(route)
    }
}

/// Find the start of an object in a native 16 KiB dnode block. Interior slots
/// of a large dnode must never be reinterpreted as independent object headers.
pub fn dnode_at(raw: &[u8], slot: usize, order: Endian) -> Result<Option<Dnode>, ParseError> {
    if raw.len() != DNODE_BLOCK_BYTES || slot >= DNODE_BLOCK_BYTES / DNODE_BYTES {
        return Err(invalid("invalid dnode block or requested slot"));
    }
    let mut current = 0;
    while current <= slot {
        let at = current * DNODE_BYTES;
        if raw[at] == 0 {
            if current == slot {
                return Ok(None);
            }
            current += 1;
            continue;
        }
        let slots = usize::from(raw[at + 12]) + 1;
        let end = (current + slots) * DNODE_BYTES;
        if end > raw.len() {
            return Err(invalid("large dnode crosses its containing block"));
        }
        if current == slot {
            return Dnode::parse(&raw[at..end], order).map(Some);
        }
        if current + slots > slot {
            return Err(invalid("object ID selects a large-dnode interior slot"));
        }
        current += slots;
    }
    Err(invalid("unreachable dnode slot"))
}

/// Native ZFS Intent Log header (`zil_header_t`, 192 bytes at offset 512 of `objset_phys_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZilHeader {
    pub claim_txg: u64,
    pub replay_seq: u64,
    pub log: BlockPointer,
    pub claim_blk_seq: u64,
    pub flags: u64,
}

impl ZilHeader {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() < 192 {
            return Err(invalid("truncated zil_header_t"));
        }
        let claim_txg = order.u64(raw, 0)?;
        let replay_seq = order.u64(raw, 8)?;
        let log = BlockPointer::parse(&raw[16..144], order)?;
        let claim_blk_seq = order.u64(raw, 144)?;
        let flags = order.u64(raw, 152)?;
        Ok(Self {
            claim_txg,
            replay_seq,
            log,
            claim_blk_seq,
            flags,
        })
    }

    #[must_use]
    pub fn has_unclaimed_log(&self) -> bool {
        self.claim_txg == 0 && !self.log.hole()
    }

    #[must_use]
    pub fn has_work(&self) -> bool {
        !self.log.hole()
    }
}

/// Decoded payload of one ZIL intent-log record (`lr_t` + operation-specific fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZilRecordPayload {
    Create {
        dir_obj: u64,
        file_obj: u64,
        mode: u64,
        uid: u64,
        gid: u64,
        generation: u64,
        crtime: [u64; 2],
        name: Vec<u8>,
        symlink_target: Option<Vec<u8>>,
        is_dir: bool,
    },
    Remove {
        dir_obj: u64,
        name: Vec<u8>,
        is_dir: bool,
    },
    Link {
        dir_obj: u64,
        file_obj: u64,
        name: Vec<u8>,
    },
    Rename {
        src_dir_obj: u64,
        dst_dir_obj: u64,
        src_name: Vec<u8>,
        dst_name: Vec<u8>,
    },
    Write {
        file_obj: u64,
        offset: u64,
        length: u64,
        blkoff: u64,
        blkptr: BlockPointer,
        inline_data: Vec<u8>,
    },
    Truncate {
        file_obj: u64,
        offset: u64,
        length: u64,
    },
    Setattr {
        file_obj: u64,
        mask: u64,
        mode: u64,
        uid: u64,
        gid: u64,
        size: u64,
        atime: [u64; 2],
        mtime: [u64; 2],
    },
}

/// One validated ZIL log record (`lr_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZilRecord {
    pub txtype: u64,
    pub reclen: u64,
    pub txg: u64,
    pub seq: u64,
    pub payload: ZilRecordPayload,
}

/// One parsed ZIL log block (`lr_t` records + trailing 184-byte `zil_chain_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZilBlock {
    pub next_blk: BlockPointer,
    pub nused: u64,
    pub records: Vec<ZilRecord>,
}

fn cstr_pair(bytes: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), ParseError> {
    let first_nul = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| invalid("unterminated ZIL record name"))?;
    let first = bytes[..first_nul].to_vec();
    if first.is_empty() {
        return Err(invalid("empty ZIL record name"));
    }
    let rest = &bytes[first_nul + 1..];
    let second = rest
        .iter()
        .position(|&b| b == 0)
        .map(|end| rest[..end].to_vec())
        .filter(|s| !s.is_empty());
    Ok((first, second))
}

impl ZilBlock {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() < 512 || !raw.len().is_multiple_of(512) || raw.len() > MAX_BLOCK_BYTES {
            return Err(invalid("invalid ZIL block size"));
        }
        let trailer_start = raw.len() - 184;
        let trailer = &raw[trailer_start..];
        let next_blk = BlockPointer::parse(&trailer[8..136], order)?;
        let nused = order.u64(trailer, 136)?;
        let records_limit = (nused as usize).min(trailer_start);
        let mut pos = 0_usize;
        let mut records = Vec::new();
        while pos + 32 <= records_limit {
            let txtype = order.u64(raw, pos)?;
            let reclen = order.u64(raw, pos + 8)?;
            if txtype == 0 || reclen < 32 || !reclen.is_multiple_of(8) {
                break;
            }
            let rec_end = pos
                .checked_add(reclen as usize)
                .filter(|&end| end <= records_limit)
                .ok_or_else(|| invalid("ZIL record exceeds block used bytes"))?;
            let rec = &raw[pos..rec_end];
            if !matches!(txtype & 0x1f, 1 | 2 | 4..=11 | 14..=20) {
                pos = rec_end;
                continue;
            }
            let record = ZilRecord::parse(rec, order)?;
            records.push(record);
            pos = rec_end;
        }
        Ok(Self {
            next_blk,
            nused,
            records,
        })
    }
}

impl ZilRecord {
    /// Decode one complete record independently of legacy/slim block framing.
    /// Consumers replaying records must first admit the exact operation flags
    /// and native layout; inspection retains its recognized-type decoding.
    pub fn parse(rec: &[u8], order: Endian) -> Result<Self, ParseError> {
        if rec.len() < 32 || !rec.len().is_multiple_of(8) {
            return Err(invalid("invalid complete ZIL record length"));
        }
        let txtype = order.u64(rec, 0)?;
        let reclen = order.u64(rec, 8)?;
        if reclen != rec.len() as u64 {
            return Err(invalid("ZIL record length disagrees with its span"));
        }
        let txg = order.u64(rec, 16)?;
        let seq = order.u64(rec, 24)?;
        let payload = match txtype & 0x1f {
            1 | 2 | 4 | 14..=19 => {
                if rec.len() < 104 {
                    return Err(invalid("truncated ZIL lr_create_t"));
                }
                let dir_obj = order.u64(rec, 32)?;
                let file_obj = order.u64(rec, 40)? & ((1_u64 << 48) - 1);
                let mode = order.u64(rec, 48)?;
                let uid = order.u64(rec, 56)?;
                let gid = order.u64(rec, 64)?;
                let generation = order.u64(rec, 72)?;
                let crtime = [order.u64(rec, 80)?, order.u64(rec, 88)?];
                let (name, symlink_target) = cstr_pair(&rec[104..])?;
                let is_dir =
                    matches!(txtype & 0x1f, 2 | 17..=19) || (mode & 0o170_000) == 0o040_000;
                ZilRecordPayload::Create {
                    dir_obj,
                    file_obj,
                    mode,
                    uid,
                    gid,
                    generation,
                    crtime,
                    name,
                    symlink_target,
                    is_dir,
                }
            }
            5 | 6 => {
                if rec.len() < 40 {
                    return Err(invalid("truncated ZIL lr_remove_t"));
                }
                let dir_obj = order.u64(rec, 32)?;
                let (name, _) = cstr_pair(&rec[40..])?;
                ZilRecordPayload::Remove {
                    dir_obj,
                    name,
                    is_dir: (txtype & 0x1f) == 6,
                }
            }
            7 => {
                if rec.len() < 48 {
                    return Err(invalid("truncated ZIL lr_link_t"));
                }
                let (name, _) = cstr_pair(&rec[48..])?;
                ZilRecordPayload::Link {
                    dir_obj: order.u64(rec, 32)?,
                    file_obj: order.u64(rec, 40)?,
                    name,
                }
            }
            8 => {
                if rec.len() < 48 {
                    return Err(invalid("truncated ZIL lr_rename_t"));
                }
                let src_dir_obj = order.u64(rec, 32)?;
                let dst_dir_obj = order.u64(rec, 40)?;
                let (src_name, dst_opt) = cstr_pair(&rec[48..])?;
                let dst_name = dst_opt
                    .ok_or_else(|| invalid("missing destination name in ZIL lr_rename_t"))?;
                ZilRecordPayload::Rename {
                    src_dir_obj,
                    dst_dir_obj,
                    src_name,
                    dst_name,
                }
            }
            9 | 20 => {
                if rec.len() < 192 {
                    return Err(invalid("truncated ZIL lr_write_t"));
                }
                let file_obj = order.u64(rec, 32)?;
                let offset = order.u64(rec, 40)?;
                let length = order.u64(rec, 48)?;
                let blkoff = order.u64(rec, 56)?;
                let blkptr = BlockPointer::parse(&rec[64..192], order)?;
                let inline_data = if rec.len() > 192 {
                    let avail = (rec.len() - 192).min(length as usize);
                    rec[192..192 + avail].to_vec()
                } else {
                    Vec::new()
                };
                ZilRecordPayload::Write {
                    file_obj,
                    offset,
                    length,
                    blkoff,
                    blkptr,
                    inline_data,
                }
            }
            10 => {
                if rec.len() < 56 {
                    return Err(invalid("truncated ZIL lr_truncate_t"));
                }
                ZilRecordPayload::Truncate {
                    file_obj: order.u64(rec, 32)?,
                    offset: order.u64(rec, 40)?,
                    length: order.u64(rec, 48)?,
                }
            }
            11 => {
                if rec.len() < 96 {
                    return Err(invalid("truncated ZIL lr_setattr_t"));
                }
                let mtime = if rec.len() >= 112 {
                    [order.u64(rec, 96)?, order.u64(rec, 104)?]
                } else {
                    [0, 0]
                };
                ZilRecordPayload::Setattr {
                    file_obj: order.u64(rec, 32)?,
                    mask: order.u64(rec, 40)?,
                    mode: order.u64(rec, 48)?,
                    uid: order.u64(rec, 56)?,
                    gid: order.u64(rec, 64)?,
                    size: order.u64(rec, 72)?,
                    atime: [order.u64(rec, 80)?, order.u64(rec, 88)?],
                    mtime,
                }
            }
            _ => return Err(invalid("unknown ZIL record payload")),
        };
        Ok(Self {
            txtype,
            reclen,
            txg,
            seq,
            payload,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ObjectSet {
    pub kind: u64,
    pub flags: u64,
    pub meta: Dnode,
    pub zil_header: ZilHeader,
}

impl ObjectSet {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if !matches!(raw.len(), 1024 | 2048 | 4096) {
            return Err(invalid("unsupported object-set physical size"));
        }
        let kind = order.u64(raw, 704)?;
        let flags = order.u64(raw, 712)?;
        if !(1..=4).contains(&kind) || flags & !7 != 0 {
            return Err(invalid("unsupported object-set type or flags"));
        }
        let meta = Dnode::parse(&raw[..DNODE_BYTES], order)?;
        if meta.object_type() != DMU_OT_DNODE
            || meta.data_bytes() != DNODE_BLOCK_BYTES
            || !meta.bonus().is_empty()
            || meta.spill().is_some()
        {
            return Err(invalid("object set has an invalid meta-dnode"));
        }
        let zil_header = ZilHeader::parse(&raw[512..704], order)?;
        Ok(Self {
            kind,
            flags,
            meta,
            zil_header,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapEntry {
    /// Native bytes. No UTF-8 replacement, normalization or host-path decoding.
    pub name: Vec<u8>,
    pub value: u64,
    pub collision: u32,
}

/// Enumerate a complete micro-ZAP. Fat-ZAP needs its own leaf/array traversal;
/// it cannot be treated as an empty map or as a micro-ZAP with a different tag.
pub fn microzap(raw: &[u8], order: Endian) -> Result<Vec<ZapEntry>, ParseError> {
    if !(512..=131_072).contains(&raw.len())
        || !raw.len().is_multiple_of(512)
        || order.u64(raw, 0)? != (1_u64 << 63) + 3
    {
        return Err(invalid("not an admitted micro-ZAP block"));
    }
    if order.u64(raw, 16)? != 0 {
        return Err(invalid("normalized micro-ZAP lookup is not implemented"));
    }
    let mut names = BTreeSet::new();
    let mut result = Vec::new();
    for entry in raw[64..].as_chunks::<64>().0 {
        if entry[14] == 0 {
            continue;
        }
        let end = entry[14..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid("unterminated micro-ZAP name"))?;
        let name = entry[14..14 + end].to_vec();
        if !names.insert(name.clone()) {
            return Err(invalid("duplicate micro-ZAP name"));
        }
        if u16_at(entry, 12, order)? != 0 {
            return Err(invalid("unknown micro-ZAP entry padding"));
        }
        let bytes: [u8; 4] = entry[8..12]
            .try_into()
            .map_err(|_| invalid("truncated collision field"))?;
        let collision = match order {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        };
        result.push(ZapEntry {
            name,
            value: order.u64(entry, 0)?,
            collision,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(raw: &mut [u8], at: usize, value: u16, order: Endian) {
        let bytes = match order {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        raw[at..at + 2].copy_from_slice(&bytes);
    }
    fn node(order: Endian, slots: usize) -> Vec<u8> {
        let mut raw = vec![0; slots * 512];
        raw[0] = 1;
        raw[1] = 12;
        raw[2] = 2;
        raw[3] = 2;
        raw[7] = 1;
        raw[12] = (slots - 1) as u8;
        word(&mut raw, 8, 1, order);
        raw[16..24].copy_from_slice(&order.encode(63));
        raw[24..32].copy_from_slice(&order.encode(123));
        raw
    }
    #[test]
    fn both_orders_preserve_bonus_spill_and_used_units() {
        for order in [Endian::Little, Endian::Big] {
            let mut raw = node(order, 2);
            raw[4] = 12;
            raw[7] = 4; // Sector accounting, plus spill.
            word(&mut raw, 10, 5, order);
            raw[320..325].copy_from_slice(b"bonus");
            let n = Dnode::parse(&raw, order).unwrap();
            assert_eq!(
                (n.slots(), n.bonus_type(), n.used_bytes()),
                (2, 12, 123 * 512)
            );
            assert_eq!(n.bonus(), b"bonus");
            assert!(n.spill().unwrap().hole());
            assert_eq!(n.order(), order);
        }
    }
    #[test]
    fn routes_include_root_slot_and_all_indirect_digits_without_overflow() {
        let order = Endian::Little;
        let n = Dnode::parse(&node(order, 1), order).unwrap();
        assert_eq!(n.route(0).unwrap(), [0, 0]);
        assert_eq!(n.route(31).unwrap(), [0, 31]);
        assert_eq!(n.route(32).unwrap(), [1, 0]);
        assert_eq!(n.route(63).unwrap(), [1, 31]);
        assert!(n.route(64).is_err());
        let mut raw = node(order, 1);
        raw[2] = 12;
        raw[1] = 17;
        raw[16..24].copy_from_slice(&order.encode(u64::MAX));
        let n = Dnode::parse(&raw, order).unwrap();
        let route = n.route(u64::MAX).unwrap();
        assert_eq!(route.len(), 12);
        assert_eq!(route[0], 0);
        assert_eq!(route[11], 1023);
        raw[2] = 1;
        assert!(Dnode::parse(&raw, order).is_err());
    }
    #[test]
    fn malformed_geometry_and_bonus_overlap_are_rejected() {
        let original = node(Endian::Little, 1);
        for (at, byte) in [
            (0, 0),
            (1, 11),
            (2, 0),
            (2, 13),
            (3, 0),
            (3, 4),
            (7, 16),
            (8, 0),
            (12, 32),
        ] {
            let mut raw = original.clone();
            raw[at] = byte;
            assert!(Dnode::parse(&raw, Endian::Little).is_err(), "{at} {byte}");
        }
        let mut raw = original.clone();
        word(&mut raw, 10, 193, Endian::Little);
        assert!(Dnode::parse(&raw, Endian::Little).is_err());
        raw[7] = 4;
        word(&mut raw, 10, 65, Endian::Little);
        assert!(Dnode::parse(&raw, Endian::Little).is_err());
        for end in 0..512 {
            assert!(Dnode::parse(&original[..end], Endian::Little).is_err());
        }
    }
    #[test]
    fn large_dnode_interiors_never_become_independent_objects() {
        let mut block = vec![0; DNODE_BLOCK_BYTES];
        let large = node(Endian::Little, 3);
        block[512..2048].copy_from_slice(&large);
        // A plausible header in bonus storage is still an interior slot.
        block[1024..1536].copy_from_slice(&node(Endian::Little, 1));
        assert!(dnode_at(&block, 0, Endian::Little).unwrap().is_none());
        assert_eq!(
            dnode_at(&block, 1, Endian::Little)
                .unwrap()
                .unwrap()
                .slots(),
            3
        );
        assert!(dnode_at(&block, 2, Endian::Little).is_err());
        assert!(dnode_at(&block, 3, Endian::Little).is_err());
        assert!(dnode_at(&block, 4, Endian::Little).unwrap().is_none());
        block[31 * 512..].copy_from_slice(&node(Endian::Little, 1));
        block[31 * 512 + 12] = 1;
        assert!(dnode_at(&block, 31, Endian::Little).is_err());
    }
    #[test]
    fn objectset_requires_a_real_bounded_meta_dnode() {
        for order in [Endian::Little, Endian::Big] {
            let mut raw = vec![0; 1024];
            let mut meta = node(order, 1);
            meta[0] = DMU_OT_DNODE;
            word(&mut meta, 8, 32, order);
            raw[..512].copy_from_slice(&meta);
            raw[704..712].copy_from_slice(&order.encode(1));
            assert_eq!(
                ObjectSet::parse(&raw, order).unwrap().meta.data_bytes(),
                16384
            );
            raw[0] = 1;
            assert!(ObjectSet::parse(&raw, order).is_err());
            raw[0] = DMU_OT_DNODE;
            raw[704..712].copy_from_slice(&order.encode(0));
            assert!(ObjectSet::parse(&raw, order).is_err());
        }
    }
    #[test]
    fn microzap_preserves_raw_names_and_refuses_duplicate_or_incomplete_maps() {
        for order in [Endian::Little, Endian::Big] {
            let mut raw = vec![0; 512];
            raw[..8].copy_from_slice(&order.encode((1_u64 << 63) + 3));
            raw[64..72].copy_from_slice(&order.encode(99));
            raw[78..82].copy_from_slice(&[b'a', 0xFF, b'b', 0]);
            let entries = microzap(&raw, order).unwrap();
            assert_eq!(entries[0].name, [b'a', 0xFF, b'b']);
            assert_eq!(entries[0].value, 99);
            let entry = raw[64..128].to_vec();
            raw[128..192].copy_from_slice(&entry);
            assert!(microzap(&raw, order).is_err());
            raw[128..192].fill(0);
            raw[78..128].fill(b'x');
            assert!(microzap(&raw, order).is_err());
            raw[..8].copy_from_slice(&order.encode((1_u64 << 63) + 1));
            assert!(microzap(&raw, order).is_err());
        }
    }
}
