//! OpenZFS `DMU_BACKUP_STREAM` wire protocol (`zfs send` / `zfs recv`) and
//! `receive_resume_token` codecs.
//!
//! Pure, bounded, `#![forbid(unsafe_code)]`, zero-I/O parsing and encoding
//! matching OpenZFS 2.3/2.4 `include/sys/zfs_ioctl.h`, `module/zfs/dmu_send.c`,
//! and `lib/libzfs/libzfs_sendrecv.c`.
//!
//! Security boundary: untrusted stream metadata (`drr_toname`, embedded nvlists,
//! resume token `toname`) is treated strictly as opaque data and NEVER chooses
//! host paths, devices, pools, key files, or import authority.

use super::crypto::{
    ZIO_DATA_IV_LEN, ZIO_DATA_MAC_LEN, ZIO_DATA_SALT_LEN, ZfsKeyFormat, ZioEncrypt,
};
use super::nvlist::{NvList, Value};
use super::{EMBEDDED_PAYLOAD_BYTES, Endian, MAX_BLOCK_BYTES, ParseError, invalid};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use std::collections::BTreeMap;

/// `DMU_BACKUP_MAGIC` (`0x0000_0002_f5ba_cbac`), used to auto-detect stream endianness.
pub const DMU_BACKUP_MAGIC: u64 = 0x0000_0002_f5ba_cbac;

/// Fixed byte length of every `dmu_replay_record_t` header (`8 + 304`).
pub const DMU_REPLAY_RECORD_BYTES: usize = 312;

/// Offset of `drr_u.drr_checksum.drr_checksum` (`[u64; 4]`) inside non-`DRR_BEGIN` headers.
pub const DRR_CHECKSUM_OFFSET: usize = 280;

/// Maximum admitted `DRR_BEGIN` XDR nvlist payload size (4 MiB).
pub const MAX_BEGIN_NVLIST_BYTES: usize = 4 * 1024 * 1024;

/// Maximum admitted `DRR_OBJECT` bonus length (16 KiB large dnode ceiling).
pub const MAX_OBJECT_BONUS_BYTES: usize = 16 * 1024;

/// Maximum admitted `receive_resume_token` ASCII length and uncompressed XDR nvlist length.
pub const MAX_RESUME_TOKEN_CHARS: usize = 65_536;
pub const MAX_RESUME_TOKEN_NVLIST_BYTES: usize = 64 * 1024;

/// OpenZFS `ZFS_SEND_RESUME_TOKEN_VERSION`.
pub const ZFS_SEND_RESUME_TOKEN_VERSION: u32 = 1;

/// OpenZFS `DMU_OST_*` objset types admitted in `DRR_BEGIN.drr_type`.
pub const DMU_OST_NONE: u32 = 0;
pub const DMU_OST_ZFS: u32 = 2;
pub const DMU_OST_ZVOL: u32 = 3;

/// `DRR_BEGIN.drr_flags` bit constants.
pub const DRR_FLAG_CLONE: u32 = 1 << 0;
pub const DRR_FLAG_CI_DATA: u32 = 1 << 1;
pub const DRR_FLAG_FREERECORDS: u32 = 1 << 2;
pub const DRR_FLAG_SPILL_BLOCK: u32 = 1 << 3;
pub const DRR_BEGIN_FLAGS_MASK: u32 =
    DRR_FLAG_CLONE | DRR_FLAG_CI_DATA | DRR_FLAG_FREERECORDS | DRR_FLAG_SPILL_BLOCK;

/// Per-record `drr_flags` bit constants (`DRR_WRITE`, `DRR_OBJECT`, `DRR_SPILL`, `DRR_OBJECT_RANGE`).
pub const DRR_CHECKSUM_DEDUP: u8 = 1 << 0;
pub const DRR_RAW_BYTESWAP: u8 = 1 << 1;
pub const DRR_OBJECT_SPILL: u8 = 1 << 2;
pub const DRR_SPILL_UNMODIFIED: u8 = 1 << 2;

/// `DMU_BACKUP_FEATURE_*` bit positions (unshifted; shifted `<< 2` inside `drr_versioninfo`).
pub const DMU_BACKUP_FEATURE_DEDUP: u64 = 1 << 0;
pub const DMU_BACKUP_FEATURE_DEDUPPROPS: u64 = 1 << 1;
pub const DMU_BACKUP_FEATURE_SA_SPILL: u64 = 1 << 2;
pub const DMU_BACKUP_FEATURE_EMBED_DATA: u64 = 1 << 16;
pub const DMU_BACKUP_FEATURE_LZ4: u64 = 1 << 17;
pub const DMU_BACKUP_FEATURE_LARGE_BLOCKS: u64 = 1 << 19;
pub const DMU_BACKUP_FEATURE_RESUMING: u64 = 1 << 20;
pub const DMU_BACKUP_FEATURE_REDACTED: u64 = 1 << 21;
pub const DMU_BACKUP_FEATURE_COMPRESSED: u64 = 1 << 22;
pub const DMU_BACKUP_FEATURE_LARGE_DNODE: u64 = 1 << 23;
pub const DMU_BACKUP_FEATURE_RAW: u64 = 1 << 24;
pub const DMU_BACKUP_FEATURE_ZSTD: u64 = 1 << 25;
pub const DMU_BACKUP_FEATURE_HOLDS: u64 = 1 << 26;
pub const DMU_BACKUP_FEATURE_SWITCH_TO_LARGE_BLOCKS: u64 = 1 << 27;
pub const DMU_BACKUP_FEATURE_LONGNAME: u64 = 1 << 28;
pub const DMU_BACKUP_FEATURE_LARGE_MICROZAP: u64 = 1 << 29;

/// Exact admitted feature mask for FrankenFS native receive.
/// Any bit outside this mask (`DEDUP`, `DEDUPPROPS`, `REDACTED`, `HOLDS`,
/// `LONGNAME`, `LARGE_MICROZAP`, reserved bit 18, or future unknown bits)
/// MUST fail closed.
pub const ADMITTED_SEND_FEATURES_MASK: u64 = DMU_BACKUP_FEATURE_SA_SPILL
    | DMU_BACKUP_FEATURE_EMBED_DATA
    | DMU_BACKUP_FEATURE_LZ4
    | DMU_BACKUP_FEATURE_LARGE_BLOCKS
    | DMU_BACKUP_FEATURE_RESUMING
    | DMU_BACKUP_FEATURE_COMPRESSED
    | DMU_BACKUP_FEATURE_LARGE_DNODE
    | DMU_BACKUP_FEATURE_RAW
    | DMU_BACKUP_FEATURE_ZSTD
    | DMU_BACKUP_FEATURE_SWITCH_TO_LARGE_BLOCKS;

/// `drr_versioninfo` header type (`vi & 0x3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamHeaderType {
    Substream = 1,
    CompoundStream = 2,
}

impl StreamHeaderType {
    pub fn from_raw(raw: u64) -> Result<Self, ParseError> {
        match raw {
            1 => Ok(Self::Substream),
            2 => Ok(Self::CompoundStream),
            _ => Err(invalid("unsupported DMU stream header type")),
        }
    }
}

/// Typed wrapper around `DMU_BACKUP_FEATURE_*` feature bits (unshifted 56-bit space).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendFeatureFlags(u64);

impl SendFeatureFlags {
    pub const EMPTY: Self = Self(0);

    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, flag: u64) -> bool {
        (self.0 & flag) == flag
    }

    #[must_use]
    pub const fn with(self, flag: u64) -> Self {
        Self(self.0 | flag)
    }

    /// Return the subset of bits NOT admitted by FrankenFS native receive.
    #[must_use]
    pub const fn unsupported_bits(self) -> u64 {
        self.0 & !ADMITTED_SEND_FEATURES_MASK
    }

    /// Pack `(hdr_type, features)` into OpenZFS `drr_versioninfo`.
    pub fn pack_versioninfo(self, hdr_type: StreamHeaderType) -> Result<u64, ParseError> {
        if self.0 >> 56 != 0 {
            return Err(invalid("DMU send feature bitfield exceeds 56 bits"));
        }
        Ok((self.0 << 2) | (hdr_type as u64))
    }

    /// Unpack OpenZFS `drr_versioninfo` into `(hdr_type, features)`.
    pub fn unpack_versioninfo(vi: u64) -> Result<(StreamHeaderType, Self), ParseError> {
        if vi >> 58 != 0 {
            return Err(invalid("reserved high bits set in drr_versioninfo"));
        }
        let hdr_type = StreamHeaderType::from_raw(vi & 0x3)?;
        let features = Self((vi >> 2) & ((1_u64 << 56) - 1));
        Ok((hdr_type, features))
    }
}

/// `dmu_replay_record.drr_type` (`u32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DrrType {
    Begin = 0,
    Object = 1,
    FreeObjects = 2,
    Write = 3,
    Free = 4,
    End = 5,
    WriteByref = 6,
    Spill = 7,
    WriteEmbedded = 8,
    ObjectRange = 9,
    Redact = 10,
}

impl DrrType {
    pub fn from_raw(raw: u32) -> Result<Self, ParseError> {
        match raw {
            0 => Ok(Self::Begin),
            1 => Ok(Self::Object),
            2 => Ok(Self::FreeObjects),
            3 => Ok(Self::Write),
            4 => Ok(Self::Free),
            5 => Ok(Self::End),
            6 => Ok(Self::WriteByref),
            7 => Ok(Self::Spill),
            8 => Ok(Self::WriteEmbedded),
            9 => Ok(Self::ObjectRange),
            10 => Ok(Self::Redact),
            _ => Err(invalid("unknown DMU replay record type")),
        }
    }
}

/// Detect stream byte order from the first 312-byte `DRR_BEGIN` header (`drr_magic` at `[8..16]`).
pub fn detect_stream_endian(
    begin_header: &[u8; DMU_REPLAY_RECORD_BYTES],
) -> Result<Endian, ParseError> {
    let magic_bytes: [u8; 8] = [
        begin_header[8],
        begin_header[9],
        begin_header[10],
        begin_header[11],
        begin_header[12],
        begin_header[13],
        begin_header[14],
        begin_header[15],
    ];
    if u64::from_le_bytes(magic_bytes) == DMU_BACKUP_MAGIC {
        Ok(Endian::Little)
    } else if u64::from_be_bytes(magic_bytes) == DMU_BACKUP_MAGIC {
        Ok(Endian::Big)
    } else {
        Err(invalid("invalid DMU_BACKUP_MAGIC in DRR_BEGIN"))
    }
}

/// Incremental Fletcher4 rolling checksum over a `DMU_SUBSTREAM` matching
/// OpenZFS `dmu_send.c:dump_record`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fletcher4Stream {
    state: [u64; 4],
    order: Endian,
}

impl Fletcher4Stream {
    #[must_use]
    pub const fn new(order: Endian) -> Self {
        Self {
            state: [0; 4],
            order,
        }
    }

    #[must_use]
    pub const fn state(&self) -> [u64; 4] {
        self.state
    }

    #[must_use]
    pub const fn order(&self) -> Endian {
        self.order
    }

    /// Update the rolling Fletcher4 state over a 4-byte-aligned byte slice.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), ParseError> {
        if !bytes.len().is_multiple_of(4) {
            return Err(invalid("unaligned Fletcher4 stream update"));
        }
        for chunk in bytes.chunks_exact(4) {
            let raw = [chunk[0], chunk[1], chunk[2], chunk[3]];
            let word = match self.order {
                Endian::Little => u32::from_le_bytes(raw),
                Endian::Big => u32::from_be_bytes(raw),
            };
            self.state[0] = self.state[0].wrapping_add(u64::from(word));
            self.state[1] = self.state[1].wrapping_add(self.state[0]);
            self.state[2] = self.state[2].wrapping_add(self.state[1]);
            self.state[3] = self.state[3].wrapping_add(self.state[2]);
        }
        Ok(())
    }

    /// Stamp a substream record header in place and advance the rolling state over
    /// the entire record (header + trailing payload).
    ///
    /// Exact OpenZFS `dmu_send.c:dump_record` order:
    /// - `DRR_BEGIN`: update all 312 header bytes (preserving `drr_toname` tail), then payload.
    /// - `DRR_END`: write prior `state` into `header[8..40]`, update `header[0..280]`,
    ///   write new `state` into `header[280..312]`, update `header[280..312]`.
    /// - All other records: clear `header[280..312]`, update `header[0..280]`,
    ///   write `state` into `header[280..312]`, update `header[280..312]`, then payload.
    pub fn stamp_record(
        &mut self,
        header: &mut [u8; DMU_REPLAY_RECORD_BYTES],
        payload: &[u8],
        record_type: DrrType,
    ) -> Result<(), ParseError> {
        if record_type == DrrType::Begin {
            self.update(header)?;
            return self.update(payload);
        }
        if record_type == DrrType::End {
            let end_cksum = self.state;
            for (idx, word) in end_cksum.iter().enumerate() {
                let off = 8 + idx * 8;
                header[off..off + 8].copy_from_slice(&self.order.encode(*word));
            }
        }
        header[DRR_CHECKSUM_OFFSET..DMU_REPLAY_RECORD_BYTES].fill(0);
        self.update(&header[..DRR_CHECKSUM_OFFSET])?;
        let trailer = self.state;
        for (idx, word) in trailer.iter().enumerate() {
            let off = DRR_CHECKSUM_OFFSET + idx * 8;
            header[off..off + 8].copy_from_slice(&self.order.encode(*word));
        }
        self.update(&header[DRR_CHECKSUM_OFFSET..DMU_REPLAY_RECORD_BYTES])?;
        self.update(payload)
    }

    /// Verify an incoming substream record header and advance rolling state over
    /// the header + payload.
    ///
    /// On `DRR_END`, verifies BOTH the per-record checksum at `[280..312]` AND
    /// the stream-wide checksum at `drr_end.drr_checksum` (`[8..40]`).
    pub fn verify_record(
        &mut self,
        header: &[u8; DMU_REPLAY_RECORD_BYTES],
        payload: &[u8],
        record_type: DrrType,
        require_per_record_cksum: bool,
    ) -> Result<(), ParseError> {
        if record_type == DrrType::Begin {
            self.update(header)?;
            return self.update(payload);
        }
        let pre_record_state = self.state;
        self.update(&header[..DRR_CHECKSUM_OFFSET])?;
        let embedded = read_cksum4(header, DRR_CHECKSUM_OFFSET, self.order)?;
        if embedded != [0; 4] || require_per_record_cksum {
            if embedded != self.state {
                return Err(invalid(
                    "DMU send stream per-record Fletcher4 checksum mismatch",
                ));
            }
        }
        if record_type == DrrType::End {
            let end_cksum = read_cksum4(header, 8, self.order)?;
            if end_cksum != pre_record_state {
                return Err(invalid(
                    "DMU send stream DRR_END Fletcher4 checksum mismatch",
                ));
            }
        }
        self.update(&header[DRR_CHECKSUM_OFFSET..DMU_REPLAY_RECORD_BYTES])?;
        self.update(payload)
    }
}

/// Compute OpenZFS `fletcher_4_native_varsize` (`chunks_exact(4)`, little-endian)
/// matching `libzfs_dataset.c:get_receive_resume_token` and OpenZFS Issue #10517.
#[must_use]
pub fn fletcher4_varsize_le(bytes: &[u8]) -> [u64; 4] {
    let mut sum = [0_u64; 4];
    for chunk in bytes.chunks_exact(4) {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        sum[0] = sum[0].wrapping_add(u64::from(word));
        sum[1] = sum[1].wrapping_add(sum[0]);
        sum[2] = sum[2].wrapping_add(sum[1]);
        sum[3] = sum[3].wrapping_add(sum[2]);
    }
    sum
}

// ── Record Structs ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrrBegin {
    pub magic: u64,
    pub hdr_type: StreamHeaderType,
    pub features: SendFeatureFlags,
    pub creation_time: u64,
    pub objset_type: u32,
    pub flags: u32,
    pub toguid: u64,
    pub fromguid: u64,
    /// Raw NUL-stripped `drr_toname` bytes (up to 255 bytes). Never trusted as a host path.
    pub toname: Vec<u8>,
    pub payload_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrrObject {
    pub object: u64,
    pub object_type: u32,
    pub bonus_type: u32,
    pub blksz: u32,
    pub bonuslen: u32,
    pub checksumtype: u8,
    pub compress: u8,
    pub dn_slots: u8,
    pub flags: u8,
    pub raw_bonuslen: u32,
    pub toguid: u64,
    pub indblkshift: u8,
    pub nlevels: u8,
    pub nblkptr: u8,
    pub maxblkid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrFreeObjects {
    pub firstobj: u64,
    pub numobjs: u64,
    pub toguid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrWrite {
    pub object: u64,
    pub object_type: u32,
    pub offset: u64,
    pub logical_size: u64,
    pub toguid: u64,
    pub checksumtype: u8,
    pub flags: u8,
    pub compressiontype: u8,
    /// Dedup key (`drr_key`: 32B checksum + 8B prop), preserved verbatim.
    pub ddt_key: [u8; 40],
    pub compressed_size: u64,
    pub salt: [u8; ZIO_DATA_SALT_LEN],
    pub iv: [u8; ZIO_DATA_IV_LEN],
    pub mac: [u8; ZIO_DATA_MAC_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrFree {
    pub object: u64,
    pub offset: u64,
    pub length: u64,
    pub toguid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrEnd {
    pub checksum: [u64; 4],
    pub toguid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrWriteByref {
    pub object: u64,
    pub offset: u64,
    pub length: u64,
    pub toguid: u64,
    pub refguid: u64,
    pub refobject: u64,
    pub refoffset: u64,
    pub checksumtype: u8,
    pub flags: u8,
    pub ddt_key: [u8; 40],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrSpill {
    pub object: u64,
    pub length: u64,
    pub toguid: u64,
    pub flags: u8,
    pub compressiontype: u8,
    pub compressed_size: u64,
    pub salt: [u8; ZIO_DATA_SALT_LEN],
    pub iv: [u8; ZIO_DATA_IV_LEN],
    pub mac: [u8; ZIO_DATA_MAC_LEN],
    pub object_type: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrWriteEmbedded {
    pub object: u64,
    pub offset: u64,
    pub length: u64,
    pub toguid: u64,
    pub compression: u8,
    pub etype: u8,
    pub lsize: u32,
    pub psize: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrObjectRange {
    pub firstobj: u64,
    pub numslots: u64,
    pub toguid: u64,
    pub salt: [u8; ZIO_DATA_SALT_LEN],
    pub iv: [u8; ZIO_DATA_IV_LEN],
    pub mac: [u8; ZIO_DATA_MAC_LEN],
    pub flags: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrRedact {
    pub object: u64,
    pub offset: u64,
    pub length: u64,
    pub toguid: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrrRecord {
    Begin(DrrBegin),
    Object(DrrObject),
    FreeObjects(DrrFreeObjects),
    Write(DrrWrite),
    Free(DrrFree),
    End(DrrEnd),
    WriteByref(DrrWriteByref),
    Spill(DrrSpill),
    WriteEmbedded(DrrWriteEmbedded),
    ObjectRange(DrrObjectRange),
    Redact(DrrRedact),
}

impl DrrRecord {
    #[must_use]
    pub const fn record_type(&self) -> DrrType {
        match self {
            Self::Begin(_) => DrrType::Begin,
            Self::Object(_) => DrrType::Object,
            Self::FreeObjects(_) => DrrType::FreeObjects,
            Self::Write(_) => DrrType::Write,
            Self::Free(_) => DrrType::Free,
            Self::End(_) => DrrType::End,
            Self::WriteByref(_) => DrrType::WriteByref,
            Self::Spill(_) => DrrType::Spill,
            Self::WriteEmbedded(_) => DrrType::WriteEmbedded,
            Self::ObjectRange(_) => DrrType::ObjectRange,
            Self::Redact(_) => DrrType::Redact,
        }
    }

    /// Exact bounded trailing payload length expected immediately after this 312-byte header.
    pub fn expected_payload_len(&self, raw_stream: bool) -> Result<usize, ParseError> {
        match self {
            Self::Begin(b) => {
                let len = usize::try_from(b.payload_len)
                    .map_err(|_| invalid("DRR_BEGIN payload length overflow"))?;
                if len > MAX_BEGIN_NVLIST_BYTES {
                    return Err(invalid("DRR_BEGIN nvlist payload exceeds 4 MiB bound"));
                }
                if !len.is_multiple_of(4) {
                    return Err(invalid("DRR_BEGIN nvlist payload is not 4-byte aligned"));
                }
                Ok(len)
            }
            Self::Object(o) => {
                let effective = if raw_stream && o.raw_bonuslen > 0 {
                    o.raw_bonuslen
                } else {
                    o.bonuslen
                };
                let len = usize::try_from(effective)
                    .map_err(|_| invalid("DRR_OBJECT bonus length overflow"))?;
                if len > MAX_OBJECT_BONUS_BYTES {
                    return Err(invalid("DRR_OBJECT bonus length exceeds 16 KiB bound"));
                }
                Ok(len.next_multiple_of(8))
            }
            Self::Write(w) => {
                let raw_len = if w.compressiontype != 0 {
                    w.compressed_size
                } else {
                    w.logical_size
                };
                let len = usize::try_from(raw_len)
                    .map_err(|_| invalid("DRR_WRITE payload length overflow"))?;
                if len == 0 || len > MAX_BLOCK_BYTES {
                    return Err(invalid("DRR_WRITE payload length out of bounds"));
                }
                if !len.is_multiple_of(4) {
                    return Err(invalid("DRR_WRITE payload length is not 4-byte aligned"));
                }
                Ok(len)
            }
            Self::Spill(s) => {
                let raw_len = if s.compressiontype != 0 {
                    s.compressed_size
                } else {
                    s.length
                };
                let len = usize::try_from(raw_len)
                    .map_err(|_| invalid("DRR_SPILL payload length overflow"))?;
                if len == 0 || len > MAX_BLOCK_BYTES {
                    return Err(invalid("DRR_SPILL payload length out of bounds"));
                }
                if !len.is_multiple_of(4) {
                    return Err(invalid("DRR_SPILL payload length is not 4-byte aligned"));
                }
                Ok(len)
            }
            Self::WriteEmbedded(e) => {
                let psize = usize::try_from(e.psize)
                    .map_err(|_| invalid("DRR_WRITE_EMBEDDED psize overflow"))?;
                if psize == 0 || psize > EMBEDDED_PAYLOAD_BYTES {
                    return Err(invalid("DRR_WRITE_EMBEDDED psize exceeds 112-byte limit"));
                }
                Ok(psize.next_multiple_of(8))
            }
            Self::FreeObjects(_)
            | Self::Free(_)
            | Self::End(_)
            | Self::WriteByref(_)
            | Self::ObjectRange(_)
            | Self::Redact(_) => Ok(0),
        }
    }

    /// Parse one 312-byte `dmu_replay_record_t` header in `order`, returning the
    /// parsed record and the embedded trailer checksum (`[280..312]`, zero for `DRR_BEGIN`).
    pub fn parse_header(
        raw: &[u8; DMU_REPLAY_RECORD_BYTES],
        order: Endian,
    ) -> Result<(Self, [u64; 4]), ParseError> {
        let rtype = DrrType::from_raw(read_u32(raw, 0, order))?;
        let payload_len = read_u32(raw, 4, order);
        let trailer = if rtype == DrrType::Begin {
            [0; 4]
        } else {
            read_cksum4(raw, DRR_CHECKSUM_OFFSET, order)?
        };

        let rec = match rtype {
            DrrType::Begin => {
                let magic = order.u64(raw, 8)?;
                if magic != DMU_BACKUP_MAGIC {
                    return Err(invalid("invalid DMU_BACKUP_MAGIC in DRR_BEGIN"));
                }
                let vi = order.u64(raw, 16)?;
                let (hdr_type, features) = SendFeatureFlags::unpack_versioninfo(vi)?;
                let creation_time = order.u64(raw, 24)?;
                let objset_type = read_u32(raw, 32, order);
                let flags = read_u32(raw, 36, order);
                if flags & !DRR_BEGIN_FLAGS_MASK != 0 {
                    return Err(invalid("unknown flags in DRR_BEGIN"));
                }
                let toguid = order.u64(raw, 40)?;
                let fromguid = order.u64(raw, 48)?;
                let name_field = &raw[56..312];
                let nul_pos = name_field
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or_else(|| invalid("DRR_BEGIN drr_toname is not NUL-terminated"))?;
                Self::Begin(DrrBegin {
                    magic,
                    hdr_type,
                    features,
                    creation_time,
                    objset_type,
                    flags,
                    toguid,
                    fromguid,
                    toname: name_field[..nul_pos].to_vec(),
                    payload_len,
                })
            }
            DrrType::Object => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_OBJECT"));
                }
                let object = order.u64(raw, 8)?;
                let object_type = read_u32(raw, 16, order);
                let bonus_type = read_u32(raw, 20, order);
                let blksz = read_u32(raw, 24, order);
                let bonuslen = read_u32(raw, 28, order);
                let checksumtype = raw[32];
                let compress = raw[33];
                let dn_slots = raw[34];
                let flags = raw[35];
                let raw_bonuslen = read_u32(raw, 36, order);
                let toguid = order.u64(raw, 40)?;
                let indblkshift = raw[48];
                let nlevels = raw[49];
                let nblkptr = raw[50];
                let maxblkid = order.u64(raw, 56)?;
                Self::Object(DrrObject {
                    object,
                    object_type,
                    bonus_type,
                    blksz,
                    bonuslen,
                    checksumtype,
                    compress,
                    dn_slots,
                    flags,
                    raw_bonuslen,
                    toguid,
                    indblkshift,
                    nlevels,
                    nblkptr,
                    maxblkid,
                })
            }
            DrrType::FreeObjects => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_FREEOBJECTS"));
                }
                Self::FreeObjects(DrrFreeObjects {
                    firstobj: order.u64(raw, 8)?,
                    numobjs: order.u64(raw, 16)?,
                    toguid: order.u64(raw, 24)?,
                })
            }
            DrrType::Write => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_WRITE"));
                }
                let mut ddt_key = [0_u8; 40];
                ddt_key.copy_from_slice(&raw[56..96]);
                let mut salt = [0_u8; ZIO_DATA_SALT_LEN];
                salt.copy_from_slice(&raw[104..112]);
                let mut iv = [0_u8; ZIO_DATA_IV_LEN];
                iv.copy_from_slice(&raw[112..124]);
                let mut mac = [0_u8; ZIO_DATA_MAC_LEN];
                mac.copy_from_slice(&raw[124..140]);
                Self::Write(DrrWrite {
                    object: order.u64(raw, 8)?,
                    object_type: read_u32(raw, 16, order),
                    offset: order.u64(raw, 24)?,
                    logical_size: order.u64(raw, 32)?,
                    toguid: order.u64(raw, 40)?,
                    checksumtype: raw[48],
                    flags: raw[49],
                    compressiontype: raw[50],
                    ddt_key,
                    compressed_size: order.u64(raw, 96)?,
                    salt,
                    iv,
                    mac,
                })
            }
            DrrType::Free => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_FREE"));
                }
                Self::Free(DrrFree {
                    object: order.u64(raw, 8)?,
                    offset: order.u64(raw, 16)?,
                    length: order.u64(raw, 24)?,
                    toguid: order.u64(raw, 32)?,
                })
            }
            DrrType::End => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_END"));
                }
                Self::End(DrrEnd {
                    checksum: read_cksum4(raw, 8, order)?,
                    toguid: order.u64(raw, 40)?,
                })
            }
            DrrType::WriteByref => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_WRITE_BYREF"));
                }
                let mut ddt_key = [0_u8; 40];
                ddt_key.copy_from_slice(&raw[72..112]);
                Self::WriteByref(DrrWriteByref {
                    object: order.u64(raw, 8)?,
                    offset: order.u64(raw, 16)?,
                    length: order.u64(raw, 24)?,
                    toguid: order.u64(raw, 32)?,
                    refguid: order.u64(raw, 40)?,
                    refobject: order.u64(raw, 48)?,
                    refoffset: order.u64(raw, 56)?,
                    checksumtype: raw[64],
                    flags: raw[65],
                    ddt_key,
                })
            }
            DrrType::Spill => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_SPILL"));
                }
                let mut salt = [0_u8; ZIO_DATA_SALT_LEN];
                salt.copy_from_slice(&raw[48..56]);
                let mut iv = [0_u8; ZIO_DATA_IV_LEN];
                iv.copy_from_slice(&raw[56..68]);
                let mut mac = [0_u8; ZIO_DATA_MAC_LEN];
                mac.copy_from_slice(&raw[68..84]);
                Self::Spill(DrrSpill {
                    object: order.u64(raw, 8)?,
                    length: order.u64(raw, 16)?,
                    toguid: order.u64(raw, 24)?,
                    flags: raw[32],
                    compressiontype: raw[33],
                    compressed_size: order.u64(raw, 40)?,
                    salt,
                    iv,
                    mac,
                    object_type: read_u32(raw, 84, order),
                })
            }
            DrrType::WriteEmbedded => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_WRITE_EMBEDDED"));
                }
                Self::WriteEmbedded(DrrWriteEmbedded {
                    object: order.u64(raw, 8)?,
                    offset: order.u64(raw, 16)?,
                    length: order.u64(raw, 24)?,
                    toguid: order.u64(raw, 32)?,
                    compression: raw[40],
                    etype: raw[41],
                    lsize: read_u32(raw, 48, order),
                    psize: read_u32(raw, 52, order),
                })
            }
            DrrType::ObjectRange => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_OBJECT_RANGE"));
                }
                let firstobj = order.u64(raw, 8)?;
                let numslots = order.u64(raw, 16)?;
                if firstobj % 32 != 0 || numslots == 0 || numslots % 32 != 0 {
                    return Err(invalid(
                        "DRR_OBJECT_RANGE firstobj and numslots must be 32-slot aligned",
                    ));
                }
                let mut salt = [0_u8; ZIO_DATA_SALT_LEN];
                salt.copy_from_slice(&raw[32..40]);
                let mut iv = [0_u8; ZIO_DATA_IV_LEN];
                iv.copy_from_slice(&raw[40..52]);
                let mut mac = [0_u8; ZIO_DATA_MAC_LEN];
                mac.copy_from_slice(&raw[52..68]);
                Self::ObjectRange(DrrObjectRange {
                    firstobj,
                    numslots,
                    toguid: order.u64(raw, 24)?,
                    salt,
                    iv,
                    mac,
                    flags: raw[68],
                })
            }
            DrrType::Redact => {
                if payload_len != 0 {
                    return Err(invalid("nonzero drr_payloadlen on DRR_REDACT"));
                }
                Self::Redact(DrrRedact {
                    object: order.u64(raw, 8)?,
                    offset: order.u64(raw, 16)?,
                    length: order.u64(raw, 24)?,
                    toguid: order.u64(raw, 32)?,
                })
            }
        };

        Ok((rec, trailer))
    }

    /// Encode this record into a 312-byte header (leaving `[280..312]` zero for
    /// `Fletcher4Stream::stamp_record` on non-`DRR_BEGIN` records).
    pub fn encode_header(
        &self,
        order: Endian,
    ) -> Result<[u8; DMU_REPLAY_RECORD_BYTES], ParseError> {
        let mut out = [0_u8; DMU_REPLAY_RECORD_BYTES];
        write_u32(&mut out, 0, self.record_type() as u32, order);
        match self {
            Self::Begin(b) => {
                if b.toname.len() >= 256 || b.toname.contains(&0) {
                    return Err(invalid("DRR_BEGIN drr_toname invalid or >= 256 bytes"));
                }
                if b.flags & !DRR_BEGIN_FLAGS_MASK != 0 {
                    return Err(invalid("unknown flags in DRR_BEGIN"));
                }
                write_u32(&mut out, 4, b.payload_len, order);
                write_u64(&mut out, 8, b.magic, order);
                write_u64(
                    &mut out,
                    16,
                    b.features.pack_versioninfo(b.hdr_type)?,
                    order,
                );
                write_u64(&mut out, 24, b.creation_time, order);
                write_u32(&mut out, 32, b.objset_type, order);
                write_u32(&mut out, 36, b.flags, order);
                write_u64(&mut out, 40, b.toguid, order);
                write_u64(&mut out, 48, b.fromguid, order);
                out[56..56 + b.toname.len()].copy_from_slice(&b.toname);
            }
            Self::Object(o) => {
                write_u64(&mut out, 8, o.object, order);
                write_u32(&mut out, 16, o.object_type, order);
                write_u32(&mut out, 20, o.bonus_type, order);
                write_u32(&mut out, 24, o.blksz, order);
                write_u32(&mut out, 28, o.bonuslen, order);
                out[32] = o.checksumtype;
                out[33] = o.compress;
                out[34] = o.dn_slots;
                out[35] = o.flags;
                write_u32(&mut out, 36, o.raw_bonuslen, order);
                write_u64(&mut out, 40, o.toguid, order);
                out[48] = o.indblkshift;
                out[49] = o.nlevels;
                out[50] = o.nblkptr;
                write_u64(&mut out, 56, o.maxblkid, order);
            }
            Self::FreeObjects(f) => {
                write_u64(&mut out, 8, f.firstobj, order);
                write_u64(&mut out, 16, f.numobjs, order);
                write_u64(&mut out, 24, f.toguid, order);
            }
            Self::Write(w) => {
                write_u64(&mut out, 8, w.object, order);
                write_u32(&mut out, 16, w.object_type, order);
                write_u64(&mut out, 24, w.offset, order);
                write_u64(&mut out, 32, w.logical_size, order);
                write_u64(&mut out, 40, w.toguid, order);
                out[48] = w.checksumtype;
                out[49] = w.flags;
                out[50] = w.compressiontype;
                out[56..96].copy_from_slice(&w.ddt_key);
                write_u64(&mut out, 96, w.compressed_size, order);
                out[104..112].copy_from_slice(&w.salt);
                out[112..124].copy_from_slice(&w.iv);
                out[124..140].copy_from_slice(&w.mac);
            }
            Self::Free(f) => {
                write_u64(&mut out, 8, f.object, order);
                write_u64(&mut out, 16, f.offset, order);
                write_u64(&mut out, 24, f.length, order);
                write_u64(&mut out, 32, f.toguid, order);
            }
            Self::End(e) => {
                for (idx, word) in e.checksum.iter().enumerate() {
                    write_u64(&mut out, 8 + idx * 8, *word, order);
                }
                write_u64(&mut out, 40, e.toguid, order);
            }
            Self::WriteByref(w) => {
                write_u64(&mut out, 8, w.object, order);
                write_u64(&mut out, 16, w.offset, order);
                write_u64(&mut out, 24, w.length, order);
                write_u64(&mut out, 32, w.toguid, order);
                write_u64(&mut out, 40, w.refguid, order);
                write_u64(&mut out, 48, w.refobject, order);
                write_u64(&mut out, 56, w.refoffset, order);
                out[64] = w.checksumtype;
                out[65] = w.flags;
                out[72..112].copy_from_slice(&w.ddt_key);
            }
            Self::Spill(s) => {
                write_u64(&mut out, 8, s.object, order);
                write_u64(&mut out, 16, s.length, order);
                write_u64(&mut out, 24, s.toguid, order);
                out[32] = s.flags;
                out[33] = s.compressiontype;
                write_u64(&mut out, 40, s.compressed_size, order);
                out[48..56].copy_from_slice(&s.salt);
                out[56..68].copy_from_slice(&s.iv);
                out[68..84].copy_from_slice(&s.mac);
                write_u32(&mut out, 84, s.object_type, order);
            }
            Self::WriteEmbedded(e) => {
                write_u64(&mut out, 8, e.object, order);
                write_u64(&mut out, 16, e.offset, order);
                write_u64(&mut out, 24, e.length, order);
                write_u64(&mut out, 32, e.toguid, order);
                out[40] = e.compression;
                out[41] = e.etype;
                write_u32(&mut out, 48, e.lsize, order);
                write_u32(&mut out, 52, e.psize, order);
            }
            Self::ObjectRange(r) => {
                if r.firstobj % 32 != 0 || r.numslots == 0 || r.numslots % 32 != 0 {
                    return Err(invalid(
                        "DRR_OBJECT_RANGE firstobj and numslots must be 32-slot aligned",
                    ));
                }
                write_u64(&mut out, 8, r.firstobj, order);
                write_u64(&mut out, 16, r.numslots, order);
                write_u64(&mut out, 24, r.toguid, order);
                out[32..40].copy_from_slice(&r.salt);
                out[40..52].copy_from_slice(&r.iv);
                out[52..68].copy_from_slice(&r.mac);
                out[68] = r.flags;
            }
            Self::Redact(r) => {
                write_u64(&mut out, 8, r.object, order);
                write_u64(&mut out, 16, r.offset, order);
                write_u64(&mut out, 24, r.length, order);
                write_u64(&mut out, 32, r.toguid, order);
            }
        }
        Ok(out)
    }
}

/// Extract and validate the snapshot suffix after `@` from `drr_toname` without
/// ever interpreting `drr_toname` as a host filesystem path.
pub fn validate_toname_snapshot(toname: &[u8]) -> Result<Vec<u8>, ParseError> {
    let Some(at_pos) = toname.iter().rposition(|&b| b == b'@') else {
        return Err(invalid("DRR_BEGIN drr_toname lacks '@snapshot' component"));
    };
    let snap = &toname[at_pos + 1..];
    if snap.is_empty()
        || snap.len() > 255
        || matches!(snap, b"." | b"..")
        || snap
            .iter()
            .any(|&b| matches!(b, 0 | b'/' | b'@' | b'#' | b'\\') || b < 0x20 || b == 0x7f)
    {
        return Err(invalid("DRR_BEGIN snapshot component is invalid"));
    }
    Ok(snap.to_vec())
}

// ── Raw Encrypted `crypt_keydata` XDR Payload ───────────────────────────────

/// Wrapped encryption key & IV-set payload carried inside raw encrypted (`-w`)
/// `DRR_BEGIN` XDR nvlists (`crypt_keydata`, `to_ivset_guid`, `from_ivset_guid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCryptoKeydata {
    pub suite: ZioEncrypt,
    pub version: u64,
    pub guid: u64,
    pub keyformat: ZfsKeyFormat,
    pub pbkdf2_salt: u64,
    pub pbkdf2_iters: u64,
    pub iv: [u8; ZIO_DATA_IV_LEN],
    pub mac: [u8; ZIO_DATA_MAC_LEN],
    pub wrapped_master_key: Vec<u8>,
    pub wrapped_hmac_key: [u8; 64],
    pub portable_mac: [u8; 32],
    pub to_ivset_guid: u64,
    pub from_ivset_guid: Option<u64>,
}

impl StreamCryptoKeydata {
    /// Encode into an OpenZFS-compatible `NvList` containing `crypt_keydata`,
    /// `to_ivset_guid`, optional `from_ivset_guid`, and `portable_mac`.
    pub fn to_nvlist(&self) -> Result<NvList, ParseError> {
        if self.wrapped_master_key.len() != self.suite.key_len() {
            return Err(invalid("wrapped master key length mismatches cipher suite"));
        }
        let mut kd = BTreeMap::new();
        kd.insert(
            "DSL_CRYPTO_SUITE".to_owned(),
            Value::Unsigned(self.suite as u64),
        );
        kd.insert(
            "DSL_CRYPTO_VERSION".to_owned(),
            Value::Unsigned(self.version),
        );
        kd.insert("DSL_CRYPTO_GUID".to_owned(), Value::Unsigned(self.guid));
        kd.insert(
            "keyformat".to_owned(),
            Value::Unsigned(self.keyformat as u64),
        );
        kd.insert("pbkdf2salt".to_owned(), Value::Unsigned(self.pbkdf2_salt));
        kd.insert("pbkdf2iters".to_owned(), Value::Unsigned(self.pbkdf2_iters));
        kd.insert("DSL_CRYPTO_IV".to_owned(), Value::Bytes(self.iv.to_vec()));
        kd.insert("DSL_CRYPTO_MAC".to_owned(), Value::Bytes(self.mac.to_vec()));
        kd.insert(
            "DSL_CRYPTO_MASTER_KEY_1".to_owned(),
            Value::Bytes(self.wrapped_master_key.clone()),
        );
        kd.insert(
            "DSL_CRYPTO_HMAC_KEY_1".to_owned(),
            Value::Bytes(self.wrapped_hmac_key.to_vec()),
        );
        kd.insert(
            "portable_mac".to_owned(),
            Value::Bytes(self.portable_mac.to_vec()),
        );

        let mut root = BTreeMap::new();
        root.insert(
            "crypt_keydata".to_owned(),
            Value::List(NvList { fields: kd }),
        );
        root.insert(
            "to_ivset_guid".to_owned(),
            Value::Unsigned(self.to_ivset_guid),
        );
        if let Some(from_ivset) = self.from_ivset_guid {
            root.insert("from_ivset_guid".to_owned(), Value::Unsigned(from_ivset));
        }
        Ok(NvList { fields: root })
    }

    /// Decode `crypt_keydata` + IV-set metadata from a `DRR_BEGIN` XDR nvlist.
    pub fn from_nvlist(root: &NvList) -> Result<Self, ParseError> {
        let kd = root
            .list("crypt_keydata")
            .ok_or_else(|| invalid("raw encrypted DRR_BEGIN missing crypt_keydata"))?;
        let suite_raw = kd
            .unsigned("DSL_CRYPTO_SUITE")
            .ok_or_else(|| invalid("crypt_keydata missing DSL_CRYPTO_SUITE"))?;
        let suite = ZioEncrypt::from_raw(suite_raw)?;
        if !suite.is_active() {
            return Err(invalid("crypt_keydata suite is not an active cipher"));
        }
        let version = kd.unsigned("DSL_CRYPTO_VERSION").unwrap_or(1);
        let guid = kd
            .unsigned("DSL_CRYPTO_GUID")
            .ok_or_else(|| invalid("crypt_keydata missing DSL_CRYPTO_GUID"))?;
        let keyformat_raw = kd
            .unsigned("keyformat")
            .ok_or_else(|| invalid("crypt_keydata missing keyformat"))?;
        let keyformat = ZfsKeyFormat::from_raw(keyformat_raw)?;
        let pbkdf2_salt = kd.unsigned("pbkdf2salt").unwrap_or(0);
        let pbkdf2_iters = kd.unsigned("pbkdf2iters").unwrap_or(0);
        let iv_bytes = nv_bytes(kd, "DSL_CRYPTO_IV")?;
        let iv: [u8; ZIO_DATA_IV_LEN] = iv_bytes
            .try_into()
            .map_err(|_| invalid("crypt_keydata DSL_CRYPTO_IV must be 12 bytes"))?;
        let mac_bytes = nv_bytes(kd, "DSL_CRYPTO_MAC")?;
        let mac: [u8; ZIO_DATA_MAC_LEN] = mac_bytes
            .try_into()
            .map_err(|_| invalid("crypt_keydata DSL_CRYPTO_MAC must be 16 bytes"))?;
        let wrapped_master_key = nv_bytes(kd, "DSL_CRYPTO_MASTER_KEY_1")?.to_vec();
        if wrapped_master_key.len() != suite.key_len() {
            return Err(invalid(
                "crypt_keydata wrapped master key length mismatches cipher suite",
            ));
        }
        let hmac_bytes = nv_bytes(kd, "DSL_CRYPTO_HMAC_KEY_1")?;
        let wrapped_hmac_key: [u8; 64] = hmac_bytes
            .try_into()
            .map_err(|_| invalid("crypt_keydata DSL_CRYPTO_HMAC_KEY_1 must be 64 bytes"))?;
        let portable_mac: [u8; 32] =
            match nv_bytes_opt(kd, "portable_mac").or_else(|| nv_bytes_opt(root, "portable_mac")) {
                Some(bytes) => bytes
                    .try_into()
                    .map_err(|_| invalid("crypt_keydata portable_mac must be 32 bytes"))?,
                None => [0_u8; 32],
            };
        let to_ivset_guid = root
            .unsigned("to_ivset_guid")
            .or_else(|| kd.unsigned("to_ivset_guid"))
            .unwrap_or(0);
        let from_ivset_guid = root
            .unsigned("from_ivset_guid")
            .or_else(|| kd.unsigned("from_ivset_guid"));
        Ok(Self {
            suite,
            version,
            guid,
            keyformat,
            pbkdf2_salt,
            pbkdf2_iters,
            iv,
            mac,
            wrapped_master_key,
            wrapped_hmac_key,
            portable_mac,
            to_ivset_guid,
            from_ivset_guid,
        })
    }
}

// ── `receive_resume_token` Codec ────────────────────────────────────────────

/// OpenZFS Version 1 `receive_resume_token` payload (`1-<cksum>-<len>-<zlib_hex>`).
///
/// Security invariant: `toname` is an informational match label only and NEVER
/// grants host path, device, pool, or key-file authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveResumeToken {
    pub toguid: u64,
    pub fromguid: Option<u64>,
    pub object: u64,
    pub offset: u64,
    pub bytes: u64,
    pub toname: String,
    pub compressok: bool,
    pub embedok: bool,
    pub largeblockok: bool,
    pub rawok: bool,
    pub saved: bool,
    pub ivsetguid: Option<u64>,
}

impl ReceiveResumeToken {
    /// Encode as an OpenZFS v1 `receive_resume_token` ASCII string:
    /// `1-<fletcher4_word0_hex>-<xdr_len_hex>-<zlib_hex>`.
    pub fn encode(&self) -> Result<String, ParseError> {
        if self.toguid == 0 || self.toname.is_empty() || self.toname.as_bytes().contains(&0) {
            return Err(invalid(
                "resume token requires nonzero toguid and valid toname",
            ));
        }
        let mut fields = BTreeMap::new();
        fields.insert("toguid".to_owned(), Value::Unsigned(self.toguid));
        if let Some(fg) = self.fromguid.filter(|&v| v != 0) {
            fields.insert("fromguid".to_owned(), Value::Unsigned(fg));
        }
        fields.insert("object".to_owned(), Value::Unsigned(self.object));
        fields.insert("offset".to_owned(), Value::Unsigned(self.offset));
        fields.insert("bytes".to_owned(), Value::Unsigned(self.bytes));
        fields.insert("toname".to_owned(), Value::String(self.toname.clone()));
        if self.compressok {
            fields.insert("compressok".to_owned(), Value::Boolean(true));
        }
        if self.embedok {
            fields.insert("embedok".to_owned(), Value::Boolean(true));
        }
        if self.largeblockok {
            fields.insert("largeblockok".to_owned(), Value::Boolean(true));
        }
        if self.rawok {
            fields.insert("rawok".to_owned(), Value::Boolean(true));
        }
        if self.saved {
            fields.insert("saved".to_owned(), Value::Boolean(true));
        }
        if let Some(ivg) = self.ivsetguid.filter(|&v| v != 0) {
            fields.insert("ivsetguid".to_owned(), Value::Unsigned(ivg));
        }
        let packed = NvList { fields }.encode_xdr()?;
        if packed.len() > MAX_RESUME_TOKEN_NVLIST_BYTES {
            return Err(invalid("encoded resume token nvlist exceeds 64 KiB bound"));
        }
        let compressed = zlib_compress(&packed)?;
        let cksum = fletcher4_varsize_le(&compressed);
        let hex_payload = hex_encode_lower(&compressed);
        let token = format!(
            "{ZFS_SEND_RESUME_TOKEN_VERSION}-{:x}-{:x}-{hex_payload}",
            cksum[0],
            packed.len()
        );
        if token.len() > MAX_RESUME_TOKEN_CHARS {
            return Err(invalid("encoded resume token exceeds 64 KiB string limit"));
        }
        Ok(token)
    }

    /// Parse and authenticate an OpenZFS v1 `receive_resume_token` ASCII string.
    pub fn parse(token: &str) -> Result<Self, ParseError> {
        let trimmed = token.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_RESUME_TOKEN_CHARS {
            return Err(invalid("resume token is empty or exceeds 64 KiB bound"));
        }
        let mut parts = trimmed.split('-');
        let ver_str = parts
            .next()
            .ok_or_else(|| invalid("resume token missing version"))?;
        let cksum_str = parts
            .next()
            .ok_or_else(|| invalid("resume token missing checksum"))?;
        let len_str = parts
            .next()
            .ok_or_else(|| invalid("resume token missing payload length"))?;
        let hex_str = parts
            .next()
            .ok_or_else(|| invalid("resume token missing compressed payload"))?;
        if parts.next().is_some() {
            return Err(invalid("resume token has unexpected extra '-' segments"));
        }
        let version: u32 = ver_str
            .parse()
            .map_err(|_| invalid("resume token version is not decimal"))?;
        if version != ZFS_SEND_RESUME_TOKEN_VERSION {
            return Err(invalid("unsupported resume token version"));
        }
        let expected_cksum = u64::from_str_radix(cksum_str, 16)
            .map_err(|_| invalid("resume token checksum is not valid hex"))?;
        let expected_len = usize::from_str_radix(len_str, 16)
            .map_err(|_| invalid("resume token uncompressed length is not valid hex"))?;
        if expected_len < 20 || expected_len > MAX_RESUME_TOKEN_NVLIST_BYTES {
            return Err(invalid("resume token uncompressed length out of bounds"));
        }
        let compressed = hex_decode(hex_str)?;
        if compressed.len() < 6 || compressed.len() > MAX_RESUME_TOKEN_NVLIST_BYTES {
            return Err(invalid(
                "resume token compressed payload length out of bounds",
            ));
        }
        let computed = fletcher4_varsize_le(&compressed);
        if computed[0] != expected_cksum {
            return Err(invalid("resume token Fletcher4 checksum mismatch"));
        }
        let unpacked = zlib_decompress_exact(&compressed, expected_len)?;
        let nvl = NvList::parse_exact(&unpacked)?;

        // Fail closed on redaction tokens we do not implement.
        if nv_bool(&nvl, "redactbookok") || nvl.fields.contains_key("redact_snaps") {
            return Err(invalid("redacted resume token is unsupported"));
        }
        let toguid = nvl
            .unsigned("toguid")
            .filter(|&v| v != 0)
            .ok_or_else(|| invalid("resume token missing nonzero toguid"))?;
        let object = nvl
            .unsigned("object")
            .ok_or_else(|| invalid("resume token missing object"))?;
        let offset = nvl
            .unsigned("offset")
            .ok_or_else(|| invalid("resume token missing offset"))?;
        let bytes = nvl
            .unsigned("bytes")
            .ok_or_else(|| invalid("resume token missing bytes"))?;
        let toname = nvl
            .text("toname")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("resume token missing toname"))?
            .to_owned();
        Ok(Self {
            toguid,
            fromguid: nvl.unsigned("fromguid").filter(|&v| v != 0),
            object,
            offset,
            bytes,
            toname,
            compressok: nv_bool(&nvl, "compressok"),
            embedok: nv_bool(&nvl, "embedok"),
            largeblockok: nv_bool(&nvl, "largeblockok"),
            rawok: nv_bool(&nvl, "rawok"),
            saved: nv_bool(&nvl, "saved"),
            ivsetguid: nvl.unsigned("ivsetguid").filter(|&v| v != 0),
        })
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn read_u32(bytes: &[u8], offset: usize, order: Endian) -> u32 {
    let raw = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    match order {
        Endian::Little => u32::from_le_bytes(raw),
        Endian::Big => u32::from_be_bytes(raw),
    }
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32, order: Endian) {
    let raw = match order {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 4].copy_from_slice(&raw);
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64, order: Endian) {
    bytes[offset..offset + 8].copy_from_slice(&order.encode(value));
}

fn read_cksum4(bytes: &[u8], offset: usize, order: Endian) -> Result<[u64; 4], ParseError> {
    Ok([
        order.u64(bytes, offset)?,
        order.u64(bytes, offset + 8)?,
        order.u64(bytes, offset + 16)?,
        order.u64(bytes, offset + 24)?,
    ])
}

fn nv_bytes_opt<'a>(nvl: &'a NvList, key: &str) -> Option<&'a [u8]> {
    match nvl.fields.get(key) {
        Some(Value::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    }
}

fn nv_bytes<'a>(nvl: &'a NvList, key: &str) -> Result<&'a [u8], ParseError> {
    nv_bytes_opt(nvl, key).ok_or_else(|| invalid("missing required byte-array field in nvlist"))
}

fn nv_bool(nvl: &NvList, key: &str) -> bool {
    matches!(nvl.fields.get(key), Some(Value::Boolean(true)))
}

fn zlib_compress(input: &[u8]) -> Result<Vec<u8>, ParseError> {
    let mut comp = Compress::new(Compression::default(), true);
    let mut out = vec![0_u8; input.len().saturating_add(64).max(128)];
    let status = comp
        .compress(input, &mut out, FlushCompress::Finish)
        .map_err(|_| invalid("zlib compression failed for resume token"))?;
    if status != Status::StreamEnd || comp.total_in() as usize != input.len() {
        return Err(invalid(
            "zlib compression did not finish within output bound",
        ));
    }
    let total = usize::try_from(comp.total_out())
        .map_err(|_| invalid("zlib compressed length overflow"))?;
    out.truncate(total);
    Ok(out)
}

fn zlib_decompress_exact(input: &[u8], expected_len: usize) -> Result<Vec<u8>, ParseError> {
    let mut dec = Decompress::new(true);
    let mut out = vec![0_u8; expected_len];
    let status = dec
        .decompress(input, &mut out, FlushDecompress::Finish)
        .map_err(|_| invalid("corrupt zlib payload in resume token"))?;
    if status != Status::StreamEnd
        || dec.total_in() as usize != input.len()
        || dec.total_out() as usize != expected_len
    {
        return Err(invalid(
            "resume token zlib stream size mismatch or trailing bytes",
        ));
    }
    Ok(out)
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, ParseError> {
    if !hex.len().is_multiple_of(2) {
        return Err(invalid("odd-length hex string in resume token"));
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

const fn hex_nibble(b: u8) -> Result<u8, ParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ParseError::InvalidField {
            field: "zfs",
            reason: "non-hex character in resume token",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eleven_drr_records_roundtrip_both_endians() {
        let samples: Vec<DrrRecord> = vec![
            DrrRecord::Begin(DrrBegin {
                magic: DMU_BACKUP_MAGIC,
                hdr_type: StreamHeaderType::Substream,
                features: SendFeatureFlags::EMPTY
                    .with(DMU_BACKUP_FEATURE_SA_SPILL)
                    .with(DMU_BACKUP_FEATURE_RAW)
                    .with(DMU_BACKUP_FEATURE_COMPRESSED),
                creation_time: 1_732_000_123,
                objset_type: DMU_OST_ZFS,
                flags: DRR_FLAG_FREERECORDS | DRR_FLAG_SPILL_BLOCK,
                toguid: 0x1122_3344_5566_7788,
                fromguid: 0x0102_0304_0506_0708,
                toname: b"tank/data@snap1".to_vec(),
                payload_len: 128,
            }),
            DrrRecord::Object(DrrObject {
                object: 42,
                object_type: 19,
                bonus_type: 44,
                blksz: 131_072,
                bonuslen: 168,
                checksumtype: 8,
                compress: 15,
                dn_slots: 1,
                flags: DRR_OBJECT_SPILL,
                raw_bonuslen: 192,
                toguid: 0x1122_3344_5566_7788,
                indblkshift: 17,
                nlevels: 2,
                nblkptr: 1,
                maxblkid: 9,
            }),
            DrrRecord::FreeObjects(DrrFreeObjects {
                firstobj: 64,
                numobjs: 32,
                toguid: 0x1122_3344_5566_7788,
            }),
            DrrRecord::Write(DrrWrite {
                object: 42,
                object_type: 19,
                offset: 131_072,
                logical_size: 131_072,
                toguid: 0x1122_3344_5566_7788,
                checksumtype: 8,
                flags: DRR_RAW_BYTESWAP,
                compressiontype: 15,
                ddt_key: [0xAB; 40],
                compressed_size: 4096,
                salt: [0x11; 8],
                iv: [0x22; 12],
                mac: [0x33; 16],
            }),
            DrrRecord::Free(DrrFree {
                object: 42,
                offset: 262_144,
                length: u64::MAX,
                toguid: 0x1122_3344_5566_7788,
            }),
            DrrRecord::End(DrrEnd {
                checksum: [1, 2, 3, 4],
                toguid: 0x1122_3344_5566_7788,
            }),
            DrrRecord::WriteByref(DrrWriteByref {
                object: 7,
                offset: 4096,
                length: 4096,
                toguid: 1,
                refguid: 2,
                refobject: 3,
                refoffset: 4096,
                checksumtype: 8,
                flags: DRR_CHECKSUM_DEDUP,
                ddt_key: [0xCD; 40],
            }),
            DrrRecord::Spill(DrrSpill {
                object: 42,
                length: 512,
                toguid: 0x1122_3344_5566_7788,
                flags: 0,
                compressiontype: 15,
                compressed_size: 512,
                salt: [0x44; 8],
                iv: [0x55; 12],
                mac: [0x66; 16],
                object_type: 44,
            }),
            DrrRecord::WriteEmbedded(DrrWriteEmbedded {
                object: 43,
                offset: 0,
                length: 512,
                toguid: 0x1122_3344_5566_7788,
                compression: 15,
                etype: 0,
                lsize: 512,
                psize: 47,
            }),
            DrrRecord::ObjectRange(DrrObjectRange {
                firstobj: 32,
                numslots: 32,
                toguid: 0x1122_3344_5566_7788,
                salt: [0x77; 8],
                iv: [0x88; 12],
                mac: [0x99; 16],
                flags: 0,
            }),
            DrrRecord::Redact(DrrRedact {
                object: 99,
                offset: 0,
                length: 4096,
                toguid: 0x1122_3344_5566_7788,
            }),
        ];

        for order in [Endian::Little, Endian::Big] {
            for rec in &samples {
                let raw = rec.encode_header(order).unwrap();
                if matches!(rec, DrrRecord::Begin(_)) {
                    assert_eq!(detect_stream_endian(&raw).unwrap(), order);
                }
                let (decoded, trailer) = DrrRecord::parse_header(&raw, order).unwrap();
                assert_eq!(&decoded, rec);
                assert_eq!(trailer, [0; 4]);
            }
        }
    }

    #[test]
    fn fletcher4_rolling_stream_verifies_and_rejects_one_bit_tamper() {
        for order in [Endian::Little, Endian::Big] {
            let begin = DrrRecord::Begin(DrrBegin {
                magic: DMU_BACKUP_MAGIC,
                hdr_type: StreamHeaderType::Substream,
                features: SendFeatureFlags::EMPTY.with(DMU_BACKUP_FEATURE_SA_SPILL),
                creation_time: 1_732_000_000,
                objset_type: DMU_OST_ZFS,
                flags: 0,
                toguid: 0xABCD_1234,
                fromguid: 0,
                toname: b"pool/ds@s1".to_vec(),
                payload_len: 0,
            });
            let write = DrrRecord::Write(DrrWrite {
                object: 7,
                object_type: 19,
                offset: 0,
                logical_size: 512,
                toguid: 0xABCD_1234,
                checksumtype: 8,
                flags: 0,
                compressiontype: 0,
                ddt_key: [0; 40],
                compressed_size: 0,
                salt: [0; 8],
                iv: [0; 12],
                mac: [0; 16],
            });
            let end = DrrRecord::End(DrrEnd {
                checksum: [0; 4],
                toguid: 0xABCD_1234,
            });
            let payload = vec![0x5A_u8; 512];

            let mut send_ck = Fletcher4Stream::new(order);
            let mut h_begin = begin.encode_header(order).unwrap();
            send_ck
                .stamp_record(&mut h_begin, &[], DrrType::Begin)
                .unwrap();
            let mut h_write = write.encode_header(order).unwrap();
            send_ck
                .stamp_record(&mut h_write, &payload, DrrType::Write)
                .unwrap();
            let mut h_end = end.encode_header(order).unwrap();
            send_ck.stamp_record(&mut h_end, &[], DrrType::End).unwrap();

            // Clean verification passes.
            let mut recv_ck = Fletcher4Stream::new(order);
            recv_ck
                .verify_record(&h_begin, &[], DrrType::Begin, true)
                .unwrap();
            recv_ck
                .verify_record(&h_write, &payload, DrrType::Write, true)
                .unwrap();
            recv_ck
                .verify_record(&h_end, &[], DrrType::End, true)
                .unwrap();
            assert_eq!(recv_ck.state(), send_ck.state());

            // 1-bit flip in DRR_WRITE payload MUST be caught by DRR_END.
            let mut bad_payload = payload.clone();
            bad_payload[13] ^= 0x01;
            let mut bad_ck = Fletcher4Stream::new(order);
            bad_ck
                .verify_record(&h_begin, &[], DrrType::Begin, true)
                .unwrap();
            bad_ck
                .verify_record(&h_write, &bad_payload, DrrType::Write, true)
                .unwrap();
            assert!(
                bad_ck
                    .verify_record(&h_end, &[], DrrType::End, true)
                    .is_err()
            );

            // 1-bit flip in DRR_WRITE header MUST be caught immediately on DRR_WRITE.
            let mut bad_hdr = h_write;
            bad_hdr[24] ^= 0x02;
            let mut bad_ck2 = Fletcher4Stream::new(order);
            bad_ck2
                .verify_record(&h_begin, &[], DrrType::Begin, true)
                .unwrap();
            assert!(
                bad_ck2
                    .verify_record(&bad_hdr, &payload, DrrType::Write, true)
                    .is_err()
            );
        }
    }

    #[test]
    fn receive_resume_token_roundtrip_and_negative_controls() {
        let tok = ReceiveResumeToken {
            toguid: 0xDEAD_BEEF_CAFE_0001,
            fromguid: Some(0x1111_2222_3333_4444),
            object: 512,
            offset: 131_072,
            bytes: 4_194_304,
            toname: "tank/enc@snap2".to_owned(),
            compressok: true,
            embedok: true,
            largeblockok: true,
            rawok: true,
            saved: false,
            ivsetguid: Some(0x9988_7766_5544_3322),
        };
        let encoded = tok.encode().unwrap();
        assert!(encoded.starts_with("1-"));
        assert!(encoded.contains("-78"));
        let decoded = ReceiveResumeToken::parse(&encoded).unwrap();
        assert_eq!(decoded, tok);

        // Negative controls:
        assert!(ReceiveResumeToken::parse(&encoded.replacen("1-", "2-", 1)).is_err());
        let parts: Vec<&str> = encoded.split('-').collect();
        assert_eq!(parts.len(), 4);
        // Tampered checksum:
        assert!(
            ReceiveResumeToken::parse(&format!("1-deadbeef-{}-{}", parts[2], parts[3])).is_err()
        );
        // Oversized uncompressed length (zip-bomb guard):
        assert!(ReceiveResumeToken::parse(&format!("1-{}-100000-{}", parts[1], parts[3])).is_err());
        // Odd-length hex payload:
        assert!(
            ReceiveResumeToken::parse(&format!("1-{}-{}-{}a", parts[1], parts[2], parts[3]))
                .is_err()
        );
        // Truncated payload:
        assert!(
            ReceiveResumeToken::parse(&format!(
                "1-{}-{}-{}",
                parts[1],
                parts[2],
                &parts[3][..parts[3].len() - 4]
            ))
            .is_err()
        );
    }

    #[test]
    fn stream_crypto_keydata_and_negative_wire_guards() {
        let kd = StreamCryptoKeydata {
            suite: ZioEncrypt::Aes256Gcm,
            version: 1,
            guid: 0x5566_7788_99AA_BBCC,
            keyformat: ZfsKeyFormat::Raw,
            pbkdf2_salt: 0,
            pbkdf2_iters: 0,
            iv: [0x12; 12],
            mac: [0x34; 16],
            wrapped_master_key: vec![0x56; 32],
            wrapped_hmac_key: [0x78; 64],
            portable_mac: [0x9A; 32],
            to_ivset_guid: 0x0102_0304_0506_0708,
            from_ivset_guid: Some(0x090A_0B0C_0D0E_0F10),
        };
        let xdr = kd.to_nvlist().unwrap().encode_xdr().unwrap();
        let parsed = StreamCryptoKeydata::from_nvlist(&NvList::parse_exact(&xdr).unwrap()).unwrap();
        assert_eq!(parsed, kd);

        // Unknown / unsupported feature bits rejected:
        assert_ne!(
            SendFeatureFlags::from_bits(DMU_BACKUP_FEATURE_DEDUP).unsupported_bits(),
            0
        );
        assert_ne!(
            SendFeatureFlags::from_bits(DMU_BACKUP_FEATURE_REDACTED).unsupported_bits(),
            0
        );
        assert_ne!(
            SendFeatureFlags::from_bits(1_u64 << 18).unsupported_bits(),
            0
        );
        assert_ne!(
            SendFeatureFlags::from_bits(1_u64 << 35).unsupported_bits(),
            0
        );
        assert_eq!(
            SendFeatureFlags::from_bits(ADMITTED_SEND_FEATURES_MASK).unsupported_bits(),
            0
        );

        // Path-traversal snapshot names rejected:
        assert_eq!(
            validate_toname_snapshot(b"tank/ds@good_snap").unwrap(),
            b"good_snap"
        );
        assert!(validate_toname_snapshot(b"tank/ds@../../etc/passwd").is_err());
        assert!(validate_toname_snapshot(b"tank/ds@..").is_err());
        assert!(validate_toname_snapshot(b"tank/ds").is_err());
    }
}
