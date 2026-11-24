//! OpenZFS `dsl_scan_phys_t` and `zbookmark_phys_t` on-disk serialization.
//!
//! Contract: OpenZFS `zfs-2.4.0` `include/sys/dsl_scan.h` (`dsl_scan_phys_t`,
//! `SCAN_PHYS_NUMINTS = 24`, `192` bytes) stored under MOS pool directory key
//! `"scan"` (`DMU_POOL_SCAN`).

use super::{Endian, invalid};
use ffs_types::ParseError;

/// Exact byte length of `dsl_scan_phys_t` (`24 × u64 = 192` bytes).
pub const DSL_SCAN_PHYS_BYTES: usize = 192;

/// Number of `u64` words in `dsl_scan_phys_t` (`SCAN_PHYS_NUMINTS`).
pub const DSL_SCAN_PHYS_WORDS: usize = 24;

/// Pool scan function (`pool_scan_func_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DslScanFunc {
    None = 0,
    Scrub = 1,
    Resilver = 2,
    ErrorScrub = 3,
}

impl DslScanFunc {
    pub fn from_raw(raw: u64) -> Result<Self, ParseError> {
        match raw {
            0 => Ok(Self::None),
            1 => Ok(Self::Scrub),
            2 => Ok(Self::Resilver),
            3 => Ok(Self::ErrorScrub),
            _ => Err(invalid("unknown dsl_scan_phys_t scn_func")),
        }
    }
}

/// Pool scan execution state (`dsl_scan_state_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DslScanState {
    None = 0,
    Scanning = 1,
    Finished = 2,
    Canceled = 3,
}

impl DslScanState {
    pub fn from_raw(raw: u64) -> Result<Self, ParseError> {
        match raw {
            0 => Ok(Self::None),
            1 => Ok(Self::Scanning),
            2 => Ok(Self::Finished),
            3 => Ok(Self::Canceled),
            _ => Err(invalid("unknown dsl_scan_phys_t scn_state")),
        }
    }
}

/// `DSF_VISIT_DS_AGAIN`: dataset traversal must revisit head on resume.
pub const DSL_SCAN_FLAG_VISIT_DS_AGAIN: u64 = 1 << 0;

/// `DSF_SCRUB_PAUSED`: scrub is paused in MOS metadata.
pub const DSL_SCAN_FLAG_SCRUB_PAUSED: u64 = 1 << 1;

/// Exact 32-byte `zbookmark_phys_t` cursor identifying a block in pool order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZBookmarkPhys {
    pub objset: u64,
    pub object: u64,
    pub level: i64,
    pub blkid: u64,
}

impl ZBookmarkPhys {
    pub fn parse(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() < 32 {
            return Err(invalid("truncated zbookmark_phys_t"));
        }
        Ok(Self {
            objset: order.u64(raw, 0)?,
            object: order.u64(raw, 8)?,
            level: order.u64(raw, 16)?.cast_signed(),
            blkid: order.u64(raw, 24)?,
        })
    }

    #[must_use]
    pub fn encode(&self, order: Endian) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out[0..8].copy_from_slice(&order.encode(self.objset));
        out[8..16].copy_from_slice(&order.encode(self.object));
        out[16..24].copy_from_slice(&order.encode(self.level.cast_unsigned()));
        out[24..32].copy_from_slice(&order.encode(self.blkid));
        out
    }
}

/// Exact 192-byte (`24 × u64`) OpenZFS `dsl_scan_phys_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DslScanPhys {
    pub func: DslScanFunc,
    pub state: DslScanState,
    pub queue_obj: u64,
    pub min_txg: u64,
    pub max_txg: u64,
    pub cur_min_txg: u64,
    pub cur_max_txg: u64,
    pub start_time: u64,
    pub end_time: u64,
    pub to_examine: u64,
    pub examined: u64,
    pub skipped: u64,
    pub processed: u64,
    pub errors: u64,
    pub ddt_class_max: u64,
    pub ddt_bookmark: [u64; 4],
    pub bookmark: ZBookmarkPhys,
    pub flags: u64,
}

impl Default for DslScanPhys {
    fn default() -> Self {
        Self {
            func: DslScanFunc::None,
            state: DslScanState::None,
            queue_obj: 0,
            min_txg: 0,
            max_txg: 0,
            cur_min_txg: 0,
            cur_max_txg: 0,
            start_time: 0,
            end_time: 0,
            to_examine: 0,
            examined: 0,
            skipped: 0,
            processed: 0,
            errors: 0,
            ddt_class_max: 0,
            ddt_bookmark: [0; 4],
            bookmark: ZBookmarkPhys::default(),
            flags: 0,
        }
    }
}

impl DslScanPhys {
    /// Parse `dsl_scan_phys_t` from 24 `u64` words (as stored in MOS directory
    /// ZAP entry `"scan"` with `integer_bytes == 8`, `values.len() == 24`).
    pub fn from_words(words: &[u64]) -> Result<Self, ParseError> {
        if words.len() < DSL_SCAN_PHYS_WORDS {
            return Err(invalid("dsl_scan_phys_t has fewer than 24 uint64 words"));
        }
        Ok(Self {
            func: DslScanFunc::from_raw(words[0])?,
            state: DslScanState::from_raw(words[1])?,
            queue_obj: words[2],
            min_txg: words[3],
            max_txg: words[4],
            cur_min_txg: words[5],
            cur_max_txg: words[6],
            start_time: words[7],
            end_time: words[8],
            to_examine: words[9],
            examined: words[10],
            skipped: words[11],
            processed: words[12],
            errors: words[13],
            ddt_class_max: words[14],
            ddt_bookmark: [words[15], words[16], words[17], words[18]],
            bookmark: ZBookmarkPhys {
                objset: words[19],
                object: words[20],
                level: words[21].cast_signed(),
                blkid: words[22],
            },
            flags: words[23],
        })
    }

    /// Encode `dsl_scan_phys_t` into exact 24 `u64` words for MOS directory
    /// ZAP entry `"scan"`.
    #[must_use]
    pub const fn to_words(&self) -> [u64; DSL_SCAN_PHYS_WORDS] {
        [
            self.func as u64,
            self.state as u64,
            self.queue_obj,
            self.min_txg,
            self.max_txg,
            self.cur_min_txg,
            self.cur_max_txg,
            self.start_time,
            self.end_time,
            self.to_examine,
            self.examined,
            self.skipped,
            self.processed,
            self.errors,
            self.ddt_class_max,
            self.ddt_bookmark[0],
            self.ddt_bookmark[1],
            self.ddt_bookmark[2],
            self.ddt_bookmark[3],
            self.bookmark.objset,
            self.bookmark.object,
            self.bookmark.level.cast_unsigned(),
            self.bookmark.blkid,
            self.flags,
        ]
    }

    /// Parse `dsl_scan_phys_t` from raw on-disk bytes (`>= 192` bytes).
    pub fn parse_bytes(raw: &[u8], order: Endian) -> Result<Self, ParseError> {
        if raw.len() < DSL_SCAN_PHYS_BYTES {
            return Err(invalid("dsl_scan_phys_t buffer shorter than 192 bytes"));
        }
        let mut words = [0_u64; DSL_SCAN_PHYS_WORDS];
        for (idx, word) in words.iter_mut().enumerate() {
            *word = order.u64(raw, idx * 8)?;
        }
        Self::from_words(&words)
    }

    /// Encode `dsl_scan_phys_t` to 192 on-disk bytes in `order`.
    #[must_use]
    pub fn encode_bytes(&self, order: Endian) -> [u8; DSL_SCAN_PHYS_BYTES] {
        let mut out = [0_u8; DSL_SCAN_PHYS_BYTES];
        for (idx, word) in self.to_words().iter().enumerate() {
            out[idx * 8..idx * 8 + 8].copy_from_slice(&order.encode(*word));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsl_scan_phys_roundtrip_both_endians_and_negative_controls() {
        let scan = DslScanPhys {
            func: DslScanFunc::Resilver,
            state: DslScanState::Scanning,
            queue_obj: 0,
            min_txg: 12,
            max_txg: 42,
            cur_min_txg: 12,
            cur_max_txg: 42,
            start_time: 1_730_000_000,
            end_time: 0,
            to_examine: 16 * 1024 * 1024,
            examined: 4 * 1024 * 1024,
            skipped: 1024 * 1024,
            processed: 3 * 1024 * 1024,
            errors: 2,
            ddt_class_max: 0,
            ddt_bookmark: [1, 2, 3, 4],
            bookmark: ZBookmarkPhys {
                objset: 54,
                object: 128,
                level: -1,
                blkid: 9,
            },
            flags: DSL_SCAN_FLAG_VISIT_DS_AGAIN,
        };
        assert_eq!(DslScanPhys::from_words(&scan.to_words()).unwrap(), scan);
        for order in [Endian::Little, Endian::Big] {
            let bytes = scan.encode_bytes(order);
            assert_eq!(DslScanPhys::parse_bytes(&bytes, order).unwrap(), scan);
            let bm = scan.bookmark.encode(order);
            assert_eq!(ZBookmarkPhys::parse(&bm, order).unwrap(), scan.bookmark);
        }

        let mut bad = scan.to_words();
        bad[0] = 99;
        assert!(DslScanPhys::from_words(&bad).is_err());
        bad[0] = 1;
        bad[1] = 77;
        assert!(DslScanPhys::from_words(&bad).is_err());
        assert!(DslScanPhys::from_words(&bad[..23]).is_err());
    }
}
