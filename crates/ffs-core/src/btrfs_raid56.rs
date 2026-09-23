//! Read-only RAID5/6 reconstruction shared by data and metadata readers.
//!
//! P is the XOR of logical data columns; Q weights column j by 2^j in
//! GF(256), polynomial 0x11d. Device rotation does not rotate Q coefficients.
//! Only the requested checksum unit is reconstructed. No device is written.
//! The caller must validate candidates before returning them to a client/cache;
//! an unchecked caller can recover known erasures but cannot diagnose bit rot.

use super::{BtrfsReadDevices, btrfs_device_error_to_ffs, parse_to_ffs_error};
use asupersync::Cx;
use ffs_btrfs::BtrfsDeviceError;
use ffs_error::{FfsError, Result};
use ffs_ondisk::{
    BtrfsChunkEntry, BtrfsRaid56Row, BtrfsRaidProfile, btrfs_raid56_gdiv as gdiv,
    btrfs_raid56_gexp as gexp, btrfs_raid56_gmul as gmul,
};
use std::collections::BTreeSet;
use std::io::ErrorKind;

const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
const CPU_CHECK_INTERVAL: usize = 4096;

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

/// An explicit unavailable stripe, not an authorization or control-plane error.
pub fn is_erasure(error: &BtrfsDeviceError) -> bool {
    match error {
        BtrfsDeviceError::MissingDevice { .. } | BtrfsDeviceError::ReadLength { .. } => true,
        BtrfsDeviceError::Io(error) => {
            error.kind() == ErrorKind::UnexpectedEof
                || (cfg!(target_os = "linux") && error.raw_os_error() == Some(5))
        }
        _ => false,
    }
}

fn invalid(logical: u64, detail: &str) -> FfsError {
    FfsError::Corruption {
        block: logical,
        detail: detail.to_owned(),
    }
}

/// Validate the same geometry for admission and reconstruction. In particular,
/// repeated physical devices do not supply independent erasure tolerance, and
/// more than 255 data columns would repeat RAID6's nonzero field coefficients.
pub fn read_shape(
    chunks: &[BtrfsChunkEntry],
    logical: u64,
    len: usize,
) -> Result<Option<(BtrfsRaid56Row, usize)>> {
    let mapping = ffs_ondisk::map_logical_to_stripes(chunks, logical)
        .map_err(|error| parse_to_ffs_error(&error))?
        .ok_or_else(|| invalid(logical, "RAID56 address is not mapped"))?;
    if !matches!(
        mapping.profile,
        BtrfsRaidProfile::Raid5 | BtrfsRaidProfile::Raid6
    ) {
        return Ok(None);
    }
    let row = ffs_ondisk::resolve_raid56_row(chunks, logical)
        .map_err(|error| parse_to_ffs_error(&error))?
        .ok_or_else(|| invalid(logical, "RAID56 row is not mapped"))?;
    let slot_count = row.data_slots.len() + row.parity_slots.len();
    let mut devices = BTreeSet::new();
    if len == 0
        || u64::try_from(len)
            .ok()
            .is_none_or(|len| len > mapping.contiguous_len)
        || row.data_slots.len() > 255
        || len
            .checked_mul(slot_count)
            .is_none_or(|size| size > MAX_CAPTURE_BYTES)
        || row
            .data_slots
            .iter()
            .chain(&row.parity_slots)
            .any(|slot| slot.devid == 0 || !devices.insert(slot.devid))
    {
        return Err(invalid(
            logical,
            "invalid or oversized RAID56 recovery geometry",
        ));
    }
    let [target] = mapping.stripes.as_slice() else {
        return Err(invalid(
            logical,
            "RAID56 mapping must identify one data slot",
        ));
    };
    let target = row
        .data_slots
        .iter()
        .position(|slot| slot == target)
        .ok_or_else(|| invalid(logical, "RAID56 data slot is absent from its row"))?;
    Ok(Some((row, target)))
}

impl BtrfsReadDevices {
    fn read_raid56_slot(
        &self,
        cx: &Cx,
        slot: &ffs_ondisk::BtrfsPhysicalMapping,
        len: usize,
    ) -> Result<Option<Vec<u8>>> {
        match self
            .readers
            .read_physical(cx, slot.devid, slot.physical, len)
        {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if is_erasure(&error) => Ok(None),
            Err(error) => Err(btrfs_device_error_to_ffs(error)),
        }
    }

    /// Recover a missing or checksum-invalid data column using P, Q, or both.
    ///
    /// Captures each partner at most once. With RAID6 and a validating caller,
    /// a failed first reconstruction also tries each readable partner as the
    /// second erasure: one silent partner error must not poison the only repair
    /// attempt. Candidate work is bounded by column count times checksum size.
    /// Success always passes `accept` and a final caller-context checkpoint.
    pub(super) fn reconstruct_raid56(
        &self,
        cx: &Cx,
        chunks: &[BtrfsChunkEntry],
        logical: u64,
        len: usize,
        mut accept: impl FnMut(&[u8]) -> bool,
    ) -> Result<Option<Vec<u8>>> {
        checkpoint(cx)?;
        let Some((row, target)) = read_shape(chunks, logical, len)? else {
            return Ok(None);
        };
        let mut data = Vec::with_capacity(row.data_slots.len());
        let mut missing = Vec::new();
        let mut xor = vec![0; len];
        let mut weighted = vec![0; len];
        for (column, slot) in row.data_slots.iter().enumerate() {
            checkpoint(cx)?;
            if column == target {
                data.push(None);
                continue;
            }
            let bytes = self.read_raid56_slot(cx, slot, len)?;
            if let Some(bytes) = &bytes {
                for (offset, &byte) in bytes.iter().enumerate() {
                    if offset % CPU_CHECK_INTERVAL == 0 {
                        checkpoint(cx)?;
                    }
                    xor[offset] ^= byte;
                    weighted[offset] ^= gmul(gexp(column), byte);
                }
            } else {
                missing.push(column);
            }
            data.push(bytes);
        }
        let p = self.read_raid56_slot(cx, &row.parity_slots[0], len)?;
        let q = match row.parity_slots.get(1) {
            Some(slot) => self.read_raid56_slot(cx, slot, len)?,
            None => None,
        };
        let captured = CapturedRow {
            data,
            xor,
            weighted,
            p,
            q,
            target,
        };
        if missing.is_empty() {
            // A missing/bad P slot must not prevent a Q-only data recovery.
            // Conversely a damaged Q slot must not poison valid XOR parity.
            for use_q in [false, true] {
                if let Some(bytes) = captured.single(cx, use_q)? {
                    let accepted = accept(&bytes);
                    checkpoint(cx)?;
                    if accepted {
                        return Ok(Some(bytes));
                    }
                }
            }
            // The requested column plus one silent peer error fits RAID6's
            // two-erasure budget. Remove each suspect from the captured sums;
            // never combine sectors or reread different source generations.
            if captured.p.is_some() && captured.q.is_some() {
                for other in 0..captured.data.len() {
                    if other == target {
                        continue;
                    }
                    if let Some(bytes) = captured.double(cx, other)? {
                        let accepted = accept(&bytes);
                        checkpoint(cx)?;
                        if accepted {
                            return Ok(Some(bytes));
                        }
                    }
                }
            }
        } else if let [other] = missing.as_slice()
            && let Some(bytes) = captured.double(cx, *other)?
        {
            let accepted = accept(&bytes);
            checkpoint(cx)?;
            if accepted {
                return Ok(Some(bytes));
            }
        }
        checkpoint(cx)?;
        Ok(None)
    }
}

struct CapturedRow {
    data: Vec<Option<Vec<u8>>>,
    xor: Vec<u8>,
    weighted: Vec<u8>,
    p: Option<Vec<u8>>,
    q: Option<Vec<u8>>,
    target: usize,
}

impl CapturedRow {
    fn single(&self, cx: &Cx, use_q: bool) -> Result<Option<Vec<u8>>> {
        let parity = if use_q { &self.q } else { &self.p };
        let Some(parity) = parity else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(parity.len());
        for (offset, &byte) in parity.iter().enumerate() {
            if offset % CPU_CHECK_INTERVAL == 0 {
                checkpoint(cx)?;
            }
            out.push(if use_q {
                gdiv(byte ^ self.weighted[offset], gexp(self.target))
            } else {
                byte ^ self.xor[offset]
            });
        }
        Ok(Some(out))
    }

    fn double(&self, cx: &Cx, other: usize) -> Result<Option<Vec<u8>>> {
        let (Some(p), Some(q)) = (&self.p, &self.q) else {
            return Ok(None);
        };
        let coefficient = gexp(other);
        let denominator = gexp(self.target) ^ coefficient;
        // read_shape bounds the column count, so distinct columns must have
        // distinct nonzero coefficients. Keep the solve explicitly guarded.
        if denominator == 0 {
            return Ok(None);
        }
        let mut out = Vec::with_capacity(p.len());
        for offset in 0..p.len() {
            if offset % CPU_CHECK_INTERVAL == 0 {
                checkpoint(cx)?;
            }
            let suspect = self.data[other].as_ref().map_or(0, |data| data[offset]);
            let a = p[offset] ^ self.xor[offset] ^ suspect;
            let b = q[offset] ^ self.weighted[offset] ^ gmul(coefficient, suspect);
            // a = target XOR other; b = g_target*target XOR g_other*other.
            out.push(gdiv(b ^ gmul(coefficient, a), denominator));
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests;
