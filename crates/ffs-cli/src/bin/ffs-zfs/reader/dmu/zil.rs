//! Native ZIL inspection and bounded, opt-in file-data recovery.
//!
//! Layout reference: OpenZFS zfs-2.3.0 zil.h, zil.c and zio_checksum.c.
//! The header lives at byte 512 of the dataset OBJECT SET, not the DSL bonus.
//! ZIL pointer checksum words identify a chain; the embedded Fletcher verifier
//! binds each block to that identity. This is not ordinary DMU I/O.
//! No pool claim, replay-sequence update, allocation or backing write occurs.

mod indirect;
mod recovery;
mod storage;

use super::super::{Pool, VdevConfig};
use super::{
    BlockPointer, Cx, Endian, FfsError, MAX_READ_BYTES, Objects, Result, checkpoint,
    corrupt, parse, unsupported,
};
use ffs_ondisk::zfs::{Dva, MAX_BLOCK_BYTES, checksum};
use ffs_ondisk::zfs_zpl::Kind;
use serde::Serialize;
use storage::ReadState;

const CHAIN_BYTES: usize = 184;
const ECK_MAGIC: u64 = 0x0210_da7a_b10c_7a11;
const MAX_LOG_BYTES: usize = 64 * 1024 * 1024;
const MAX_LOG_BLOCKS: usize = 4096;
const MAX_RECORDS: usize = 65_536;
const MAX_RECOVERY_WORK_BYTES: usize = 128 * 1024 * 1024;
const CLAIM_LR_VALID: u64 = 2;

#[derive(Debug)]
struct Pointer {
    bp: BlockPointer,
    identity: [u64; 4],
    dvas: Vec<Dva>,
}

fn word(raw: &[u8], at: usize, order: Endian) -> Result<u64> {
    order.u64(raw, at).map_err(|error| parse(&error))
}

fn identity(raw: &[u8], order: Endian) -> Result<[u64; 4]> {
    Ok([word(raw, 96, order)?, word(raw, 104, order)?, word(raw, 112, order)?, word(raw, 120, order)?])
}

impl Pointer {
    fn parse(raw: &[u8], order: Endian, dataset: u64) -> Result<Option<Self>> {
        let bp = BlockPointer::parse(raw, order).map_err(|error| parse(&error))?;
        if bp.hole() {
            return Ok(None);
        }
        let property = word(raw, 48, order)?;
        if bp.embedded() || bp.protected() || property & (1_u64 << 62) != 0
            || bp.gang() || bp.level() != 0 || bp.object_type() != 9
            || bp.compression() != 2 || !matches!(bp.checksum_type(), 5 | 9)
        {
            return Err(unsupported("ZIL requires unencrypted, uncompressed ZILOG/ZILOG2 log blocks"));
        }
        if bp.birth() == 0 || bp.physical_birth() > bp.birth()
            || word(raw, 56, order)? != 0 || word(raw, 64, order)? != 0
            || bp.physical_bytes() != bp.logical_bytes()
            || !(4096..=MAX_BLOCK_BYTES).contains(&bp.physical_bytes())
            || !bp.physical_bytes().is_multiple_of(4096)
        {
            return Err(corrupt("invalid ZIL block geometry, padding or birth"));
        }
        let identity = identity(raw, order)?;
        if identity[2] != dataset || identity[3] == 0 {
            return Err(corrupt("ZIL chain identifies a different dataset or a zero sequence"));
        }
        // Ordinary regular_dvas deliberately refuses ZIL checksum algorithms.
        // Decode their native address slots here, then reuse the leaf's complete
        // sector/allocation/partition exclusion checks before issuing any I/O.
        let mut dvas = Vec::new();
        let mut ended = false;
        for index in 0..3 {
            let first = word(raw, index * 16, order)?;
            let second = word(raw, index * 16 + 8, order)?;
            if first == 0 && second == 0 {
                ended = true;
                continue;
            }
            if ended || first & 0xff00_0000_ff00_0000 != 0 || first & 0x00ff_ffff == 0 || second >> 63 != 0 {
                return Err(corrupt("invalid, ganged or noncontiguous ZIL DVA"));
            }
            dvas.push(Dva {
                vdev: ((first >> 32) & 0x00ff_ffff) as u32,
                offset: second.checked_mul(512).ok_or_else(|| corrupt("ZIL DVA offset overflow"))?,
                allocated_bytes: (first & 0x00ff_ffff) * 512,
                gang: false,
            });
        }
        if dvas.is_empty() {
            return Err(corrupt("allocated ZIL block has no DVA"));
        }
        Ok(Some(Self { bp, identity, dvas }))
    }

    /// False is an unverified block, potentially the native unwritten tail.
    /// The caller, not this verifier, decides whether that tail may be accepted.
    fn checksum_valid(&self, raw: &[u8]) -> Result<bool> {
        if raw.len() != self.bp.physical_bytes() {
            return Err(corrupt("short ZIL physical block"));
        }
        let order = self.bp.payload_order();
        let modern = self.bp.checksum_type() == 9;
        let chain = if modern { 0 } else { raw.len() - CHAIN_BYTES };
        let eck = chain + 144;
        if word(raw, eck, order)? != ECK_MAGIC {
            return Ok(false);
        }
        let used = word(raw, chain + 136, order)?;
        let covered = if modern {
            if used < CHAIN_BYTES as u64 || used > raw.len() as u64 {
                return Ok(false);
            }
            usize::try_from(used.div_ceil(4096) * 4096).map_err(|_| corrupt("ZIL checksum span overflow"))?
        } else {
            raw.len()
        };
        let mut expected = [0; 4];
        let mut bytes = raw[..covered].to_vec();
        for (index, value) in expected.iter_mut().enumerate() {
            let at = eck + 8 + index * 8;
            *value = word(raw, at, order)?;
            bytes[at..at + 8].copy_from_slice(&order.encode(self.identity[index]));
        }
        let algorithm = if modern { 7 } else { 6 };
        Ok(checksum(&bytes, algorithm, order).map_err(|error| parse(&error))? == expected)
    }
}

#[derive(Debug, Serialize)]
pub struct Header {
    pub claim_txg: u64,
    pub replay_sequence: u64,
    pub claimed_block_sequence: u64,
    pub claimed_record_sequence: u64,
    pub flags: u64,
}

impl Header {
    fn parse(raw: &[u8], order: Endian, txg: u64) -> Result<Self> {
        if raw.len() != 192 {
            return Err(corrupt("ZIL header must contain 192 bytes"));
        }
        let header = Self {
            claim_txg: word(raw, 0, order)?,
            replay_sequence: word(raw, 8, order)?,
            claimed_block_sequence: word(raw, 144, order)?,
            flags: word(raw, 152, order)?,
            claimed_record_sequence: word(raw, 160, order)?,
        };
        if header.flags & !3 != 0 || raw[168..].iter().any(|byte| *byte != 0) {
            return Err(unsupported("unknown ZIL header flags or reserved fields"));
        }
        if header.claim_txg > txg {
            return Err(corrupt("ZIL claim is newer than the selected pool TXG"));
        }
        if header.claim_txg == 0 && (header.replay_sequence != 0
            || header.claimed_block_sequence != 0 || header.claimed_record_sequence != 0
            || header.flags != 0)
        {
            return Err(corrupt("unclaimed ZIL header contains claim or replay state"));
        }
        if header.claim_txg != 0 {
            if header.flags & CLAIM_LR_VALID == 0 {
                return Err(unsupported("legacy ZIL claims without a record-sequence boundary"));
            }
            if header.replay_sequence > header.claimed_record_sequence {
                return Err(corrupt("ZIL replay sequence exceeds its claimed boundary"));
            }
        }
        Ok(header)
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    Empty,
    Hole,
    ClaimedBoundary,
    UnverifiedTail,
}

#[derive(Debug, Serialize)]
pub struct Record {
    pub kind: u64,
    pub txg: u64,
    pub sequence: u64,
    pub record_bytes: usize,
    pub pending: bool,
    #[serde(skip)]
    order: Endian,
    #[serde(skip)]
    raw: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct IntentLog {
    pub pool_guid: u64,
    pub dataset_guid: u64,
    pub dataset_object: u64,
    pub selected_txg: u64,
    pub header: Header,
    pub verified_blocks: usize,
    pub physical_work_bytes: usize,
    pub reconstruction_work_bytes: usize,
    pub termination: Termination,
    pub records: Vec<Record>,
}

#[derive(Clone, Copy)]
struct Selection {
    dataset: u64,
    guid: u64,
    txg: u64,
}

fn scan(
    cx: &Cx,
    pool: &Pool,
    config: &VdevConfig,
    header_bytes: &[u8],
    order: Endian,
    selection: Selection,
) -> Result<IntentLog> {
    checkpoint(cx)?;
    let Selection { dataset, guid, txg } = selection;
    let header = Header::parse(header_bytes, order, txg)?;
    let mut pointer = Pointer::parse(&header_bytes[16..144], order, dataset)?;
    let mut result = IntentLog {
        pool_guid: config.pool_guid,
        dataset_guid: guid,
        dataset_object: dataset,
        selected_txg: txg,
        header,
        verified_blocks: 0,
        physical_work_bytes: 0,
        reconstruction_work_bytes: 0,
        termination: Termination::Empty,
        records: Vec::new(),
    };
    let claimed = result.header.claim_txg != 0;
    if claimed && pointer.as_ref().is_some_and(|first| first.identity[3] > result.header.claimed_block_sequence) {
        return Err(corrupt("ZIL first block exceeds its claimed boundary"));
    }
    let mut last_record = 0;
    let mut storage = ReadState::default();
    while let Some(current) = pointer {
        checkpoint(cx)?;
        if claimed && current.identity[3] >= result.header.claimed_block_sequence && last_record == result.header.claimed_record_sequence {
            result.termination = Termination::ClaimedBoundary;
            break;
        }
        if claimed && current.identity[3] > result.header.claimed_block_sequence {
            return Err(corrupt("ZIL chain ended before all claimed records were read"));
        }
        if result.verified_blocks == MAX_LOG_BLOCKS {
            return Err(unsupported("ZIL scan exceeds 4096 log blocks"));
        }
        let raw = storage::read_block(cx, pool, config, &current, &mut storage)?;
        result.physical_work_bytes = storage.physical_bytes;
        result.reconstruction_work_bytes = storage.reconstruction_bytes;
        let Some(raw) = raw else {
            if claimed {
                return Err(corrupt("claimed ZIL block failed every embedded checksum"));
            }
            result.termination = Termination::UnverifiedTail;
            break;
        };
        let payload_order = current.bp.payload_order();
        let modern = current.bp.checksum_type() == 9;
        let chain = if modern { 0 } else { raw.len() - CHAIN_BYTES };
        let used = usize::try_from(word(&raw, chain + 136, payload_order)?)
            .map_err(|_| corrupt("ZIL used length overflow"))?;
        let (mut at, end) = if modern {
            (CHAIN_BYTES, used)
        } else {
            if used > chain {
                return Err(corrupt("legacy ZIL records overlap the chain trailer"));
            }
            (0, used)
        };
        let next = &raw[chain + 8..chain + 136];
        let mut expected = current.identity;
        expected[3] = expected[3].checked_add(1).ok_or_else(|| corrupt("ZIL block sequence exhausted"))?;
        if identity(next, payload_order)? != expected {
            return Err(corrupt("ZIL next pointer changes chain identity or skips a sequence"));
        }
        result.verified_blocks += 1;
        while at < end {
            checkpoint(cx)?;
            if end - at < 32 {
                return Err(corrupt("truncated ZIL record header"));
            }
            let length = usize::try_from(word(&raw, at + 8, payload_order)?)
                .map_err(|_| corrupt("ZIL record length overflow"))?;
            let sequence = word(&raw, at + 24, payload_order)?;
            let record_txg = word(&raw, at + 16, payload_order)?;
            if length < 32 || !length.is_multiple_of(8) || length > end - at || sequence <= last_record || record_txg == 0 {
                return Err(corrupt("invalid ZIL record length, transaction or sequence"));
            }
            if claimed && sequence > result.header.claimed_record_sequence {
                if last_record != result.header.claimed_record_sequence {
                    return Err(corrupt("ZIL skipped its claimed record boundary"));
                }
                result.termination = Termination::ClaimedBoundary;
                checkpoint(cx)?;
                return Ok(result);
            }
            if result.records.len() == MAX_RECORDS {
                return Err(unsupported("ZIL scan exceeds 65536 records"));
            }
            let pending = sequence > result.header.replay_sequence
                && if claimed { record_txg >= result.header.claim_txg } else { record_txg > txg };
            result.records.push(Record {
                kind: word(&raw, at, payload_order)?,
                txg: record_txg,
                sequence,
                record_bytes: length,
                pending,
                order: payload_order,
                raw: raw[at..at + length].to_vec(),
            });
            last_record = sequence;
            at += length;
        }
        pointer = Pointer::parse(next, payload_order, dataset)?;
        result.termination = Termination::Hole;
    }
    if claimed && last_record != result.header.claimed_record_sequence {
        return Err(corrupt("ZIL terminated before its claimed record boundary"));
    }
    checkpoint(cx)?;
    Ok(result)
}

impl Objects {
    /// Inspect a head's native log through its checked DSL and object-set root.
    /// Log reads retain the same complete native storage set as the MOS/ZPL
    /// view, with a dedicated ZIL verifier for replicas and RAIDZ reconstruction.
    pub fn intent_log(&mut self, cx: &Cx, components: &[Vec<u8>]) -> Result<IntentLog> {
        checkpoint(cx)?;
        let dataset = self.datasets(cx)?.into_iter().find(|row| row.components == components)
            .ok_or_else(|| FfsError::NotFound("ZFS head dataset".into()))?;
        if dataset.objectset_kind != 2 {
            return Err(unsupported("ZIL file recovery requires a filesystem head, not a snapshot or zvol"));
        }
        let object = self.load(cx, dataset.head_object)?;
        let bp = BlockPointer::parse(&object.node.bonus()[128..256], object.node.order())
            .map_err(|error| parse(&error))?;
        let root = self.checked(cx, &bp, 11, 0, bp.logical_bytes(), object.ceiling)?
            .ok_or_else(|| corrupt("ZIL owner object set is a hole"))?;
        scan(
            cx, &self.pool, &self.config, &root.bytes[512..704], root.order,
            Selection { dataset: dataset.head_object, guid: dataset.guid, txg: self.txg },
        )
    }
}

#[derive(Debug)]
enum Edit<'a> {
    Write { object: u64, offset: u64, data: &'a [u8] },
    Truncate { object: u64, size: u64 },
}
impl Edit<'_> {
    fn object(&self) -> u64 {
        match self {
            Self::Write { object, .. } | Self::Truncate { object, .. } => *object,
        }
    }
    fn size_after(&self, size: u64) -> u64 {
        match self {
            Self::Write { offset, data, .. } => size.max(*offset + data.len() as u64),
            Self::Truncate { size, .. } => *size,
        }
    }
}

fn file_range(record: &Record) -> Result<(u64, u64, u64)> {
    let raw = &record.raw;
    let object = word(raw, 32, record.order)?;
    let offset = word(raw, 40, record.order)?;
    let length = word(raw, 48, record.order)?;
    if object == 0 || object >= (1_u64 << 48) || offset > i64::MAX as u64 || length > i64::MAX as u64 - offset {
        return Err(corrupt("ZIL file identity or signed file range is invalid"));
    }
    Ok((object, offset, length))
}

fn edit(record: &Record) -> Result<Edit<'_>> {
    if !matches!(record.kind, 9 | 10) {
        return Err(unsupported("file-data ZIL recovery refuses pending namespace, attribute and other record types"));
    }
    let raw = &record.raw;
    let (object, offset, length) = file_range(record)?;
    if record.kind == 10 {
        if raw.len() != 56 || length != 0 {
            return Err(unsupported("file-data ZIL recovery admits EOF truncation, not range-free records"));
        }
        return Ok(Edit::Truncate { object, size: offset });
    }
    if raw.len() <= 192 {
        return Err(unsupported("file-data ZIL recovery requires copied writes; indirect writes are not replayed"));
    }
    let size = usize::try_from(length).map_err(|_| corrupt("ZIL copied-write length overflow"))?;
    if size == 0 || size > raw.len() - 192 || raw.len() - 192 - size > 7 {
        return Err(corrupt("ZIL copied-write payload length disagrees with its record"));
    }
    Ok(Edit::Write { object, offset, data: &raw[192..192 + size] })
}

fn overlap(start: u64, size: usize, from: u64, to: u64) -> std::ops::Range<usize> {
    let left = from.saturating_sub(start).min(size as u64) as usize;
    let right = to.saturating_sub(start).min(size as u64) as usize;
    left..right.max(left)
}

fn apply(cx: &Cx, bytes: &mut [u8], start: u64, mut size: u64, edits: &[Edit<'_>]) -> Result<()> {
    let mut remaining = MAX_RECOVERY_WORK_BYTES;
    for edit in edits {
        checkpoint(cx)?;
        match edit {
            Edit::Write { offset, data, .. } => {
                if *offset > size {
                    let gap = overlap(start, bytes.len(), size, *offset);
                    charge_recovery(&mut remaining, gap.len())?;
                    bytes[gap].fill(0);
                }
                let end = *offset + data.len() as u64;
                let range = overlap(start, bytes.len(), *offset, end);
                if !range.is_empty() {
                    charge_recovery(&mut remaining, range.len())?;
                    let within = (start + range.start as u64 - *offset) as usize;
                    bytes[range.clone()].copy_from_slice(&data[within..within + range.len()]);
                }
            }
            Edit::Truncate { size: next, .. } => {
                let range = if *next < size {
                    overlap(start, bytes.len(), *next, u64::MAX)
                } else {
                    overlap(start, bytes.len(), size, *next)
                };
                charge_recovery(&mut remaining, range.len())?;
                bytes[range].fill(0);
            }
        }
        size = edit.size_after(size);
    }
    checkpoint(cx)
}

fn charge_recovery(remaining: &mut usize, bytes: usize) -> Result<()> {
    *remaining = remaining.checked_sub(bytes).ok_or_else(|| {
        unsupported("ZIL recovered range exceeds 128 MiB of cumulative copy/zero work")
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;

pub struct RecoveredRead {
    pub bytes: Vec<u8>,
    pub file_size: u64,
    pub applied_records: usize,
    pub log: IntentLog,
}

impl Objects {
    /// Recover a bounded range of an EXISTING regular file into memory only.
    /// Every pending record is admitted before any file bytes can escape. This
    /// is not namespace replay, native durable recovery or a writable mount.
    pub fn read_with_intent_log(&mut self, cx: &Cx, components: &[Vec<u8>], path: &[u8], start: u64, bytes: usize, allow_unverified_tail: bool) -> Result<RecoveredRead> {
        checkpoint(cx)?;
        if bytes > MAX_READ_BYTES {
            return Err(unsupported("ZIL recovered range exceeds 16 MiB"));
        }
        let log = self.intent_log(cx, components)?;
        if log.termination == Termination::UnverifiedTail && !allow_unverified_tail {
            return Err(unsupported("unverified ZIL tail: explicit prefix-recovery authorization is required"));
        }
        let plan = indirect::Plan::new(cx, &log.records)?;
        let mut view = self.zpl(cx, components)?;
        let object = view.resolve(cx, path)?;
        let (metadata, _) = view.stat(cx, object)?;
        if metadata.kind != Kind::Regular {
            return Err(unsupported("ZIL recovered read requires an existing regular file"));
        }
        let data = plan.load(cx, &self.pool, &self.config, object)?;
        let edits = indirect::edits(cx, &log.records, &data, object)?;
        let file_size = edits.iter().fold(metadata.size, |size, edit| edit.size_after(size));
        let length = file_size.saturating_sub(start).min(bytes as u64) as usize;
        let result = recovery::read(cx, metadata.size, start, length, &edits, |at, count| {
            view.read(cx, object, at, count)
        })?;
        let applied_records = edits.len();
        drop(edits);
        checkpoint(cx)?;
        Ok(RecoveredRead { bytes: result, file_size, applied_records, log })
    }
}
