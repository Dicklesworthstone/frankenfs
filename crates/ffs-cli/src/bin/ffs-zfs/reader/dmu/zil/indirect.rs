//! Memory-only recovery of native full-block TX_WRITE data pointers.
//!
//! OpenZFS zfs-2.3.0 zil.h / zil_read_log_data / zfs_replay_write: a
//! 192-byte write record stores a block pointer, not copied inline bytes.
//! Partial indirect writes and TX_WRITE2 require separate EOF/hidden-tail
//! replay semantics. They remain refused rather than guessing their contents.

use super::{
    BlockPointer, Cx, Edit, MAX_LOG_BYTES, MAX_RECORDS, Pool, Record, Result, VdevConfig,
    checkpoint, corrupt, edit, file_range, parse, unsupported,
};
use std::collections::BTreeMap;

pub(super) struct Plan {
    writes: Vec<Write>,
}

struct Write {
    record: usize,
    object: u64,
    pointer: BlockPointer,
}

impl Plan {
    /// Admit every pending operation before loading any indirect file payload.
    pub(super) fn new(cx: &Cx, records: &[Record]) -> Result<Self> {
        checkpoint(cx)?;
        if records.len() > MAX_RECORDS {
            return Err(unsupported("ZIL recovery exceeds 65536 records"));
        }
        let mut writes = Vec::new();
        for (index, record) in records.iter().enumerate() {
            checkpoint(cx)?;
            if !record.pending {
                continue;
            }
            if record.kind != 9 || record.raw.len() != 192 {
                edit(record)?;
                continue;
            }
            let (object, offset, length) = file_range(record)?;
            let pointer = BlockPointer::parse(&record.raw[64..192], record.order)
                .map_err(|error| parse(&error))?;
            if pointer.hole() || pointer.embedded() || pointer.protected() || pointer.gang() {
                return Err(unsupported(
                    "indirect ZIL recovery requires an ordinary unencrypted data block",
                ));
            }
            if pointer.object_type() != 19 || pointer.level() != 0 || pointer.birth() == 0 {
                return Err(corrupt("indirect ZIL write does not reference file data"));
            }
            if length == 0
                || length != pointer.logical_bytes() as u64
                || !offset.is_multiple_of(length)
            {
                return Err(unsupported(
                    "indirect ZIL recovery requires a complete aligned logical block; partial-block EOF replay is not implemented",
                ));
            }
            // Enforce the existing ordinary BP grammar before any payload is
            // read. Verification and decoding still use the shared pipeline.
            // lr_blkoff is obsolete and
            // intentionally ignored, just as in the pinned native reader.
            pointer.regular_dvas().map_err(|error| parse(&error))?;
            writes.push(Write {
                record: index,
                object,
                pointer,
            });
        }
        checkpoint(cx)?;
        Ok(Self { writes })
    }

    /// Pending writes may have births newer than the selected committed TXG.
    /// The verified log owns their pointers. Never insert them into a committed
    /// object-set cache or relax the DMU parent-birth checks to read them.
    pub(super) fn load(
        &self,
        cx: &Cx,
        pool: &Pool,
        config: &VdevConfig,
        object: u64,
    ) -> Result<BTreeMap<usize, Vec<u8>>> {
        checkpoint(cx)?;
        let mut logical = 0_usize;
        let mut physical = 0_u64;
        for write in self.writes.iter().filter(|write| write.object == object) {
            checkpoint(cx)?;
            logical = logical
                .checked_add(write.pointer.logical_bytes())
                .filter(|bytes| *bytes <= MAX_LOG_BYTES)
                .ok_or_else(|| {
                    unsupported("indirect ZIL recovery exceeds 64 MiB retained logical data")
                })?;
            let copies = write
                .pointer
                .regular_dvas()
                .map_err(|error| parse(&error))?;
            let multiplier = if config.raidz_members.is_none() {
                pool.leaves().len() as u64
            } else {
                1
            };
            for copy in copies {
                physical = copy.allocated_bytes.checked_mul(multiplier)
                    .and_then(|bytes| physical.checked_add(bytes))
                    .filter(|bytes| *bytes <= MAX_LOG_BYTES as u64)
                    .ok_or_else(|| unsupported("indirect ZIL recovery exceeds 64 MiB physical allocation work including replicas"))?;
            }
        }
        let mut data = BTreeMap::new();
        for write in self.writes.iter().filter(|write| write.object == object) {
            checkpoint(cx)?;
            let block = pool.read_block(cx, config, &write.pointer)?;
            if block.bytes.len() != write.pointer.logical_bytes() {
                return Err(corrupt("indirect ZIL data has the wrong logical length"));
            }
            checkpoint(cx)?;
            data.insert(write.record, block.bytes);
        }
        checkpoint(cx)?;
        Ok(data)
    }
}

pub(super) fn edits<'a>(
    cx: &Cx,
    records: &'a [Record],
    data: &'a BTreeMap<usize, Vec<u8>>,
    object: u64,
) -> Result<Vec<Edit<'a>>> {
    let mut edits = Vec::new();
    for (index, record) in records.iter().enumerate() {
        checkpoint(cx)?;
        if !record.pending {
            continue;
        }
        if record.kind == 9 && record.raw.len() == 192 {
            let (target, offset, length) = file_range(record)?;
            if target != object {
                continue;
            }
            let bytes = data
                .get(&index)
                .ok_or_else(|| corrupt("admitted indirect ZIL payload is missing"))?;
            if bytes.len() as u64 != length {
                return Err(corrupt(
                    "indirect ZIL payload does not match the logged write",
                ));
            }
            edits.push(Edit::Write {
                object,
                offset,
                data: bytes,
            });
        } else {
            let edit = edit(record)?;
            if edit.object() == object {
                edits.push(edit);
            }
        }
    }
    checkpoint(cx)?;
    Ok(edits)
}
