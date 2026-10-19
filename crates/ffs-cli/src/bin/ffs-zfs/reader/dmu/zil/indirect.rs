//! Memory-only recovery of native TX_WRITE data pointers.
//!
//! OpenZFS zfs-2.3.0 zil.h / zil_read_log_data / zfs_replay_write: a
//! 192-byte write record stores a block pointer, not copied inline bytes.
//! A partial indirect write restores the complete logical block while its
//! logged end, not the hidden block tail, determines visible EOF.

use super::{
    BlockPointer, Cx, Edit, IntentRecord, MAX_LOG_BYTES, MAX_RECORDS, OwnedEdit, Pool, Result,
    VdevConfig, checkpoint, corrupt, edit, file_range, parse, unsupported,
};
use std::collections::BTreeMap;

pub(in super::super) struct Plan {
    writes: Vec<Write>,
}

struct Write {
    record: usize,
    object: u64,
    pointer: BlockPointer,
}

impl Plan {
    /// Admit every pending operation before loading any indirect file payload.
    pub(super) fn new(cx: &Cx, records: &[IntentRecord]) -> Result<Self> {
        for record in records.iter().filter(|record| record.pending) {
            checkpoint(cx)?;
            if record.kind != 9 || record.raw.len() != 192 {
                edit(record)?;
            }
        }
        Self::for_namespace(cx, records)
    }

    /// Namespace replay separately admits every operation with its strict
    /// decoder. This plan owns only native write-pointer admission and I/O.
    pub(in super::super) fn for_namespace(cx: &Cx, records: &[IntentRecord]) -> Result<Self> {
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
                if record.kind == 9 {
                    edit(record)?;
                }
                continue;
            }
            let (object, _, _) = file_range(record)?;
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
            indirect_range(record, pointer.logical_bytes())?;
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
        self.load_selected(cx, pool, config, Some(object), |pointer| {
            Ok(pool.read_block(cx, config, pointer)?.bytes)
        })
    }

    pub(in super::super) fn load_all(
        &self,
        cx: &Cx,
        objects: &super::super::Objects,
    ) -> Result<BTreeMap<usize, Vec<u8>>> {
        self.load_selected(cx, &objects.pool, &objects.config, None, |pointer| {
            objects
                .read_zil_block(cx, pointer)?
                .map(|(bytes, _)| bytes)
                .ok_or_else(|| corrupt("indirect ZIL data unexpectedly became a hole"))
        })
    }

    fn load_selected(
        &self,
        cx: &Cx,
        pool: &Pool,
        config: &VdevConfig,
        object: Option<u64>,
        mut read: impl FnMut(&BlockPointer) -> Result<Vec<u8>>,
    ) -> Result<BTreeMap<usize, Vec<u8>>> {
        checkpoint(cx)?;
        let mut logical = 0_usize;
        let mut physical = 0_u64;
        for write in self
            .writes
            .iter()
            .filter(|write| object.is_none_or(|object| write.object == object))
        {
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
        for write in self
            .writes
            .iter()
            .filter(|write| object.is_none_or(|object| write.object == object))
        {
            checkpoint(cx)?;
            let bytes = read(&write.pointer)?;
            if bytes.len() != write.pointer.logical_bytes() {
                return Err(corrupt("indirect ZIL data has the wrong logical length"));
            }
            checkpoint(cx)?;
            data.insert(write.record, bytes);
        }
        checkpoint(cx)?;
        Ok(data)
    }
}

fn indirect_range(record: &IntentRecord, block_bytes: usize) -> Result<(u64, u64, u64)> {
    let (object, offset, length) = file_range(record)?;
    let block = block_bytes as u64;
    if length == 0 || length > block || offset % block > block - length {
        return Err(corrupt("indirect ZIL write exceeds its logical block"));
    }
    let start = if length < block {
        offset - offset % block
    } else {
        offset
    };
    if start
        .checked_add(block)
        .is_none_or(|end| end > i64::MAX as u64)
    {
        return Err(corrupt("indirect ZIL block range overflows"));
    }
    Ok((object, start, offset + length))
}

pub(in super::super) fn take_write(
    record: &IntentRecord,
    index: usize,
    data: &mut BTreeMap<usize, Vec<u8>>,
) -> Result<OwnedEdit> {
    if record.kind == 9 && record.raw.len() == 192 {
        let bytes = data
            .remove(&index)
            .ok_or_else(|| corrupt("admitted indirect ZIL payload is missing"))?;
        let (object, offset, end) = indirect_range(record, bytes.len())?;
        return Ok(OwnedEdit::Indirect {
            object,
            offset,
            data: bytes,
            end,
        });
    }
    match edit(record)? {
        Edit::Write {
            object,
            offset,
            data,
        } => Ok(OwnedEdit::Write {
            object,
            offset,
            data: data.to_vec(),
        }),
        _ => Err(corrupt("expected an admitted ZIL write")),
    }
}

pub(super) fn edits<'a>(
    cx: &Cx,
    records: &'a [IntentRecord],
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
            let (target, _, _) = file_range(record)?;
            if target != object {
                continue;
            }
            let bytes = data
                .get(&index)
                .ok_or_else(|| corrupt("admitted indirect ZIL payload is missing"))?;
            let pointer = BlockPointer::parse(&record.raw[64..192], record.order)
                .map_err(|error| parse(&error))?;
            if bytes.len() != pointer.logical_bytes() {
                return Err(corrupt(
                    "indirect ZIL payload does not match the logged write",
                ));
            }
            let (_, offset, end) = indirect_range(record, bytes.len())?;
            edits.push(Edit::Indirect {
                object,
                offset,
                data: bytes,
                end,
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
