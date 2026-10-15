//! Logical sparse seeks over authenticated DMU pointer trees.
//!
//! Allocation is determined by native hole pointers, never by compressed sizes
//! or zero-filled payloads. Only indirect metadata is read; this is not a scrub.

use super::{BlockPointer, Cx, Kind, Objects, Result, Zpl, checkpoint, corrupt, parse, unsupported};
use ffs_core::SeekWhence;
use ffs_error::FfsError;
use ffs_ondisk::zfs_dmu::Dnode;

const MAX_POINTERS: usize = 1_048_576;
const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;

fn errno(code: i32) -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(code))
}

struct Search<'a> {
    objects: &'a mut Objects,
    cx: &'a Cx,
    node: &'a Dnode,
    first: u128,
    end: u128,
    data: bool,
    pointers_left: usize,
    bytes_left: usize,
}

impl Search<'_> {
    /// `base` and `span` are logical data-block coordinates. Native geometry
    /// permits capacities greater than u64::MAX, so keep these in u128 until
    /// the result has been clipped to the file's u64 byte-size boundary.
    fn visit(
        &mut self,
        bp: &BlockPointer,
        level: u8,
        base: u128,
        span: u128,
        ceiling: u64,
    ) -> Result<Option<u128>> {
        checkpoint(self.cx)?;
        let first = self.first.max(base);
        let end = self.end.min(base + span);
        if first >= end {
            return Ok(None);
        }
        self.pointers_left = self
            .pointers_left
            .checked_sub(1)
            .ok_or_else(|| unsupported("ZPL sparse seek exceeds pointer traversal budget"))?;
        // Match the interpretation checks in Objects::checked even when no
        // payload I/O is needed. A future-born or encrypted hole is not EOF.
        if bp.protected() {
            return Err(unsupported(
                "encrypted DMU blocks need their native pipeline",
            ));
        }
        if bp.birth() > ceiling || bp.birth() > self.objects.txg {
            return Err(corrupt(
                "DMU child birth is newer than its parent or selected TXG",
            ));
        }
        if bp.hole() {
            return Ok((!self.data).then_some(first));
        }
        let bytes = if level == 0 {
            self.node.data_bytes()
        } else {
            self.node.indirect_bytes()
        };
        if bp.birth() == 0
            || bp.level() != level
            || bp.object_type() != self.node.object_type()
            || bp.logical_bytes() != bytes
        {
            return Err(corrupt(
                "DMU block type, level or size disagrees with its dnode",
            ));
        }
        if bp.embedded()
            && (self.objects.config.version != 5000
                || !self
                    .objects
                    .config
                    .read_features
                    .iter()
                    .any(|feature| feature == "com.delphix:embedded_data"))
        {
            return Err(unsupported(
                "embedded DMU block is not declared by the selected label features",
            ));
        }
        if level == 0 {
            return Ok(self.data.then_some(first));
        }
        self.bytes_left = self
            .bytes_left
            .checked_sub(bytes)
            .ok_or_else(|| unsupported("ZPL sparse seek exceeds metadata traversal budget"))?;
        // This verifies checksum, decompression, byte order, type/level/size
        // and birth before any child pointer may influence a seek result.
        let block = self
            .objects
            .checked(self.cx, bp, self.node.object_type(), level, bytes, ceiling)?
            .ok_or_else(|| corrupt("allocated sparse-seek branch became a hole"))?;
        let fanout = (bytes / 128) as u128;
        let child_span = span / fanout;
        let start_slot = (first - base) / child_span;
        let end_slot = (end - base).div_ceil(child_span);
        for slot in start_slot..end_slot {
            checkpoint(self.cx)?;
            let at = slot as usize * 128;
            let child = BlockPointer::parse(&block.bytes[at..at + 128], block.order)
                .map_err(|error| parse(&error))?;
            if let Some(found) = self.visit(
                &child,
                level - 1,
                base + slot * child_span,
                child_span,
                block.birth,
            )? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }
}

impl Zpl {
    /// Find native logical data/hole boundaries in this immutable head/snapshot.
    /// Budget exhaustion, bad metadata and cancellation remain errors, never
    /// "no more data". Zero-filled allocated and embedded blocks count as data.
    pub fn seek(&mut self, cx: &Cx, number: u64, offset: u64, whence: SeekWhence) -> Result<u64> {
        checkpoint(cx)?;
        let data = match whence {
            SeekWhence::Data => true,
            SeekWhence::Hole => false,
            _ => return Err(errno(libc::EINVAL)),
        };
        let (object, metadata) = self.file(cx, number)?;
        if metadata.kind != Kind::Regular {
            return Err(unsupported("ZPL seek requires a regular file"));
        }
        if offset >= metadata.size {
            return Err(errno(libc::ENXIO));
        }
        let node = &object.node;
        let block_bytes = node.data_bytes() as u128;
        let first = u128::from(offset) / block_bytes;
        let file_end = u128::from(metadata.size).div_ceil(block_bytes);
        let end = (u128::from(node.max_block()) + 1).min(file_end);
        // The suffix beyond dn_maxblkid is a logical hole, not an invented tree.
        if first >= end {
            checkpoint(cx)?;
            return if data {
                Err(errno(libc::ENXIO))
            } else {
                Ok(offset)
            };
        }
        let level = node.levels() - 1;
        let fanout = (node.indirect_bytes() / 128) as u128;
        let span = fanout.pow(u32::from(level));
        let mut search = Search {
            objects: &mut self.objects,
            cx,
            node,
            first,
            end,
            data,
            pointers_left: MAX_POINTERS,
            bytes_left: MAX_METADATA_BYTES,
        };
        for (slot, bp) in node.pointers().iter().enumerate() {
            if let Some(found) =
                search.visit(bp, level, slot as u128 * span, span, object.ceiling)?
            {
                let position = (found * block_bytes).max(u128::from(offset));
                let position = u64::try_from(position)
                    .map_err(|_| corrupt("ZPL sparse seek result exceeds native file size"))?;
                checkpoint(cx)?;
                return Ok(position);
            }
        }
        checkpoint(cx)?;
        if data {
            Err(errno(libc::ENXIO))
        } else {
            // EOF is an implicit hole even when the last record is allocated.
            let position = (end * block_bytes).min(u128::from(metadata.size));
            u64::try_from(position).map_err(|_| corrupt("ZPL sparse seek result overflow"))
        }
    }
}
