//! Validate an entire checkpoint before publishing its history or replay horizon.
//!
//! A CRC proves byte integrity, not that version chains are meaningful. Recovery
//! enforces the writer's identities, ordering and deduplication invariants too.
//! The captured file range bounds every count and payload; no checkpoint error
//! may advance counters or authorize discarding entries from the WAL.

use super::{
    BlockVersion, CHECKPOINT_HEADER_SIZE, CHECKPOINT_IO_CHUNK_BYTES, CHECKPOINT_MAGIC,
    CHECKPOINT_VERSION, CommitSeq, Crc32cHasher, MvccStore, checkpoint_corruption,
    validate_checkpoint_counters, validate_checkpoint_version,
};
use crate::compression::{VersionData, resolve_data_with};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, TxnId};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

const BLOCK_HEADER_BYTES: u64 = 12;
const VERSION_HEADER_BYTES: u64 = 20;
const MIN_BLOCK_BYTES: u64 = BLOCK_HEADER_BYTES + VERSION_HEADER_BYTES;
const CRC_BYTES: u64 = 4;

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

/// Do not hide retries inside Read::read_exact: an interrupted device may keep
/// returning EINTR after cancellation. Check the caller before every retry and
/// after every successful read, including the final checksum bytes.
fn read_checkpoint_exact(cx: &Cx, reader: &mut impl Read, mut bytes: &mut [u8]) -> Result<()> {
    while !bytes.is_empty() {
        checkpoint(cx)?;
        let requested = bytes.len().min(CHECKPOINT_IO_CHUNK_BYTES);
        match reader.read(&mut bytes[..requested]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "checkpoint ended during recovery",
                )
                .into());
            }
            Ok(count) => {
                checkpoint(cx)?;
                bytes = &mut bytes[count..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    checkpoint(cx)
}

fn same_payload(cx: &Cx, left: &[u8], right: &[u8]) -> Result<bool> {
    checkpoint(cx)?;
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .chunks(CHECKPOINT_IO_CHUNK_BYTES)
        .zip(right.chunks(CHECKPOINT_IO_CHUNK_BYTES))
    {
        checkpoint(cx)?;
        if left != right {
            return Ok(false);
        }
    }
    checkpoint(cx)?;
    Ok(true)
}

pub(super) fn load_checkpoint(cx: &Cx, path: &Path, store: &mut MvccStore) -> Result<()> {
    checkpoint(cx)?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(FfsError::Format(
            "checkpoint is not a regular file".to_owned(),
        ));
    }
    let file_len = metadata.len();
    // Bound even buffered read-ahead to the captured inode, not a reopened path.
    let mut reader = BufReader::new((&file).take(file_len));
    let decoded = decode_checkpoint(
        cx,
        &mut reader,
        file_len,
        store.compression_policy().dedup_identical,
    )?;
    publish_checkpoint(cx, &file, file_len, decoded, store)
}

#[derive(Debug)]
struct DecodedCheckpoint {
    next_txn: u64,
    next_commit: u64,
    blocks: Vec<(BlockNumber, Vec<BlockVersion>)>,
}

fn publish_checkpoint(
    cx: &Cx,
    file: &File,
    captured_len: u64,
    decoded: DecodedCheckpoint,
    store: &mut MvccStore,
) -> Result<()> {
    checkpoint(cx)?;
    let observed_len = file.metadata()?.len();
    if observed_len != captured_len {
        return Err(FfsError::Io(std::io::Error::other(format!(
            "checkpoint length changed during recovery: captured {captured_len}, observed {observed_len}"
        ))));
    }
    checkpoint(cx)?;
    // This is the publication boundary. All fallible I/O, cancellation and
    // validation are complete. Do not interrupt the following state transition.
    for (block, versions) in decoded.blocks {
        store.insert_versions(block, versions);
    }
    store.advance_counters(decoded.next_commit - 1, decoded.next_txn - 1);
    Ok(())
}

/// Counts are bounded by their minimum encoded sizes before reserving memory.
/// The trailer is never part of the available payload budget.
struct Decoder<'a, R> {
    cx: &'a Cx,
    reader: &'a mut R,
    remaining: u64,
    hasher: Crc32cHasher,
}

impl<R: Read> Decoder<'_, R> {
    fn read<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }

    fn read_into(&mut self, bytes: &mut [u8]) -> Result<()> {
        checkpoint(self.cx)?;
        let len = u64::try_from(bytes.len())
            .map_err(|_| checkpoint_corruption(BlockNumber(0), "read size overflow"))?;
        if len > self.remaining {
            return Err(checkpoint_corruption(
                BlockNumber(0),
                "fields exceed checkpoint body",
            ));
        }
        read_checkpoint_exact(self.cx, self.reader, bytes)?;
        self.hasher.update(bytes);
        self.remaining -= len;
        Ok(())
    }

    fn payload(&mut self, block: BlockNumber, len: u32, reserved: u64) -> Result<Vec<u8>> {
        checkpoint(self.cx)?;
        if self
            .remaining
            .checked_sub(reserved)
            .is_none_or(|available| u64::from(len) > available)
        {
            return Err(checkpoint_corruption(
                block,
                "data length exceeds remaining checkpoint payload",
            ));
        }
        let len = usize::try_from(len)
            .map_err(|_| checkpoint_corruption(block, "data length exceeds address space"))?;
        // Grow only as bytes are consumed, rather than allocating from an
        // untrusted length field up front. Memory still holds the decoded state.
        let mut data = Vec::new();
        while data.len() < len {
            checkpoint(self.cx)?;
            let step = (len - data.len()).min(CHECKPOINT_IO_CHUNK_BYTES);
            data.try_reserve(step)
                .map_err(|error| allocation_error(&error))?;
            let start = data.len();
            data.resize(start + step, 0);
            self.read_into(&mut data[start..])?;
        }
        Ok(data)
    }

    fn finish(self) -> Result<()> {
        checkpoint(self.cx)?;
        if self.remaining != 0 {
            return Err(checkpoint_corruption(
                BlockNumber(0),
                "checkpoint has trailing bytes after CRC or undeclared records",
            ));
        }
        let mut bytes = [0; 4];
        read_checkpoint_exact(self.cx, self.reader, &mut bytes)?;
        let stored = u32::from_le_bytes(bytes);
        let computed = self.hasher.finalize();
        if stored != computed {
            return Err(checkpoint_corruption(
                BlockNumber(0),
                &format!(
                    "checkpoint CRC mismatch: stored {stored:#010x}, computed {computed:#010x}"
                ),
            ));
        }
        Ok(())
    }
}

fn allocation_error(error: &std::collections::TryReserveError) -> FfsError {
    FfsError::Io(std::io::Error::other(format!(
        "checkpoint allocation failed: {error}"
    )))
}

fn decode_checkpoint(
    cx: &Cx,
    reader: &mut impl Read,
    file_len: u64,
    dedup: bool,
) -> Result<DecodedCheckpoint> {
    checkpoint(cx)?;
    let body_len = file_len
        .checked_sub(CRC_BYTES)
        .filter(|len| *len >= CHECKPOINT_HEADER_SIZE as u64)
        .ok_or_else(|| {
            checkpoint_corruption(
                BlockNumber(0),
                "checkpoint is shorter than its header and CRC",
            )
        })?;
    let mut decoder = Decoder {
        cx,
        reader,
        remaining: body_len,
        hasher: Crc32cHasher::new(),
    };
    let magic = u32::from_le_bytes(decoder.read()?);
    if magic != CHECKPOINT_MAGIC {
        return Err(FfsError::Format(format!(
            "checkpoint magic mismatch: expected {CHECKPOINT_MAGIC:#010x}, got {magic:#010x}"
        )));
    }
    let version = u16::from_le_bytes(decoder.read()?);
    if version != CHECKPOINT_VERSION {
        return Err(FfsError::Format(format!(
            "unsupported checkpoint version: {version}"
        )));
    }
    if decoder.read::<2>()? != [0; 2] {
        return Err(checkpoint_corruption(
            BlockNumber(0),
            "nonzero reserved checkpoint header",
        ));
    }
    let next_txn = u64::from_le_bytes(decoder.read()?);
    let next_commit = u64::from_le_bytes(decoder.read()?);
    validate_checkpoint_counters(next_txn, next_commit)?;
    let num_blocks = u32::from_le_bytes(decoder.read()?);
    if u64::from(num_blocks) > decoder.remaining / MIN_BLOCK_BYTES {
        return Err(checkpoint_corruption(
            BlockNumber(0),
            "block count exceeds checkpoint body",
        ));
    }
    let mut blocks = Vec::new();
    let mut previous_block = None;
    for index in 0..num_blocks {
        let block = BlockNumber(u64::from_le_bytes(decoder.read()?));
        if previous_block.is_some_and(|previous| previous >= block) {
            return Err(checkpoint_corruption(
                block,
                "duplicate or unordered block entry",
            ));
        }
        previous_block = Some(block);
        let future_blocks = u64::from(num_blocks - index - 1) * MIN_BLOCK_BYTES;
        let versions = decode_chain(
            &mut decoder,
            block,
            next_txn,
            next_commit,
            future_blocks,
            dedup,
        )?;
        blocks
            .try_reserve(1)
            .map_err(|error| allocation_error(&error))?;
        blocks.push((block, versions));
    }
    decoder.finish()?;
    checkpoint(cx)?;
    Ok(DecodedCheckpoint {
        next_txn,
        next_commit,
        blocks,
    })
}

fn decode_chain(
    decoder: &mut Decoder<'_, impl Read>,
    block: BlockNumber,
    next_txn: u64,
    next_commit: u64,
    future_blocks: u64,
    dedup: bool,
) -> Result<Vec<BlockVersion>> {
    let count = u32::from_le_bytes(decoder.read()?);
    if count == 0 {
        return Err(checkpoint_corruption(block, "empty version chain"));
    }
    if decoder
        .remaining
        .checked_sub(future_blocks)
        .is_none_or(|available| u64::from(count) > available / VERSION_HEADER_BYTES)
    {
        return Err(checkpoint_corruption(
            block,
            "version count exceeds checkpoint body",
        ));
    }
    let mut versions: Vec<BlockVersion> = Vec::new();
    let mut last_concrete = None;
    let mut previous_seq = None;
    for index in 0..count {
        let commit_seq = CommitSeq(u64::from_le_bytes(decoder.read()?));
        let writer = TxnId(u64::from_le_bytes(decoder.read()?));
        let data_len = u32::from_le_bytes(decoder.read()?);
        let mut version = BlockVersion {
            block,
            commit_seq,
            writer,
            data: if data_len == u32::MAX {
                VersionData::Identical
            } else {
                VersionData::full(Vec::new())
            },
        };
        validate_checkpoint_version(block, &version, previous_seq, next_txn, next_commit)?;
        previous_seq = Some(commit_seq.0);
        if data_len != u32::MAX {
            let reserved = future_blocks + u64::from(count - index - 1) * VERSION_HEADER_BYTES;
            let data = decoder.payload(block, data_len, reserved)?;
            // Resolve only the last concrete version. Walking backward over
            // an ever-growing run of dedup markers would be quadratic.
            let identical = if dedup && let Some(last) = last_concrete {
                let previous = resolve_data_with(&versions, last, |v: &BlockVersion| &v.data)
                    .ok_or_else(|| checkpoint_corruption(block, "dedup base is unreadable"))?;
                same_payload(decoder.cx, &previous, &data)?
            } else {
                false
            };
            version.data = if identical {
                VersionData::Identical
            } else {
                VersionData::full(data)
            };
        }
        if !version.data.is_identical() {
            last_concrete = Some(versions.len());
        }
        versions
            .try_reserve(1)
            .map_err(|error| allocation_error(&error))?;
        versions.push(version);
    }
    Ok(versions)
}

#[cfg(test)]
#[path = "checkpoint_reader/tests.rs"]
mod tests;
