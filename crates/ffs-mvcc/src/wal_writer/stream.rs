//! Bounded-memory WAL encoding and append, without a second copy of payloads.
//!
//! A batch is preflighted in full before any I/O. The immutable record borrows
//! keep that layout valid for both encoding and byte-for-byte readback. The
//! chunk buffer has no Drop implementation and never flushes after an error:
//! rollback must remain the last write performed by a failed append.

use super::{AppendResult, WalWriteError, WalWriter};
use crate::wal::{MIN_COMMIT_RECORD_SIZE, RECORD_TYPE_COMMIT, WalCommit};
use std::collections::TryReserveError;
use std::os::unix::fs::FileExt;
use tracing::{debug, error, info, warn};

type WriteResult<T> = std::result::Result<T, WalWriteError>;
const CHUNK_BYTES: usize = 64 * 1024;
const BODY_HEADER_BYTES: usize = 21;
const WRITE_HEADER_BYTES: u32 = 12;

fn invalid(detail: &str) -> WalWriteError {
    WalWriteError::FormatViolation {
        detail: detail.to_owned(),
    }
}

fn allocation_error(error: &TryReserveError, bytes_attempted: usize) -> WalWriteError {
    // No storage has been touched when these allocations fail.
    WalWriteError::AppendIo {
        source: std::io::Error::other(format!("WAL streaming allocation failed: {error}")),
        bytes_attempted,
    }
}

fn scratch(size: usize) -> WriteResult<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|error| allocation_error(&error, size))?;
    bytes.resize(size, 0);
    Ok(bytes)
}

/// Validate the wire widths before allocating or visiting any payload bytes.
/// Accepting lengths separately lets tests cover overflow without giant inputs.
fn layout(lengths: impl ExactSizeIterator<Item = usize>) -> WriteResult<(u32, u32, usize)> {
    let count = u32::try_from(lengths.len()).map_err(|_| invalid("too many WAL writes"))?;
    let minimum_body = u32::try_from(MIN_COMMIT_RECORD_SIZE - 4)
        .map_err(|_| invalid("WAL minimum record size exceeds u32"))?;
    let mut body = count
        .checked_mul(WRITE_HEADER_BYTES)
        .and_then(|bytes| bytes.checked_add(minimum_body))
        .ok_or_else(|| invalid("WAL write headers exceed record length limit"))?;
    for len in lengths {
        let len = u32::try_from(len).map_err(|_| invalid("WAL write length exceeds u32"))?;
        body = body
            .checked_add(len)
            .ok_or_else(|| invalid("WAL record length exceeds u32"))?;
    }
    let bytes = usize::try_from(body)
        .ok()
        .and_then(|body| body.checked_add(4))
        .ok_or_else(|| invalid("WAL record exceeds process address space"))?;
    Ok((body, count, bytes))
}

struct PreparedRecord<'a> {
    commit: &'a WalCommit,
    body: u32,
    count: u32,
    bytes: usize,
}

impl<'a> PreparedRecord<'a> {
    fn new(commit: &'a WalCommit) -> WriteResult<Self> {
        let (body, count, bytes) = layout(commit.writes.iter().map(|write| write.data.len()))?;
        Ok(Self {
            commit,
            body,
            count,
            bytes,
        })
    }

    /// Emit exactly the existing v1 format. CRC covers the body, not the length
    /// prefix or the stored CRC itself. Input write order is unchanged.
    fn emit(&self, mut sink: impl FnMut(&[u8]) -> WriteResult<()>) -> WriteResult<()> {
        sink(&self.body.to_le_bytes())?;
        let mut header = [0; BODY_HEADER_BYTES];
        header[0] = RECORD_TYPE_COMMIT;
        header[1..9].copy_from_slice(&self.commit.commit_seq.0.to_le_bytes());
        header[9..17].copy_from_slice(&self.commit.txn_id.0.to_le_bytes());
        header[17..21].copy_from_slice(&self.count.to_le_bytes());
        let mut crc = crc32c::crc32c(&header);
        sink(&header)?;
        for write in &self.commit.writes {
            let len = u32::try_from(write.data.len())
                .map_err(|_| invalid("preflighted WAL write length changed"))?;
            let mut header = [0; 12];
            header[..8].copy_from_slice(&write.block.0.to_le_bytes());
            header[8..].copy_from_slice(&len.to_le_bytes());
            crc = crc32c::crc32c_append(crc, &header);
            sink(&header)?;
            for bytes in write.data.chunks(CHUNK_BYTES) {
                crc = crc32c::crc32c_append(crc, bytes);
                sink(bytes)?;
            }
        }
        sink(&crc.to_le_bytes())
    }
}

/// Coalesce small headers and records into bounded writes. Unlike BufWriter,
/// this function cannot retry buffered writes from Drop after rollback.
fn emit_chunks(
    records: &[PreparedRecord<'_>],
    buffer: &mut [u8],
    mut sink: impl FnMut(&[u8]) -> WriteResult<()>,
) -> WriteResult<()> {
    if buffer.is_empty() {
        return Err(invalid("empty WAL streaming buffer"));
    }
    let mut used = 0;
    for record in records {
        record.emit(|mut bytes| {
            while !bytes.is_empty() {
                let count = bytes.len().min(buffer.len() - used);
                buffer[used..used + count].copy_from_slice(&bytes[..count]);
                used += count;
                bytes = &bytes[count..];
                if used == buffer.len() {
                    sink(buffer)?;
                    used = 0;
                }
            }
            Ok(())
        })?;
    }
    if used != 0 {
        sink(&buffer[..used])?;
    }
    Ok(())
}

fn next_offset(offset: u64, bytes: usize) -> WriteResult<u64> {
    u64::try_from(bytes)
        .ok()
        .and_then(|bytes| offset.checked_add(bytes))
        .ok_or_else(|| invalid("WAL write position overflowed"))
}

impl WalWriter {
    fn check_stream_backpressure(&self, op_id: u64) -> WriteResult<()> {
        if self.is_backpressured() {
            warn!(
                operation_id = op_id,
                wal_size = self.write_pos,
                threshold = self.config.backpressure_threshold_bytes,
                "wal_backpressure"
            );
            return Err(WalWriteError::Backpressure {
                wal_size: self.write_pos,
                threshold: self.config.backpressure_threshold_bytes,
            });
        }
        Ok(())
    }

    pub(super) fn append_one_streamed(&mut self, commit: &WalCommit) -> WriteResult<AppendResult> {
        self.ensure_ready()?;
        let op_id = self.next_op_id();
        self.validate_coalesced_commits(std::slice::from_ref(commit))?;
        self.check_stream_backpressure(op_id)?;
        let record = PreparedRecord::new(commit)?;
        let mut results = [AppendResult {
            offset: self.write_pos,
            bytes_written: u64::try_from(record.bytes)
                .map_err(|_| invalid("WAL record length exceeds u64"))?,
            synced: false,
            pending_sync_count: 0,
        }];
        debug!(
            operation_id = op_id,
            commit_seq = commit.commit_seq.0,
            txn_id = commit.txn_id.0,
            num_writes = commit.writes.len(),
            "wal_append_start"
        );
        let total = record.bytes;
        self.append_prepared_streamed(&[record], &mut results, total, op_id)?;
        let result = results[0];
        info!(
            operation_id = op_id,
            commit_seq = commit.commit_seq.0,
            txn_id = commit.txn_id.0,
            bytes_written = result.bytes_written,
            offset = result.offset,
            synced = result.synced,
            "wal_append_ok"
        );
        Ok(result)
    }

    pub(super) fn append_many_streamed(
        &mut self,
        commits: &[WalCommit],
    ) -> WriteResult<Vec<AppendResult>> {
        self.ensure_ready()?;
        if commits.is_empty() {
            return Ok(Vec::new());
        }
        let op_id = self.next_op_id();
        self.validate_coalesced_commits(commits)?;
        self.check_stream_backpressure(op_id)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(commits.len())
            .map_err(|error| allocation_error(&error, 0))?;
        let mut results = Vec::new();
        // Allocate results BEFORE appending: allocation failure must never turn
        // a durable success into an unacknowledged or panicking return path.
        results
            .try_reserve_exact(commits.len())
            .map_err(|error| allocation_error(&error, 0))?;
        let mut total = 0usize;
        let mut offset = self.write_pos;
        for commit in commits {
            let record = PreparedRecord::new(commit)?;
            let end = next_offset(offset, record.bytes)?;
            total = total
                .checked_add(record.bytes)
                .ok_or_else(|| invalid("WAL batch exceeds process address space"))?;
            results.push(AppendResult {
                offset,
                bytes_written: end - offset,
                synced: false,
                pending_sync_count: 0,
            });
            records.push(record);
            offset = end;
        }
        debug!(
            operation_id = op_id,
            num_commits = commits.len(),
            total_bytes = total,
            "wal_coalesced_append_start"
        );
        self.append_prepared_streamed(&records, &mut results, total, op_id)?;
        info!(
            operation_id = op_id,
            num_commits = commits.len(),
            total_bytes = total,
            synced = results[0].synced,
            "wal_coalesced_append_ok"
        );
        Ok(results)
    }

    fn append_prepared_streamed(
        &mut self,
        records: &[PreparedRecord<'_>],
        results: &mut [AppendResult],
        total: usize,
        op_id: u64,
    ) -> WriteResult<()> {
        let Some(last) = records.last() else {
            return Err(invalid("empty prepared WAL append"));
        };
        let base = self.write_pos;
        let end = next_offset(base, total)?;
        let pending_before = self.appends_since_sync;
        let mut encoded = scratch(total.min(CHUNK_BYTES))?;
        let mut readback = if self.config.verify_writes {
            scratch(encoded.len())?
        } else {
            Vec::new()
        };
        #[cfg(test)]
        if self.fail_append {
            return Err(WalWriteError::AppendIo {
                source: std::io::Error::other("injected append failure"),
                bytes_attempted: total,
            });
        }
        if let Err(error) = self.write_streamed(records, &mut encoded, total) {
            error!(operation_id = op_id, error = %error, "wal_stream_append_err");
            return Err(self.rollback_failed_append(base, pending_before, error));
        }
        if self.config.verify_writes
            && let Err(error) = self.verify_streamed(records, &mut encoded, &mut readback, total)
        {
            return Err(self.rollback_failed_append(base, pending_before, error));
        }
        self.write_pos = end;
        self.increment_pending_sync_count(u32::try_from(records.len()).unwrap_or(u32::MAX));
        let synced = match self.maybe_sync(op_id, last.commit.commit_seq.0) {
            Ok(synced) => synced,
            Err(error) => return Err(self.rollback_failed_append(base, pending_before, error)),
        };
        self.last_commit_seq = last.commit.commit_seq.0;
        for result in results {
            result.synced = synced;
            result.pending_sync_count = self.appends_since_sync;
        }
        Ok(())
    }

    /// Never publish intermediate cursors. An error in any chunk is rolled
    /// back by the caller to the start of the entire record or batch.
    fn write_streamed(
        &self,
        records: &[PreparedRecord<'_>],
        buffer: &mut [u8],
        total: usize,
    ) -> WriteResult<()> {
        let mut offset = self.write_pos;
        #[cfg(test)]
        let mut remaining_before_failure = self.fail_append_after.map(|limit| limit.min(total));
        emit_chunks(records, buffer, |bytes| {
            #[cfg(test)]
            if let Some(remaining) = &mut remaining_before_failure {
                let count = bytes.len().min(*remaining);
                self.file
                    .write_all_at(&bytes[..count], offset)
                    .map_err(|source| WalWriteError::AppendIo {
                        source,
                        bytes_attempted: total,
                    })?;
                *remaining -= count;
                offset = next_offset(offset, count)?;
                if *remaining == 0 {
                    return Err(WalWriteError::AppendIo {
                        source: std::io::Error::other("injected failure after partial append"),
                        bytes_attempted: total,
                    });
                }
                return Ok(());
            }
            self.file
                .write_all_at(bytes, offset)
                .map_err(|source| WalWriteError::AppendIo {
                    source,
                    bytes_attempted: total,
                })?;
            offset = next_offset(offset, bytes.len())?;
            Ok(())
        })
    }

    /// Re-encode borrowed inputs into bounded expected chunks after ALL writes
    /// finish. Compare bytes, not just the CRC residue of a self-checksummed
    /// record. Positional reads do not disturb the shared file cursor.
    fn verify_streamed(
        &self,
        records: &[PreparedRecord<'_>],
        expected: &mut [u8],
        readback: &mut [u8],
        total: usize,
    ) -> WriteResult<()> {
        next_offset(self.write_pos, total)?;
        if readback.len() < expected.len() {
            return Err(invalid("short WAL readback scratch buffer"));
        }
        let mut offset = self.write_pos;
        let mut equal = true;
        let mut expected_crc = 0;
        let mut actual_crc = 0;
        emit_chunks(records, expected, |bytes| {
            let actual = &mut readback[..bytes.len()];
            self.file
                .read_exact_at(actual, offset)
                .map_err(|source| WalWriteError::AppendIo {
                    source,
                    bytes_attempted: total,
                })?;
            equal &= actual == bytes;
            expected_crc = crc32c::crc32c_append(expected_crc, bytes);
            actual_crc = crc32c::crc32c_append(actual_crc, actual);
            offset = next_offset(offset, bytes.len())?;
            Ok(())
        })?;
        if !equal {
            return Err(WalWriteError::VerificationFailed {
                expected_crc,
                actual_crc,
                offset: self.write_pos,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
