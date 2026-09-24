//! Incremental framing for a fixed, caller-owned WAL byte range.

use crate::wal::{self, DecodeResult, MIN_COMMIT_RECORD_SIZE};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use std::io::{ErrorKind, Read};

const READ_CHUNK_BYTES: usize = 64 * 1024;

pub(super) struct RecordReader<'a, R> {
    reader: &'a mut R,
    remaining: u64,
    record: Vec<u8>,
}

impl<'a, R: Read> RecordReader<'a, R> {
    pub(super) fn new(reader: &'a mut R, remaining: u64) -> Self {
        Self {
            reader,
            remaining,
            record: Vec::new(),
        }
    }

    pub(super) fn next(&mut self, cx: &Cx) -> Result<(DecodeResult, Option<usize>)> {
        checkpoint(cx)?;
        if self.remaining == 0 {
            return Ok((DecodeResult::EndOfData, None));
        }
        let mut header = [0_u8; 4];
        if self.remaining < 4 {
            let len = usize::try_from(self.remaining)
                .map_err(|_| FfsError::Format("WAL header length overflow".to_owned()))?;
            read_exact(cx, self.reader, &mut header[..len])?;
            self.remaining = 0;
            return Ok((DecodeResult::NeedMore(4), None));
        }
        read_exact(cx, self.reader, &mut header)?;
        self.remaining -= 4;
        let body_len = u32::from_le_bytes(header);
        if body_len == 0 {
            // A zero prefix is an end marker only if the ENTIRE captured tail
            // is zero. Looking at just this four-byte header hides later data.
            let all_zero = self.read_tail(cx, true)?;
            return Ok((
                if all_zero {
                    DecodeResult::EndOfData
                } else {
                    DecodeResult::Corrupted(
                        "zero record length followed by non-zero tail".to_owned(),
                    )
                },
                None,
            ));
        }
        let total = usize::try_from(u64::from(body_len) + 4).map_err(|_| {
            FfsError::Format("WAL record exceeds process address space".to_owned())
        })?;
        if total < MIN_COMMIT_RECORD_SIZE {
            return Ok((
                DecodeResult::Corrupted(format!(
                    "record length too small: {body_len} < {}",
                    MIN_COMMIT_RECORD_SIZE - 4
                )),
                None,
            ));
        }
        if u64::from(body_len) > self.remaining {
            // Do not reserve memory from an untrusted length before checking
            // the captured file range. Consume the actual tail in bounded
            // chunks so an I/O failure cannot masquerade as a torn record.
            self.read_tail(cx, false)?;
            return Ok((DecodeResult::NeedMore(total), None));
        }

        self.record.clear();
        self.record.try_reserve_exact(total).map_err(|error| {
            FfsError::Io(std::io::Error::other(format!(
                "cannot allocate WAL replay record ({total} bytes): {error}"
            )))
        })?;
        self.record.extend_from_slice(&header);
        while self.record.len() < total {
            checkpoint(cx)?;
            let start = self.record.len();
            let count = (total - start).min(READ_CHUNK_BYTES);
            self.record.resize(start + count, 0);
            read_exact(cx, self.reader, &mut self.record[start..])?;
            self.remaining -= u64::try_from(count).unwrap_or(u64::MAX);
        }
        checkpoint(cx)?;
        let decoded = wal::decode_commit(&self.record);
        checkpoint(cx)?;
        Ok((decoded, Some(total)))
    }

    fn read_tail(&mut self, cx: &Cx, check_zero: bool) -> Result<bool> {
        let mut scratch = [0_u8; READ_CHUNK_BYTES];
        let mut all_zero = true;
        while self.remaining > 0 {
            let count = usize::try_from(self.remaining)
                .unwrap_or(usize::MAX)
                .min(scratch.len());
            read_exact(cx, self.reader, &mut scratch[..count])?;
            self.remaining -= u64::try_from(count).unwrap_or(u64::MAX);
            if check_zero && scratch[..count].iter().any(|&byte| byte != 0) {
                all_zero = false;
            }
        }
        checkpoint(cx)?;
        Ok(all_zero)
    }
}

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn read_exact<R: Read>(cx: &Cx, reader: &mut R, mut buffer: &mut [u8]) -> Result<()> {
    while !buffer.is_empty() {
        checkpoint(cx)?;
        let count = match reader.read(buffer) {
            Ok(0) => {
                return Err(FfsError::Io(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "WAL ended before its captured length",
                )));
            }
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(FfsError::Io(error)),
        };
        checkpoint(cx)?;
        buffer = &mut buffer[count..];
    }
    Ok(())
}
