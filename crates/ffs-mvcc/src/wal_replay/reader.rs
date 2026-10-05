//! Incremental decoding for a fixed, caller-owned WAL byte range.
//!
//! Payloads are read directly into their final allocations. The encoded record
//! is never retained alongside its decoded copy, and CRC work is checkpointed
//! in bounded chunks. No commit escapes before its complete CRC is verified.

use crate::wal::{DecodeResult, MIN_COMMIT_RECORD_SIZE, RECORD_TYPE_COMMIT, WalCommit, WalWrite};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::io::{ErrorKind, Read};

const READ_CHUNK_BYTES: usize = 64 * 1024;
const SCRATCH_BYTES: usize = 4096;
const COMMIT_HEADER_BYTES: usize = 21;
const WRITE_HEADER_BYTES: usize = 12;

pub(super) struct RecordReader<'a, R> {
    reader: &'a mut R,
    remaining: u64,
}

impl<'a, R: Read> RecordReader<'a, R> {
    pub(super) fn new(reader: &'a mut R, remaining: u64) -> Self {
        Self { reader, remaining }
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
            // An end marker cannot hide nonzero bytes later in the captured tail.
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
        let total = usize::try_from(u64::from(body_len) + 4)
            .map_err(|_| FfsError::Format("WAL record exceeds process address space".to_owned()))?;
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
            // Read the actual tail before classifying a torn record: premature
            // EOF or another I/O failure never authorizes truncating the WAL.
            self.read_tail(cx, false)?;
            return Ok((DecodeResult::NeedMore(total), None));
        }

        let mut body = RecordBody {
            reader: &mut *self.reader,
            remaining: total - 8, // Neither the length prefix nor stored CRC.
            crc: 0,
        };
        let decoded = body.decode(cx)?;
        let decoded = body.finish(cx, decoded)?;
        self.remaining -= u64::from(body_len);
        checkpoint(cx)?;
        Ok((decoded, Some(total)))
    }

    fn read_tail(&mut self, cx: &Cx, check_zero: bool) -> Result<bool> {
        let mut scratch = [0_u8; SCRATCH_BYTES];
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

/// A checksum-bounded body, excluding its stored CRC. Structural rejection is
/// provisional until `finish` consumes and checks the rest of the record. This
/// preserves checksum-first diagnostics and, more importantly, propagates an
/// I/O failure even when an earlier field was already known to be malformed.
struct RecordBody<'a, R> {
    reader: &'a mut R,
    remaining: usize,
    crc: u32,
}

impl<R: Read> RecordBody<'_, R> {
    fn read(&mut self, cx: &Cx, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() > self.remaining {
            return Err(FfsError::Format("WAL body read crosses its CRC".to_owned()));
        }
        for chunk in buffer.chunks_mut(READ_CHUNK_BYTES) {
            read_exact(cx, self.reader, chunk)?;
            self.crc = crc32c::crc32c_append(self.crc, chunk);
            self.remaining -= chunk.len();
            checkpoint(cx)?;
        }
        Ok(())
    }

    fn decode(&mut self, cx: &Cx) -> Result<DecodeResult> {
        let crc_offset = self.remaining;
        let mut header = [0_u8; COMMIT_HEADER_BYTES];
        self.read(cx, &mut header)?;
        if header[0] != RECORD_TYPE_COMMIT {
            return Ok(DecodeResult::Corrupted(format!(
                "unknown record type: {}",
                header[0]
            )));
        }
        let commit_seq = CommitSeq(u64::from_le_bytes(fixed_array(&header[1..9])?));
        let txn_id = TxnId(u64::from_le_bytes(fixed_array(&header[9..17])?));
        let num_writes = usize::try_from(u32::from_le_bytes(fixed_array(&header[17..21])?))
            .map_err(|_| FfsError::Format("WAL write count exceeds address space".to_owned()))?;
        let max_writes = self.remaining / WRITE_HEADER_BYTES;
        if num_writes > max_writes {
            return Ok(DecodeResult::Corrupted(format!(
                "num_writes ({num_writes}) exceeds body capacity ({max_writes} max)"
            )));
        }

        let mut writes = Vec::new();
        for index in 0..num_writes {
            if self.remaining < WRITE_HEADER_BYTES {
                return Ok(DecodeResult::Corrupted(format!(
                    "write {index} header extends past CRC"
                )));
            }
            let mut header = [0_u8; WRITE_HEADER_BYTES];
            self.read(cx, &mut header)?;
            let block = BlockNumber(u64::from_le_bytes(fixed_array(&header[..8])?));
            let len = usize::try_from(u32::from_le_bytes(fixed_array(&header[8..])?))
                .map_err(|_| FfsError::Format("WAL data length exceeds address space".to_owned()))?;
            if len > self.remaining {
                let offset = crc_offset - self.remaining;
                return Ok(DecodeResult::Corrupted(format!(
                    "write {index} data extends past CRC: offset={offset}, len={len}, crc_offset={crc_offset}"
                )));
            }
            // Payload and write-index allocations are fallible. Do not
            // allocate a second copy of these bytes for CRC verification.
            // Allocation failure is an error, never a discardable WAL tail.
            writes.try_reserve(1).map_err(allocation_error)?;
            let mut data = Vec::new();
            data.try_reserve_exact(len).map_err(allocation_error)?;
            while data.len() < len {
                checkpoint(cx)?;
                let start = data.len();
                let count = (len - start).min(READ_CHUNK_BYTES);
                data.resize(start + count, 0);
                self.read(cx, &mut data[start..])?;
            }
            writes.push(WalWrite { block, data });
        }
        if self.remaining != 0 {
            return Ok(DecodeResult::Corrupted(format!(
                "trailing payload bytes before CRC: {}",
                self.remaining
            )));
        }
        Ok(DecodeResult::Commit(WalCommit {
            commit_seq,
            txn_id,
            writes,
        }))
    }

    fn finish(mut self, cx: &Cx, decoded: DecodeResult) -> Result<DecodeResult> {
        let mut scratch = [0_u8; SCRATCH_BYTES];
        while self.remaining > 0 {
            let count = self.remaining.min(scratch.len());
            self.read(cx, &mut scratch[..count])?;
        }
        let mut stored = [0_u8; 4];
        read_exact(cx, self.reader, &mut stored)?;
        let stored_crc = u32::from_le_bytes(stored);
        checkpoint(cx)?;
        if stored_crc != self.crc {
            return Ok(DecodeResult::Corrupted(format!(
                "CRC mismatch: stored {stored_crc:#010x}, computed {:#010x}",
                self.crc
            )));
        }
        Ok(decoded)
    }
}

fn fixed_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| FfsError::Format("invalid fixed WAL field width".to_owned()))
}

fn allocation_error(error: std::collections::TryReserveError) -> FfsError {
    FfsError::Io(std::io::Error::other(format!(
        "cannot allocate WAL replay payload: {error}"
    )))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal;
    use std::io::Cursor;

    fn record(lengths: &[usize]) -> Vec<u8> {
        wal::encode_commit(&WalCommit {
            commit_seq: CommitSeq(7),
            txn_id: TxnId(9),
            writes: lengths
                .iter()
                .enumerate()
                .map(|(index, &len)| WalWrite {
                    block: BlockNumber(u64::try_from(index).unwrap()),
                    data: (0..len).map(|n| u8::try_from(n % 251).unwrap()).collect(),
                })
                .collect(),
        })
        .unwrap()
    }

    fn decode(bytes: &[u8]) -> DecodeResult {
        RecordReader::new(&mut Cursor::new(bytes), u64::try_from(bytes.len()).unwrap())
            .next(&Cx::for_testing())
            .unwrap()
            .0
    }

    fn assert_equivalent(bytes: &[u8]) {
        match (decode(bytes), wal::decode_commit(bytes)) {
            (DecodeResult::Commit(actual), DecodeResult::Commit(expected)) => {
                assert_eq!(actual, expected);
            }
            (DecodeResult::NeedMore(actual), DecodeResult::NeedMore(expected)) => {
                assert_eq!(actual, expected);
            }
            (DecodeResult::Corrupted(_), DecodeResult::Corrupted(_))
            | (DecodeResult::EndOfData, DecodeResult::EndOfData) => {}
            pair => panic!("stream/slice disagreement: {pair:?}"),
        }
    }

    fn restamp(bytes: &mut [u8]) {
        let end = bytes.len() - 4;
        let crc = crc32c::crc32c(&bytes[4..end]);
        bytes[end..].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn direct_payload_decode_matches_codec_across_chunk_boundaries() {
        for lengths in [
            vec![],
            vec![0, 1, 0, 7],
            vec![READ_CHUNK_BYTES - 1, READ_CHUNK_BYTES, READ_CHUNK_BYTES + 1],
            vec![READ_CHUNK_BYTES * 3 + 17],
        ] {
            assert_equivalent(&record(&lengths));
        }
    }

    #[test]
    fn direct_decode_matches_every_torn_prefix_and_corrupt_byte() {
        let bytes = record(&[0, 7, 13]);
        for end in 0..=bytes.len() {
            assert_equivalent(&bytes[..end]);
        }
        for index in 0..bytes.len() {
            let mut corrupt = bytes.clone();
            corrupt[index] ^= 0xFF;
            assert_equivalent(&corrupt);
        }
    }

    #[test]
    fn payload_is_read_directly_into_the_returned_allocation() {
        struct ObservedRead<'a> {
            input: Cursor<&'a [u8]>,
            payload: Option<*const u8>,
        }

        impl Read for ObservedRead<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                assert!(buffer.len() <= READ_CHUNK_BYTES);
                if self.input.position() == 37 {
                    self.payload = Some(buffer.as_ptr());
                }
                self.input.read(buffer)
            }
        }

        let bytes = record(&[READ_CHUNK_BYTES * 3 + 1]);
        let mut input = ObservedRead {
            input: Cursor::new(&bytes),
            payload: None,
        };
        let (decoded, size) = RecordReader::new(&mut input, u64::try_from(bytes.len()).unwrap())
            .next(&Cx::for_testing())
            .unwrap();
        let DecodeResult::Commit(commit) = decoded else {
            panic!("expected commit");
        };
        assert_eq!(size, Some(bytes.len()));
        assert_eq!(input.payload, Some(commit.writes[0].data.as_ptr()));
        assert_eq!(input.input.position(), u64::try_from(bytes.len()).unwrap());
    }

    #[test]
    fn checksummed_malformed_fields_are_rejected_without_crossing_record() {
        let base = record(&[8, 8]);
        let mut cases = Vec::new();
        let mut unknown_type = base.clone();
        unknown_type[4] = 99;
        cases.push(unknown_type);
        let mut too_many = base.clone();
        too_many[21..25].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(too_many);
        let mut too_long = base.clone();
        too_long[33..37].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(too_long);
        let mut short_header = base.clone();
        short_header[33..37].copy_from_slice(&20_u32.to_le_bytes());
        cases.push(short_header);
        let mut trailing = base;
        trailing[21..25].copy_from_slice(&0_u32.to_le_bytes());
        cases.push(trailing);
        for mut malformed in cases {
            restamp(&mut malformed);
            assert_equivalent(&malformed);
            assert!(matches!(decode(&malformed), DecodeResult::Corrupted(_)));
            let end = u64::try_from(malformed.len()).unwrap();
            let mut bytes = malformed;
            bytes.extend(record(&[3]));
            let mut input = Cursor::new(bytes);
            let total = u64::try_from(input.get_ref().len()).unwrap();
            let mut reader = RecordReader::new(&mut input, total);
            assert!(matches!(
                reader.next(&Cx::for_testing()).unwrap().0,
                DecodeResult::Corrupted(_)
            ));
            assert_eq!(reader.reader.position(), end);
            assert!(matches!(
                reader.next(&Cx::for_testing()).unwrap().0,
                DecodeResult::Commit(_)
            ));
        }
    }

    #[test]
    fn checksum_mismatch_takes_precedence_over_malformed_fields() {
        let mut bytes = record(&[READ_CHUNK_BYTES * 2 + 7]);
        bytes[4] = 99;
        let DecodeResult::Corrupted(expected) = wal::decode_commit(&bytes) else {
            panic!("expected CRC failure");
        };
        let DecodeResult::Corrupted(actual) = decode(&bytes) else {
            panic!("expected CRC failure");
        };
        assert_eq!(actual, expected);
        assert!(actual.starts_with("CRC mismatch"));
    }

    struct FailingRead<'a> {
        input: Cursor<&'a [u8]>,
        fail_at: u64,
    }

    impl Read for FailingRead<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let remaining = self.fail_at.saturating_sub(self.input.position());
            if remaining == 0 {
                return Err(std::io::Error::from(ErrorKind::PermissionDenied));
            }
            let len = buffer.len().min(usize::try_from(remaining).unwrap());
            self.input.read(&mut buffer[..len])
        }
    }

    #[test]
    fn malformed_body_does_not_hide_later_payload_or_crc_io_failure() {
        let mut bytes = record(&[SCRATCH_BYTES * 2]);
        bytes[4] = 99;
        restamp(&mut bytes);
        let total = u64::try_from(bytes.len()).unwrap();
        for fail_at in [25, 100, total - 4, total - 1] {
            let mut input = FailingRead {
                input: Cursor::new(&bytes),
                fail_at,
            };
            let error = RecordReader::new(&mut input, total)
                .next(&Cx::for_testing())
                .unwrap_err();
            assert!(
                matches!(error, FfsError::Io(error) if error.kind() == ErrorKind::PermissionDenied)
            );
        }
    }

    struct CancelAfterRead<'a> {
        input: Cursor<&'a [u8]>,
        cx: &'a Cx,
        cancel_at: u64,
        calls: usize,
    }

    impl Read for CancelAfterRead<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            assert!(buffer.len() <= READ_CHUNK_BYTES);
            self.calls += 1;
            let count = self.input.read(buffer)?;
            if self.input.position() >= self.cancel_at {
                self.cx.set_cancel_requested(true);
            }
            Ok(count)
        }
    }

    #[test]
    fn cancellation_during_payload_or_rejected_body_never_returns_a_commit() {
        for malformed in [false, true] {
            let mut bytes = record(&[READ_CHUNK_BYTES * 3]);
            if malformed {
                bytes[4] = 99;
                restamp(&mut bytes);
            }
            let cx = Cx::for_testing();
            let mut input = CancelAfterRead {
                input: Cursor::new(&bytes),
                cx: &cx,
                cancel_at: 100,
                calls: 0,
            };
            let error = RecordReader::new(&mut input, u64::try_from(bytes.len()).unwrap())
                .next(&cx)
                .unwrap_err();
            assert!(matches!(error, FfsError::Cancelled));
            assert!(input.input.position() < u64::try_from(bytes.len()).unwrap());
        }
    }
}
