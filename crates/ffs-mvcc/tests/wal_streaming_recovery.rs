#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_mvcc::wal::{WalCommit, WalWrite, encode_commit};
use ffs_mvcc::wal_replay::{ReplayOutcome, ReplayReport, TailPolicy, WalReplayEngine};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::cell::Cell;
use std::io::{Cursor, ErrorKind, Read};
use std::rc::Rc;

const CHUNK: usize = 64 * 1024;

fn record(seq: u64, bytes: usize) -> Vec<u8> {
    encode_commit(&WalCommit {
        commit_seq: CommitSeq(seq),
        txn_id: TxnId(seq),
        writes: vec![WalWrite {
            block: BlockNumber(seq),
            data: vec![0xA5; bytes],
        }],
    })
    .expect("encode")
}

fn byte_count(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

fn assert_same_report(actual: &ReplayReport, expected: &ReplayReport) {
    assert_eq!(actual.outcome, expected.outcome);
    assert_eq!(actual.commits_replayed, expected.commits_replayed);
    assert_eq!(actual.versions_replayed, expected.versions_replayed);
    assert_eq!(actual.records_discarded, expected.records_discarded);
    assert_eq!(actual.last_valid_offset, expected.last_valid_offset);
    assert_eq!(actual.total_data_bytes, expected.total_data_bytes);
    assert_eq!(actual.last_commit_seq, expected.last_commit_seq);
}

struct ShortReads<'a> {
    input: Cursor<&'a [u8]>,
    interrupt_next: bool,
    largest_request: usize,
}

impl<'a> ShortReads<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            input: Cursor::new(data),
            interrupt_next: true,
            largest_request: 0,
        }
    }
}

impl Read for ShortReads<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.largest_request = self.largest_request.max(buffer.len());
        assert!(buffer.len() <= CHUNK, "unbounded read request");
        if self.interrupt_next {
            self.interrupt_next = false;
            return Err(std::io::Error::from(ErrorKind::Interrupted));
        }
        self.interrupt_next = true;
        let len = buffer.len().min(7);
        self.input.read(&mut buffer[..len])
    }
}

fn assert_equivalent(data: &[u8], skip: u64, policy: TailPolicy) {
    let engine = WalReplayEngine::new(policy);
    let mut expected_commits = Vec::new();
    let expected = engine.replay(data, skip, |commit| expected_commits.push(commit.clone()));
    let mut actual_commits = Vec::new();
    let mut reader = ShortReads::new(data);
    let actual = engine.replay_reader(
        &Cx::for_testing(),
        &mut reader,
        byte_count(data),
        skip,
        |commit| {
            actual_commits.push(commit.clone());
            Ok(())
        },
    );
    assert_eq!(actual_commits, expected_commits);
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_same_report(&actual, &expected),
        (Err(actual), Err(expected)) => assert_eq!(actual.to_string(), expected.to_string()),
        pair => panic!("stream/slice mismatch: {pair:?}"),
    }
}

#[test]
fn streaming_matches_slice_decoder_at_every_torn_boundary_and_corrupt_byte() {
    let data: Vec<_> = (1..=3).flat_map(|seq| record(seq, 17)).collect();
    for policy in [TailPolicy::TruncateToLastGood, TailPolicy::FailFast] {
        for skip in [0, 2] {
            for cut in 0..=data.len() {
                assert_equivalent(&data[..cut], skip, policy);
            }
            for position in 0..data.len() {
                let mut corrupt = data.clone();
                corrupt[position] ^= 0xFF;
                assert_equivalent(&corrupt, skip, policy);
            }
        }
    }
}

#[test]
fn streaming_validates_zero_padding_across_chunk_boundaries() {
    let first = record(1, 19);
    let mut padded = first.clone();
    padded.resize(first.len() + CHUNK * 2 + 5, 0);
    assert_equivalent(&padded, 0, TailPolicy::TruncateToLastGood);
    let report = WalReplayEngine::new(TailPolicy::FailFast)
        .replay_reader(
            &Cx::for_testing(),
            &mut Cursor::new(&padded),
            byte_count(&padded),
            0,
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(report.last_valid_offset, byte_count(&first));
    assert_eq!(report.commits_replayed, 1);
    *padded.last_mut().unwrap() = 1;
    for policy in [TailPolicy::TruncateToLastGood, TailPolicy::FailFast] {
        assert_equivalent(&padded, 0, policy);
    }
}

#[test]
fn streaming_preserves_invariants_in_checkpoint_covered_prefixes() {
    for sequences in [[1, 3, 2], [1, 1, 2], [1, 2, u64::MAX], [0, 1, 2]] {
        let data: Vec<_> = sequences
            .into_iter()
            .flat_map(|seq| record(seq, 9))
            .collect();
        for policy in [TailPolicy::TruncateToLastGood, TailPolicy::FailFast] {
            assert_equivalent(&data, u64::MAX, policy);
        }
    }
}

#[test]
fn captured_length_excludes_later_appends() {
    let first = record(1, 32);
    let mut data = first.clone();
    data.extend(record(2, 32));
    let mut reader = Cursor::new(data);
    let report = WalReplayEngine::new(TailPolicy::FailFast)
        .replay_reader(
            &Cx::for_testing(),
            &mut reader,
            byte_count(&first),
            0,
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(report.commits_replayed, 1);
    assert_eq!(report.last_commit_seq, 1);
    assert_eq!(reader.position(), byte_count(&first));
}

struct BrokenRead<'a> {
    input: Cursor<&'a [u8]>,
    fail_at: u64,
    eof: bool,
}

impl Read for BrokenRead<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.fail_at.saturating_sub(self.input.position());
        if remaining == 0 {
            return if self.eof {
                Ok(0)
            } else {
                Err(std::io::Error::from(ErrorKind::PermissionDenied))
            };
        }
        let len = buffer.len().min(usize::try_from(remaining).unwrap());
        self.input.read(&mut buffer[..len])
    }
}

#[test]
fn io_failures_never_become_truncation_permission() {
    let mut torn = u32::MAX.to_le_bytes().to_vec();
    torn.extend([1; 30]);
    let cases = [record(1, 32), vec![0; 64], torn];
    for data in &cases {
        for eof in [false, true] {
            for policy in [TailPolicy::TruncateToLastGood, TailPolicy::FailFast] {
                let mut reader = BrokenRead {
                    input: Cursor::new(data),
                    fail_at: 7,
                    eof,
                };
                let error = WalReplayEngine::new(policy)
                    .replay_reader(&Cx::for_testing(), &mut reader, byte_count(data), 0, |_| {
                        panic!("incomplete read must never apply")
                    })
                    .unwrap_err();
                assert!(matches!(error, FfsError::Io(_)));
            }
        }
    }
}

struct CancelRead<'a> {
    cx: &'a Cx,
    input: Cursor<Vec<u8>>,
    calls: usize,
    interrupted: bool,
}

impl Read for CancelRead<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.calls += 1;
        if self.calls == 2 {
            self.cx.set_cancel_requested(true);
        }
        if self.interrupted {
            Err(std::io::Error::from(ErrorKind::Interrupted))
        } else {
            self.input.read(buffer)
        }
    }
}

#[test]
fn cancellation_during_record_padding_or_interrupted_retry_stops_without_apply() {
    for data in [record(1, CHUNK * 3), vec![0; CHUNK * 3]] {
        for interrupted in [false, true] {
            let cx = Cx::for_testing();
            let len = byte_count(&data);
            let mut reader = CancelRead {
                cx: &cx,
                input: Cursor::new(data.clone()),
                calls: 0,
                interrupted,
            };
            let error = WalReplayEngine::new(TailPolicy::TruncateToLastGood)
                .replay_reader(&cx, &mut reader, len, 0, |_| {
                    panic!("cancelled read must never apply")
                })
                .unwrap_err();
            assert!(matches!(error, FfsError::Cancelled));
            assert_eq!(reader.calls, 2);
        }
    }
}

#[test]
fn already_cancelled_empty_or_nonempty_replay_does_no_io() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    for len in [0, 500] {
        let mut reader = Cursor::new(record(1, 32));
        let error = WalReplayEngine::new(TailPolicy::TruncateToLastGood)
            .replay_reader(&cx, &mut reader, len, 0, |_| panic!("no apply"))
            .unwrap_err();
        assert!(matches!(error, FfsError::Cancelled));
        assert_eq!(reader.position(), 0);
    }
}

#[test]
fn apply_error_and_final_apply_cancellation_do_not_return_success() {
    let data: Vec<_> = (1..=2).flat_map(|seq| record(seq, 8)).collect();
    for cancel in [false, true] {
        let cx = Cx::for_testing();
        let mut applied = Vec::new();
        let result = WalReplayEngine::new(TailPolicy::TruncateToLastGood).replay_reader(
            &cx,
            &mut Cursor::new(&data),
            byte_count(&data),
            0,
            |commit| {
                applied.push(commit.commit_seq.0);
                if commit.commit_seq.0 == 2 {
                    if cancel {
                        cx.set_cancel_requested(true);
                    } else {
                        return Err(FfsError::Io(std::io::Error::other("apply failed")));
                    }
                }
                Ok(())
            },
        );
        assert_eq!(applied, [1, 2]);
        match result.unwrap_err() {
            FfsError::Cancelled => assert!(cancel),
            FfsError::Io(_) => assert!(!cancel),
            error => panic!("wrong error: {error}"),
        }
    }
}

struct GeneratedLog {
    next_seq: u64,
    count: u64,
    current: Cursor<Vec<u8>>,
    applied: Rc<Cell<u64>>,
}

impl Read for GeneratedLog {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        assert!(buffer.len() <= CHUNK);
        if self.current.position() == byte_count(self.current.get_ref()) {
            if self.next_seq > self.count {
                return Ok(0);
            }
            assert_eq!(
                self.applied.get(),
                self.next_seq - 1,
                "previous record must be applied before the next is read"
            );
            self.current = Cursor::new(record(self.next_seq, 1024));
            self.next_seq += 1;
        }
        self.current.read(buffer)
    }
}

#[test]
fn large_generated_log_is_consumed_and_applied_one_record_at_a_time() {
    let count = 10_000;
    let applied = Rc::new(Cell::new(0));
    let mut reader = GeneratedLog {
        next_seq: 1,
        count,
        current: Cursor::new(Vec::new()),
        applied: Rc::clone(&applied),
    };
    let total = byte_count(&record(1, 1024)) * count;
    let report: Result<_> = WalReplayEngine::new(TailPolicy::FailFast).replay_reader(
        &Cx::for_testing(),
        &mut reader,
        total,
        0,
        |commit| {
            assert_eq!(commit.commit_seq.0, applied.get() + 1);
            assert_eq!(commit.writes[0].data, vec![0xA5; 1024]);
            applied.set(commit.commit_seq.0);
            Ok(())
        },
    );
    let report = report.unwrap();
    assert_eq!(report.outcome, ReplayOutcome::Clean);
    assert_eq!(report.commits_replayed, count);
    assert_eq!(report.last_valid_offset, total);
    assert_eq!(report.last_commit_seq, count);
}
