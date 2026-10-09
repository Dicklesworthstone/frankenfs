use super::*;
use crate::wal::{self, HEADER_SIZE, WalWrite};
use crate::wal_replay::{TailPolicy, WalReplayEngine};
use crate::wal_writer::{SyncPolicy, WalWriterConfig};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::io::{Seek, SeekFrom};

fn commit(seq: u64, lengths: &[usize]) -> WalCommit {
    WalCommit {
        commit_seq: CommitSeq(seq),
        txn_id: TxnId(seq + 1),
        writes: lengths
            .iter()
            .enumerate()
            .map(|(index, &len)| WalWrite {
                block: BlockNumber(u64::try_from(index).unwrap()),
                data: (0..len)
                    .map(|byte| u8::try_from((byte + index) % 251).unwrap())
                    .collect(),
            })
            .collect(),
    }
}

fn legacy_bytes(commits: &[WalCommit]) -> Vec<u8> {
    commits
        .iter()
        .flat_map(|commit| wal::encode_commit(commit).unwrap())
        .collect()
}

fn prepared(commits: &[WalCommit]) -> Vec<PreparedRecord<'_>> {
    commits
        .iter()
        .map(|commit| PreparedRecord::new(commit).unwrap())
        .collect()
}

fn replay(bytes: &[u8]) -> Vec<WalCommit> {
    let mut commits = Vec::new();
    let report = WalReplayEngine::new(TailPolicy::FailFast)
        .replay(&bytes[HEADER_SIZE..], 0, |commit| {
            commits.push(commit.clone());
        })
        .unwrap();
    assert!(report.outcome.is_clean());
    commits
}

#[test]
fn stream_is_byte_identical_to_v1_across_all_field_and_chunk_boundaries() {
    let mut commits = vec![
        commit(1, &[]),
        commit(2, &[0, 1, 4, 8, 12, 21, 29]),
        commit(3, &[CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1]),
        commit(4, &[7, 0, 113]),
    ];
    // Encoding, unlike the writer, accepts arbitrary IDs and preserves input
    // order, duplicates, and empty writes. Keep the legacy format contract.
    commits[3].commit_seq = CommitSeq(u64::MAX);
    commits[3].txn_id = TxnId(u64::MAX);
    commits[3].writes[0].block = BlockNumber(42);
    commits[3].writes[1].block = BlockNumber(42);
    commits[3].writes[2].block = BlockNumber(1);
    let expected = legacy_bytes(&commits);
    let records = prepared(&commits);
    assert_eq!(
        records.iter().map(|record| record.bytes).sum::<usize>(),
        expected.len()
    );
    for size in [1, 3, 4, 7, 12, 13, 21, 25, 29, 4096, CHUNK_BYTES] {
        let mut buffer = vec![0; size];
        let mut actual = Vec::new();
        emit_chunks(&records, &mut buffer, |bytes| {
            assert_ne!(bytes, [0u8; 0]);
            assert!(bytes.len() <= size);
            actual.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
        assert_eq!(actual, expected, "chunk size {size}");
    }
}

#[test]
fn large_inputs_never_emit_an_unbounded_payload_or_batch_chunk() {
    let commits = [
        commit(1, &[CHUNK_BYTES * 17 + 13]),
        commit(2, &[CHUNK_BYTES * 3]),
    ];
    let records = prepared(&commits);
    for record in &records {
        let mut emitted = 0;
        record
            .emit(|bytes| {
                assert!(bytes.len() <= CHUNK_BYTES);
                emitted += bytes.len();
                Ok(())
            })
            .unwrap();
        assert_eq!(emitted, record.bytes);
    }
    let total = records.iter().map(|record| record.bytes).sum::<usize>();
    let mut chunks = Vec::new();
    emit_chunks(&records, &mut scratch(CHUNK_BYTES).unwrap(), |bytes| {
        chunks.push(bytes.len());
        Ok(())
    })
    .unwrap();
    assert_eq!(chunks.len(), total.div_ceil(CHUNK_BYTES));
    assert!(
        chunks[..chunks.len() - 1]
            .iter()
            .all(|&len| len == CHUNK_BYTES)
    );
    assert_eq!(chunks.iter().sum::<usize>(), total);
}

#[test]
fn tiny_batch_still_coalesces_into_one_write() {
    let commits = [commit(1, &[1]), commit(2, &[]), commit(3, &[12])];
    let records = prepared(&commits);
    let mut calls = 0;
    emit_chunks(&records, &mut scratch(CHUNK_BYTES).unwrap(), |_| {
        calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 1);
}

#[test]
fn width_and_offset_overflow_are_rejected_without_large_allocations() {
    let maximum = usize::try_from(u32::MAX).unwrap();
    assert!(layout(std::iter::repeat_n(0, maximum)).is_err());
    assert!(layout([maximum].into_iter()).is_err());
    assert!(layout([maximum - 37, 1].into_iter()).is_err());
    if let Some(too_wide) = maximum.checked_add(1) {
        assert!(layout([too_wide].into_iter()).is_err());
    }
    assert_eq!(layout([].into_iter()).unwrap(), (25, 0, 29));
    assert_eq!(layout([0, 3].into_iter()).unwrap(), (52, 2, 56));
    let largest = layout([maximum - 37].into_iter());
    if usize::BITS > 32 {
        assert_eq!(largest.unwrap(), (u32::MAX, 1, maximum + 4));
    } else {
        assert!(largest.is_err());
    }
    assert!(next_offset(u64::MAX, 1).is_err());
    assert_eq!(next_offset(u64::MAX - 29, 29).unwrap(), u64::MAX);
}

#[test]
fn sink_failure_stops_emission_and_never_flushes_from_drop() {
    let commits = [commit(1, &[CHUNK_BYTES * 3]), commit(2, &[100])];
    let records = prepared(&commits);
    let expected = legacy_bytes(&commits);
    for stop in 1..=4 {
        let mut calls = 0;
        let mut written = Vec::new();
        let result = emit_chunks(&records, &mut scratch(CHUNK_BYTES).unwrap(), |bytes| {
            calls += 1;
            if calls == stop {
                return Err(invalid("injected sink failure"));
            }
            written.extend_from_slice(bytes);
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(calls, stop);
        assert_eq!(written, expected[..(stop - 1) * CHUNK_BYTES]);
    }
}

#[test]
fn public_single_and_batch_appends_preserve_bytes_results_and_sync_policies() {
    for policy in [
        SyncPolicy::Immediate,
        SyncPolicy::EveryN(3),
        SyncPolicy::Manual,
    ] {
        for verify in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("stream.wal");
            let mut writer = WalWriter::create(
                &path,
                WalWriterConfig {
                    sync_policy: policy,
                    verify_writes: verify,
                    ..WalWriterConfig::default()
                },
            )
            .unwrap();
            let commits = [
                commit(1, &[CHUNK_BYTES + 7]),
                commit(2, &[0, CHUNK_BYTES * 2]),
                commit(3, &[113]),
            ];
            let first = writer.append_commit(&commits[0]).unwrap();
            assert_eq!(first.synced, policy == SyncPolicy::Immediate);
            let batch = writer.append_commits_coalesced(&commits[1..]).unwrap();
            assert_eq!(batch.len(), 2);
            let expected_sync = policy != SyncPolicy::Manual;
            assert!(batch.iter().all(|result| result.synced == expected_sync));
            let expected_pending = if expected_sync { 0 } else { 3 };
            assert_eq!(writer.pending_sync_count(), expected_pending);
            let mut offset = u64::try_from(HEADER_SIZE).unwrap();
            for (result, commit) in std::iter::once(&first).chain(&batch).zip(&commits) {
                let len = u64::try_from(wal::encode_commit(commit).unwrap().len()).unwrap();
                assert_eq!(result.offset, offset);
                assert_eq!(result.bytes_written, len);
                offset += len;
            }
            assert_eq!(writer.size(), offset);
            assert_eq!(writer.last_commit_seq(), 3);
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(&bytes[HEADER_SIZE..], legacy_bytes(&commits));
            assert_eq!(replay(&bytes), commits);
            assert_eq!(writer.flush().unwrap(), expected_pending);
        }
    }
}

#[test]
fn multichunk_append_failure_rolls_back_whole_batch_and_allows_exact_retry() {
    let first = commit(1, &[8]);
    let commits = [
        commit(2, &[CHUNK_BYTES + 1]),
        commit(3, &[CHUNK_BYTES + 13]),
    ];
    let total = legacy_bytes(&commits).len();
    let first_boundary = wal::encode_commit(&commits[0]).unwrap().len();
    for limit in [
        0,
        1,
        4,
        25,
        37,
        CHUNK_BYTES - 1,
        CHUNK_BYTES,
        CHUNK_BYTES + 1,
        first_boundary,
        first_boundary + 1,
        total - 1,
        total,
        total + 100,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rollback.wal");
        let mut writer = WalWriter::create(
            &path,
            WalWriterConfig {
                sync_policy: SyncPolicy::Manual,
                verify_writes: true,
                ..WalWriterConfig::default()
            },
        )
        .unwrap();
        writer.append_commit(&first).unwrap();
        let prefix = std::fs::read(&path).unwrap();
        let base = writer.size();
        writer.fail_append_after = Some(limit);
        let error = writer.append_commits_coalesced(&commits).unwrap_err();
        assert!(
            matches!(error, WalWriteError::AppendIo { bytes_attempted, .. } if bytes_attempted == total)
        );
        assert_eq!(std::fs::read(&path).unwrap(), prefix, "limit {limit}");
        assert_eq!(writer.size(), base);
        assert_eq!(writer.last_commit_seq(), 1);
        assert_eq!(writer.pending_sync_count(), 1);
        writer.ensure_ready().unwrap();
        writer.fail_append_after = None;
        writer.append_commits_coalesced(&commits).unwrap();
        assert_eq!(
            replay(&std::fs::read(&path).unwrap()),
            [first.clone(), commits[0].clone(), commits[1].clone()]
        );
    }
}

#[test]
fn sync_failure_after_all_chunks_restores_prior_pending_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sync.wal");
    let mut writer = WalWriter::create(
        &path,
        WalWriterConfig {
            sync_policy: SyncPolicy::EveryN(3),
            ..WalWriterConfig::default()
        },
    )
    .unwrap();
    writer.append_commit(&commit(1, &[8])).unwrap();
    let prefix = std::fs::read(&path).unwrap();
    let base = writer.size();
    let commits = [commit(2, &[CHUNK_BYTES * 2]), commit(3, &[CHUNK_BYTES + 7])];
    writer.fail_sync = true;
    assert!(matches!(
        writer.append_commits_coalesced(&commits),
        Err(WalWriteError::SyncIo { .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), prefix);
    assert_eq!(writer.size(), base);
    assert_eq!(writer.last_commit_seq(), 1);
    assert_eq!(writer.pending_sync_count(), 1);
    writer.ensure_ready().unwrap();
    writer.fail_sync = false;
    assert!(
        writer
            .append_commits_coalesced(&commits)
            .unwrap()
            .iter()
            .all(|result| result.synced)
    );
}

#[test]
fn uncertain_multichunk_rollback_seals_writer_without_an_implicit_retry() {
    for fail_truncate in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sealed.wal");
        let mut writer = WalWriter::create(&path, WalWriterConfig::default()).unwrap();
        writer.append_commit(&commit(1, &[8])).unwrap();
        writer.fail_append_after = Some(CHUNK_BYTES + 3);
        writer.fail_rollback_truncate = fail_truncate;
        writer.fail_rollback_sync = !fail_truncate;
        assert!(matches!(
            writer.append_commit(&commit(2, &[CHUNK_BYTES * 3])),
            Err(WalWriteError::RecoveryRequired { .. })
        ));
        let before_retry = std::fs::read(&path).unwrap();
        writer.fail_append_after = None;
        writer.fail_rollback_truncate = false;
        writer.fail_rollback_sync = false;
        assert!(matches!(
            writer.append_commit(&commit(3, &[])),
            Err(WalWriteError::RecoveryRequired { .. })
        ));
        assert!(matches!(
            writer.append_commits_coalesced(&[]),
            Err(WalWriteError::RecoveryRequired { .. })
        ));
        assert!(matches!(
            writer.flush(),
            Err(WalWriteError::RecoveryRequired { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before_retry);
    }
}

#[test]
fn late_invalid_record_and_position_overflow_do_not_write_or_truncate() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("preflight.wal");
    let mut writer = WalWriter::create(&path, WalWriterConfig::default()).unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut commits = [commit(1, &[CHUNK_BYTES * 2]), commit(2, &[])];
    commits[1].txn_id = TxnId(u64::MAX);
    assert!(matches!(
        writer.append_commits_coalesced(&commits),
        Err(WalWriteError::FormatViolation { .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    commits[1].txn_id = TxnId(3);
    writer.write_pos = u64::MAX - 4;
    assert!(matches!(
        writer.append_commits_coalesced(&commits),
        Err(WalWriteError::FormatViolation { .. })
    ));
    assert!(matches!(
        writer.append_commit(&commits[0]),
        Err(WalWriteError::FormatViolation { .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(writer.write_pos, u64::MAX - 4);
    writer.ensure_ready().unwrap();
}

#[test]
fn streaming_verification_rejects_crc_valid_substitution_without_moving_cursor() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("verify.wal");
    let mut writer = WalWriter::create(&path, WalWriterConfig::default()).unwrap();
    let expected = [commit(1, &[CHUNK_BYTES * 2 + 7]), commit(2, &[8])];
    let mut substituted = expected.clone();
    substituted[0].writes[0].data[CHUNK_BYTES] ^= 0x80;
    substituted[1].writes[0].block = BlockNumber(99);
    let actual = legacy_bytes(&substituted);
    let wanted = legacy_bytes(&expected);
    assert_ne!(actual, wanted);
    assert_eq!(crc32c::crc32c(&actual), crc32c::crc32c(&wanted));
    writer.file.write_all_at(&actual, writer.write_pos).unwrap();
    writer.file_mut().seek(SeekFrom::Start(3)).unwrap();
    let error = writer
        .verify_streamed(
            &prepared(&expected),
            &mut scratch(CHUNK_BYTES).unwrap(),
            &mut scratch(CHUNK_BYTES).unwrap(),
            actual.len(),
        )
        .unwrap_err();
    assert!(
        matches!(error, WalWriteError::VerificationFailed { expected_crc, actual_crc, offset }
        if expected_crc == actual_crc && offset == u64::try_from(HEADER_SIZE).unwrap())
    );
    assert_eq!(writer.file_mut().stream_position().unwrap(), 3);
    writer.file.write_all_at(&wanted, writer.write_pos).unwrap();
    writer
        .verify_streamed(
            &prepared(&expected),
            &mut scratch(CHUNK_BYTES).unwrap(),
            &mut scratch(CHUNK_BYTES).unwrap(),
            wanted.len(),
        )
        .unwrap();
    writer
        .file
        .set_len(writer.write_pos + u64::try_from(wanted.len()).unwrap() - 1)
        .unwrap();
    assert!(matches!(
        writer.verify_streamed(
            &prepared(&expected),
            &mut scratch(CHUNK_BYTES).unwrap(),
            &mut scratch(CHUNK_BYTES).unwrap(),
            wanted.len()
        ),
        Err(WalWriteError::AppendIo { .. })
    ));
    assert_eq!(writer.file_mut().stream_position().unwrap(), 3);
}
