//! Real-file and byte-level recovery regressions. Fixtures deliberately bypass
//! the production writer so CRC-valid invalid histories can reach the reader.

use super::*;
use crate::Snapshot;
use crate::persist::{PersistOptions, PersistentMvccStore};
use crate::wal::{self, WalCommit, WalHeader, WalWrite};
use std::io::Cursor;
use tempfile::tempdir;

#[derive(Clone)]
struct Version {
    seq: u64,
    writer: u64,
    data: Option<Vec<u8>>,
}

impl Version {
    fn full(seq: u64, data: Vec<u8>) -> Self {
        Self {
            seq,
            writer: seq,
            data: Some(data),
        }
    }

    fn identical(seq: u64) -> Self {
        Self {
            seq,
            writer: seq,
            data: None,
        }
    }
}

#[derive(Clone)]
struct Block {
    number: u64,
    versions: Vec<Version>,
}

#[derive(Clone)]
struct Fixture {
    next_txn: u64,
    next_commit: u64,
    reserved: u16,
    blocks: Vec<Block>,
}

impl Fixture {
    fn valid() -> Self {
        Self {
            next_txn: 4,
            next_commit: 4,
            reserved: 0,
            blocks: vec![
                Block {
                    number: 7,
                    versions: vec![
                        Version::full(1, vec![1; 128]),
                        Version::full(2, vec![2; 128]),
                    ],
                },
                Block {
                    number: 8,
                    versions: vec![Version::full(3, vec![3; 128])],
                },
            ],
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CHECKPOINT_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&CHECKPOINT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.reserved.to_le_bytes());
        bytes.extend_from_slice(&self.next_txn.to_le_bytes());
        bytes.extend_from_slice(&self.next_commit.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(self.blocks.len()).unwrap().to_le_bytes());
        for block in &self.blocks {
            bytes.extend_from_slice(&block.number.to_le_bytes());
            bytes.extend_from_slice(&u32::try_from(block.versions.len()).unwrap().to_le_bytes());
            for version in &block.versions {
                bytes.extend_from_slice(&version.seq.to_le_bytes());
                bytes.extend_from_slice(&version.writer.to_le_bytes());
                match &version.data {
                    Some(data) => {
                        bytes.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
                        bytes.extend_from_slice(data);
                    }
                    None => bytes.extend_from_slice(&u32::MAX.to_le_bytes()),
                }
            }
        }
        bytes.extend_from_slice(&crc32c::crc32c(&bytes).to_le_bytes());
        bytes
    }
}

fn seed_store() -> MvccStore {
    let mut store = MvccStore::new();
    let mut txn = store.begin();
    txn.stage_write(BlockNumber(99), vec![99; 16]);
    store.commit(txn).unwrap();
    store
}

fn assert_seed_unchanged(store: &MvccStore) {
    assert_eq!(store.next_txn, 2);
    assert_eq!(store.next_commit, 2);
    assert_eq!(store.version_count(), 1);
    assert_eq!(
        store
            .read_visible(BlockNumber(99), store.current_snapshot())
            .as_deref(),
        Some(&[99; 16][..])
    );
    for block in [7, 8] {
        assert!(
            store
                .read_visible(BlockNumber(block), store.current_snapshot())
                .is_none()
        );
    }
}

fn restamp(bytes: &mut [u8]) {
    let trailer = bytes.len() - 4;
    let crc = crc32c::crc32c(&bytes[..trailer]);
    bytes[trailer..].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn crc_valid_invalid_histories_never_publish_versions_or_counters() {
    let mut cases = Vec::new();
    for field in ["next_txn", "next_commit", "reserved"] {
        let mut fixture = Fixture::valid();
        match field {
            "next_txn" => fixture.next_txn = 0,
            "next_commit" => fixture.next_commit = 0,
            _ => fixture.reserved = 1,
        }
        cases.push((field, fixture));
    }
    for seq in [0, 4, u64::MAX] {
        let mut fixture = Fixture::valid();
        fixture.blocks[0].versions[0].seq = seq;
        cases.push(("invalid sequence", fixture));
    }
    for writer in [4, u64::MAX] {
        let mut fixture = Fixture::valid();
        fixture.blocks[0].versions[0].writer = writer;
        cases.push(("invalid writer", fixture));
    }
    let mut duplicate_seq = Fixture::valid();
    duplicate_seq.blocks[0].versions[1].seq = 1;
    cases.push(("duplicate sequence", duplicate_seq));
    let mut descending_seq = Fixture::valid();
    descending_seq.blocks[0].versions.swap(0, 1);
    cases.push(("descending sequence", descending_seq));
    let mut duplicate_block = Fixture::valid();
    duplicate_block.blocks[1].number = 7;
    cases.push(("duplicate block", duplicate_block));
    let mut descending_blocks = Fixture::valid();
    descending_blocks.blocks.swap(0, 1);
    cases.push(("descending blocks", descending_blocks));
    let mut empty = Fixture::valid();
    empty.blocks[0].versions.clear();
    cases.push(("empty chain", empty));
    let mut root_marker = Fixture::valid();
    root_marker.blocks[0].versions[0].data = None;
    cases.push(("root dedup marker", root_marker));

    let directory = tempdir().unwrap();
    let path = directory.path().join("invalid.ckpt");
    for (name, fixture) in cases {
        let bytes = fixture.bytes();
        let trailer = bytes.len() - 4;
        assert_eq!(
            u32::from_le_bytes(bytes[trailer..].try_into().unwrap()),
            crc32c::crc32c(&bytes[..trailer]),
            "{name} must reach semantic validation with a correct CRC"
        );
        std::fs::write(&path, &bytes).unwrap();
        let mut store = seed_store();
        let error = load_checkpoint(&Cx::for_testing(), &path, &mut store).expect_err(name);
        assert!(
            matches!(error, FfsError::Corruption { .. }),
            "{name}: {error:?}"
        );
        assert_seed_unchanged(&store);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    // Negative cases must not accidentally make every checkpoint unreadable.
    std::fs::write(&path, Fixture::valid().bytes()).unwrap();
    let mut store = MvccStore::new();
    load_checkpoint(&Cx::for_testing(), &path, &mut store).unwrap();
    assert_eq!(store.current_snapshot().high, CommitSeq(3));
    assert_eq!(store.version_count(), 3);
}

#[test]
fn every_truncation_boundary_leaves_the_destination_unchanged() {
    let bytes = Fixture::valid().bytes();
    let directory = tempdir().unwrap();
    let path = directory.path().join("truncated.ckpt");
    for end in 0..bytes.len() {
        std::fs::write(&path, &bytes[..end]).unwrap();
        let mut store = seed_store();
        assert!(
            load_checkpoint(&Cx::for_testing(), &path, &mut store).is_err(),
            "end={end}"
        );
        assert_seed_unchanged(&store);
        assert_eq!(std::fs::read(&path).unwrap(), bytes[..end]);
    }
}

#[test]
fn checksum_or_trailing_data_errors_do_not_publish_a_valid_prefix() {
    let good = Fixture::valid().bytes();
    let mut bad_crc = good.clone();
    bad_crc[60] ^= 0x80;
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"undeclared bytes");
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 1;
    restamp(&mut bad_magic);
    let mut bad_version = good;
    bad_version[4..6].copy_from_slice(&2_u16.to_le_bytes());
    restamp(&mut bad_version);
    let directory = tempdir().unwrap();
    let path = directory.path().join("rejected.ckpt");
    for bytes in [bad_crc, trailing, bad_magic, bad_version] {
        std::fs::write(&path, &bytes).unwrap();
        let mut store = seed_store();
        assert!(load_checkpoint(&Cx::for_testing(), &path, &mut store).is_err());
        assert_seed_unchanged(&store);
    }
}

#[test]
fn counts_and_lengths_are_rejected_before_payload_reads_or_large_allocations() {
    let good = Fixture::valid().bytes();
    let first_payload = CHECKPOINT_HEADER_SIZE + 12 + 20;
    let remaining_body = good.len() - 4 - first_payload;
    let mandatory_successors = 20 + 32; // one version and one nonempty block
    for (offset, value, consumed) in [
        (24, u32::MAX, 28),
        (36, u32::MAX, 40),
        (
            56,
            u32::try_from(remaining_body + 1).unwrap(),
            first_payload,
        ),
        (
            56,
            u32::try_from(remaining_body - mandatory_successors + 1).unwrap(),
            first_payload,
        ),
    ] {
        let mut bytes = good.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        restamp(&mut bytes);
        let len = bytes.len() as u64;
        let mut reader = Cursor::new(bytes);
        let error = decode_checkpoint(&Cx::for_testing(), &mut reader, len, false).unwrap_err();
        assert!(matches!(error, FfsError::Corruption { .. }));
        assert_eq!(reader.position(), consumed as u64);
    }
}

#[test]
fn large_payloads_empty_data_and_dedup_runs_restore_every_snapshot() {
    let payload = vec![0xD3; 3 * CHECKPOINT_IO_CHUNK_BYTES + 17];
    let fixture = Fixture {
        next_txn: 7,
        next_commit: 7,
        reserved: 0,
        blocks: vec![Block {
            number: 7,
            versions: vec![
                Version::full(1, payload.clone()),
                Version::identical(2),
                Version::identical(3),
                Version::full(4, payload.clone()),
                Version::full(5, Vec::new()),
                Version::identical(6),
            ],
        }],
    };
    let bytes = fixture.bytes();
    let directory = tempdir().unwrap();
    let path = directory.path().join("history.ckpt");
    std::fs::write(&path, &bytes).unwrap();
    let file = File::open(&path).unwrap();
    let cx = Cx::for_testing();
    for dedup in [false, true] {
        let mut reader = Cursor::new(&bytes);
        let decoded = decode_checkpoint(&cx, &mut reader, bytes.len() as u64, dedup).unwrap();
        assert_eq!(decoded.blocks[0].1[3].data.is_identical(), dedup);
        let mut store = MvccStore::new();
        publish_checkpoint(&cx, &file, bytes.len() as u64, decoded, &mut store).unwrap();
        assert_eq!(store.version_count(), 6);
        for seq in 1..=6 {
            let expected = if seq < 5 { payload.as_slice() } else { &[] };
            assert_eq!(
                store
                    .read_visible(
                        BlockNumber(7),
                        Snapshot {
                            high: CommitSeq(seq),
                        },
                    )
                    .as_deref(),
                Some(expected)
            );
        }
    }
}

#[test]
fn empty_and_exhausted_checkpoints_follow_the_existing_writer_contract() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("counters.ckpt");
    let mut fixture = Fixture {
        next_txn: 1,
        next_commit: 1,
        reserved: 0,
        blocks: Vec::new(),
    };
    std::fs::write(&path, fixture.bytes()).unwrap();
    let mut store = MvccStore::new();
    load_checkpoint(&Cx::for_testing(), &path, &mut store).unwrap();
    assert_eq!(store.current_snapshot().high, CommitSeq(0));
    assert_eq!(store.version_count(), 0);

    fixture.next_txn = u64::MAX;
    fixture.next_commit = u64::MAX;
    fixture.blocks.push(Block {
        number: 7,
        versions: vec![Version {
            seq: u64::MAX - 1,
            writer: 0,
            data: Some(vec![7]),
        }],
    });
    std::fs::write(&path, fixture.bytes()).unwrap();
    load_checkpoint(&Cx::for_testing(), &path, &mut store).unwrap();
    assert_eq!(store.next_txn, u64::MAX);
    assert_eq!(store.next_commit, u64::MAX);
    assert_eq!(
        store
            .read_visible(BlockNumber(7), store.current_snapshot())
            .as_deref(),
        Some(&[7][..])
    );
}

#[test]
fn invalid_checkpoint_cannot_authorize_wal_tail_repair_or_skip_commits() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("state.wal");
    let checkpoint_path = path.with_extension("ckpt");
    let cx = Cx::for_testing();
    let mut wal_bytes = wal::encode_header(&WalHeader::default()).to_vec();
    wal_bytes.extend(
        wal::encode_commit(&WalCommit {
            commit_seq: CommitSeq(4),
            txn_id: TxnId(4),
            writes: vec![WalWrite {
                block: BlockNumber(8),
                data: vec![4; 128],
            }],
        })
        .unwrap(),
    );
    let valid_wal_len = wal_bytes.len();
    wal_bytes.extend([1, 2, 3]); // recoverable WAL tail, but only after a valid checkpoint
    std::fs::write(&path, &wal_bytes).unwrap();
    let mut bad = Fixture::valid();
    bad.next_commit = 100;
    bad.blocks[0].versions[1].seq = 1; // CRC-valid duplicate version
    let bad_bytes = bad.bytes();
    std::fs::write(&checkpoint_path, &bad_bytes).unwrap();
    for mode in 0..3 {
        let result = match mode {
            0 => PersistentMvccStore::open(&cx, &path),
            1 => PersistentMvccStore::open_with_checkpoint(&cx, &path, &checkpoint_path),
            _ => PersistentMvccStore::open_with_checkpoint_and_options(
                &cx,
                &path,
                &checkpoint_path,
                &PersistOptions::default(),
            ),
        };
        assert!(matches!(result, Err(FfsError::Corruption { .. })));
        assert_eq!(std::fs::read(&path).unwrap(), wal_bytes);
        assert_eq!(std::fs::read(&checkpoint_path).unwrap(), bad_bytes);
    }
    // A valid replacement allows normal recovery, tail repair and durable writes.
    std::fs::write(&checkpoint_path, Fixture::valid().bytes()).unwrap();
    let store = PersistentMvccStore::open(&cx, &path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), valid_wal_len as u64);
    assert_eq!(store.recovery_report().commits_replayed, 1);
    assert_eq!(store.recovery_report().records_discarded, 1);
    assert_eq!(store.current_snapshot().high, CommitSeq(4));
    assert_eq!(
        store.read_visible(BlockNumber(8), store.current_snapshot()),
        Some(vec![4; 128])
    );
    let mut txn = store.begin();
    txn.stage_write(BlockNumber(9), vec![9; 16]);
    assert_eq!(store.commit(txn).unwrap(), CommitSeq(5));
    drop(store);
    let reopened = PersistentMvccStore::open(&cx, &path).unwrap();
    assert_eq!(reopened.current_snapshot().high, CommitSeq(5));
    assert_eq!(
        reopened.read_visible(BlockNumber(9), reopened.current_snapshot()),
        Some(vec![9; 16])
    );
    assert_eq!(
        reopened.read_visible(BlockNumber(7), Snapshot { high: CommitSeq(1) }),
        Some(vec![1; 128])
    );
}
