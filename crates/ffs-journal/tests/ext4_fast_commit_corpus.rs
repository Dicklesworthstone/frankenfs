#![forbid(unsafe_code)]

use ffs_journal::{FcOperation, replay_fast_commit};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct FastCommitFixture {
    scenario_id: String,
    description: String,
    fast_commit_hex: String,
    expected: ExpectedReplay,
}

#[derive(Debug, Deserialize)]
struct ExpectedReplay {
    transactions_found: u64,
    last_tid: u32,
    blocks_scanned: u64,
    incomplete_transactions: u64,
    fallback_required: bool,
    operations: Vec<ExpectedOperation>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExpectedOperation {
    InodeUpdate {
        ino: u32,
    },
    AddRange {
        ino: u32,
        logical_block: u32,
        len: u32,
        physical_block: u64,
    },
    Create {
        parent_ino: u32,
        ino: u32,
        name: String,
    },
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("tests")
        .join("fixtures")
        .join("golden")
        .join(name)
}

fn load_fixture(name: &str) -> FastCommitFixture {
    let path = fixture_path(name);
    let raw = std::fs::read_to_string(&path).expect("fixture json");
    serde_json::from_str(&raw).expect("valid fixture json")
}

fn decode_hex_string(hex: &str) -> Vec<u8> {
    let compact: String = hex.chars().filter(|ch| !ch.is_whitespace()).collect();
    hex::decode(compact).expect("valid fast-commit hex payload")
}

fn assert_expected_operation(actual: &FcOperation, expected: &ExpectedOperation) {
    match (actual, expected) {
        (FcOperation::InodeUpdate(actual_ino, _raw), ExpectedOperation::InodeUpdate { ino }) => {
            assert_eq!(actual_ino, ino);
        }
        (
            FcOperation::AddRange(actual),
            ExpectedOperation::AddRange {
                ino,
                logical_block,
                len,
                physical_block,
            },
        ) => {
            assert_eq!(actual.ino, *ino);
            assert_eq!(actual.logical_block, *logical_block);
            assert_eq!(actual.len, *len);
            assert_eq!(actual.physical_block, *physical_block);
        }
        (
            FcOperation::Create(actual),
            ExpectedOperation::Create {
                parent_ino,
                ino,
                name,
            },
        ) => {
            assert_eq!(actual.parent_ino, *parent_ino);
            assert_eq!(actual.ino, *ino);
            assert_eq!(actual.name, name.as_bytes());
        }
        _ => panic!("operation mismatch: actual={actual:?} expected={expected:?}"),
    }
}

#[test]
fn fast_commit_clean_replay_fixture_matches_oracle() {
    let fixture = load_fixture("ext4_fast_commit_clean_replay.json");
    let bytes = decode_hex_string(&fixture.fast_commit_hex);
    let replay = replay_fast_commit(&bytes).expect("replay should succeed");

    assert_eq!(fixture.scenario_id, "ext4_fast_commit_clean_replay");
    assert!(
        fixture.description.contains("Committed"),
        "fixture description should explain the committed replay path"
    );
    assert_eq!(
        replay.transactions_found,
        fixture.expected.transactions_found
    );
    assert_eq!(replay.last_tid, fixture.expected.last_tid);
    assert_eq!(replay.blocks_scanned, fixture.expected.blocks_scanned);
    assert_eq!(
        replay.incomplete_transactions,
        fixture.expected.incomplete_transactions
    );
    assert_eq!(replay.fallback_required, fixture.expected.fallback_required);
    assert_eq!(replay.operations.len(), fixture.expected.operations.len());

    for (actual, expected) in replay.operations.iter().zip(&fixture.expected.operations) {
        assert_expected_operation(actual, expected);
    }
}

#[test]
fn fast_commit_missing_tail_fixture_forces_fallback() {
    let fixture = load_fixture("ext4_fast_commit_fallback_missing_tail.json");
    let bytes = decode_hex_string(&fixture.fast_commit_hex);
    let replay = replay_fast_commit(&bytes).expect("replay should succeed");

    assert_eq!(
        fixture.scenario_id,
        "ext4_fast_commit_fallback_missing_tail"
    );
    assert!(
        fixture.description.contains("truncated"),
        "fixture description should explain the fallback reason"
    );
    assert_eq!(
        replay.transactions_found,
        fixture.expected.transactions_found
    );
    assert_eq!(replay.last_tid, fixture.expected.last_tid);
    assert_eq!(replay.blocks_scanned, fixture.expected.blocks_scanned);
    assert_eq!(
        replay.incomplete_transactions,
        fixture.expected.incomplete_transactions
    );
    assert_eq!(replay.fallback_required, fixture.expected.fallback_required);
    assert!(replay.operations.is_empty());
    assert!(fixture.expected.operations.is_empty());
}
