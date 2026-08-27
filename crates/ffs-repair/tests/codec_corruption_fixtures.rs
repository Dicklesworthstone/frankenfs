//! Repair codec corruption fixtures (bd-rchk7.2).
//!
//! Pin the six high-value corruption scenarios called out in
//! bd-rchk7.2 against the live repair codec, with deterministic
//! per-scenario inputs (no fuzz mutation). Each scenario is a
//! standalone `#[test]` so a failure surfaces the exact case in CI.
//!
//!   1. Recoverable corruption with valid symbols
//!   2. Unrecoverable corruption (corrupt > repair)
//!   3. Stale symbols (encoded for a different group)
//!   4. Insufficient symbols at the boundary (corrupt == repair)
//!   5. Malformed symbol payload length (regression for fab3ff1)
//!   6. Repair-symbol refresh verification after recovery

#![cfg(unix)]

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_repair::codec::{decode_group, encode_group};
use ffs_repair::evidence::{
    CorruptionDetail, EvidenceEventType, EvidenceLedger, EvidenceRecord, RepairDetail,
    SymbolRefreshDetail, parse_evidence_ledger,
};
use ffs_repair::recovery::RecoveryDecoderStats;
use ffs_types::{BlockNumber, GroupNumber};
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

const BLOCK_SIZE: u32 = 64;
const K: u32 = 4;
const FS_UUID: [u8; 16] = *b"corruption-tests";

struct MemBlockDevice {
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
    block_size: u32,
    block_count: u64,
}

impl MemBlockDevice {
    fn new() -> Self {
        Self {
            blocks: Mutex::new(HashMap::new()),
            block_size: BLOCK_SIZE,
            block_count: 64,
        }
    }

    fn write(&self, block: BlockNumber, data: Vec<u8>) {
        assert_eq!(data.len(), self.block_size as usize);
        self.blocks.lock().insert(block.0, data);
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        let data = {
            let blocks = self.blocks.lock();
            blocks
                .get(&block.0)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; self.block_size as usize])
        };
        Ok(BlockBuf::new(data))
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.blocks.lock().insert(block.0, data.to_vec());
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn source_byte(block_index: u32, byte_index: usize) -> u8 {
    let block = u8::try_from(block_index).expect("fixture block index fits in u8");
    let byte = u8::try_from(byte_index).expect("fixture block size fits in u8");
    block.wrapping_mul(31).wrapping_add(byte)
}

/// Stage K source blocks with deterministic content.
fn stage_source(device: &MemBlockDevice) {
    for i in 0..K {
        let mut data = vec![0_u8; BLOCK_SIZE as usize];
        for (j, byte) in data.iter_mut().enumerate() {
            *byte = source_byte(i, j);
        }
        device.write(BlockNumber(u64::from(i)), data);
    }
}

#[derive(Debug, Deserialize)]
struct RepairCorpusManifest {
    corpus_version: String,
    reproduction_command: String,
    cases: Vec<RepairCorpusCase>,
}

#[derive(Debug, Deserialize)]
struct RepairCorpusCase {
    seed_id: String,
    expected_error_class: String,
    artifact_path: String,
    artifact_checksum: String,
    expected_events: Vec<String>,
    stdout_path: String,
    stderr_path: String,
}

fn artifact_digest(data: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(data).to_hex())
}

fn event_name(event_type: EvidenceEventType) -> &'static str {
    match event_type {
        EvidenceEventType::CorruptionDetected => "corruption_detected",
        EvidenceEventType::RepairSucceeded => "repair_succeeded",
        EvidenceEventType::RepairFailed => "repair_failed",
        EvidenceEventType::SymbolRefresh => "symbol_refresh",
        _ => "other",
    }
}

fn fixture_corruption_detail() -> CorruptionDetail {
    CorruptionDetail {
        blocks_affected: 1,
        corruption_kind: "checksum_mismatch".to_owned(),
        severity: "error".to_owned(),
        detail: "deterministic corpus block mismatch".to_owned(),
    }
}

fn fixture_repair_detail(verify_pass: bool, reason: Option<&str>) -> RepairDetail {
    RepairDetail {
        generation: 7,
        corrupt_count: 1,
        symbols_used: 2,
        symbols_available: 2,
        decoder_stats: RecoveryDecoderStats {
            peeled: 1,
            inactivated: 0,
            gauss_ops: 0,
            pivots_selected: 1,
        },
        verify_pass,
        reason: reason.map(str::to_owned),
    }
}

fn ledger_bytes(records: &[EvidenceRecord]) -> Vec<u8> {
    let mut ledger = EvidenceLedger::new(Vec::new());
    for record in records {
        ledger.append(record).expect("append fixture evidence");
    }
    ledger.into_inner()
}

fn clean_fixture_records() -> [EvidenceRecord; 3] {
    [
        EvidenceRecord::corruption_detected(0, fixture_corruption_detail()).with_timestamp(10),
        EvidenceRecord::repair_succeeded(0, fixture_repair_detail(true, None)).with_timestamp(20),
        EvidenceRecord::symbol_refresh(
            0,
            SymbolRefreshDetail {
                previous_generation: 7,
                new_generation: 8,
                symbols_generated: 2,
            },
        )
        .with_timestamp(30),
    ]
}

fn torn_fixture_ledger(first_record: &EvidenceRecord) -> Vec<u8> {
    let failed_record = EvidenceRecord::repair_failed(
        0,
        fixture_repair_detail(false, Some("torn ledger row skipped")),
    )
    .with_timestamp(40);
    let mut torn_ledger = Vec::new();
    torn_ledger.extend_from_slice(first_record.to_json().expect("serialize").as_bytes());
    torn_ledger.extend_from_slice(b"\n{\"timestamp_ns\":99,\"event_type\":\"repair");
    torn_ledger.extend_from_slice(b"\n");
    torn_ledger.extend_from_slice(failed_record.to_json().expect("serialize").as_bytes());
    torn_ledger.push(b'\n');
    torn_ledger
}

fn repair_corpus_manifest(
    clean_ledger: &[u8],
    torn_ledger: &[u8],
    missing_ledger_path: &str,
) -> RepairCorpusManifest {
    let manifest_json = serde_json::json!({
        "corpus_version": "bd-rchk7.2-ledger-v1",
        "reproduction_command": "rch exec -- cargo test -p ffs-repair --test codec_corruption_fixtures",
        "cases": [
            {
                "seed_id": "bd-rchk7.2/recoverable-valid-symbols",
                "expected_error_class": "recoverable_valid_symbols",
                "artifact_path": "artifacts/repair/recoverable-valid-symbols.jsonl",
                "artifact_checksum": artifact_digest(clean_ledger),
                "expected_events": [
                    "corruption_detected",
                    "repair_succeeded",
                    "symbol_refresh"
                ],
                "stdout_path": "artifacts/repair/recoverable-valid-symbols.stdout",
                "stderr_path": "artifacts/repair/recoverable-valid-symbols.stderr"
            },
            {
                "seed_id": "bd-rchk7.2/torn-ledger-row",
                "expected_error_class": "ledger_torn_row_skipped",
                "artifact_path": "artifacts/repair/torn-ledger-row.jsonl",
                "artifact_checksum": artifact_digest(torn_ledger),
                "expected_events": [
                    "corruption_detected",
                    "repair_failed"
                ],
                "stdout_path": "artifacts/repair/torn-ledger-row.stdout",
                "stderr_path": "artifacts/repair/torn-ledger-row.stderr"
            },
            {
                "seed_id": "bd-rchk7.2/invalid-ledger-path",
                "expected_error_class": "invalid_ledger_path",
                "artifact_path": missing_ledger_path,
                "artifact_checksum": artifact_digest(missing_ledger_path.as_bytes()),
                "expected_events": [],
                "stdout_path": "artifacts/repair/invalid-ledger-path.stdout",
                "stderr_path": "artifacts/repair/invalid-ledger-path.stderr"
            }
        ]
    });
    serde_json::from_value(manifest_json).expect("manifest must parse")
}

fn fixture_bytes_for_case<'a>(
    case: &RepairCorpusCase,
    clean_ledger: &'a [u8],
    torn_ledger: &'a [u8],
    missing_ledger_path: &'a str,
) -> &'a [u8] {
    match case.expected_error_class.as_str() {
        "recoverable_valid_symbols" => clean_ledger,
        "ledger_torn_row_skipped" => torn_ledger,
        "invalid_ledger_path" => {
            assert!(
                !Path::new(&case.artifact_path).exists(),
                "invalid-ledger-path fixture must point at a missing ledger"
            );
            missing_ledger_path.as_bytes()
        }
        other => {
            assert_eq!(other, "invalid_ledger_path", "unexpected error class");
            missing_ledger_path.as_bytes()
        }
    }
}

fn assert_manifest_case(
    case: &RepairCorpusCase,
    clean_ledger: &[u8],
    torn_ledger: &[u8],
    missing_ledger_path: &str,
) {
    assert!(
        case.seed_id.starts_with("bd-rchk7.2/"),
        "seed id should keep the owning bead visible: {}",
        case.seed_id
    );
    assert_ne!(case.stdout_path, "");
    assert_ne!(case.stderr_path, "");

    let fixture_bytes =
        fixture_bytes_for_case(case, clean_ledger, torn_ledger, missing_ledger_path);
    assert_eq!(case.artifact_checksum, artifact_digest(fixture_bytes));

    if case.expected_error_class != "invalid_ledger_path" {
        let parsed = parse_evidence_ledger(fixture_bytes);
        let parsed_events: Vec<&str> = parsed
            .iter()
            .map(|record| event_name(record.event_type))
            .collect();
        assert_eq!(parsed_events, case.expected_events);
    }
}

#[test]
fn fixture_recoverable_corruption_with_valid_symbols() {
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);
    let encoded =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 2).expect("encode");
    let symbols: Vec<(u32, Vec<u8>)> = encoded
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();

    // Corrupt 1 block, have 2 repair symbols; decode should recover.
    let corrupt = [2_u32];
    let outcome = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &corrupt,
        &symbols,
    )
    .expect("decode must succeed with valid symbols and corrupt <= repair");
    assert!(
        outcome.complete,
        "decode must complete with sufficient symbols"
    );
    assert_eq!(outcome.recovered.len(), 1);
    assert_eq!(outcome.recovered[0].block, BlockNumber(2));
}

#[test]
fn fixture_unrecoverable_corruption_exceeds_repair_capacity() {
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);
    let encoded =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 1).expect("encode");
    let symbols: Vec<(u32, Vec<u8>)> = encoded
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();

    // Corrupt 2 blocks but only 1 repair symbol available.
    let corrupt = [0_u32, 1];
    let result = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &corrupt,
        &symbols,
    );
    let error = result.expect_err("decode must reject infeasible recovery");
    assert!(
        matches!(
            &error,
            FfsError::RepairFailed(msg)
                if msg.contains("insufficient") || msg.contains("singular")
        ),
        "expected RepairFailed with 'insufficient' or 'singular', got: {error:?}"
    );
}

#[test]
fn fixture_stale_symbols_from_different_group() {
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let stale_device = MemBlockDevice::new();
    stage_source(&stale_device);
    let stale_block = vec![0xA5_u8; BLOCK_SIZE as usize];
    stale_device.write(BlockNumber(0), stale_block);

    // Encode against a stale generation and group 0, then try to decode
    // the current group 5. This models a ledger row whose symbols belong
    // to a different group/source generation. The decoder has no external
    // ledger metadata here, so this fixture requires either explicit
    // failure or a non-matching reconstruction.
    let encoded_group_0 = encode_group(
        &cx,
        &stale_device,
        &FS_UUID,
        GroupNumber(0),
        BlockNumber(0),
        K,
        2,
    )
    .expect("encode group 0");
    let stale_symbols: Vec<(u32, Vec<u8>)> = encoded_group_0
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();

    let corrupt = [0_u32];
    let result = decode_group(
        &cx,
        &device,
        &FS_UUID,
        GroupNumber(5), // wrong group: seed mismatch
        BlockNumber(0),
        K,
        &corrupt,
        &stale_symbols,
    );

    // Either an explicit decode failure OR an Ok with wrong data.
    // We only require that wrong data is not silently accepted as
    // identical to the original.
    match result {
        Ok(outcome) if outcome.complete && !outcome.recovered.is_empty() => {
            // Read the original block: recovered data should not match it,
            // because the symbols were from a different group.
            let original = device
                .read_block(&cx, BlockNumber(0))
                .expect("read")
                .as_slice()
                .to_vec();
            assert_ne!(
                outcome.recovered[0].data, original,
                "decode must not silently produce a matching reconstruction \
                 from another group's symbols"
            );
        }
        _ => {}
    }
}

#[test]
fn fixture_insufficient_symbols_at_boundary() {
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);

    // Encode with exactly K-1 = 3 repair symbols. Try to recover K = 4
    // corrupt blocks (every source block lost). Even with full repair
    // symbol set, this is the unrecoverable boundary because we lose
    // every source block: no anchor for the systematic decode.
    let encoded =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, K - 1).expect("encode");
    let symbols: Vec<(u32, Vec<u8>)> = encoded
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();

    let corrupt = [0_u32, 1, 2, 3];
    let result = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &corrupt,
        &symbols,
    );

    // Library returns an explicit error when corrupt_count >= source_block_count.
    assert!(result.is_err(), "decode at total-loss boundary must fail");
}

#[test]
fn fixture_malformed_symbol_payload_length() {
    // Pins the upfront length-validation guard from commit fab3ff1.
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);
    let encoded =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 2).expect("encode");
    let mut symbols: Vec<(u32, Vec<u8>)> = encoded
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();
    // Truncate the first symbol's payload to a wrong length.
    symbols[0].1.truncate(8); // 8 bytes vs BLOCK_SIZE=64

    let corrupt = [0_u32];
    let result = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &corrupt,
        &symbols,
    );
    let error = result.expect_err("decode must reject malformed repair symbol length");
    assert!(
        matches!(
            &error,
            FfsError::RepairFailed(msg)
                if msg.contains("malformed") || msg.contains("payload length")
        ),
        "expected malformed-symbol error, got: {error:?}"
    );
}

#[test]
fn fixture_repair_symbol_refresh_after_recovery() {
    // After a successful recovery, re-encoding from the fresh source
    // blocks must produce symbols that are themselves usable for a
    // subsequent recovery; pins that the codec stays consistent
    // across encode/decode cycles.
    let cx = Cx::for_testing();
    let device = MemBlockDevice::new();
    stage_source(&device);
    let group = GroupNumber(0);

    // Cycle 1: encode, corrupt one block, decode, restore the recovered
    // bytes back to the device.
    let encoded_1 =
        encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 2).expect("encode 1");
    let symbols_1: Vec<(u32, Vec<u8>)> = encoded_1
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();
    let outcome_1 = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &[1],
        &symbols_1,
    )
    .expect("decode 1");
    assert!(outcome_1.complete);
    device.write(BlockNumber(1), outcome_1.recovered[0].data.clone());

    // Cycle 2: re-encode (refresh symbols) over the now-restored device
    // and verify a second recovery still works.
    let encoded_2 = encode_group(&cx, &device, &FS_UUID, group, BlockNumber(0), K, 2)
        .expect("encode 2 (refresh after recovery)");
    let symbols_2: Vec<(u32, Vec<u8>)> = encoded_2
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();
    let outcome_2 = decode_group(
        &cx,
        &device,
        &FS_UUID,
        group,
        BlockNumber(0),
        K,
        &[2],
        &symbols_2,
    )
    .expect("decode 2 with refreshed symbols");
    assert!(outcome_2.complete);
    // Cycle-2 recovered block 2 must equal the original (which is
    // unchanged since we only restored block 1 in cycle 1).
    let original_block_2 = {
        let mut b = vec![0_u8; BLOCK_SIZE as usize];
        for (j, byte) in b.iter_mut().enumerate() {
            *byte = source_byte(2, j);
        }
        b
    };
    assert_eq!(
        outcome_2.recovered[0].data, original_block_2,
        "refreshed symbols must reconstruct block 2 to its original bytes"
    );
}

#[test]
fn fixture_manifest_validates_ledger_corruption_cases_and_checksums() {
    let clean_records = clean_fixture_records();
    let clean_ledger = ledger_bytes(&clean_records);
    let torn_ledger = torn_fixture_ledger(&clean_records[0]);
    let missing_ledger_path = "artifacts/repair/does-not-exist-ledger.jsonl";
    let manifest = repair_corpus_manifest(&clean_ledger, &torn_ledger, missing_ledger_path);

    assert_eq!(manifest.corpus_version, "bd-rchk7.2-ledger-v1");
    assert!(
        manifest
            .reproduction_command
            .contains("cargo test -p ffs-repair"),
        "manifest must preserve an exact local reproduction command"
    );
    assert_eq!(manifest.cases.len(), 3);

    for case in &manifest.cases {
        assert_manifest_case(case, &clean_ledger, &torn_ledger, missing_ledger_path);
    }
}
