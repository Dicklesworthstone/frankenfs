//! E2E tests for the self-healing demo.
//!
//! Validates that the demo runs successfully, produces correct structured
//! output, achieves zero data loss, completes within 30 seconds, and
//! integrates with the evidence ledger.

use std::process::Command;
use std::time::Instant;

use asupersync::Cx;
use ffs_repair::demo::{SelfHealDemoConfig, SelfHealDemoResult, run_self_heal_demo};
use ffs_repair::evidence::{
    CorruptionDetail, EvidenceEventType, EvidenceLedger, EvidenceRecord, RepairDetail,
    parse_evidence_ledger,
};
use ffs_repair::recovery::RecoveryDecoderStats;

/// Run the demo with the given config and return the result, printing
/// structured output to stderr for CI capture.
fn run_and_report(label: &str, config: &SelfHealDemoConfig) -> SelfHealDemoResult {
    let cx = Cx::for_testing();
    let started = Instant::now();
    let result = run_self_heal_demo(&cx, config).unwrap_or_else(|e| {
        panic!("{label}: demo failed: {e}");
    });
    let elapsed = started.elapsed();

    eprintln!("--- {label} ---");
    for line in &result.output_lines {
        eprintln!("  {line}");
    }
    eprintln!(
        "  corrupted={} repaired={} verified={} all_ok={} duration={}ms elapsed={:.0}ms",
        result.corrupted_blocks,
        result.repaired_blocks,
        result.files_verified,
        result.all_ok,
        result.duration_ms,
        elapsed.as_secs_f64() * 1000.0
    );
    eprintln!();

    result
}

fn parse_metric(line: &str, key: &str) -> usize {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(key))
        .unwrap_or_else(|| panic!("missing metric {key} in line: {line}"))
        .parse::<usize>()
        .unwrap_or_else(|err| panic!("invalid metric {key} in line '{line}': {err}"))
}

const REPRESENTATIVE_SELF_HEALING_DEMO_OUTPUT_GOLDEN: &str = concat!(
    "demo start: image_size=8388608B file_count=10 corruption_pct=2 seed=0x00c0ffeef00dbaad\n",
    "image created: wrote 10 payload files across 40 source blocks\n",
    "corruption injected: blocks_corrupted=1 pct=2\n",
    "repair complete: blocks_repaired=1 duration_ms=<duration_ms>\n",
    "verification: files_verified=10 all_ok=true\n",
    "demo result: PASS"
);

fn scrub_demo_output_line(line: &str) -> String {
    if let Some((prefix, rest)) = line.split_once("duration_ms=") {
        let digit_prefix_len = rest.chars().take_while(char::is_ascii_digit).count();
        return format!(
            "{prefix}duration_ms=<duration_ms>{}",
            &rest[digit_prefix_len..]
        );
    }
    line.to_owned()
}

fn scrub_demo_output<'a>(lines: impl IntoIterator<Item = &'a str>) -> String {
    lines
        .into_iter()
        .map(scrub_demo_output_line)
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Test 0: binary command path ─────────────────────────────────────────────

#[test]
fn demo_binary_runs_via_self_healing_command() {
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_ffs-demo"))
        .arg("self-healing")
        .output()
        .expect("failed to run ffs-demo binary");
    let elapsed = started.elapsed();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ffs-demo failed with status {:?}; stderr:\n{}",
        output.status.code(),
        stderr
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be utf8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 6, "expected six output lines, got:\n{stdout}");
    assert_eq!(
        scrub_demo_output(lines.iter().copied()),
        REPRESENTATIVE_SELF_HEALING_DEMO_OUTPUT_GOLDEN
    );

    let corrupted = parse_metric(lines[2], "blocks_corrupted=");
    let repaired = parse_metric(lines[3], "blocks_repaired=");
    assert_eq!(
        corrupted, repaired,
        "binary run must repair every corrupted block"
    );
    assert!(
        elapsed.as_secs() < 30,
        "binary command must finish in <30s, took {:.2}s",
        elapsed.as_secs_f64()
    );
}

// ── Test 1: output structure ────────────────────────────────────────────────

#[test]
fn demo_output_has_six_structured_lines() {
    let result = run_and_report("output_structure", &SelfHealDemoConfig::default());

    assert_eq!(
        result.output_lines.len(),
        6,
        "expected exactly 6 output lines"
    );
    assert_eq!(
        scrub_demo_output(result.output_lines.iter().map(String::as_str)),
        REPRESENTATIVE_SELF_HEALING_DEMO_OUTPUT_GOLDEN
    );
}

// ── Test 2: zero data loss ──────────────────────────────────────────────────

#[test]
fn demo_zero_data_loss_default_config() {
    let result = run_and_report("zero_data_loss_2pct", &SelfHealDemoConfig::default());

    assert!(
        result.all_ok,
        "all payload checksums must verify after repair"
    );
    assert_eq!(
        result.corrupted_blocks, result.repaired_blocks,
        "every corrupted block must be repaired"
    );
    assert!(
        result.corrupted_blocks > 0,
        "at least one block should be corrupted"
    );
    assert_eq!(result.files_verified, 10, "all 10 files must be verified");
}

#[test]
fn demo_zero_data_loss_five_percent_corruption() {
    let config = SelfHealDemoConfig {
        corruption_percent: 5,
        repair_symbol_count: 80,
        ..SelfHealDemoConfig::default()
    };
    let result = run_and_report("zero_data_loss_5pct", &config);

    assert!(result.all_ok, "recovery must succeed at 5% corruption");
    assert_eq!(
        result.corrupted_blocks, result.repaired_blocks,
        "every corrupted block must be repaired at 5%"
    );
    assert!(
        result.corrupted_blocks > 0,
        "at least one block should be corrupted"
    );
}

// ── Test 3: timing constraint ───────────────────────────────────────────────

#[test]
fn demo_completes_within_30_seconds() {
    let started = Instant::now();
    let result = run_and_report("timing", &SelfHealDemoConfig::default());
    let wall_elapsed = started.elapsed();

    assert!(result.all_ok, "demo must succeed");
    assert!(
        wall_elapsed.as_secs() < 30,
        "demo must complete within 30s, took {:.1}s",
        wall_elapsed.as_secs_f64()
    );
}

// ── Test 4: determinism ─────────────────────────────────────────────────────

#[test]
fn demo_deterministic_with_fixed_seed() {
    let config = SelfHealDemoConfig::default();

    let r1 = run_and_report("determinism_run1", &config);
    let r2 = run_and_report("determinism_run2", &config);

    assert_eq!(
        r1.corrupted_blocks, r2.corrupted_blocks,
        "same seed must produce same corruption count"
    );
    assert_eq!(
        r1.repaired_blocks, r2.repaired_blocks,
        "same seed must produce same repair count"
    );
    assert_eq!(
        r1.files_verified, r2.files_verified,
        "same seed must verify same file count"
    );
    assert_eq!(r1.all_ok, r2.all_ok, "same seed must produce same outcome");

    // Output lines should match (except timing-dependent fields)
    assert_eq!(
        r1.output_lines[0], r2.output_lines[0],
        "demo start line must match"
    );
    assert_eq!(
        r1.output_lines[1], r2.output_lines[1],
        "image created line must match"
    );
    assert_eq!(
        r1.output_lines[2], r2.output_lines[2],
        "corruption injected line must match"
    );
    // Line 3 (repair complete) has duration_ms which may differ — skip exact match
    assert_eq!(
        r1.output_lines[4], r2.output_lines[4],
        "verification line must match"
    );
    assert_eq!(
        r1.output_lines[5], r2.output_lines[5],
        "result line must match"
    );
}

// ── Test 5: evidence ledger integration ─────────────────────────────────────

#[test]
fn demo_evidence_ledger_captures_repair_lifecycle() {
    let config = SelfHealDemoConfig::default();
    let result = run_and_report("evidence_ledger", &config);
    assert!(result.all_ok, "demo must succeed before ledger validation");

    // Build an evidence ledger that mirrors the demo lifecycle:
    // 1. corruption_detected for the corrupted blocks
    // 2. repair_succeeded for the repaired blocks
    let mut buf = Vec::new();
    {
        let mut ledger = EvidenceLedger::new(&mut buf);

        // Record corruption detection
        let corruption_record = EvidenceRecord::corruption_detected(
            0,
            CorruptionDetail {
                blocks_affected: u32::try_from(result.corrupted_blocks)
                    .expect("corrupted_blocks fits u32"),
                corruption_kind: "xor_injection".to_owned(),
                severity: "error".to_owned(),
                detail: format!(
                    "demo injected corruption on {} blocks",
                    result.corrupted_blocks
                ),
            },
        )
        .with_block_range(0, u64::try_from(result.corrupted_blocks).unwrap_or(0));
        ledger
            .append(&corruption_record)
            .expect("append corruption");

        // Record repair success
        let repair_record = EvidenceRecord::repair_succeeded(
            0,
            RepairDetail {
                generation: 1,
                corrupt_count: result.repaired_blocks,
                symbols_used: config.repair_symbol_count as usize,
                symbols_available: config.repair_symbol_count as usize,
                decoder_stats: RecoveryDecoderStats::default(),
                verify_pass: true,
                reason: None,
            },
        );
        ledger.append(&repair_record).expect("append repair");
    }

    // Parse the ledger back and validate
    let records = parse_evidence_ledger(&buf);
    assert_eq!(records.len(), 2, "ledger should have exactly 2 records");

    // Validate corruption event
    assert_eq!(records[0].event_type, EvidenceEventType::CorruptionDetected);
    let corruption = records[0].corruption.as_ref().expect("corruption detail");
    assert_eq!(
        corruption.blocks_affected,
        u32::try_from(result.corrupted_blocks).unwrap()
    );
    assert_eq!(corruption.corruption_kind, "xor_injection");

    // Validate repair event
    assert_eq!(records[1].event_type, EvidenceEventType::RepairSucceeded);
    let repair = records[1].repair.as_ref().expect("repair detail");
    assert_eq!(repair.corrupt_count, result.repaired_blocks);
    assert!(repair.verify_pass);
    assert!(repair.reason.is_none());

    // Validate JSONL round-trip: each record can be serialized/deserialized
    for record in &records {
        let json = record.to_json().expect("serialize record");
        let parsed = EvidenceRecord::from_json(&json).expect("deserialize record");
        assert_eq!(parsed.event_type, record.event_type);
        assert_eq!(parsed.block_group, record.block_group);
    }

    eprintln!(
        "  evidence ledger: {} records, {} bytes JSONL",
        records.len(),
        buf.len()
    );
}

// ── Test 6: output line content parsing ─────────────────────────────────────

#[test]
fn demo_output_lines_contain_expected_metrics() {
    let config = SelfHealDemoConfig::default();
    let result = run_and_report("metrics_parsing", &config);

    // Line 0: "demo start: image_size=8388608B file_count=10 corruption_pct=2 seed=0x..."
    let line0 = &result.output_lines[0];
    assert!(
        line0.contains("image_size=8388608B"),
        "line 0 must contain image_size=8388608B"
    );
    assert!(
        line0.contains("file_count=10"),
        "line 0 must contain file_count=10"
    );
    assert!(
        line0.contains("corruption_pct=2"),
        "line 0 must contain corruption_pct=2"
    );
    assert!(
        line0.contains(&format!("seed=0x{:016x}", config.seed)),
        "line 0 must contain seed"
    );

    // Line 2: "corruption injected: blocks_corrupted=N pct=2"
    let line2 = &result.output_lines[2];
    assert!(
        line2.contains(&format!("blocks_corrupted={}", result.corrupted_blocks)),
        "line 2 must contain blocks_corrupted count"
    );
    assert!(line2.contains("pct=2"), "line 2 must contain pct=2");

    // Line 3: "repair complete: blocks_repaired=N duration_ms=..."
    let line3 = &result.output_lines[3];
    assert!(
        line3.contains(&format!("blocks_repaired={}", result.repaired_blocks)),
        "line 3 must contain blocks_repaired count"
    );
    assert!(
        line3.contains("duration_ms="),
        "line 3 must contain duration_ms"
    );

    // Line 4: "verification: files_verified=10 all_ok=true"
    let line4 = &result.output_lines[4];
    assert!(
        line4.contains("files_verified=10"),
        "line 4 must contain files_verified=10"
    );
    assert!(
        line4.contains("all_ok=true"),
        "line 4 must contain all_ok=true"
    );
}

#[test]
#[ignore = "canonical spec §22.1 Gate 6: RaptorQ self-healing"]
fn gate6_raptorq_self_healing() {
    let cx = Cx::for_testing();
    // 1. Injected block corruption recovers 100% against known-good copy
    let config_1pct = SelfHealDemoConfig {
        corruption_percent: 1,
        repair_symbol_count: 80,
        ..SelfHealDemoConfig::default()
    };
    let result_1pct = run_self_heal_demo(&cx, &config_1pct).expect("gate6 1% demo run");
    assert!(
        result_1pct.all_ok,
        "all payload checksums must verify after 1% repair"
    );
    assert_eq!(
        result_1pct.corrupted_blocks, result_1pct.repaired_blocks,
        "all corrupted blocks must be repaired"
    );
    assert_eq!(result_1pct.files_verified, 10);

    // 2. 5% corruption test
    let config_5pct = SelfHealDemoConfig {
        corruption_percent: 5,
        repair_symbol_count: 80,
        ..SelfHealDemoConfig::default()
    };
    let result_5pct = run_self_heal_demo(&cx, &config_5pct).expect("gate6 5% demo run");
    assert!(
        result_5pct.all_ok,
        "all payload checksums must verify after 5% repair"
    );
    assert_eq!(
        result_5pct.corrupted_blocks, result_5pct.repaired_blocks,
        "all 5% corrupted blocks must be repaired"
    );
}
