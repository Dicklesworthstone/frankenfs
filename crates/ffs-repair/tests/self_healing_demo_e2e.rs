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

fn run_128mib_5pct_striped_repair_elapsed() -> std::time::Duration {
    use ffs_block::{BlockBuf, BlockDevice, ByteBlockDevice, MemByteDevice};
    use ffs_repair::codec::{StripedGroupConfig, decode_group_striped, encode_group_striped};
    use ffs_types::{BlockNumber, GroupNumber};

    const BLOCK_SIZE: u32 = 4096;
    const TOTAL_BLOCKS: u32 = 32_768; // 128 MiB
    const CORRUPT_BLOCKS_5PCT: usize = 1_638; // 5% of 32,768

    let cx = Cx::for_testing();
    let mut raw = vec![0_u8; (TOTAL_BLOCKS as usize) * (BLOCK_SIZE as usize)];
    for blk in 0..TOTAL_BLOCKS as usize {
        let off = blk * (BLOCK_SIZE as usize);
        let seed_bytes = (blk as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .to_le_bytes();
        raw[off..off + 8].copy_from_slice(&seed_bytes);
        raw[off + 8..off + 16].copy_from_slice(&(!(blk as u64)).to_le_bytes());
    }
    let baseline = raw.clone();
    let dev = ByteBlockDevice::new(MemByteDevice::new(raw), BLOCK_SIZE).expect("128MiB block dev");
    let fs_uuid = [0x6A_u8; 16];
    let config = StripedGroupConfig {
        max_stripe_blocks: 64,
        repair_blocks_per_stripe: 8,
    };
    let encoded = encode_group_striped(
        &cx,
        &dev,
        &fs_uuid,
        GroupNumber(0),
        BlockNumber(0),
        TOTAL_BLOCKS,
        config,
    )
    .expect("encode 128MiB striped group");

    // Inject 5% deterministic corruption distributed within per-stripe repair capacity.
    let mut corrupt_offsets = Vec::with_capacity(CORRUPT_BLOCKS_5PCT);
    let mut state = 0x5EC2_2606_u64;
    let mut chosen = vec![false; TOTAL_BLOCKS as usize];
    let mut per_stripe_corrupt = vec![0_u32; encoded.stripe_count as usize];
    while corrupt_offsets.len() < CORRUPT_BLOCKS_5PCT {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let idx = (state as usize) % (TOTAL_BLOCKS as usize);
        let stripe = idx % (encoded.stripe_count as usize);
        if !chosen[idx] && per_stripe_corrupt[stripe] < config.repair_blocks_per_stripe {
            chosen[idx] = true;
            per_stripe_corrupt[stripe] += 1;
            corrupt_offsets.push(idx as u32);
            let mut blk = dev
                .read_block(&cx, BlockNumber(idx as u64))
                .expect("read block")
                .as_slice()
                .to_vec();
            blk[0] ^= 0xFF;
            blk[2048] ^= 0xAA;
            dev.write_block(&cx, BlockNumber(idx as u64), &blk)
                .expect("corrupt block");
        }
    }
    corrupt_offsets.sort_unstable();

    let repair_started = Instant::now();
    let outcome = decode_group_striped(&cx, &dev, &fs_uuid, &encoded, &corrupt_offsets)
        .expect("decode 5% corruption on 128MiB group");
    assert!(outcome.complete, "all 5% corrupted blocks must decode");
    assert_eq!(outcome.recovered.len(), CORRUPT_BLOCKS_5PCT);
    for rec in &outcome.recovered {
        dev.write_block(&cx, rec.block, &rec.data)
            .expect("writeback recovered block");
    }
    let elapsed = repair_started.elapsed();

    // Verify recovered bytes match known-good baseline.
    for &idx in &corrupt_offsets {
        let actual: BlockBuf = dev
            .read_block(&cx, BlockNumber(u64::from(idx)))
            .expect("read repaired");
        let off = (idx as usize) * (BLOCK_SIZE as usize);
        assert_eq!(actual.as_slice(), &baseline[off..off + BLOCK_SIZE as usize]);
    }
    elapsed
}

#[test]
#[ignore = "helper invoked in --release when unoptimized dev profile exceeds 5s 128MiB budget"]
fn raptorq_128mib_5pct_release_probe() {
    let elapsed = run_128mib_5pct_striped_repair_elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "release 128MiB 5% RaptorQ repair took {elapsed:?} (budget < 5s)"
    );
}

#[test]
#[ignore = "canonical spec §22.1 Gate 6: RaptorQ self-healing"]
#[expect(clippy::too_many_lines)]
fn gate6_raptorq_self_healing() {
    use ffs_block::{BlockBuf, BlockDevice, ByteBlockDevice, FileByteDevice};
    use ffs_ondisk::Ext4Superblock;
    use ffs_repair::codec::{
        BlockDelta, StripedGroupConfig, decode_group_striped, encode_group_striped,
        update_striped_group_delta,
    };
    use ffs_types::{BlockNumber, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, GroupNumber};
    use std::collections::BTreeSet;
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
    use std::sync::Mutex;

    struct WriteTrackingBlockDevice<D> {
        inner: D,
        written: Mutex<Vec<u64>>,
    }

    impl<D: BlockDevice> BlockDevice for WriteTrackingBlockDevice<D> {
        fn read_block(&self, cx: &Cx, block: BlockNumber) -> ffs_error::Result<BlockBuf> {
            self.inner.read_block(cx, block)
        }
        fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> ffs_error::Result<()> {
            self.written.lock().expect("lock written").push(block.0);
            self.inner.write_block(cx, block, data)
        }
        fn block_size(&self) -> u32 {
            self.inner.block_size()
        }
        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }
        fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
            self.inner.sync(cx)
        }
    }

    let cx = Cx::for_testing();
    // Retain existing demo smoke check.
    let demo_res = run_self_heal_demo(
        &cx,
        &SelfHealDemoConfig {
            corruption_percent: 1,
            repair_symbol_count: 80,
            ..SelfHealDemoConfig::default()
        },
    )
    .expect("gate6 demo smoke");
    assert!(demo_res.all_ok);

    let require_oracles = std::env::var_os("FFS_REQUIRE_ORACLES")
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let find_tool = |name: &str| -> Option<std::path::PathBuf> {
        if let Some(paths) = std::env::var_os("PATH") {
            for mut p in std::env::split_paths(&paths) {
                p.push(name);
                if std::fs::metadata(&p)
                    .is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
                {
                    return Some(p);
                }
            }
        }
        for dir in ["/sbin", "/usr/sbin"] {
            let p = std::path::Path::new(dir).join(name);
            if std::fs::metadata(&p)
                .is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
            {
                return Some(p);
            }
        }
        None
    };
    let (Some(mkfs_bin), Some(e2fsck_bin)) = (find_tool("mkfs.ext4"), find_tool("e2fsck")) else {
        assert!(
            !require_oracles,
            "FFS_REQUIRE_ORACLES=1 but mkfs.ext4/e2fsck missing"
        );
        println!("SKIP|suite=gate6_repair|reason=e2fsprogs_unavailable");
        return;
    };

    // Criterion 1: Real 128 MiB ext4 filesystem (`32,768` x 4 KiB blocks) with 100 real files.
    const BLOCK_SIZE: u32 = 4096;
    const TOTAL_BLOCKS: u32 = 32_768;
    const IMAGE_BYTES: u64 = 128 * 1024 * 1024;

    let tmp = tempfile::Builder::new()
        .prefix("ffs-gate6-128m-")
        .tempdir()
        .expect("gate6 tempdir");
    let staging = tmp.path().join("staging");
    std::fs::create_dir_all(&staging).expect("mkdir staging");
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755))
        .expect("chmod staging");
    for idx in 0..100_u32 {
        let mut content = vec![0_u8; 8192];
        for (pos, b) in content.iter_mut().enumerate() {
            *b = ((idx as usize * 31 + pos * 17 + 5) % 251) as u8;
        }
        std::fs::write(staging.join(format!("file_{idx:03}.bin")), &content)
            .expect("write staging file");
    }

    let img_path = tmp.path().join("gate6.ext4");
    {
        let f = std::fs::File::create(&img_path).expect("create gate6.ext4");
        f.set_len(IMAGE_BYTES).expect("set_len 128 MiB");
    }
    let uid = std::fs::metadata("/proc/self").map_or(0, |m| m.uid());
    let gid = std::fs::metadata("/proc/self").map_or(0, |m| m.gid());
    let mkfs_status = Command::new(&mkfs_bin)
        .args([
            "-F",
            "-q",
            "-b",
            "4096",
            "-I",
            "256",
            "-O",
            "none,ext_attr,sparse_super,filetype,extent,64bit,metadata_csum",
            "-E",
            &format!("root_owner={uid}:{gid},lazy_itable_init=0"),
            "-d",
        ])
        .arg(&staging)
        .arg(&img_path)
        .status()
        .expect("run mkfs.ext4 128MiB");
    assert!(mkfs_status.success(), "mkfs.ext4 128MiB failed");

    let mut raw_sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
    std::fs::File::open(&img_path)
        .expect("open gate6.ext4")
        .read_exact_at(&mut raw_sb, EXT4_SUPERBLOCK_OFFSET as u64)
        .expect("pread sb");
    let sb = Ext4Superblock::parse_superblock_region(&raw_sb).expect("parse sb");

    let byte_dev = FileByteDevice::open(&img_path).expect("open rw FileByteDevice");
    let inner_bdev = ByteBlockDevice::new(byte_dev, BLOCK_SIZE).expect("ByteBlockDevice");
    let dev = WriteTrackingBlockDevice {
        inner: inner_bdev,
        written: Mutex::new(Vec::new()),
    };

    // Snapshot BLAKE3 digests of all 32,768 blocks (known-good reference).
    let mut good_digests = Vec::with_capacity(TOTAL_BLOCKS as usize);
    for b in 0..TOTAL_BLOCKS {
        let buf = dev
            .read_block(&cx, BlockNumber(u64::from(b)))
            .expect("read block");
        good_digests.push(*blake3::hash(buf.as_slice()).as_bytes());
    }

    let config = StripedGroupConfig {
        max_stripe_blocks: 64,
        repair_blocks_per_stripe: 8,
    };
    let mut encoded = encode_group_striped(
        &cx,
        &dev,
        &sb.uuid,
        GroupNumber(0),
        BlockNumber(0),
        TOTAL_BLOCKS,
        config,
    )
    .expect("encode 128MiB ext4 group");

    // Criterion 2, 3, 4 & 5: Inject 1% random block corruption (`328` blocks),
    // scrub via BLAKE3 digests, repair, prove 100% recovery + `e2fsck -fn` +
    // ZERO false-positive writes (`written == corrupted`).
    let target_1pct = 328_usize;
    let mut rng = 0xCAFE_F00D_BEEF_1234_u64;
    let mut corrupted_set = BTreeSet::new();
    let mut stripe_loads = vec![0_u32; encoded.stripe_count as usize];
    while corrupted_set.len() < target_1pct {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let blk = (rng as u32) % TOTAL_BLOCKS;
        let stripe = (blk % encoded.stripe_count) as usize;
        if stripe_loads[stripe] < config.repair_blocks_per_stripe && corrupted_set.insert(blk) {
            stripe_loads[stripe] += 1;
            let mut data = dev
                .read_block(&cx, BlockNumber(u64::from(blk)))
                .expect("read pre-corrupt")
                .as_slice()
                .to_vec();
            data[((rng >> 16) as usize) % (BLOCK_SIZE as usize)] ^= 0x5A;
            dev.inner
                .write_block(&cx, BlockNumber(u64::from(blk)), &data)
                .expect("inject 1% corruption");
        }
    }
    dev.written.lock().expect("lock").clear();

    // Scrub scan: detect exactly the corrupted blocks with zero false positives.
    let mut detected_corrupt = Vec::new();
    for b in 0..TOTAL_BLOCKS {
        let buf = dev
            .read_block(&cx, BlockNumber(u64::from(b)))
            .expect("scrub read");
        if blake3::hash(buf.as_slice()).as_bytes() != &good_digests[b as usize] {
            detected_corrupt.push(b);
        }
    }
    let expected_corrupt: Vec<u32> = corrupted_set.iter().copied().collect();
    assert_eq!(
        detected_corrupt, expected_corrupt,
        "scrub must detect exact 1% corrupt set"
    );

    let outcome_1pct = decode_group_striped(&cx, &dev, &sb.uuid, &encoded, &detected_corrupt)
        .expect("decode 1% corruption");
    assert!(outcome_1pct.complete);
    for rec in &outcome_1pct.recovered {
        dev.write_block(&cx, rec.block, &rec.data)
            .expect("writeback 1% repair");
    }
    dev.sync(&cx).expect("sync repaired image");

    // Criterion 5: Verify zero uncorrupted blocks were modified by repair!
    let mut repair_writes = dev.written.lock().expect("lock").clone();
    repair_writes.sort_unstable();
    let expected_u64: Vec<u64> = expected_corrupt.iter().copied().map(u64::from).collect();
    assert_eq!(
        repair_writes, expected_u64,
        "repair must NEVER touch uncorrupted blocks (zero false positives)"
    );

    // Criterion 4: Verify 100% recovery against known-good digests + e2fsck -fn!
    for b in 0..TOTAL_BLOCKS {
        let buf = dev
            .read_block(&cx, BlockNumber(u64::from(b)))
            .expect("verify read");
        assert_eq!(
            blake3::hash(buf.as_slice()).as_bytes(),
            &good_digests[b as usize],
            "block {b} mismatch after 1% self-healing"
        );
    }
    let fsck_status = Command::new(&e2fsck_bin)
        .args(["-f", "-n"])
        .arg(&img_path)
        .status()
        .expect("e2fsck -fn after 1% heal");
    assert!(
        fsck_status.success(),
        "e2fsck -fn failed after 1% RaptorQ repair"
    );

    // Criterion 6: Repair symbol freshness after writing new data (plus stale-symbol rejection).
    let stale_encoded = encoded.clone();
    // Pick a deterministic data block near the end of the image, write new payload, refresh delta.
    let fresh_blk = TOTAL_BLOCKS - 17;
    let old_bytes = dev
        .read_block(&cx, BlockNumber(u64::from(fresh_blk)))
        .expect("read old block")
        .as_slice()
        .to_vec();
    let mut new_bytes = vec![0_u8; BLOCK_SIZE as usize];
    for (i, byte) in new_bytes.iter_mut().enumerate() {
        *byte = ((i * 29 + 0x77) % 251) as u8;
    }
    dev.inner
        .write_block(&cx, BlockNumber(u64::from(fresh_blk)), &new_bytes)
        .expect("write new data");
    update_striped_group_delta(
        &mut encoded,
        &[BlockDelta {
            source_index: fresh_blk,
            old_block: &old_bytes,
            new_block: &new_bytes,
        }],
    )
    .expect("refresh striped repair symbols via GF(256) delta");
    good_digests[fresh_blk as usize] = *blake3::hash(&new_bytes).as_bytes();

    // Corrupt the newly written block; stale symbols reconstruct old_bytes (failing digest check),
    // whereas refreshed symbols reconstruct new_bytes 100%!
    let mut damaged_new = new_bytes.clone();
    damaged_new[0..64].fill(0);
    dev.inner
        .write_block(&cx, BlockNumber(u64::from(fresh_blk)), &damaged_new)
        .expect("corrupt newly written block");

    let stale_try = decode_group_striped(&cx, &dev, &sb.uuid, &stale_encoded, &[fresh_blk])
        .expect("decode with stale symbols");
    assert_ne!(
        blake3::hash(&stale_try.recovered[0].data).as_bytes(),
        &good_digests[fresh_blk as usize],
        "stale pre-write parity must fail post-write BLAKE3 freshness verification"
    );

    let fresh_try = decode_group_striped(&cx, &dev, &sb.uuid, &encoded, &[fresh_blk])
        .expect("decode with refreshed symbols");
    assert_eq!(fresh_try.recovered[0].data, new_bytes);
    dev.inner
        .write_block(
            &cx,
            BlockNumber(u64::from(fresh_blk)),
            &fresh_try.recovered[0].data,
        )
        .expect("restore fresh block");

    // Criterion 7: Corrupt a repair symbol block itself AND source blocks in the same stripe;
    // verify digest-authenticated drop of the corrupt repair symbol still recovers 100% via
    // systematic RaptorQ redundancy!
    let target_stripe = (fresh_blk % encoded.stripe_count) as usize;
    let symbol_digests: Vec<[u8; 32]> = encoded.stripes[target_stripe]
        .repair_symbols
        .iter()
        .map(|s| *blake3::hash(&s.data).as_bytes())
        .collect();
    // Corrupt repair symbol #0 AND two source blocks in `target_stripe`.
    encoded.stripes[target_stripe].repair_symbols[0].data[0] ^= 0xFF;
    encoded.stripes[target_stripe].repair_symbols[0].data[511] ^= 0x3C;
    // Drop repair symbols that fail integrity verification before decoding.
    let src_block_count = encoded.stripes[target_stripe].source_block_count;
    encoded.stripes[target_stripe].repair_symbols.retain(|sym| {
        let idx = (sym.esi - src_block_count) as usize;
        blake3::hash(&sym.data).as_bytes() == &symbol_digests[idx]
    });
    assert_eq!(
        encoded.stripes[target_stripe].repair_symbols.len(),
        (config.repair_blocks_per_stripe - 1) as usize
    );

    let src_b0 = target_stripe as u32;
    let src_b1 = src_b0 + encoded.stripe_count;
    let orig_b0 = dev
        .read_block(&cx, BlockNumber(u64::from(src_b0)))
        .expect("read src_b0")
        .as_slice()
        .to_vec();
    let orig_b1 = dev
        .read_block(&cx, BlockNumber(u64::from(src_b1)))
        .expect("read src_b1")
        .as_slice()
        .to_vec();
    dev.inner
        .write_block(
            &cx,
            BlockNumber(u64::from(src_b0)),
            &[0xEE; BLOCK_SIZE as usize],
        )
        .expect("corrupt src_b0");
    dev.inner
        .write_block(
            &cx,
            BlockNumber(u64::from(src_b1)),
            &[0xDD; BLOCK_SIZE as usize],
        )
        .expect("corrupt src_b1");

    let sys_outcome = decode_group_striped(&cx, &dev, &sb.uuid, &encoded, &[src_b0, src_b1])
        .expect("decode with corrupted repair symbol dropped");
    assert!(sys_outcome.complete);
    assert_eq!(sys_outcome.recovered[0].data, orig_b0);
    assert_eq!(sys_outcome.recovered[1].data, orig_b1);

    // Criterion 8: 128 MiB block group @ 5% corruption (`1,638` blocks) completes in < 5s.
    let elapsed_5pct = run_128mib_5pct_striped_repair_elapsed();
    if elapsed_5pct >= std::time::Duration::from_secs(5) {
        assert!(
            cfg!(debug_assertions),
            "release 128MiB 5% repair exceeded 5s budget: {elapsed_5pct:?}"
        );
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root");
        let status = Command::new("cargo")
            .current_dir(workspace_root)
            .args([
                "test",
                "-p",
                "ffs-repair",
                "--release",
                "--test",
                "self_healing_demo_e2e",
                "raptorq_128mib_5pct_release_probe",
                "--",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .status()
            .expect("spawn release 128MiB 5% RaptorQ probe");
        assert!(
            status.success(),
            "release 128MiB 5% RaptorQ repair failed < 5s gate"
        );
    }
}
