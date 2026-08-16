#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

//! Null-controlled retry of the same-transaction JBD2 write-combining probe.
//!
//! A descriptor group occupies one descriptor block followed by its data
//! blocks. The frozen scalar arm issues one positioned write per block. The
//! candidate issues one positioned write for the same preassembled contiguous
//! bytes. This source-neutral probe tests the syscall seam before any
//! wrap-aware production grouping is attempted. The second A/A/B pair runs
//! `Jbd2Writer::commit_transaction` itself: a scalar-only device wrapper freezes
//! the old per-block path while the byte device exercises production grouping.

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice, ByteBlockDevice, FileByteDevice};
use ffs_error::Result;
use ffs_journal::{Jbd2Transaction, Jbd2Writer, JournalRegion};
use ffs_types::BlockNumber;
use nix::sys::memfd::{MemFdCreateFlag, memfd_create};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fmt::Write as _;
use std::fs::File;
use std::hint::black_box;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::process::{Command, Stdio};
use std::time::Instant;

const BLOCK_SIZE: usize = 4096;
const DATA_BLOCKS: usize = 64;
const BLOCKS_PER_GROUP: usize = DATA_BLOCKS + 1;
const REGION_BYTES: usize = BLOCKS_PER_GROUP * BLOCK_SIZE;
const GROUPS_PER_SAMPLE: usize = 512;
const PRODUCTION_COMMITS_PER_SAMPLE: usize = 64;
const DEVICE_BLOCKS: u64 = 1_024;
const JOURNAL_START: u64 = 128;
const JOURNAL_BLOCKS: u64 = 128;
const TARGET_START: u64 = 512;
const ROUNDS: usize = 31;
const MIN_OF: usize = 3;
const BOOTSTRAP_RESAMPLES: usize = 10_000;
const BOOTSTRAP_SEED: u64 = 0xF5A1_4A22_2026_0725;

#[derive(Clone, Copy)]
enum Arm {
    Scalar,
    Combined,
}

struct PairedStats {
    p50_a_ns: f64,
    p50_b_ns: f64,
    p50_a_ci: (f64, f64),
    p50_b_ci: (f64, f64),
    ratio_p50: f64,
    ratio_ci: (f64, f64),
    cv_pct: f64,
    mad: f64,
    checksum: u64,
}

fn self_identity() -> String {
    let Ok(path) = std::env::current_exe() else {
        return "unavailable".to_owned();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return "unavailable".to_owned();
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    format!("{} ({} bytes) {}", encoded, bytes.len(), path.display())
}

fn print_codegen_isa() {
    #[cfg(target_arch = "x86_64")]
    println!(
        "codegen_isa,target_arch=x86_64,compile_sse2={},compile_sse4_2={},compile_avx2={},compile_fma={},runtime_sse4_2={},runtime_avx2={},runtime_fma={}",
        cfg!(target_feature = "sse2"),
        cfg!(target_feature = "sse4.2"),
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "fma"),
        std::arch::is_x86_feature_detected!("sse4.2"),
        std::arch::is_x86_feature_detected!("avx2"),
        std::arch::is_x86_feature_detected!("fma"),
    );

    #[cfg(not(target_arch = "x86_64"))]
    println!("codegen_isa,target_arch={}", std::env::consts::ARCH);
}

fn make_device(bytes: usize) -> File {
    let name = CString::new("ffs-jbd2-write-combining").expect("memfd name");
    let fd = memfd_create(name.as_c_str(), MemFdCreateFlag::MFD_CLOEXEC)
        .expect("create anonymous benchmark file");
    let file = File::from(fd);
    file.set_len(u64::try_from(bytes).expect("device size fits u64"))
        .expect("size anonymous benchmark file");
    file
}

fn make_region() -> Vec<u8> {
    (0..REGION_BYTES)
        .map(|idx| {
            let block = idx / BLOCK_SIZE;
            let within = idx % BLOCK_SIZE;
            (block.wrapping_mul(131) ^ within.wrapping_mul(17) ^ 0xA5) as u8
        })
        .collect()
}

fn scalar_write(file: &File, region: &[u8]) {
    let (blocks, _tail) = region.as_chunks::<BLOCK_SIZE>();
    for (block, bytes) in blocks.iter().enumerate() {
        let offset = u64::try_from(block * BLOCK_SIZE).expect("offset fits u64");
        file.write_all_at(bytes, offset).expect("scalar pwrite");
    }
}

fn combined_write(file: &File, region: &[u8]) {
    file.write_all_at(region, 0).expect("combined pwrite");
}

fn run_arm(arm: Arm, file: &File, region: &[u8]) -> u64 {
    let mut checksum = 0_u64;
    for group in 0..GROUPS_PER_SAMPLE {
        match arm {
            Arm::Scalar => scalar_write(file, region),
            Arm::Combined => combined_write(file, region),
        }
        checksum = checksum
            .wrapping_mul(1_000_003)
            .wrapping_add(group as u64)
            .wrapping_add(u64::from(region[group % region.len()]));
    }
    checksum
}

struct ScalarWriteDevice(ByteBlockDevice<FileByteDevice>);

impl BlockDevice for ScalarWriteDevice {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        self.0.read_block(cx, block)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.0.write_block(cx, block, data)
    }

    fn block_size(&self) -> u32 {
        self.0.block_size()
    }

    fn block_count(&self) -> u64 {
        self.0.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.0.sync(cx)
    }
}

fn journal_region() -> JournalRegion {
    JournalRegion {
        start: BlockNumber(JOURNAL_START),
        blocks: JOURNAL_BLOCKS,
    }
}

fn make_transaction() -> Jbd2Transaction {
    let mut writer = Jbd2Writer::new(journal_region(), 1);
    let mut txn = writer.begin_transaction();
    for index in 0..DATA_BLOCKS {
        let index_u64 = u64::try_from(index).expect("data index fits u64");
        let byte = (index.wrapping_mul(29) ^ 0x6D) as u8;
        txn.add_write(
            BlockNumber(TARGET_START + index_u64),
            vec![byte; BLOCK_SIZE],
        );
    }
    txn
}

fn run_production_commit(device: &dyn BlockDevice, cx: &Cx, txn: &Jbd2Transaction) -> u64 {
    let mut checksum = 0_u64;
    for iteration in 0..PRODUCTION_COMMITS_PER_SAMPLE {
        let mut writer = Jbd2Writer::new(journal_region(), 1);
        let (sequence, stats) = writer
            .commit_transaction(cx, device, txn)
            .expect("production JBD2 commit");
        checksum = checksum
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::from(sequence))
            .wrapping_add(stats.descriptor_blocks)
            .wrapping_add(stats.data_blocks)
            .wrapping_add(stats.commit_blocks)
            .wrapping_add(iteration as u64);
    }
    checksum
}

fn read_journal_bytes(file: &File) -> Vec<u8> {
    let len = usize::try_from(JOURNAL_BLOCKS)
        .expect("journal blocks fit usize")
        .checked_mul(BLOCK_SIZE)
        .expect("journal byte length");
    let offset = JOURNAL_START
        .checked_mul(u64::try_from(BLOCK_SIZE).expect("block size fits u64"))
        .expect("journal byte offset");
    let mut bytes = vec![0_u8; len];
    file.read_exact_at(&mut bytes, offset)
        .expect("read production journal bytes");
    bytes
}

fn time_min(run: &impl Fn() -> u64) -> (u64, u64) {
    let mut best = u64::MAX;
    let mut checksum = 0_u64;
    for replicate in 0..MIN_OF {
        let started = Instant::now();
        let observed = black_box(run());
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        best = best.min(elapsed.max(1));
        checksum ^= observed.rotate_left((replicate % u64::BITS as usize) as u32);
    }
    (best, checksum)
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable_by(f64::total_cmp);
    sorted[sorted.len() / 2]
}

fn bootstrap_median_ci(values: &[f64], seed: u64) -> (f64, f64) {
    let mut state = seed;
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = Vec::with_capacity(values.len());

    for _ in 0..BOOTSTRAP_RESAMPLES {
        resample.clear();
        for _ in 0..values.len() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            resample.push(values[(state as usize) % values.len()]);
        }
        medians.push(median(&resample));
    }

    medians.sort_unstable_by(f64::total_cmp);
    let low = BOOTSTRAP_RESAMPLES * 25 / 1_000;
    let high = BOOTSTRAP_RESAMPLES * 975 / 1_000;
    (medians[low], medians[high.min(medians.len() - 1)])
}

fn paired(run_a: &impl Fn() -> u64, run_b: &impl Fn() -> u64) -> PairedStats {
    let mut times_a = Vec::with_capacity(ROUNDS);
    let mut times_b = Vec::with_capacity(ROUNDS);
    let mut ratios = Vec::with_capacity(ROUNDS);
    let mut checksum = 0_u64;

    for round in 0..ROUNDS {
        let ((elapsed_a, checksum_a), (elapsed_b, checksum_b)) = if round % 2 == 0 {
            (time_min(run_a), time_min(run_b))
        } else {
            let b = time_min(run_b);
            let a = time_min(run_a);
            (a, b)
        };
        times_a.push(elapsed_a as f64);
        times_b.push(elapsed_b as f64);
        ratios.push(elapsed_a as f64 / elapsed_b.max(1) as f64);
        checksum ^= checksum_a.rotate_left((round % u64::BITS as usize) as u32);
        checksum ^= checksum_b.rotate_right((round % u64::BITS as usize) as u32);
    }

    let ratio_p50 = median(&ratios);
    let mean = ratios.iter().sum::<f64>() / ratios.len() as f64;
    let variance = ratios
        .iter()
        .map(|ratio| {
            let delta = ratio - mean;
            delta * delta
        })
        .sum::<f64>()
        / (ratios.len() - 1) as f64;
    let deviations = ratios
        .iter()
        .map(|ratio| (ratio - ratio_p50).abs())
        .collect::<Vec<_>>();

    PairedStats {
        p50_a_ns: median(&times_a),
        p50_b_ns: median(&times_b),
        p50_a_ci: bootstrap_median_ci(&times_a, BOOTSTRAP_SEED ^ 0xA11C_E001),
        p50_b_ci: bootstrap_median_ci(&times_b, BOOTSTRAP_SEED ^ 0xB11C_E002),
        ratio_p50,
        ratio_ci: bootstrap_median_ci(&ratios, BOOTSTRAP_SEED ^ 0xAB11_CE03),
        cv_pct: variance.sqrt() / mean * 100.0,
        mad: median(&deviations),
        checksum,
    }
}

fn print_stats(label: &str, stats: &PairedStats) {
    println!(
        "{label},rounds={ROUNDS},min_of={MIN_OF},p50_a_ns={:.0},p50_b_ns={:.0},p50_a_ci95_ns=[{:.0},{:.0}],p50_b_ci95_ns=[{:.0},{:.0}],ratio_p50={:.6},ratio_ci95=[{:.6},{:.6}],cv_pct={:.3},mad={:.6},checksum={:016x}",
        stats.p50_a_ns,
        stats.p50_b_ns,
        stats.p50_a_ci.0,
        stats.p50_a_ci.1,
        stats.p50_b_ci.0,
        stats.p50_b_ci.1,
        stats.ratio_p50,
        stats.ratio_ci.0,
        stats.ratio_ci.1,
        stats.cv_pct,
        stats.mad,
        stats.checksum,
    );
}

fn print_gate(label: &str, null: &PairedStats, real: &PairedStats, direction_labels: (&str, &str)) {
    let null_half_width = (null.ratio_ci.0 - 1.0)
        .abs()
        .max((null.ratio_ci.1 - 1.0).abs());
    let effect = if real.ratio_p50 >= 1.0 {
        real.ratio_p50 - 1.0
    } else {
        real.ratio_p50.recip() - 1.0
    };
    let outside_null_ci = real.ratio_p50 < null.ratio_ci.0 || real.ratio_p50 > null.ratio_ci.1;
    let decisive = outside_null_ci && effect >= 2.0 * null_half_width;
    let direction = if real.ratio_p50 >= 1.0 {
        direction_labels.0
    } else {
        direction_labels.1
    };
    println!(
        "{label},median_ci_gate={},direction={direction},effect={effect:.6},null_half_width={null_half_width:.6},required_2x_margin={:.6},cv_is_provenance_only=true",
        if decisive { "decidable" } else { "unresolved" },
        2.0 * null_half_width
    );
}

fn make_grouped_production_device(file: &File) -> ByteBlockDevice<FileByteDevice> {
    let production_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    ByteBlockDevice::new(
        FileByteDevice::open(&production_path).expect("open grouped memfd"),
        u32::try_from(BLOCK_SIZE).expect("block size fits u32"),
    )
    .expect("build grouped block device")
}

fn profile_only() {
    const PROFILE_SAMPLES: usize = 2_048;
    let device_bytes = usize::try_from(DEVICE_BLOCKS)
        .expect("device blocks fit usize")
        .checked_mul(BLOCK_SIZE)
        .expect("device byte length");
    let file = make_device(device_bytes);
    let grouped_device = make_grouped_production_device(&file);
    let cx = Cx::for_testing();
    let txn = make_transaction();
    let mut checksum = 0_u64;
    for sample in 0..PROFILE_SAMPLES {
        checksum ^= black_box(run_production_commit(&grouped_device, &cx, &txn))
            .rotate_left((sample % u64::BITS as usize) as u32);
    }
    black_box(checksum);
}

fn profile_percent(report: &str, symbol: &str) -> Option<f64> {
    report
        .lines()
        .filter(|line| line.contains(symbol))
        .filter_map(|line| {
            line.split_whitespace().find_map(|field| {
                field
                    .strip_suffix('%')
                    .and_then(|percent| percent.parse::<f64>().ok())
            })
        })
        .reduce(f64::max)
}

fn spawn_profile_report() {
    const ATTRIBUTION_FLOOR_PCT: f64 = 5.0;
    let exe = std::env::current_exe().expect("bench executable");
    let executable_name = exe
        .file_name()
        .and_then(|name| name.to_str())
        .expect("bench executable file name");
    let record = Command::new("perf")
        .args([
            "record",
            "-q",
            "-F",
            "999",
            "-g",
            "--call-graph",
            "fp",
            "-o",
            "-",
        ])
        .arg("--")
        .arg(&exe)
        .arg("--profile-only")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();
    let Ok(mut record) = record else {
        println!("profile_blocker=perf_record_unavailable");
        return;
    };
    let perf_data = record.stdout.take().expect("perf pipe");
    let report = Command::new("perf")
        .args([
            "report",
            "-q",
            "--stdio",
            "--children",
            "-i",
            "-",
            "--percent-limit",
            "0",
            "--dsos",
        ])
        .arg(executable_name)
        .env("DEBUGINFOD_URLS", "")
        .stdin(Stdio::from(perf_data))
        .output();
    let Ok(report) = report else {
        println!("profile_blocker=perf_report_unavailable");
        let _ = record.wait();
        return;
    };
    let Ok(record_status) = record.wait() else {
        println!("profile_blocker=perf_record_wait_failed");
        return;
    };
    let text = String::from_utf8_lossy(&report.stdout);
    println!("profile_frame_table_begin\n{text}profile_frame_table_end");

    let mut frames: Vec<(f64, String)> = text
        .lines()
        .filter(|line| line.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pct = fields.next()?.strip_suffix('%')?.parse::<f64>().ok()?;
            let symbol = line.split("] ").nth(1).unwrap_or("?").trim();
            Some((pct, symbol.chars().take(70).collect::<String>()))
        })
        .collect();
    frames.sort_by(|a, b| b.0.total_cmp(&a.0));
    frames.truncate(15);
    let mut top = String::new();
    for (pct, symbol) in &frames {
        if !top.is_empty() {
            top.push(';');
        }
        write!(&mut top, "{pct:.2}%={symbol}").expect("format top frame");
    }
    println!("profile_top_frames,mode=grouped_jbd2,frames={top}");

    if !record_status.success() || !report.status.success() {
        println!(
            "profile_blocker=perf_permission_denied,record_status={record_status},report_status={}",
            report.status
        );
        return;
    }
    let assembly_pct = profile_percent(&text, "assemble_jbd2_descriptor_data_run").unwrap_or(0.0);
    let admitted = assembly_pct >= ATTRIBUTION_FLOOR_PCT;
    println!(
        "profile_target_attribution,assembly_children_pct={assembly_pct:.6},attribution_floor_pct={ATTRIBUTION_FLOOR_PCT:.6},admitted={admitted}"
    );
    if !admitted {
        println!("profile_blocker=assembly_below_attribution_floor");
    }
}

fn run_profile_report_only() {
    println!(
        "profile_scope=source_attribution_only,ratio_published=false,aa_gate=not_applicable,gate_basis=numeric_self_time,cv_used_as_gate=false,instructions_used_as_gate=false"
    );
    let device_bytes = usize::try_from(DEVICE_BLOCKS)
        .expect("device blocks fit usize")
        .checked_mul(BLOCK_SIZE)
        .expect("device byte length");
    let production_file = make_device(device_bytes);
    let production_path = format!("/proc/self/fd/{}", production_file.as_raw_fd());
    let scalar_device = ScalarWriteDevice(
        ByteBlockDevice::new(
            FileByteDevice::open(&production_path).expect("open scalar memfd"),
            u32::try_from(BLOCK_SIZE).expect("block size fits u32"),
        )
        .expect("build scalar block device"),
    );
    let grouped_device = make_grouped_production_device(&production_file);
    let cx = Cx::for_testing();
    let txn = make_transaction();
    black_box(run_production_commit(&scalar_device, &cx, &txn));
    let scalar_journal = read_journal_bytes(&production_file);
    black_box(run_production_commit(&grouped_device, &cx, &txn));
    let grouped_journal = read_journal_bytes(&production_file);
    assert_eq!(
        scalar_journal, grouped_journal,
        "production grouped journal bytes diverged from scalar"
    );
    println!(
        "production_behavior_parity=exact,writes_per_txn={DATA_BLOCKS},journal_bytes={}",
        scalar_journal.len()
    );
    spawn_profile_report();
}

fn main() {
    if std::env::args().any(|arg| arg == "--profile-only") {
        profile_only();
        return;
    }
    println!("bench_elf_sha256={}", self_identity());
    print_codegen_isa();
    if std::env::args().any(|arg| arg == "--profile-report-only") {
        run_profile_report_only();
        return;
    }

    let file = make_device(REGION_BYTES);
    let region = make_region();
    scalar_write(&file, &region);
    let mut scalar_bytes = vec![0_u8; REGION_BYTES];
    file.read_exact_at(&mut scalar_bytes, 0)
        .expect("read scalar bytes");
    combined_write(&file, &region);
    let mut combined_bytes = vec![0_u8; REGION_BYTES];
    file.read_exact_at(&mut combined_bytes, 0)
        .expect("read combined bytes");
    assert_eq!(scalar_bytes, region, "scalar bytes diverged from input");
    assert_eq!(combined_bytes, region, "combined bytes diverged from input");
    assert_eq!(scalar_bytes, combined_bytes, "write arms diverged");
    println!(
        "behavior_parity=exact,blocks_per_group={BLOCKS_PER_GROUP},region_bytes={REGION_BYTES}"
    );
    println!(
        "bench_config=groups_per_sample={GROUPS_PER_SAMPLE},rounds={ROUNDS},min_of={MIN_OF},bootstrap_resamples={BOOTSTRAP_RESAMPLES},bootstrap_seed={BOOTSTRAP_SEED:016x}"
    );

    black_box(run_arm(Arm::Scalar, &file, &region));
    black_box(run_arm(Arm::Combined, &file, &region));

    let scalar = || run_arm(Arm::Scalar, &file, &region);
    let combined = || run_arm(Arm::Combined, &file, &region);
    let null = paired(&scalar, &scalar);
    let real = paired(&scalar, &combined);
    print_stats("null_scalar_scalar", &null);
    print_stats("real_scalar_combined", &real);
    print_gate(
        "source_neutral_gate",
        &null,
        &real,
        ("combined_faster", "scalar_faster"),
    );

    let device_bytes = usize::try_from(DEVICE_BLOCKS)
        .expect("device blocks fit usize")
        .checked_mul(BLOCK_SIZE)
        .expect("device byte length");
    let production_file = make_device(device_bytes);
    let production_path = format!("/proc/self/fd/{}", production_file.as_raw_fd());
    let scalar_device = ScalarWriteDevice(
        ByteBlockDevice::new(
            FileByteDevice::open(&production_path).expect("open scalar memfd"),
            u32::try_from(BLOCK_SIZE).expect("block size fits u32"),
        )
        .expect("build scalar block device"),
    );
    let grouped_device = make_grouped_production_device(&production_file);
    assert!(!scalar_device.supports_contiguous_writes());
    assert!(grouped_device.supports_contiguous_writes());

    let cx = Cx::for_testing();
    let txn = make_transaction();
    black_box(run_production_commit(&scalar_device, &cx, &txn));
    let scalar_journal = read_journal_bytes(&production_file);
    black_box(run_production_commit(&grouped_device, &cx, &txn));
    let grouped_journal = read_journal_bytes(&production_file);
    assert_eq!(
        scalar_journal, grouped_journal,
        "production grouped journal bytes diverged from scalar"
    );
    println!(
        "production_behavior_parity=exact,writes_per_txn={DATA_BLOCKS},commits_per_sample={PRODUCTION_COMMITS_PER_SAMPLE},journal_bytes={}",
        scalar_journal.len()
    );

    let production_scalar = || run_production_commit(&scalar_device, &cx, &txn);
    let production_grouped = || run_production_commit(&grouped_device, &cx, &txn);
    let production_null = paired(&production_scalar, &production_scalar);
    let production_real = paired(&production_scalar, &production_grouped);
    print_stats("production_null_scalar_scalar", &production_null);
    print_stats("production_real_scalar_grouped", &production_real);
    print_gate(
        "production_gate",
        &production_null,
        &production_real,
        ("grouped_faster", "scalar_faster"),
    );
}
