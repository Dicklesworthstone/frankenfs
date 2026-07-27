#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the ext4 `listxattr` names-only enumeration.
//!
//! `listxattr` needs only the attribute NAMES, but the reader backend built the
//! full name list via `parse_xattr_block` — which allocates a name `Vec` AND a
//! value `Vec` per entry (and validates every value's in-block bounds) — then
//! mapped `full_name()` over the result and dropped the values.
//! `parse_xattr_block_names` builds the `full_name` strings during a single
//! entry-table walk and never touches the value region.
//!
//! The Criterion rows retain the original 24-entry VALUE_LEN sweep. The hidden
//! `--external-merge-contract` route profiles the current reader-level merge:
//! four inode-body names plus 128 external names. It compares actual production
//! against a source-neutral direct-append model, with an in-process ELF hash,
//! exact output parity, a counted temporary-vector mechanism, same-invocation
//! A/A+B, and a bootstrap median-CI gate.

use criterion::Criterion;
use ffs_ondisk::{
    Ext4ImageReader, Ext4Inode, Ext4Xattr, parse_ibody_xattr_names, parse_xattr_block,
    parse_xattr_block_names,
};
use ffs_types::ParseError;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::hint::black_box;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Instant;

const N: usize = 24;
const BLOCK_LEN: usize = 4096;
const EXT4_XATTR_MAGIC: u32 = 0xEA02_0000;
const EXT4_XATTR_INDEX_USER: u8 = 1;
const EXTERNAL_NAMES: usize = 128;
const IBODY_NAMES: usize = 4;
const CONTRACT_PAIRS: usize = 31;
const CONTRACT_BATCH: usize = 256;
const CONTRACT_MIN_OF: usize = 3;
const BOOTSTRAP_RESAMPLES: usize = 20_000;
const MAX_NULL_FLOOR_RATIO: f64 = 1.025;
const MIN_SAVED_FRACTION: f64 = 0.05;

#[derive(Clone, Copy)]
struct BootstrapMedianCi {
    median: f64,
    low: f64,
    high: f64,
}

struct ReaderFixture {
    reader: Ext4ImageReader,
    image: Vec<u8>,
    inode: Ext4Inode,
}

fn median(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "median requires at least one sample");
    values.sort_by(f64::total_cmp);
    let midpoint = values.len() / 2;
    if values.len() % 2 == 0 {
        values[midpoint - 1].midpoint(values[midpoint])
    } else {
        values[midpoint]
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn bootstrap_median_ci(log_ratios: &[f64], seed: u64) -> BootstrapMedianCi {
    assert!(
        !log_ratios.is_empty(),
        "bootstrap median CI requires paired samples"
    );
    let mut state = seed ^ u64::try_from(log_ratios.len()).expect("sample count fits");
    let mut bootstrapped = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let mut sample = Vec::with_capacity(log_ratios.len());
        for _ in log_ratios {
            let draw = splitmix64(&mut state)
                % u64::try_from(log_ratios.len()).expect("sample count fits");
            sample.push(log_ratios[usize::try_from(draw).expect("draw fits usize")]);
        }
        bootstrapped.push(median(sample));
    }
    bootstrapped.sort_by(f64::total_cmp);
    let low_index = BOOTSTRAP_RESAMPLES.saturating_mul(25) / 1000;
    let high_index = BOOTSTRAP_RESAMPLES
        .saturating_mul(975)
        .div_ceil(1000)
        .saturating_sub(1);
    BootstrapMedianCi {
        median: median(log_ratios.to_vec()).exp(),
        low: bootstrapped[low_index].exp(),
        high: bootstrapped[high_index].exp(),
    }
}

fn print_bench_evidence_metadata() {
    let exe = std::env::current_exe().expect("bench executable");
    let mut file = File::open(&exe).expect("open bench executable for hashing");
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer).expect("hash bench executable");
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let worker = Command::new("hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let digest = hasher.finalize();
    let mut sha256 = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        write!(&mut sha256, "{byte:02x}").expect("format bench executable hash");
    }
    println!(
        "bench_evidence,binary_sha256={sha256},binary_bytes={},worker={worker}",
        file.metadata().expect("stat bench executable").len()
    );
}

#[cfg(target_arch = "x86_64")]
fn print_codegen_isa() {
    println!(
        "codegen_isa,target_arch=x86_64,compile_sse2={},compile_sse4_2={},compile_avx2={},compile_fma={},runtime_sse4_2={},runtime_avx2={},runtime_fma={}",
        cfg!(target_feature = "sse2"),
        cfg!(target_feature = "sse4.2"),
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "fma"),
        std::is_x86_feature_detected!("sse4.2"),
        std::is_x86_feature_detected!("avx2"),
        std::is_x86_feature_detected!("fma"),
    );
}

#[cfg(not(target_arch = "x86_64"))]
fn print_codegen_isa() {
    println!("codegen_isa,target_arch=non_x86_64");
}

fn write_name_entry(data: &mut [u8], offset: usize, name_index: u8, name: &[u8]) -> usize {
    let name_end = offset + 16 + name.len();
    assert!(name_end + 4 <= data.len(), "xattr name fixture fits");
    data[offset] = u8::try_from(name.len()).expect("xattr fixture name fits u8");
    data[offset + 1] = name_index;
    data[offset + 16..name_end].copy_from_slice(name);
    (name_end + 3) & !3
}

fn build_name_region(prefix: u8, count: usize, name_index: u8) -> Vec<u8> {
    let mut data = vec![0_u8; count.saturating_mul(24).saturating_add(4)];
    let mut offset = 0;
    for index in 0..count {
        let name = [
            prefix,
            b'0' + u8::try_from((index / 100) % 10).expect("digit fits"),
            b'0' + u8::try_from((index / 10) % 10).expect("digit fits"),
            b'0' + u8::try_from(index % 10).expect("digit fits"),
        ];
        offset = write_name_entry(&mut data, offset, name_index, &name);
    }
    data
}

fn build_external_name_block(count: usize) -> Vec<u8> {
    let mut block = vec![0_u8; BLOCK_LEN];
    block[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let region = build_name_region(b'e', count, ffs_types::EXT4_XATTR_INDEX_USER);
    block[32..32 + region.len()].copy_from_slice(&region);
    block
}

fn build_prefix_oracle_block() -> Vec<u8> {
    let indices = [
        ffs_types::EXT4_XATTR_INDEX_USER,
        ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_ACCESS,
        ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
        ffs_types::EXT4_XATTR_INDEX_TRUSTED,
        ffs_types::EXT4_XATTR_INDEX_LUSTRE,
        ffs_types::EXT4_XATTR_INDEX_SECURITY,
        ffs_types::EXT4_XATTR_INDEX_SYSTEM,
        ffs_types::EXT4_XATTR_INDEX_RICHACL,
        u8::MAX,
    ];
    let mut block = vec![0_u8; BLOCK_LEN];
    block[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let mut offset = 32;
    for (position, index) in indices.into_iter().enumerate() {
        let name = [
            b'n',
            u8::try_from(position).expect("prefix fixture position fits"),
            0xff,
        ];
        offset = write_name_entry(&mut block, offset, index, &name);
    }
    block
}

fn reader_fixture() -> ReaderFixture {
    const IMAGE_BLOCKS: usize = 64;
    const XATTR_BLOCK: usize = 50;
    let mut image = vec![0_u8; IMAGE_BLOCKS * BLOCK_LEN];
    let superblock = &mut image[1024..2048];
    superblock[0x38..0x3a].copy_from_slice(&0xEF53_u16.to_le_bytes());
    superblock[0x18..0x1c].copy_from_slice(&2_u32.to_le_bytes());
    superblock[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes());
    superblock[0x04..0x08].copy_from_slice(
        &u32::try_from(IMAGE_BLOCKS)
            .expect("image blocks fit")
            .to_le_bytes(),
    );
    superblock[0x20..0x24].copy_from_slice(
        &u32::try_from(IMAGE_BLOCKS)
            .expect("image blocks fit")
            .to_le_bytes(),
    );
    superblock[0x28..0x2c].copy_from_slice(&8192_u32.to_le_bytes());
    superblock[0x58..0x5a].copy_from_slice(&256_u16.to_le_bytes());
    superblock[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes());

    let external = build_external_name_block(EXTERNAL_NAMES);
    let block_start = XATTR_BLOCK * BLOCK_LEN;
    image[block_start..block_start + BLOCK_LEN].copy_from_slice(&external);

    let mut xattr_ibody = vec![0_u8; 4];
    xattr_ibody[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    xattr_ibody.extend(build_name_region(
        b'i',
        IBODY_NAMES,
        ffs_types::EXT4_XATTR_INDEX_SECURITY,
    ));
    let inode = Ext4Inode {
        mode: 0o100_644,
        uid: 0,
        gid: 0,
        size: 0,
        links_count: 1,
        blocks: 0,
        flags: 0,
        version: 0,
        generation: 0,
        file_acl: u64::try_from(XATTR_BLOCK).expect("xattr block fits"),
        atime: 0,
        ctime: 0,
        mtime: 0,
        dtime: 0,
        atime_extra: 0,
        ctime_extra: 0,
        mtime_extra: 0,
        crtime: 0,
        crtime_extra: 0,
        extra_isize: 32,
        checksum: 0,
        version_hi: 0,
        projid: 0,
        extent_bytes: vec![0_u8; 60].into(),
        xattr_ibody,
        number: 1,
    };
    let reader = Ext4ImageReader::new(&image).expect("parse xattr benchmark image");
    ReaderFixture {
        reader,
        image,
        inode,
    }
}

fn model_prefix(name_index: u8) -> &'static str {
    match name_index {
        ffs_types::EXT4_XATTR_INDEX_USER => "user.",
        ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_ACCESS => "system.posix_acl_access",
        ffs_types::EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT => "system.posix_acl_default",
        ffs_types::EXT4_XATTR_INDEX_TRUSTED => "trusted.",
        ffs_types::EXT4_XATTR_INDEX_SECURITY => "security.",
        ffs_types::EXT4_XATTR_INDEX_SYSTEM => "system.",
        ffs_types::EXT4_XATTR_INDEX_RICHACL => "system.richacl",
        _ => "unknown.",
    }
}

fn append_entry_names_model(data: &[u8], names: &mut Vec<String>) -> Result<(), ParseError> {
    let mut offset = 0_usize;
    loop {
        if offset + 4 > data.len() {
            break;
        }
        let name_len = data[offset];
        let name_index = data[offset + 1];
        if name_len == 0 && name_index == 0 {
            break;
        }
        if offset + 16 > data.len() {
            break;
        }
        let name_start = offset + 16;
        let name_end = name_start + usize::from(name_len);
        if name_end > data.len() {
            return Err(ParseError::InvalidField {
                field: "xattr_name",
                reason: "name extends past data boundary",
            });
        }
        let prefix = model_prefix(name_index);
        let name = String::from_utf8_lossy(&data[name_start..name_end]);
        let mut full_name = String::with_capacity(prefix.len() + name.len());
        full_name.push_str(prefix);
        full_name.push_str(&name);
        names.push(full_name);
        offset = (name_end + 3) & !3;
    }
    Ok(())
}

fn append_block_names_model(block_data: &[u8], names: &mut Vec<String>) -> Result<(), ParseError> {
    if block_data.len() < 32 {
        return Err(ParseError::InsufficientData {
            needed: 32,
            offset: 0,
            actual: block_data.len(),
        });
    }
    let magic = u32::from_le_bytes(block_data[0..4].try_into().expect("checked block header"));
    if magic != EXT4_XATTR_MAGIC {
        return Err(ParseError::InvalidMagic {
            expected: u64::from(EXT4_XATTR_MAGIC),
            actual: u64::from(magic),
        });
    }
    append_entry_names_model(&block_data[32..], names)
}

#[inline(never)]
fn production_materialized_merge(
    reader: &Ext4ImageReader,
    image: &[u8],
    inode: &Ext4Inode,
) -> Result<Vec<String>, ParseError> {
    reader.list_xattr_names(image, inode)
}

#[inline(never)]
fn direct_external_append_model(
    reader: &Ext4ImageReader,
    image: &[u8],
    inode: &Ext4Inode,
) -> Result<Vec<String>, ParseError> {
    let mut names = parse_ibody_xattr_names(inode)?;
    if inode.file_acl != 0 {
        let block_data = reader.read_block(image, ffs_types::BlockNumber(inode.file_acl))?;
        append_block_names_model(block_data, &mut names)?;
    }
    Ok(names)
}

fn names_checksum(names: &[String]) -> u64 {
    let mut checksum = u64::try_from(names.len()).expect("name count fits");
    for name in names {
        checksum = checksum
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::try_from(name.len()).expect("name length fits"));
        for &byte in name.as_bytes() {
            checksum = checksum.rotate_left(5) ^ u64::from(byte);
        }
    }
    checksum
}

type MergeOperation = fn(&Ext4ImageReader, &[u8], &Ext4Inode) -> Result<Vec<String>, ParseError>;

fn run_contract_batch(fixture: &ReaderFixture, operation: MergeOperation) -> u64 {
    let mut checksum = 0_u64;
    for iteration in 0..CONTRACT_BATCH {
        let names = operation(
            black_box(&fixture.reader),
            black_box(&fixture.image),
            black_box(&fixture.inode),
        )
        .expect("run names merge arm");
        checksum ^= names_checksum(black_box(&names))
            .rotate_left(u32::try_from(iteration % u64::BITS as usize).expect("rotation fits"));
    }
    checksum
}

fn observe_contract(fixture: &ReaderFixture, operation: MergeOperation) -> (f64, u64) {
    let mut best_ns = f64::INFINITY;
    let mut checksum = 0_u64;
    for replicate in 0..CONTRACT_MIN_OF {
        let started = Instant::now();
        let observed = black_box(run_contract_batch(fixture, operation));
        let elapsed_ns = started.elapsed().as_secs_f64() * 1e9;
        best_ns = best_ns.min(elapsed_ns.max(1.0));
        checksum ^= observed.rotate_left(u32::try_from(replicate).expect("rotation fits"));
    }
    (best_ns, checksum)
}

fn external_merge_contract() {
    print_bench_evidence_metadata();
    print_codegen_isa();
    let fixture = reader_fixture();
    let control = production_materialized_merge(&fixture.reader, &fixture.image, &fixture.inode)
        .expect("production names");
    let model = direct_external_append_model(&fixture.reader, &fixture.image, &fixture.inode)
        .expect("direct-append model names");
    assert_eq!(control, model, "direct append changed complete name vector");
    assert_eq!(control.len(), IBODY_NAMES + EXTERNAL_NAMES);

    let prefix_block = build_prefix_oracle_block();
    let prefix_control = parse_xattr_block_names(&prefix_block).expect("prefix control");
    let mut prefix_model = Vec::new();
    append_block_names_model(&prefix_block, &mut prefix_model).expect("prefix model");
    assert_eq!(
        prefix_control, prefix_model,
        "direct append changed prefixes or invalid UTF-8 handling"
    );
    let expected_checksum = names_checksum(&control);
    println!(
        "external_merge_parity=exact,ibody_names={IBODY_NAMES},external_names={EXTERNAL_NAMES},total_names={},name_checksum={expected_checksum:016x},prefix_invalid_utf8_cases={}",
        control.len(),
        prefix_control.len()
    );
    println!(
        "external_merge_mechanism,control_temporary_external_vecs=1,candidate_temporary_external_vecs=0,control_string_objects_moved={EXTERNAL_NAMES},candidate_string_objects_moved=0"
    );

    black_box(run_contract_batch(&fixture, production_materialized_merge));
    black_box(run_contract_batch(&fixture, direct_external_append_model));
    let mut control_lhs = Vec::with_capacity(CONTRACT_PAIRS);
    let mut control_rhs = Vec::with_capacity(CONTRACT_PAIRS);
    let mut candidate = Vec::with_capacity(CONTRACT_PAIRS);
    let mut raw_pairs = String::new();
    let mut checksum = 0_u64;
    for pair_index in 0..CONTRACT_PAIRS {
        let (lhs, rhs, modeled, order) = if pair_index % 2 == 0 {
            let lhs = observe_contract(&fixture, production_materialized_merge);
            let rhs = observe_contract(&fixture, production_materialized_merge);
            let modeled = observe_contract(&fixture, direct_external_append_model);
            (lhs, rhs, modeled, "AAB")
        } else {
            let modeled = observe_contract(&fixture, direct_external_append_model);
            let rhs = observe_contract(&fixture, production_materialized_merge);
            let lhs = observe_contract(&fixture, production_materialized_merge);
            (lhs, rhs, modeled, "BAA")
        };
        assert_eq!(lhs.1, rhs.1, "A/A checksums diverged");
        assert_eq!(lhs.1, modeled.1, "A/B checksums diverged");
        checksum ^= lhs
            .1
            .rotate_left(u32::try_from(pair_index).expect("rotation fits"));
        control_lhs.push(lhs.0);
        control_rhs.push(rhs.0);
        candidate.push(modeled.0);
        if pair_index > 0 {
            raw_pairs.push(';');
        }
        write!(
            &mut raw_pairs,
            "{order}:{:.0}:{:.0}:{:.0}",
            lhs.0, rhs.0, modeled.0
        )
        .expect("format external merge pair");
    }

    let null_logs = control_lhs
        .iter()
        .zip(&control_rhs)
        .map(|(lhs, rhs)| (lhs / rhs).ln())
        .collect::<Vec<_>>();
    let speedup_logs = control_lhs
        .iter()
        .zip(&control_rhs)
        .zip(&candidate)
        .map(|((lhs, rhs), modeled)| (lhs.midpoint(*rhs) / modeled).ln())
        .collect::<Vec<_>>();
    let null = bootstrap_median_ci(&null_logs, 0xAA11_2026_0727_0001);
    let speedup = bootstrap_median_ci(&speedup_logs, 0xAB11_2026_0727_0002);
    let null_log_radius = null.low.ln().abs().max(null.high.ln().abs());
    let null_floor = null_log_radius.exp();
    let twice_null = (2.0 * null_log_radius).exp();
    let saved_fraction_lower = 1.0 - speedup.low.recip();
    let admitted = null_floor <= MAX_NULL_FLOOR_RATIO
        && speedup.low > twice_null
        && saved_fraction_lower >= MIN_SAVED_FRACTION;
    let verdict = if admitted {
        "ADMIT_PRODUCTION_EDIT"
    } else if null_floor > MAX_NULL_FLOOR_RATIO {
        "REJECT_NULL_FLOOR"
    } else if speedup.low <= twice_null {
        "REJECT_BELOW_TWICE_NULL"
    } else {
        "REJECT_BELOW_SAVED_FRACTION"
    };
    println!(
        "external_merge_pairs,pairs={CONTRACT_PAIRS},batch={CONTRACT_BATCH},min_of={CONTRACT_MIN_OF},format=order:control_lhs_ns:control_rhs_ns:candidate_ns,values={raw_pairs}"
    );
    println!(
        "external_merge_ab,control_aa_median={:.6},control_aa_ci_low={:.6},control_aa_ci_high={:.6},control_aa_null_floor_ratio={null_floor:.6},maximum_null_floor_ratio={MAX_NULL_FLOOR_RATIO:.6},twice_null_ratio={twice_null:.6},control_over_candidate_median={:.6},control_over_candidate_ci_low={:.6},control_over_candidate_ci_high={:.6},saved_fraction_ci_lower={saved_fraction_lower:.6},minimum_saved_fraction={MIN_SAVED_FRACTION:.6},admitted={admitted},verdict={verdict},checksum={checksum:016x},gate_metric=wall_ns,gate_basis=bootstrap_median_ci,bootstrap_resamples={BOOTSTRAP_RESAMPLES},cv_used=false,instructions_used=false",
        null.median, null.low, null.high, speedup.median, speedup.low, speedup.high,
    );
}

fn external_merge_profile_only() {
    const PROFILE_BATCHES: usize = 1_024;
    let fixture = reader_fixture();
    let mut checksum = 0_u64;
    for batch in 0..PROFILE_BATCHES {
        checksum ^= black_box(run_contract_batch(&fixture, production_materialized_merge))
            .rotate_left(u32::try_from(batch % u64::BITS as usize).expect("rotation fits"));
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

fn external_merge_profile_report() {
    const ATTRIBUTION_FLOOR_PCT: f64 = 5.0;
    print_bench_evidence_metadata();
    print_codegen_isa();
    println!(
        "profile_scope=actual_production_ext4_list_xattr_names,ratio_published=false,aa_gate=not_applicable,gate_basis=numeric_self_time,cv_used=false,instructions_used=false"
    );
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
        .arg("--external-merge-profile-only")
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
    if !record_status.success() || !report.status.success() {
        println!(
            "profile_blocker=perf_permission_denied,record_status={record_status},report_status={}",
            report.status
        );
        return;
    }
    let list_pct = profile_percent(&text, "Ext4ImageReader::list_xattr_names").unwrap_or(0.0);
    let parser_pct = profile_percent(&text, "parse_xattr_entry_names").unwrap_or(0.0);
    let attributed = list_pct >= ATTRIBUTION_FLOOR_PCT && parser_pct > 0.0;
    println!(
        "profile_target_attribution,list_xattr_names_children_pct={list_pct:.6},parse_xattr_entry_names_pct={parser_pct:.6},attribution_floor_pct={ATTRIBUTION_FLOOR_PCT:.6},admitted={attributed}"
    );
    if !attributed {
        println!("profile_blocker=xattr_names_frames_below_attribution_floor");
    }
}

fn build_block(value_len: usize) -> Vec<u8> {
    let mut block = vec![0_u8; BLOCK_LEN];
    block[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let mut entry_off = 32_usize;
    for i in 0..N {
        let name = format!("attr{i:02}");
        let name_bytes = name.as_bytes();
        // Pack values backwards from the end of the block. The previous
        // `2048 + i * value_len` layout overflowed the 4 KiB fixture for the
        // 24 x 128-byte row before Criterion could benchmark it.
        let value_offs = BLOCK_LEN - (i + 1) * value_len;
        block[entry_off] = name_bytes.len() as u8;
        block[entry_off + 1] = EXT4_XATTR_INDEX_USER;
        block[entry_off + 2..entry_off + 4].copy_from_slice(&(value_offs as u16).to_le_bytes());
        block[entry_off + 4..entry_off + 8].copy_from_slice(&0_u32.to_le_bytes());
        block[entry_off + 8..entry_off + 12].copy_from_slice(&(value_len as u32).to_le_bytes());
        block[entry_off + 12..entry_off + 16].copy_from_slice(&0_u32.to_le_bytes());
        block[entry_off + 16..entry_off + 16 + name_bytes.len()].copy_from_slice(name_bytes);
        for (j, b) in block[value_offs..value_offs + value_len]
            .iter_mut()
            .enumerate()
        {
            *b = (i as u8).wrapping_mul(31).wrapping_add(j as u8);
        }
        entry_off = (entry_off + 16 + name_bytes.len() + 3) & !3;
    }
    block[entry_off] = 0;
    block[entry_off + 1] = 0;
    block
}

/// Old path: materialise every attribute (name + value), then map full_name.
fn parse_all_then_names(block: &[u8]) -> Vec<String> {
    parse_xattr_block(block)
        .unwrap()
        .iter()
        .map(ffs_ondisk::Ext4Xattr::full_name)
        .collect()
}

/// Frozen control for the former names-only formatter. This intentionally
/// mirrors the old `format!("{}{}", prefix, from_utf8_lossy(name))` shape while
/// walking the same valid user-namespace fixture as the production parser.
fn parse_names_format_control(block: &[u8]) -> Vec<String> {
    assert_eq!(
        u32::from_le_bytes(block[0..4].try_into().unwrap()),
        EXT4_XATTR_MAGIC
    );
    let data = &block[32..];
    let mut names = Vec::new();
    let mut offset = 0_usize;
    loop {
        let name_len = usize::from(data[offset]);
        let name_index = data[offset + 1];
        if name_len == 0 && name_index == 0 {
            break;
        }
        assert_eq!(name_index, EXT4_XATTR_INDEX_USER);
        let name_start = offset + 16;
        let name_end = name_start + name_len;
        names.push(format!(
            "user.{}",
            String::from_utf8_lossy(&data[name_start..name_end])
        ));
        offset = (name_end + 3) & !3;
    }
    names
}

/// Frozen control for `Ext4Xattr::full_name` before exact-capacity assembly.
fn full_name_format_control(xattr: &Ext4Xattr) -> String {
    assert_eq!(xattr.name_index, EXT4_XATTR_INDEX_USER);
    format!("user.{}", String::from_utf8_lossy(&xattr.name))
}

fn bench_group(c: &mut Criterion, value_len: usize, label: &str) {
    let block = build_block(value_len);
    // Isomorphism: names-only returns the same full names as materialise-all.
    let old = parse_all_then_names(&block);
    let new = parse_xattr_block_names(&block).unwrap();
    assert_eq!(
        old, new,
        "names-only diverged from materialise-all ({label})"
    );
    assert_eq!(new.len(), N);

    let mut g = c.benchmark_group(format!("ext4_listxattr_block_24_{label}"));
    g.bench_function("parse_all_then_names", |b| {
        b.iter(|| black_box(parse_all_then_names(black_box(&block))));
    });
    g.bench_function("names_only", |b| {
        b.iter(|| black_box(parse_xattr_block_names(black_box(&block)).unwrap()));
    });
    g.finish();
}

fn bench_formatter_ab(c: &mut Criterion) {
    let block = build_block(32);
    let control = parse_names_format_control(&block);
    let candidate = parse_xattr_block_names(&block).unwrap();
    assert_eq!(
        control, candidate,
        "formatter candidate changed listxattr output"
    );

    let mut g = c.benchmark_group("ext4_listxattr_block_24_formatter_ab");
    g.bench_function("format_control_a", |b| {
        b.iter(|| black_box(parse_names_format_control(black_box(&block))));
    });
    g.bench_function("format_control_b", |b| {
        b.iter(|| black_box(parse_names_format_control(black_box(&block))));
    });
    g.bench_function("preallocated", |b| {
        b.iter(|| black_box(parse_xattr_block_names(black_box(&block)).unwrap()));
    });
    g.finish();
}

fn bench_full_name_ab(c: &mut Criterion) {
    let xattrs = parse_xattr_block(&build_block(32)).unwrap();
    let control: Vec<String> = xattrs.iter().map(full_name_format_control).collect();
    let candidate: Vec<String> = xattrs.iter().map(Ext4Xattr::full_name).collect();
    assert_eq!(control, candidate, "full_name candidate changed output");

    let mut g = c.benchmark_group("ext4_xattr_full_name_24_ab");
    g.bench_function("format_control_a", |b| {
        b.iter(|| {
            black_box(
                black_box(&xattrs)
                    .iter()
                    .map(full_name_format_control)
                    .collect::<Vec<_>>(),
            )
        });
    });
    g.bench_function("format_control_b", |b| {
        b.iter(|| {
            black_box(
                black_box(&xattrs)
                    .iter()
                    .map(full_name_format_control)
                    .collect::<Vec<_>>(),
            )
        });
    });
    g.bench_function("exact_capacity_candidate", |b| {
        b.iter(|| {
            black_box(
                black_box(&xattrs)
                    .iter()
                    .map(Ext4Xattr::full_name)
                    .collect::<Vec<_>>(),
            )
        });
    });
    g.finish();
}

fn bench(c: &mut Criterion) {
    bench_group(c, 32, "smallval"); // SELinux/caps-sized values
    bench_group(c, 128, "largeval"); // ACL/EA-sized values
    bench_formatter_ab(c);
    bench_full_name_ab(c);
}

fn main() {
    if std::env::args().any(|arg| arg == "--external-merge-contract") {
        external_merge_contract();
        return;
    }
    if std::env::args().any(|arg| arg == "--external-merge-profile-only") {
        external_merge_profile_only();
        return;
    }
    if std::env::args().any(|arg| arg == "--external-merge-profile-report") {
        external_merge_profile_report();
        return;
    }

    let mut criterion = Criterion::default().configure_from_args();
    bench(&mut criterion);
    criterion.final_summary();
}
