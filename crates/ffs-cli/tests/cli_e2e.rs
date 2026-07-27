//! CLI binary E2E tests for ffs-cli.
//!
//! These tests spawn actual `cargo run -p ffs-cli` processes against real
//! filesystem images created via mkfs.ext4/mkfs.btrfs. No mocks are used.

#![allow(
    clippy::uninlined_format_args,
    clippy::nonminimal_bool,
    clippy::cast_possible_truncation,
    clippy::if_not_else
)]

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn emit_scenario_result(scenario_id: &str, outcome: &str, detail: Option<&str>) {
    match detail {
        Some(detail) => {
            eprintln!(
                "SCENARIO_RESULT|scenario_id={scenario_id}|outcome={outcome}|detail={detail}"
            );
        }
        None => eprintln!("SCENARIO_RESULT|scenario_id={scenario_id}|outcome={outcome}"),
    }
}

fn command_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn cli_prerequisites_available() -> bool {
    command_available("mkfs.ext4") && command_available("debugfs")
}

fn btrfs_prerequisites_available() -> bool {
    command_available("mkfs.btrfs")
}

fn create_minimal_btrfs_image(dir: &Path, size_mb: u32) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");

    let dd_status = Command::new("dd")
        .args(["if=/dev/zero", &format!("of={}", image.display()), "bs=1M"])
        .arg(format!("count={}", size_mb))
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .expect("dd failed");
    assert!(dd_status.success(), "dd failed to create image file");

    let mkfs_status = Command::new("mkfs.btrfs")
        .args(["-f", "-q"])
        .arg(&image)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("mkfs.btrfs failed");
    assert!(mkfs_status.success(), "mkfs.btrfs failed");

    image
}

fn create_minimal_ext4_image(dir: &Path, size_mb: u32) -> std::path::PathBuf {
    let image = dir.join("test.ext4");
    let size_str = format!("{}M", size_mb);

    let dd_status = Command::new("dd")
        .args(["if=/dev/zero", &format!("of={}", image.display()), "bs=1M"])
        .arg(format!("count={}", size_mb))
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .expect("dd failed");
    assert!(dd_status.success(), "dd failed to create image file");

    let mkfs_status = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-b", "4096"])
        .arg(&image)
        .arg(&size_str)
        .status()
        .expect("mkfs.ext4 failed");
    assert!(mkfs_status.success(), "mkfs.ext4 failed");

    let debugfs_cmds = "mkdir testdir\nwrite /dev/null testdir/empty.txt\nquit\n";
    let debugfs_status = Command::new("debugfs")
        .args(["-w", "-f", "-"])
        .arg(&image)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(debugfs_cmds.as_bytes())?;
            }
            child.wait()
        })
        .expect("debugfs failed");
    assert!(debugfs_status.success(), "debugfs failed");

    image
}

fn run_ffs_cli(args: &[&str]) -> std::process::Output {
    let bin_path = env!("CARGO_BIN_EXE_ffs-cli");

    Command::new(bin_path)
        .args(args)
        .output()
        .expect("failed to execute ffs-cli")
}

fn required_env_path(name: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(
        || panic!("{name} must be set for the ignored bd-b9dug driver"),
        PathBuf::from,
    )
}

fn required_env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set for the ignored bd-b9dug driver"))
}

fn sha256_file(path: &Path) -> String {
    let mut file =
        fs::File::open(path).unwrap_or_else(|error| panic!("open {}: {error}", path.display()));
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("format SHA-256");
    }
    encoded
}

fn run_cli_binary(binary: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("execute {}: {error}", binary.display()))
}

fn run_cli_binary_checked(label: &str, binary: &Path, args: &[&str]) -> Output {
    let output = run_cli_binary(binary, args);
    assert!(
        output.status.success(),
        "{label} failed for {} {:?}: status={:?}\nstdout:\n{}\nstderr:\n{}",
        binary.display(),
        args,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!(
        "bd_b9dug_training_step,label={label},status=ok\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

struct CliEvidence {
    binary_sha256: String,
    pgo_profile_sha256: String,
    codegen_line: String,
}

fn cli_evidence(binary: &Path) -> CliEvidence {
    let output = run_cli_binary_checked("bench_evidence", binary, &["bench-evidence"]);
    let stdout = String::from_utf8(output.stdout).expect("bench-evidence stdout is UTF-8");
    let mut lines = stdout.lines().filter(|line| !line.trim().is_empty());
    let identity = lines.next().expect("bench-evidence identity line");
    let binary_sha256 = identity
        .strip_prefix("bench_evidence,binary_sha256=")
        .expect("bench-evidence stdout line one is the in-process ELF SHA")
        .to_owned();
    assert!(
        binary_sha256.len() == 64 && binary_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid in-process ELF SHA-256: {binary_sha256}"
    );
    let codegen_line = lines
        .next()
        .expect("bench-evidence codegen line")
        .to_owned();
    assert!(
        codegen_line.starts_with("codegen_isa,"),
        "invalid codegen witness: {codegen_line}"
    );
    let build_profile = lines.next().expect("bench-evidence build-profile line");
    let pgo_profile_sha256 = build_profile
        .strip_prefix("build_profile,pgo_profile_sha256=")
        .expect("bench-evidence PGO profile line")
        .to_owned();
    CliEvidence {
        binary_sha256,
        pgo_profile_sha256,
        codegen_line,
    }
}

fn find_llvm_profdata() -> PathBuf {
    if let Some(path) = std::env::var_os("LLVM_PROFDATA") {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "LLVM_PROFDATA is not a file: {}",
            path.display()
        );
        return path;
    }

    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
        .expect("RUSTUP_HOME or HOME is set");
    let toolchains = rustup_home.join("toolchains");
    let mut candidates = fs::read_dir(&toolchains)
        .unwrap_or_else(|error| panic!("read {}: {error}", toolchains.display()))
        .map(|entry| {
            entry
                .expect("read rustup toolchain entry")
                .path()
                .join("lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata")
        })
        .filter(|candidate| candidate.is_file())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.into_iter().next().unwrap_or_else(|| {
        panic!(
            "llvm-profdata unavailable under {}; install llvm-tools-preview",
            toolchains.display()
        )
    })
}

#[derive(Clone, Copy)]
struct BootstrapMedianCi {
    median: f64,
    low: f64,
    high: f64,
}

fn median(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "median requires a non-empty sample");
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

fn bootstrap_median_ci(log_ratios: &[f64]) -> BootstrapMedianCi {
    const RESAMPLES: usize = 20_000;
    assert!(
        !log_ratios.is_empty(),
        "bootstrap median CI requires paired observations"
    );
    let mut state =
        0xB9D0_6202_6072_7001_u64 ^ u64::try_from(log_ratios.len()).expect("length fits u64");
    let mut bootstrapped = Vec::with_capacity(RESAMPLES);
    for _ in 0..RESAMPLES {
        let mut sample = Vec::with_capacity(log_ratios.len());
        for _ in log_ratios {
            let draw =
                splitmix64(&mut state) % u64::try_from(log_ratios.len()).expect("length fits u64");
            sample.push(log_ratios[usize::try_from(draw).expect("draw fits usize")]);
        }
        bootstrapped.push(median(sample));
    }
    bootstrapped.sort_by(f64::total_cmp);
    let low_index = RESAMPLES.saturating_mul(25) / 1000;
    let high_index = RESAMPLES
        .saturating_mul(975)
        .div_ceil(1000)
        .saturating_sub(1);
    BootstrapMedianCi {
        median: median(log_ratios.to_vec()).exp(),
        low: bootstrapped[low_index].exp(),
        high: bootstrapped[high_index].exp(),
    }
}

fn lookup_observation(binary: &Path, image: &Path, count: usize) -> (f64, String) {
    let image = image.to_str().expect("lookup image path is UTF-8");
    let count = count.to_string();
    let output = run_cli_binary(binary, &["lookup-bench", image, "/", "--count", &count]);
    assert!(
        output.status.success(),
        "lookup observation failed: binary={} status={:?}\nstdout:\n{}\nstderr:\n{}",
        binary.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("lookup stderr is UTF-8");
    let line = stderr
        .lines()
        .find(|line| line.contains("lookupbench:") && line.contains(" found in "))
        .unwrap_or_else(|| panic!("lookup result line missing from:\n{stderr}"));
    let (signature, elapsed) = line
        .split_once(" found in ")
        .expect("lookup result contains elapsed delimiter");
    let duration_us = elapsed
        .split_once(" us")
        .expect("lookup result contains microsecond suffix")
        .0
        .parse::<f64>()
        .expect("lookup duration is numeric");
    assert!(duration_us > 0.0, "lookup duration must be positive");
    (duration_us, signature.to_owned())
}

fn csv_value<'a>(line: &'a str, key: &str) -> &'a str {
    line.split(',')
        .find_map(|field| field.strip_prefix(key))
        .unwrap_or_else(|| panic!("missing {key} in {line}"))
}

struct CreateObservation {
    create_us: f64,
    persisted_us: f64,
    state_signature: String,
}

fn create_bench_timings(stdout: &str, count: usize, rounds: usize) -> (f64, f64) {
    let count_arg = count.to_string();
    let rounds_arg = rounds.to_string();
    let create_rounds = stdout
        .lines()
        .filter(|line| line.starts_with("createbench_round,"))
        .collect::<Vec<_>>();
    assert_eq!(
        create_rounds.len(),
        rounds,
        "create observation did not report every requested round"
    );
    let mut create_us = 0.0;
    for (round, line) in create_rounds.iter().enumerate() {
        assert_eq!(
            csv_value(line, "round="),
            round.to_string(),
            "create round order changed"
        );
        assert_eq!(csv_value(line, "threads="), "1");
        assert_eq!(csv_value(line, "count="), count_arg);
        create_us += csv_value(line, "create_us=")
            .parse::<f64>()
            .expect("create_us is numeric");
    }
    let flush_line = stdout
        .lines()
        .find(|line| line.starts_with("createbench_flush,"))
        .expect("create observation flush line");
    assert_eq!(csv_value(flush_line, "rounds="), rounds_arg);
    let flush_us = csv_value(flush_line, "flush_us=")
        .parse::<f64>()
        .expect("flush_us is numeric");
    (create_us, flush_us)
}

fn walk_state_signature(binary: &Path, image: &str) -> String {
    let walk = run_cli_binary(binary, &["walk", image, "--no-stat"]);
    assert!(
        walk.status.success(),
        "walk after create failed: binary={} status={:?}\nstdout:\n{}\nstderr:\n{}",
        binary.display(),
        walk.status,
        String::from_utf8_lossy(&walk.stdout),
        String::from_utf8_lossy(&walk.stderr)
    );
    let walk_stderr = String::from_utf8(walk.stderr).expect("walk stderr is UTF-8");
    let walk_line = walk_stderr
        .lines()
        .find(|line| line.starts_with("walked "))
        .unwrap_or_else(|| panic!("walk result line missing from:\n{walk_stderr}"));
    walk_line
        .split_once(" [")
        .expect("walk result contains mode/timing delimiter")
        .0
        .to_owned()
}

fn create_observation(
    binary: &Path,
    expected_binary_sha256: &str,
    source_image: &Path,
    source_image_sha256: &str,
    working_image: &Path,
    count: usize,
    rounds: usize,
) -> CreateObservation {
    let copied_bytes = fs::copy(source_image, working_image).unwrap_or_else(|error| {
        panic!(
            "copy create input {} -> {}: {error}",
            source_image.display(),
            working_image.display()
        )
    });
    assert_eq!(
        copied_bytes,
        fs::metadata(source_image)
            .expect("create source image metadata")
            .len(),
        "create input copy length changed"
    );
    assert_eq!(
        sha256_file(working_image),
        source_image_sha256,
        "create observation did not start from the exact source image"
    );

    let image = working_image
        .to_str()
        .expect("create working image path is UTF-8");
    let count_arg = count.to_string();
    let rounds_arg = rounds.to_string();
    let output = run_cli_binary(
        binary,
        &[
            "create-bench",
            image,
            "/",
            "--count",
            &count_arg,
            "--threads",
            "1",
            "--rounds",
            &rounds_arg,
        ],
    );
    assert!(
        output.status.success(),
        "create observation failed: binary={} status={:?}\nstdout:\n{}\nstderr:\n{}",
        binary.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("create stdout is UTF-8");
    let self_sha256 = stdout
        .lines()
        .find_map(|line| line.strip_prefix("bench_evidence,binary_sha256="))
        .expect("create observation self-reported executing ELF SHA");
    assert_eq!(
        self_sha256, expected_binary_sha256,
        "create observation executed an unexpected ELF"
    );
    let (create_us, flush_us) = create_bench_timings(&stdout, count, rounds);
    let state_signature = walk_state_signature(binary, image);

    CreateObservation {
        create_us,
        persisted_us: create_us + flush_us,
        state_signature,
    }
}

fn bd_b9dug_run_id() -> String {
    let run_id = required_env("FFS_B9DUG_RUN_ID");
    assert!(
        !run_id.is_empty()
            && run_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "FFS_B9DUG_RUN_ID must be a non-empty safe identifier"
    );
    run_id
}

fn prepare_pgo_training_image(profile_dir: &Path, run_id: &str) -> PathBuf {
    fs::create_dir_all(profile_dir).expect("create remote PGO profile directory");
    let training_image = profile_dir.join(format!("training-{run_id}.ext4"));
    assert!(
        !training_image.exists(),
        "refusing to overwrite training image {}",
        training_image.display()
    );
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/golden/ext4_dir_index_reference.ext4");
    fs::copy(&fixture, &training_image).unwrap_or_else(|error| {
        panic!(
            "copy PGO fixture {} -> {}: {error}",
            fixture.display(),
            training_image.display()
        )
    });
    training_image
}

fn run_pgo_training_workload(binary: &Path, training_image: &Path) {
    let image = training_image
        .to_str()
        .expect("training image path is UTF-8");
    run_cli_binary_checked(
        "create",
        binary,
        &[
            "create-bench",
            image,
            "/",
            "--count",
            "3000",
            "--threads",
            "1",
            "--rounds",
            "2",
        ],
    );
    run_cli_binary_checked(
        "lookup",
        binary,
        &["lookup-bench", image, "/", "--count", "1000000"],
    );
    run_cli_binary_checked(
        "rename",
        binary,
        &["rename-bench", image, "/", "--count", "2000"],
    );
    run_cli_binary_checked(
        "delete",
        binary,
        &["delbench", image, "/", "--count", "2000"],
    );
    run_cli_binary_checked("walk", binary, &["walk", image, "--no-stat"]);
}

fn raw_profiles_for_run(profile_dir: &Path, run_id: &str) -> Vec<PathBuf> {
    let raw_prefix = format!("bd-b9dug-{run_id}-");
    let mut raw_profiles = fs::read_dir(profile_dir)
        .expect("read remote PGO profile directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "profraw")
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&raw_prefix))
        })
        .collect::<Vec<_>>();
    raw_profiles.sort();
    assert!(
        raw_profiles.len() >= 6,
        "expected one raw profile per CLI child, found {} under {} with prefix {raw_prefix}",
        raw_profiles.len(),
        profile_dir.display()
    );
    raw_profiles
}

fn merge_raw_profiles(profile_dir: &Path, run_id: &str, raw_profiles: &[PathBuf]) -> PathBuf {
    let merged = profile_dir.join(format!("merged-{run_id}.profdata"));
    assert!(
        !merged.exists(),
        "refusing to overwrite merged profile {}",
        merged.display()
    );
    let merge = Command::new(find_llvm_profdata())
        .args(["merge", "-o"])
        .arg(&merged)
        .args(raw_profiles)
        .output()
        .expect("run llvm-profdata merge");
    assert!(
        merge.status.success(),
        "llvm-profdata merge failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        merge.status,
        String::from_utf8_lossy(&merge.stdout),
        String::from_utf8_lossy(&merge.stderr)
    );
    merged
}

struct LookupSamples {
    anchor_us: Vec<f64>,
    repeat_us: Vec<f64>,
    candidate_us: Vec<f64>,
    reference_signature: String,
    raw_pairs: String,
}

fn collect_lookup_samples(
    generic: &Path,
    pgo: &Path,
    image: &Path,
    pairs: usize,
    lookups: usize,
) -> LookupSamples {
    let mut anchor_us = Vec::with_capacity(pairs);
    let mut repeat_us = Vec::with_capacity(pairs);
    let mut candidate_us = Vec::with_capacity(pairs);
    let mut reference_signature = None;
    let mut raw_pairs = String::with_capacity(pairs.saturating_mul(64));
    for pair in 0..pairs {
        let (anchor, repeat, candidate, order) = if pair % 2 == 0 {
            (
                lookup_observation(generic, image, lookups),
                lookup_observation(generic, image, lookups),
                lookup_observation(pgo, image, lookups),
                "AAB",
            )
        } else {
            let candidate = lookup_observation(pgo, image, lookups);
            let repeat = lookup_observation(generic, image, lookups);
            let anchor = lookup_observation(generic, image, lookups);
            (anchor, repeat, candidate, "BAA")
        };
        for signature in [&anchor.1, &repeat.1, &candidate.1] {
            if let Some(expected) = &reference_signature {
                assert_eq!(
                    signature, expected,
                    "generic and PGO binaries observed different lookup results"
                );
            } else {
                reference_signature = Some(signature.clone());
            }
        }
        anchor_us.push(anchor.0);
        repeat_us.push(repeat.0);
        candidate_us.push(candidate.0);
        if pair > 0 {
            raw_pairs.push(';');
        }
        write!(
            &mut raw_pairs,
            "{order}:{:.3}:{:.3}:{:.3}",
            anchor.0, repeat.0, candidate.0
        )
        .expect("format whole-binary lookup pair");
    }
    LookupSamples {
        anchor_us,
        repeat_us,
        candidate_us,
        reference_signature: reference_signature.expect("lookup signature"),
        raw_pairs,
    }
}

struct LookupIdentity<'a> {
    generic: &'a CliEvidence,
    pgo: &'a CliEvidence,
    profile_sha256: &'a str,
    image: &'a Path,
}

struct CreateSamples {
    anchor_persisted_us: Vec<f64>,
    repeat_persisted_us: Vec<f64>,
    candidate_persisted_us: Vec<f64>,
    anchor_create_us: Vec<f64>,
    repeat_create_us: Vec<f64>,
    candidate_create_us: Vec<f64>,
    reference_signature: String,
    raw_persisted_pairs: String,
    raw_create_pairs: String,
}

struct CreateInputs<'a> {
    generic: &'a Path,
    pgo: &'a Path,
    generic_sha256: &'a str,
    pgo_sha256: &'a str,
    source_image: &'a Path,
    source_image_sha256: &'a str,
    anchor_image: &'a Path,
    repeat_image: &'a Path,
    candidate_image: &'a Path,
}

fn assert_create_gate_identity(generic: &CliEvidence, pgo: &CliEvidence, expected_profile: &str) {
    assert_eq!(
        generic.pgo_profile_sha256, "none",
        "generic control must not embed profile-use identity"
    );
    assert_eq!(
        pgo.pgo_profile_sha256, expected_profile,
        "candidate did not embed the consumed profile SHA"
    );
    assert!(
        generic.codegen_line.contains("compile_avx2=false")
            && generic.codegen_line.contains("compile_fma=false"),
        "generic control unexpectedly widened its compile-time ISA: {}",
        generic.codegen_line
    );
    assert!(
        pgo.codegen_line.contains("compile_avx2=true")
            && pgo.codegen_line.contains("compile_fma=true"),
        "profile-use candidate is not witnessed x86-64-v3: {}",
        pgo.codegen_line
    );
}

fn collect_create_samples(
    inputs: &CreateInputs<'_>,
    pairs: usize,
    count: usize,
    rounds: usize,
) -> CreateSamples {
    let mut anchor_persisted_us = Vec::with_capacity(pairs);
    let mut repeat_persisted_us = Vec::with_capacity(pairs);
    let mut candidate_persisted_us = Vec::with_capacity(pairs);
    let mut anchor_create_us = Vec::with_capacity(pairs);
    let mut repeat_create_us = Vec::with_capacity(pairs);
    let mut candidate_create_us = Vec::with_capacity(pairs);
    let mut reference_signature = None;
    let mut raw_persisted_pairs = String::with_capacity(pairs.saturating_mul(72));
    let mut raw_create_pairs = String::with_capacity(pairs.saturating_mul(72));
    for pair in 0..pairs {
        let observe_generic = |working_image: &Path| {
            create_observation(
                inputs.generic,
                inputs.generic_sha256,
                inputs.source_image,
                inputs.source_image_sha256,
                working_image,
                count,
                rounds,
            )
        };
        let observe_pgo = || {
            create_observation(
                inputs.pgo,
                inputs.pgo_sha256,
                inputs.source_image,
                inputs.source_image_sha256,
                inputs.candidate_image,
                count,
                rounds,
            )
        };
        let (anchor, repeat, candidate, order) = if pair % 2 == 0 {
            (
                observe_generic(inputs.anchor_image),
                observe_generic(inputs.repeat_image),
                observe_pgo(),
                "AAB",
            )
        } else {
            let candidate = observe_pgo();
            let repeat = observe_generic(inputs.repeat_image);
            let anchor = observe_generic(inputs.anchor_image);
            (anchor, repeat, candidate, "BAA")
        };
        for signature in [
            &anchor.state_signature,
            &repeat.state_signature,
            &candidate.state_signature,
        ] {
            if let Some(expected) = &reference_signature {
                assert_eq!(
                    signature, expected,
                    "generic and PGO create outputs have different filesystem state"
                );
            } else {
                reference_signature = Some(signature.clone());
            }
        }
        anchor_persisted_us.push(anchor.persisted_us);
        repeat_persisted_us.push(repeat.persisted_us);
        candidate_persisted_us.push(candidate.persisted_us);
        anchor_create_us.push(anchor.create_us);
        repeat_create_us.push(repeat.create_us);
        candidate_create_us.push(candidate.create_us);
        if pair > 0 {
            raw_persisted_pairs.push(';');
            raw_create_pairs.push(';');
        }
        write!(
            &mut raw_persisted_pairs,
            "{order}:{:.3}:{:.3}:{:.3}",
            anchor.persisted_us, repeat.persisted_us, candidate.persisted_us
        )
        .expect("format persisted-create pair");
        write!(
            &mut raw_create_pairs,
            "{order}:{:.3}:{:.3}:{:.3}",
            anchor.create_us, repeat.create_us, candidate.create_us
        )
        .expect("format create-loop pair");
    }
    CreateSamples {
        anchor_persisted_us,
        repeat_persisted_us,
        candidate_persisted_us,
        anchor_create_us,
        repeat_create_us,
        candidate_create_us,
        reference_signature: reference_signature.expect("create state signature"),
        raw_persisted_pairs,
        raw_create_pairs,
    }
}

fn paired_ratio_summaries(
    anchor: &[f64],
    repeat: &[f64],
    candidate: &[f64],
) -> (BootstrapMedianCi, BootstrapMedianCi, f64, f64) {
    let null_log_ratios = anchor
        .iter()
        .zip(repeat)
        .map(|(anchor, repeat)| (anchor / repeat).ln())
        .collect::<Vec<_>>();
    let candidate_log_ratios = anchor
        .iter()
        .zip(repeat)
        .zip(candidate)
        .map(|((anchor, repeat), candidate)| (anchor.midpoint(*repeat) / candidate).ln())
        .collect::<Vec<_>>();
    let null = bootstrap_median_ci(&null_log_ratios);
    let candidate_ratio = bootstrap_median_ci(&candidate_log_ratios);
    let null_log_radius = null.low.ln().abs().max(null.high.ln().abs());
    (
        null,
        candidate_ratio,
        null_log_radius.exp(),
        (2.0 * null_log_radius).exp(),
    )
}

fn report_create_gate(
    identity: &LookupIdentity<'_>,
    samples: CreateSamples,
    pairs: usize,
    count: usize,
    rounds: usize,
) {
    let (persisted_null, persisted_ratio, null_floor_ratio, twice_null_ratio) =
        paired_ratio_summaries(
            &samples.anchor_persisted_us,
            &samples.repeat_persisted_us,
            &samples.candidate_persisted_us,
        );
    let (create_null, create_ratio, create_null_floor_ratio, create_twice_null_ratio) =
        paired_ratio_summaries(
            &samples.anchor_create_us,
            &samples.repeat_create_us,
            &samples.candidate_create_us,
        );
    let verdict = if null_floor_ratio >= 1.10 {
        "BLOCKED_NULL_FLOOR"
    } else if persisted_ratio.low > twice_null_ratio {
        "PGO_FASTER"
    } else if persisted_ratio.high < twice_null_ratio.recip() {
        "PGO_SLOWER"
    } else {
        "INDETERMINATE_WITHIN_TWICE_NULL"
    };
    let generic_persisted_midpoints = samples
        .anchor_persisted_us
        .iter()
        .zip(&samples.repeat_persisted_us)
        .map(|(anchor, repeat)| anchor.midpoint(*repeat))
        .collect::<Vec<_>>();
    let generic_create_midpoints = samples
        .anchor_create_us
        .iter()
        .zip(&samples.repeat_create_us)
        .map(|(anchor, repeat)| anchor.midpoint(*repeat))
        .collect::<Vec<_>>();
    println!(
        "bd_b9dug_create_identity,generic_binary_sha256={},pgo_binary_sha256={},\
pgo_profile_sha256={},input_image={},input_image_sha256={},output_signature={}",
        identity.generic.binary_sha256,
        identity.pgo.binary_sha256,
        identity.profile_sha256,
        identity.image.display(),
        sha256_file(identity.image),
        samples.reference_signature
    );
    println!(
        "bd_b9dug_create_persisted_pairs,pairs={pairs},rounds_per_observation={rounds},\
creates_per_round={count},format=order:generic_anchor_us:generic_repeat_us:pgo_us,values={}",
        samples.raw_persisted_pairs
    );
    println!(
        "bd_b9dug_create_loop_pairs,pairs={pairs},rounds_per_observation={rounds},\
creates_per_round={count},format=order:generic_anchor_us:generic_repeat_us:pgo_us,values={}",
        samples.raw_create_pairs
    );
    println!(
        "bd_b9dug_whole_binary_create,generic_persisted_median_us={:.3},\
pgo_persisted_median_us={:.3},generic_aa_median={:.6},\
generic_aa_ci_low={:.6},generic_aa_ci_high={:.6},\
null_floor_ratio={null_floor_ratio:.6},twice_null_ratio={twice_null_ratio:.6},\
generic_over_pgo_median={:.6},generic_over_pgo_ci_low={:.6},\
generic_over_pgo_ci_high={:.6},create_loop_generic_median_us={:.3},\
create_loop_pgo_median_us={:.3},create_loop_aa_median={:.6},\
create_loop_aa_ci_low={:.6},create_loop_aa_ci_high={:.6},\
create_loop_null_floor_ratio={create_null_floor_ratio:.6},\
create_loop_twice_null_ratio={create_twice_null_ratio:.6},\
create_loop_generic_over_pgo_median={:.6},create_loop_generic_over_pgo_ci_low={:.6},\
create_loop_generic_over_pgo_ci_high={:.6},verdict={verdict},\
gate_metric=persisted_wall_us,gate_basis=bootstrap_median_ci,\
bootstrap_resamples=20000,cv_used=false",
        median(generic_persisted_midpoints),
        median(samples.candidate_persisted_us),
        persisted_null.median,
        persisted_null.low,
        persisted_null.high,
        persisted_ratio.median,
        persisted_ratio.low,
        persisted_ratio.high,
        median(generic_create_midpoints),
        median(samples.candidate_create_us),
        create_null.median,
        create_null.low,
        create_null.high,
        create_ratio.median,
        create_ratio.low,
        create_ratio.high,
    );
}

fn report_lookup_gate(
    identity: &LookupIdentity<'_>,
    samples: LookupSamples,
    pairs: usize,
    lookups: usize,
) {
    let null_log_ratios = samples
        .anchor_us
        .iter()
        .zip(&samples.repeat_us)
        .map(|(anchor, repeat)| (anchor / repeat).ln())
        .collect::<Vec<_>>();
    let pgo_log_ratios = samples
        .anchor_us
        .iter()
        .zip(&samples.repeat_us)
        .zip(&samples.candidate_us)
        .map(|((anchor, repeat), candidate)| (anchor.midpoint(*repeat) / candidate).ln())
        .collect::<Vec<_>>();
    let null = bootstrap_median_ci(&null_log_ratios);
    let pgo_ratio = bootstrap_median_ci(&pgo_log_ratios);
    let null_log_radius = null.low.ln().abs().max(null.high.ln().abs());
    let null_floor_ratio = null_log_radius.exp();
    let twice_null_ratio = (2.0 * null_log_radius).exp();
    assert!(
        null_floor_ratio < 1.10,
        "whole-binary lookup A/A null is too noisy: {null_floor_ratio:.6}x"
    );
    let verdict = if pgo_ratio.low > twice_null_ratio {
        "PGO_FASTER"
    } else if pgo_ratio.high < twice_null_ratio.recip() {
        "PGO_SLOWER"
    } else {
        "INDETERMINATE_WITHIN_TWICE_NULL"
    };
    let generic_midpoints = samples
        .anchor_us
        .iter()
        .zip(&samples.repeat_us)
        .map(|(anchor, repeat)| anchor.midpoint(*repeat))
        .collect::<Vec<_>>();
    println!(
        "bd_b9dug_whole_binary_identity,generic_binary_sha256={},\
pgo_binary_sha256={},pgo_profile_sha256={},lookup_image={},lookup_image_sha256={},\
output_signature={}",
        identity.generic.binary_sha256,
        identity.pgo.binary_sha256,
        identity.profile_sha256,
        identity.image.display(),
        sha256_file(identity.image),
        samples.reference_signature
    );
    println!(
        "bd_b9dug_whole_binary_pairs,pairs={pairs},lookups_per_observation={lookups},\
format=order:generic_anchor_us:generic_repeat_us:pgo_us,values={}",
        samples.raw_pairs
    );
    println!(
        "bd_b9dug_whole_binary_lookup,generic_median_us={:.3},pgo_median_us={:.3},\
generic_aa_median={:.6},generic_aa_ci_low={:.6},generic_aa_ci_high={:.6},\
null_floor_ratio={null_floor_ratio:.6},twice_null_ratio={twice_null_ratio:.6},\
generic_over_pgo_median={:.6},generic_over_pgo_ci_low={:.6},\
generic_over_pgo_ci_high={:.6},verdict={verdict},gate_basis=bootstrap_median_ci,\
bootstrap_resamples=20000,cv_used=false",
        median(generic_midpoints),
        median(samples.candidate_us),
        null.median,
        null.low,
        null.high,
        pgo_ratio.median,
        pgo_ratio.low,
        pgo_ratio.high
    );
}

/// Save the generic release-perf CLI on the pinned worker before a subsequent
/// profile-use build replaces Cargo's output. The destination must be unique;
/// this driver refuses to overwrite an earlier artifact.
#[test]
#[ignore = "strict-remote bd-b9dug driver"]
fn bd_b9dug_store_generic_cli() {
    let source = Path::new(env!("CARGO_BIN_EXE_ffs-cli"));
    let destination = required_env_path("FFS_B9DUG_GENERIC_CLI");
    assert!(
        !destination.exists(),
        "refusing to overwrite generic CLI artifact {}",
        destination.display()
    );
    fs::create_dir_all(destination.parent().expect("generic CLI has parent"))
        .expect("create generic CLI artifact directory");

    let source_evidence = cli_evidence(source);
    assert_eq!(
        source_evidence.pgo_profile_sha256, "none",
        "generic control unexpectedly embeds a PGO profile"
    );
    fs::copy(source, &destination).unwrap_or_else(|error| {
        panic!(
            "copy generic CLI {} -> {}: {error}",
            source.display(),
            destination.display()
        )
    });
    let copied_evidence = cli_evidence(&destination);
    assert_eq!(
        source_evidence.binary_sha256, copied_evidence.binary_sha256,
        "copied generic CLI changed bytes"
    );
    assert_eq!(
        source_evidence.binary_sha256,
        sha256_file(&destination),
        "in-process and adjacent generic CLI hashes disagree"
    );
    println!(
        "bd_b9dug_generic_stored,path={},binary_sha256={},codegen={}",
        destination.display(),
        copied_evidence.binary_sha256,
        copied_evidence.codegen_line
    );
}

/// Exercise the same CLI workload family as `scripts/build-perf.sh` with the
/// instrumented production binary, then merge only this run's raw profiles.
#[test]
#[ignore = "strict-remote bd-b9dug driver"]
fn bd_b9dug_remote_pgo_training_driver() {
    let run_id = bd_b9dug_run_id();
    let profile_dir = required_env_path("FFS_B9DUG_PROFILE_DIR");
    let training_image = prepare_pgo_training_image(&profile_dir, &run_id);
    let binary = Path::new(env!("CARGO_BIN_EXE_ffs-cli"));
    let evidence = cli_evidence(binary);
    assert_eq!(
        evidence.pgo_profile_sha256, "none",
        "profile-generation binary must not claim profile-use"
    );
    assert!(
        evidence.codegen_line.contains("compile_avx2=true")
            && evidence.codegen_line.contains("compile_fma=true"),
        "profile-generation binary is not witnessed x86-64-v3: {}",
        evidence.codegen_line
    );
    run_pgo_training_workload(binary, &training_image);
    let raw_profiles = raw_profiles_for_run(&profile_dir, &run_id);
    let merged = merge_raw_profiles(&profile_dir, &run_id, &raw_profiles);
    let merged_bytes = fs::metadata(&merged)
        .expect("merged profile metadata")
        .len();
    let merged_sha256 = sha256_file(&merged);
    println!(
        "pgo_profile_generated,path={},bytes={merged_bytes},sha256={merged_sha256},\
training_cli_sha256={},training_image={},training_image_sha256={},raw_profiles={},\
corpus=create:6000+lookup:1000000+rename:2000+delete:2000+walk",
        merged.display(),
        evidence.binary_sha256,
        training_image.display(),
        sha256_file(&training_image),
        raw_profiles.len()
    );
}

/// One parent process controls the generic/generic A/A and generic/PGO lookup
/// observations. The decision consumes only a deterministic bootstrap median
/// confidence interval; CV is deliberately never computed.
#[test]
#[ignore = "strict-remote bd-b9dug driver"]
fn bd_b9dug_whole_binary_lookup_gate() {
    const PAIRS: usize = 31;
    const LOOKUPS: usize = 200_000;

    let generic = required_env_path("FFS_B9DUG_GENERIC_CLI");
    let pgo = Path::new(env!("CARGO_BIN_EXE_ffs-cli"));
    let image = required_env_path("FFS_B9DUG_LOOKUP_IMAGE");
    let expected_profile = required_env("FFS_PGO_PROFILE_SHA256");
    assert!(
        expected_profile.len() == 64
            && expected_profile
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "FFS_PGO_PROFILE_SHA256 must be a full SHA-256"
    );

    let generic_evidence = cli_evidence(&generic);
    let pgo_evidence = cli_evidence(pgo);
    assert_eq!(
        generic_evidence.pgo_profile_sha256, "none",
        "generic control must not embed profile-use identity"
    );
    assert_eq!(
        pgo_evidence.pgo_profile_sha256, expected_profile,
        "candidate did not embed the consumed profile SHA"
    );
    assert!(
        generic_evidence.codegen_line.contains("compile_avx2=false")
            && generic_evidence.codegen_line.contains("compile_fma=false"),
        "generic control unexpectedly widened its compile-time ISA: {}",
        generic_evidence.codegen_line
    );
    assert!(
        pgo_evidence.codegen_line.contains("compile_avx2=true")
            && pgo_evidence.codegen_line.contains("compile_fma=true"),
        "profile-use candidate is not witnessed x86-64-v3: {}",
        pgo_evidence.codegen_line
    );

    for _ in 0..2 {
        lookup_observation(&generic, &image, 50_000);
        lookup_observation(pgo, &image, 50_000);
    }
    let samples = collect_lookup_samples(&generic, pgo, &image, PAIRS, LOOKUPS);
    report_lookup_gate(
        &LookupIdentity {
            generic: &generic_evidence,
            pgo: &pgo_evidence,
            profile_sha256: &expected_profile,
            image: &image,
        },
        samples,
        PAIRS,
        LOOKUPS,
    );
}

/// Production-shaped generic/PGO create decision. One parent process copies the
/// same immutable image before every child observation, alternates `AAB`/`BAA`,
/// and gates on persisted wall time (create rounds plus the final flush).
#[test]
#[ignore = "strict-remote bd-b9dug driver"]
fn bd_b9dug_whole_binary_create_gate() {
    const PAIRS: usize = 31;
    const CREATES_PER_ROUND: usize = 2_000;
    const ROUNDS: usize = 2;

    let generic = required_env_path("FFS_B9DUG_GENERIC_CLI");
    let pgo = Path::new(env!("CARGO_BIN_EXE_ffs-cli"));
    let source_image = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/golden/ext4_dir_index_reference.ext4");
    let create_dir = required_env_path("FFS_B9DUG_CREATE_DIR");
    let run_id = bd_b9dug_run_id();
    let expected_profile = required_env("FFS_PGO_PROFILE_SHA256");
    assert!(
        expected_profile.len() == 64
            && expected_profile
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "FFS_PGO_PROFILE_SHA256 must be a full SHA-256"
    );
    fs::create_dir_all(&create_dir).expect("create bd-b9dug create artifact directory");
    let anchor_image = create_dir.join(format!("create-{run_id}-anchor.ext4"));
    let repeat_image = create_dir.join(format!("create-{run_id}-repeat.ext4"));
    let candidate_image = create_dir.join(format!("create-{run_id}-candidate.ext4"));
    for image in [&anchor_image, &repeat_image, &candidate_image] {
        assert!(
            !image.exists(),
            "refusing to overwrite create-gate artifact {}",
            image.display()
        );
    }

    let generic_evidence = cli_evidence(&generic);
    let pgo_evidence = cli_evidence(pgo);
    assert_create_gate_identity(&generic_evidence, &pgo_evidence, &expected_profile);
    let source_image_sha256 = sha256_file(&source_image);
    let inputs = CreateInputs {
        generic: &generic,
        pgo,
        generic_sha256: &generic_evidence.binary_sha256,
        pgo_sha256: &pgo_evidence.binary_sha256,
        source_image: &source_image,
        source_image_sha256: &source_image_sha256,
        anchor_image: &anchor_image,
        repeat_image: &repeat_image,
        candidate_image: &candidate_image,
    };

    create_observation(
        inputs.generic,
        inputs.generic_sha256,
        inputs.source_image,
        inputs.source_image_sha256,
        inputs.anchor_image,
        CREATES_PER_ROUND,
        ROUNDS,
    );
    create_observation(
        inputs.generic,
        inputs.generic_sha256,
        inputs.source_image,
        inputs.source_image_sha256,
        inputs.repeat_image,
        CREATES_PER_ROUND,
        ROUNDS,
    );
    create_observation(
        inputs.pgo,
        inputs.pgo_sha256,
        inputs.source_image,
        inputs.source_image_sha256,
        inputs.candidate_image,
        CREATES_PER_ROUND,
        ROUNDS,
    );

    let samples = collect_create_samples(&inputs, PAIRS, CREATES_PER_ROUND, ROUNDS);
    report_create_gate(
        &LookupIdentity {
            generic: &generic_evidence,
            pgo: &pgo_evidence,
            profile_sha256: &expected_profile,
            image: &source_image,
        },
        samples,
        PAIRS,
        CREATES_PER_ROUND,
        ROUNDS,
    );
}

#[test]
fn cli_inspect_ext4_returns_json() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["inspect", "--json", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("\"filesystem\"") && stdout.contains("ext4") {
            emit_scenario_result("cli_inspect_ext4_json_valid", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_ext4_json_valid",
                "FAIL",
                Some("JSON output missing expected fields"),
            );
            panic!("JSON output missing expected fields: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_ext4_json_valid",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect failed: {}", stderr);
    }
}

#[test]
fn cli_inspect_ext4_human_readable() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("ext4") || stdout.contains("Ext4") {
            emit_scenario_result("cli_inspect_ext4_human_output", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_ext4_human_output",
                "FAIL",
                Some("output missing ext4 identifier"),
            );
            panic!("output missing ext4 identifier: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_ext4_human_output",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect failed: {}", stderr);
    }
}

#[test]
fn cli_inspect_truncated_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("truncated.img");

    fs::write(&image, vec![0u8; 512]).expect("write truncated image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_inspect_truncated_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_inspect_truncated_error",
            "FAIL",
            Some("expected non-zero exit for truncated image"),
        );
        panic!("expected ffs inspect to fail on truncated image");
    }
}

#[test]
fn cli_inspect_nonexistent_file_returns_error() {
    let output = run_ffs_cli(&["inspect", "/nonexistent/path/to/image.img"]);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such file")
            || stderr.contains("not found")
            || stderr.contains("does not exist")
        {
            emit_scenario_result("cli_inspect_nonexistent_error", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_nonexistent_error",
                "FAIL",
                Some("error message unclear"),
            );
            panic!("error message should indicate file not found: {}", stderr);
        }
    } else {
        emit_scenario_result(
            "cli_inspect_nonexistent_error",
            "FAIL",
            Some("expected non-zero exit for nonexistent file"),
        );
        panic!("expected ffs inspect to fail on nonexistent file");
    }
}

#[test]
fn cli_info_ext4_shows_superblock() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["info", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("block_size") || stdout.contains("inodes") || stdout.contains("groups") {
            emit_scenario_result("cli_info_ext4_superblock", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_info_ext4_superblock",
                "FAIL",
                Some("output missing superblock fields"),
            );
            panic!("output missing expected superblock fields: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_info_ext4_superblock",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs info failed: {}", stderr);
    }
}

#[test]
fn cli_fsck_ext4_clean_image() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["fsck", image.to_str().unwrap()]);

    if output.status.success() {
        emit_scenario_result("cli_fsck_ext4_clean_image", "PASS", None);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_fsck_ext4_clean_image",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs fsck failed on clean image: {}", stderr);
    }
}

#[test]
fn cli_fsck_json_output() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["fsck", "--json", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains('{') && stdout.contains('}') {
            emit_scenario_result("cli_fsck_ext4_json_output", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_fsck_ext4_json_output",
                "FAIL",
                Some("output not valid JSON"),
            );
            panic!("fsck --json output not valid JSON: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_fsck_ext4_json_output",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs fsck --json failed: {}", stderr);
    }
}

#[test]
fn cli_repair_verify_only_ext4() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let output = run_ffs_cli(&["repair", "--verify-only", image.to_str().unwrap()]);

    if output.status.success() {
        emit_scenario_result("cli_repair_verify_only_ext4", "PASS", None);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code().unwrap_or(-1);
        if code == 1 && stderr.contains("staleness") {
            emit_scenario_result(
                "cli_repair_verify_only_ext4",
                "PASS",
                Some("no staleness detected"),
            );
        } else {
            emit_scenario_result(
                "cli_repair_verify_only_ext4",
                "FAIL",
                Some(&format!("exit code {}", code)),
            );
            panic!("ffs repair --verify-only failed unexpectedly: {}", stderr);
        }
    }
}

#[test]
fn cli_inspect_corrupted_superblock_returns_error() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let mut data = fs::read(&image).expect("read image");
    let sb_off = 1024;
    data[sb_off..sb_off + 64].fill(0xFF);
    fs::write(&image, data).expect("write corrupted image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_inspect_corrupted_superblock_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_inspect_corrupted_superblock_error",
            "FAIL",
            Some("expected error for corrupted superblock"),
        );
        panic!("expected ffs inspect to fail on corrupted superblock");
    }
}

#[test]
fn cli_inspect_zero_filled_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("zeros.img");

    fs::write(&image, vec![0u8; 4 * 1024 * 1024]).expect("write zero-filled image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_inspect_zero_filled_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_inspect_zero_filled_error",
            "FAIL",
            Some("expected error for zero-filled image"),
        );
        panic!("expected ffs inspect to fail on zero-filled image");
    }
}

#[test]
fn cli_fsck_corrupted_superblock_reports_error() {
    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);

    let mut data = fs::read(&image).expect("read image");
    let sb_off = 1024;
    data[sb_off..sb_off + 64].fill(0xFF);
    fs::write(&image, data).expect("write corrupted image");

    let output = run_ffs_cli(&["fsck", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_fsck_corrupted_superblock_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_fsck_corrupted_superblock_error",
            "FAIL",
            Some("expected error for corrupted superblock"),
        );
        panic!("expected ffs fsck to fail on corrupted superblock");
    }
}

#[test]
fn cli_inspect_random_garbage_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("garbage.img");

    let mut rng_data = vec![0u8; 4 * 1024 * 1024];
    for (i, byte) in rng_data.iter_mut().enumerate() {
        *byte = ((i * 7 + 13) % 256) as u8;
    }
    fs::write(&image, rng_data).expect("write garbage image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_inspect_random_garbage_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_inspect_random_garbage_error",
            "FAIL",
            Some("expected error for random garbage image"),
        );
        panic!("expected ffs inspect to fail on random garbage image");
    }
}

#[test]
fn cli_info_truncated_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("truncated.img");

    fs::write(&image, vec![0u8; 2048]).expect("write truncated image");

    let output = run_ffs_cli(&["info", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_info_truncated_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_info_truncated_error",
            "FAIL",
            Some("expected error for truncated image"),
        );
        panic!("expected ffs info to fail on truncated image");
    }
}

#[test]
fn cli_fsck_truncated_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("truncated.img");

    fs::write(&image, vec![0u8; 2048]).expect("write truncated image");

    let output = run_ffs_cli(&["fsck", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_fsck_truncated_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_fsck_truncated_error",
            "FAIL",
            Some("expected error for truncated image"),
        );
        panic!("expected ffs fsck to fail on truncated image");
    }
}

#[test]
fn cli_repair_truncated_image_returns_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("truncated.img");

    fs::write(&image, vec![0u8; 2048]).expect("write truncated image");

    let output = run_ffs_cli(&["repair", "--verify-only", image.to_str().unwrap()]);

    if !output.status.success() {
        emit_scenario_result("cli_repair_truncated_error", "PASS", None);
    } else {
        emit_scenario_result(
            "cli_repair_truncated_error",
            "FAIL",
            Some("expected error for truncated image"),
        );
        panic!("expected ffs repair to fail on truncated image");
    }
}

// ── Btrfs CLI E2E Tests ─────────────────────────────────────────────────────

#[test]
fn cli_inspect_btrfs_returns_json() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["inspect", "--json", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("\"filesystem\"") && stdout.contains("btrfs") {
            emit_scenario_result("cli_inspect_btrfs_json_valid", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_btrfs_json_valid",
                "FAIL",
                Some("JSON output missing expected fields"),
            );
            panic!("JSON output missing expected fields: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_btrfs_json_valid",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect failed: {}", stderr);
    }
}

#[test]
fn cli_inspect_btrfs_human_readable() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("btrfs") || stdout.contains("Btrfs") {
            emit_scenario_result("cli_inspect_btrfs_human_output", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_inspect_btrfs_human_output",
                "FAIL",
                Some("output missing btrfs identifier"),
            );
            panic!("output missing btrfs identifier: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_btrfs_human_output",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect failed: {}", stderr);
    }
}

#[test]
fn cli_info_btrfs_shows_superblock() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["info", image.to_str().unwrap()]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("sector_size")
            || stdout.contains("node_size")
            || stdout.contains("generation")
        {
            emit_scenario_result("cli_info_btrfs_superblock", "PASS", None);
        } else {
            emit_scenario_result(
                "cli_info_btrfs_superblock",
                "FAIL",
                Some("output missing superblock fields"),
            );
            panic!("output missing expected superblock fields: {}", stdout);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_info_btrfs_superblock",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs info failed: {}", stderr);
    }
}

#[test]
fn cli_fsck_btrfs_runs_without_crash() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["fsck", image.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("filesystem: btrfs") && stdout.contains("outcome:") {
        emit_scenario_result("cli_fsck_btrfs_runs_without_crash", "PASS", None);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_fsck_btrfs_runs_without_crash",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!(
            "ffs fsck did not produce expected output: stdout={}, stderr={}",
            stdout, stderr
        );
    }
}

#[test]
fn cli_inspect_btrfs_subvolumes() {
    if !btrfs_prerequisites_available() {
        eprintln!("SKIP: mkfs.btrfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_btrfs_image(tmpdir.path(), 128);

    let output = run_ffs_cli(&["inspect", "--subvolumes", image.to_str().unwrap()]);

    if output.status.success() {
        emit_scenario_result("cli_inspect_btrfs_subvolumes", "PASS", None);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        emit_scenario_result(
            "cli_inspect_btrfs_subvolumes",
            "FAIL",
            Some(&format!("exit code {:?}", output.status.code())),
        );
        panic!("ffs inspect --subvolumes failed: {}", stderr);
    }
}

#[test]
fn cli_mount_help_advertises_runtime_modes_and_rw_toggles() {
    let output = run_ffs_cli(&["mount", "--help"]);
    assert!(
        output.status.success(),
        "`ffs mount --help` should exit 0: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for token in &[
        "--runtime-mode",
        "standard",
        "managed",
        "per-core",
        "--rw",
        "--allow-other",
        "--native",
        "--managed-unmount-timeout-secs",
    ] {
        assert!(
            stdout.contains(token),
            "`ffs mount --help` should advertise `{token}`, got: {stdout}"
        );
    }
    emit_scenario_result(
        "cli_mount_help_surface",
        "PASS",
        Some("runtime_mode+rw+allow_other+native+managed_unmount_timeout_secs"),
    );
}

#[test]
fn cli_mount_nonexistent_image_reports_error() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let missing_image = tmpdir.path().join("no_such.img");
    let mountpoint = tmpdir.path().join("mnt");
    fs::create_dir(&mountpoint).expect("create mountpoint dir");

    let output = run_ffs_cli(&[
        "mount",
        missing_image.to_str().unwrap(),
        mountpoint.to_str().unwrap(),
    ]);

    assert!(
        !output.status.success(),
        "`ffs mount` on missing image must not report success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "`ffs mount` on missing image must emit a non-empty diagnostic, got stderr=<empty>"
    );
    emit_scenario_result("cli_mount_missing_image_error", "PASS", None);
}

#[test]
fn cli_mount_managed_unmount_timeout_rejected_in_standard_mode() {
    // AGENTS.md / CLI help documents that `--managed-unmount-timeout-secs`
    // is invalid with `--runtime-mode standard`; prove the CLI rejects it
    // before any FUSE work happens, so users get a deterministic error.
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("anywhere.img");
    let mountpoint = tmpdir.path().join("mnt");
    fs::create_dir(&mountpoint).expect("create mountpoint dir");

    let output = run_ffs_cli(&[
        "mount",
        "--runtime-mode",
        "standard",
        "--managed-unmount-timeout-secs",
        "5",
        image.to_str().unwrap(),
        mountpoint.to_str().unwrap(),
    ]);

    assert!(
        !output.status.success(),
        "`ffs mount --runtime-mode standard --managed-unmount-timeout-secs` must be rejected"
    );
    emit_scenario_result("cli_mount_standard_rejects_managed_timeout", "PASS", None);
}

#[test]
fn cli_inspect_unreadable_image_reports_permission_error() {
    use std::os::unix::fs::PermissionsExt;

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("locked.img");
    fs::write(&image, vec![0u8; 4096]).expect("write empty image");
    fs::set_permissions(&image, fs::Permissions::from_mode(0o000)).expect("chmod 000 on image");

    // Root bypasses POSIX mode 0o000, so skip rather than silently pass.
    if fs::read(&image).is_ok() {
        let _ = fs::set_permissions(&image, fs::Permissions::from_mode(0o600));
        eprintln!("SKIP: cannot exercise EACCES — current process can read mode-0 files");
        emit_scenario_result(
            "cli_inspect_unreadable_image_permission_error",
            "SKIP",
            Some("process_bypasses_mode_000"),
        );
        return;
    }

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    // Restore perms so tempdir cleanup can run even if the assertions below fire.
    let _ = fs::set_permissions(&image, fs::Permissions::from_mode(0o600));

    assert!(
        !output.status.success(),
        "`ffs inspect` on mode-0 image must not succeed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "`ffs inspect` on mode-0 image must emit a diagnostic, got stderr=<empty>"
    );
    let hints_permission = stderr.contains("Permission denied")
        || stderr.contains("permission denied")
        || stderr.contains("EACCES")
        || stderr.contains("os error 13");
    assert!(
        hints_permission,
        "diagnostic should mention permission/EACCES, got: {stderr}"
    );
    emit_scenario_result(
        "cli_inspect_unreadable_image_permission_error",
        "PASS",
        Some("stderr_hints_permission"),
    );
}

#[test]
fn cli_inspect_directory_as_image_reports_error() {
    // Operator-visible contract: pointing `ffs inspect` at a directory must
    // fail with a non-empty diagnostic, not panic or hang reading a device.
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let dir_path = tmpdir.path().join("not_an_image");
    fs::create_dir(&dir_path).expect("create directory to stand in for image");

    let output = run_ffs_cli(&["inspect", dir_path.to_str().unwrap()]);

    assert!(
        !output.status.success(),
        "`ffs inspect` on a directory must not succeed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "`ffs inspect` on a directory must emit a diagnostic, got stderr=<empty>"
    );
    emit_scenario_result("cli_inspect_directory_as_image_error", "PASS", None);
}

#[test]
fn cli_inspect_empty_file_reports_error() {
    // Zero-byte images exercise the short-read / EOF permission-adjacent
    // path: `ffs inspect` must report an error, not panic and not claim a
    // format was detected.
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = tmpdir.path().join("empty.img");
    fs::write(&image, b"").expect("write empty image");

    let output = run_ffs_cli(&["inspect", image.to_str().unwrap()]);

    assert!(
        !output.status.success(),
        "`ffs inspect` on an empty file must not succeed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "`ffs inspect` on an empty file must emit a diagnostic, got stderr=<empty>"
    );
    emit_scenario_result("cli_inspect_empty_file_error", "PASS", None);
}
