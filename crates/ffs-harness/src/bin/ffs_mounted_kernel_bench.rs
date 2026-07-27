#![forbid(unsafe_code)]

//! Real mounted-kernel versus FrankenFS FUSE comparator.
//!
//! The harness owns four live mounts in one invocation:
//! two byte-identical kernel filesystems and two byte-identical FrankenFS FUSE
//! filesystems. A balanced schedule interleaves all four arms, so the two
//! kernel mounts provide an incumbent A/A null and the two FUSE mounts provide
//! a candidate A/A null. Competitive latency is reported only when both null
//! confidence intervals are tight, mount identity is proven at runtime, the
//! FUSE daemons self-report their executing ELF SHA-256, and untimed content
//! and metadata parity pass.

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BOOTSTRAP_RESAMPLES: usize = 20_000;
const MIN_FREE_BYTES: u64 = 120 * 1024 * 1024 * 1024;
const MAX_IMAGE_MIB: u64 = 2048;
const PAYLOAD_BYTES: usize = 1024 * 1024;
const MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(20);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const CPU_SAMPLE_INTERVAL: Duration = Duration::from_millis(300);
const MAX_DRIVER_PREFLIGHT_BUSY: f64 = 0.20;
const MAX_FUSE_PREFLIGHT_BUSY: f64 = 0.35;
const MOUNT_ROOT: &str = "/tmp/frankenfs-mounted-kernel-mounts";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilesystemKind {
    Ext4,
    Btrfs,
}

impl FilesystemKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Btrfs => "btrfs",
        }
    }

    const fn kernel_module(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Btrfs => "btrfs",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestedFilesystems {
    Ext4,
    Btrfs,
    Both,
}

#[derive(Debug)]
struct Config {
    ffs_cli: PathBuf,
    artifact_root: PathBuf,
    filesystems: RequestedFilesystems,
    pairs: usize,
    operations: usize,
    observation_repeats: usize,
    image_size_mib: u64,
    maximum_null_ratio: f64,
    output: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ffs_cli: PathBuf::new(),
            artifact_root: PathBuf::from("/data/tmp/frankenfs-mounted-kernel"),
            filesystems: RequestedFilesystems::Both,
            pairs: 32,
            operations: 2_000,
            observation_repeats: 3,
            image_size_mib: 256,
            maximum_null_ratio: 1.025,
            output: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Arm {
    KernelA,
    KernelB,
    FuseA,
    FuseB,
}

impl Arm {
    const fn label(self) -> &'static str {
        match self {
            Self::KernelA => "kernel_a",
            Self::KernelB => "kernel_b",
            Self::FuseA => "fuse_a",
            Self::FuseB => "fuse_b",
        }
    }
}

const BALANCED_ORDERS: [[Arm; 4]; 4] = [
    [Arm::KernelA, Arm::FuseA, Arm::KernelB, Arm::FuseB],
    [Arm::FuseB, Arm::KernelB, Arm::FuseA, Arm::KernelA],
    [Arm::KernelB, Arm::FuseB, Arm::KernelA, Arm::FuseA],
    [Arm::FuseA, Arm::KernelA, Arm::FuseB, Arm::KernelB],
];

#[derive(Clone, Copy, Debug)]
struct BootstrapMedianCi {
    median: f64,
    low: f64,
    high: f64,
}

impl BootstrapMedianCi {
    fn symmetric_spread(self) -> f64 {
        self.high.max(1.0 / self.low)
    }

    fn contains_null(self) -> bool {
        self.low <= 1.0 && self.high >= 1.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountInfo {
    major_minor: String,
    root: String,
    mountpoint: PathBuf,
    mount_options: BTreeSet<String>,
    filesystem_type: String,
    source: String,
    super_options: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default)]
struct CpuTicks {
    total: u64,
    idle: u64,
}

#[derive(Clone, Debug)]
struct CpuPlacement {
    driver_cpu: usize,
    fuse_cpus: Vec<usize>,
    driver_guard_cpus: BTreeSet<usize>,
    fuse_guard_cpus: BTreeSet<usize>,
    last_level_cache_cpus: BTreeSet<usize>,
    busy_fractions: BTreeMap<usize, f64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParityWitness {
    file_sha256: String,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FfsBinaryIdentity {
    binary_sha256: String,
    pgo_profile_sha256: String,
}

#[derive(Debug)]
struct TimedSamples {
    values: BTreeMap<Arm, Vec<u64>>,
    digests: BTreeMap<Arm, u64>,
}

#[derive(Debug)]
struct MountedArm {
    arm: Arm,
    mountpoint: PathBuf,
    image: PathBuf,
    mount_info: MountInfo,
    kind: MountedArmKind,
}

#[derive(Debug)]
enum MountedArmKind {
    Kernel,
    Fuse {
        child: Child,
        stdout_log: PathBuf,
        stderr_log: PathBuf,
        self_reported_sha256: String,
        proc_exe_sha256: String,
        pgo_profile_sha256: String,
    },
}

impl MountedArm {
    fn workload_path(&self) -> PathBuf {
        self.mountpoint.join("payload.bin")
    }

    fn unmount(&mut self) -> Result<()> {
        match &mut self.kind {
            MountedArmKind::Kernel => {
                let status = Command::new("sudo")
                    .args(["-n", "umount"])
                    .arg(&self.mountpoint)
                    .status()
                    .with_context(|| format!("unmount kernel arm {}", self.mountpoint.display()))?;
                ensure!(
                    status.success(),
                    "kernel unmount failed for {}: {status}",
                    self.mountpoint.display()
                );
            }
            MountedArmKind::Fuse { child, .. } => {
                let unmount = Command::new("fusermount3")
                    .args(["-u", "--"])
                    .arg(&self.mountpoint)
                    .status()
                    .with_context(|| format!("unmount FUSE arm {}", self.mountpoint.display()))?;
                ensure!(
                    unmount.success(),
                    "FUSE unmount failed for {}: {unmount}",
                    self.mountpoint.display()
                );
                wait_for_child(child, CHILD_EXIT_TIMEOUT).with_context(|| {
                    format!("wait for FUSE daemon at {}", self.mountpoint.display())
                })?;
            }
        }
        ensure!(
            find_mount(&self.mountpoint)?.is_none(),
            "mount remained active after cleanup: {}",
            self.mountpoint.display()
        );
        Ok(())
    }

    fn identity_json(&self) -> Value {
        let base = json!({
            "arm": self.arm.label(),
            "image": self.image,
            "mountpoint": self.mountpoint,
            "major_minor": self.mount_info.major_minor,
            "root": self.mount_info.root,
            "mount_options": self.mount_info.mount_options,
            "filesystem_type": self.mount_info.filesystem_type,
            "source": self.mount_info.source,
            "super_options": self.mount_info.super_options,
        });
        match &self.kind {
            MountedArmKind::Kernel => base,
            MountedArmKind::Fuse {
                child,
                stdout_log,
                stderr_log,
                self_reported_sha256,
                proc_exe_sha256,
                pgo_profile_sha256,
                ..
            } => {
                let mut object = base.as_object().cloned().unwrap_or_default();
                object.insert("stdout_log".to_owned(), json!(stdout_log));
                object.insert("stderr_log".to_owned(), json!(stderr_log));
                object.insert("pid".to_owned(), json!(child.id()));
                object.insert(
                    "self_reported_sha256".to_owned(),
                    json!(self_reported_sha256),
                );
                object.insert("proc_exe_sha256".to_owned(), json!(proc_exe_sha256));
                object.insert("pgo_profile_sha256".to_owned(), json!(pgo_profile_sha256));
                Value::Object(object)
            }
        }
    }
}

impl Drop for MountedArm {
    fn drop(&mut self) {
        let Ok(Some(_)) = find_mount(&self.mountpoint) else {
            return;
        };
        match &mut self.kind {
            MountedArmKind::Kernel => {
                let _ = Command::new("sudo")
                    .args(["-n", "umount"])
                    .arg(&self.mountpoint)
                    .status();
            }
            MountedArmKind::Fuse { child, .. } => {
                let _ = Command::new("fusermount3")
                    .args(["-u", "--"])
                    .arg(&self.mountpoint)
                    .status();
                if wait_for_child(child, Duration::from_secs(2)).is_err() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}

fn usage() {
    println!(
        "Usage: ffs-mounted-kernel-bench --ffs-cli PATH [OPTIONS]\n\
         \n\
         Options:\n\
           --filesystem ext4|btrfs|both   Filesystem arm(s), default both\n\
           --artifact-root PATH           Persistent artifacts under /data/tmp\n\
          --pairs N                      Paired rounds, multiple of 4 and >= 12 (default 32)\n\
           --operations N                 stat calls per observation (default 2000)\n\
           --observation-repeats N        min-of-N repeats (default 3)\n\
           --image-size-mib N             Per-image size, <= 2048 (default 256)\n\
           --maximum-null-ratio R         Max symmetric A/A CI spread (default 1.025)\n\
           --out PATH                     JSON report path (default inside run dir)\n\
           -h, --help                     Show this help"
    );
}

fn parse_value<T: std::str::FromStr>(args: &[String], index: &mut usize, name: &str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    *index += 1;
    let value = args
        .get(*index)
        .ok_or_else(|| anyhow!("missing value for {name}"))?;
    value
        .parse::<T>()
        .map_err(|error| anyhow!("invalid value for {name}: {value}: {error}"))
}

fn parse_args() -> Result<Option<Config>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut config = Config::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                usage();
                return Ok(None);
            }
            "--ffs-cli" => {
                config.ffs_cli = parse_value::<PathBuf>(&args, &mut index, "--ffs-cli")?;
            }
            "--artifact-root" => {
                config.artifact_root =
                    parse_value::<PathBuf>(&args, &mut index, "--artifact-root")?;
            }
            "--filesystem" => {
                let value = parse_value::<String>(&args, &mut index, "--filesystem")?;
                config.filesystems = match value.as_str() {
                    "ext4" => RequestedFilesystems::Ext4,
                    "btrfs" => RequestedFilesystems::Btrfs,
                    "both" => RequestedFilesystems::Both,
                    _ => bail!("unsupported --filesystem {value}; expected ext4|btrfs|both"),
                };
            }
            "--pairs" => config.pairs = parse_value(&args, &mut index, "--pairs")?,
            "--operations" => {
                config.operations = parse_value(&args, &mut index, "--operations")?;
            }
            "--observation-repeats" => {
                config.observation_repeats =
                    parse_value(&args, &mut index, "--observation-repeats")?;
            }
            "--image-size-mib" => {
                config.image_size_mib = parse_value(&args, &mut index, "--image-size-mib")?;
            }
            "--maximum-null-ratio" => {
                config.maximum_null_ratio = parse_value(&args, &mut index, "--maximum-null-ratio")?;
            }
            "--out" => config.output = Some(parse_value(&args, &mut index, "--out")?),
            other => bail!("unknown argument: {other}"),
        }
        index += 1;
    }

    ensure!(
        !config.ffs_cli.as_os_str().is_empty(),
        "--ffs-cli is required"
    );
    ensure!(
        config.ffs_cli.is_file(),
        "ffs-cli does not exist: {}",
        config.ffs_cli.display()
    );
    ensure!(
        config.pairs >= 12 && config.pairs % BALANCED_ORDERS.len() == 0,
        "--pairs must be a multiple of 4 and at least 12"
    );
    ensure!(config.operations > 0, "--operations must be positive");
    ensure!(
        config.observation_repeats > 0,
        "--observation-repeats must be positive"
    );
    ensure!(
        (1..=MAX_IMAGE_MIB).contains(&config.image_size_mib),
        "--image-size-mib must be in 1..={MAX_IMAGE_MIB}"
    );
    ensure!(
        config.maximum_null_ratio > 1.0,
        "--maximum-null-ratio must exceed 1.0"
    );
    Ok(Some(config))
}

fn sha256_reader(mut reader: impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buffer).context("read for SHA-256")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn file_sha256(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("open {} for SHA-256", path.display()))?;
    sha256_reader(file)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn current_elf_sha256() -> Result<String> {
    let executable = env::current_exe().context("resolve current executable")?;
    file_sha256(&executable)
        .with_context(|| format!("self-hash executing ELF {}", executable.display()))
}

fn unique_prefixed_line<'a>(content: &'a str, prefix: &str, label: &str) -> Result<&'a str> {
    let mut matches = content
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .map(str::trim);
    let value = matches
        .next()
        .ok_or_else(|| anyhow!("{label} was not reported"))?;
    ensure!(
        matches.next().is_none(),
        "{label} was reported more than once"
    );
    Ok(value)
}

fn inspect_ffs_binary(path: &Path) -> Result<FfsBinaryIdentity> {
    let output = Command::new(path)
        .arg("bench-evidence")
        .env("RUST_LOG", "off")
        .output()
        .with_context(|| format!("run {} bench-evidence", path.display()))?;
    ensure!(
        output.status.success(),
        "{} bench-evidence failed: {}",
        path.display(),
        output.status
    );
    let stdout = String::from_utf8(output.stdout).context("bench-evidence stdout is not UTF-8")?;
    let binary_sha256 = unique_prefixed_line(
        &stdout,
        "bench_evidence,binary_sha256=",
        "candidate ELF SHA-256",
    )?
    .to_owned();
    ensure!(
        is_sha256(&binary_sha256),
        "candidate reported invalid ELF SHA-256: {binary_sha256}"
    );
    ensure!(
        file_sha256(path)? == binary_sha256,
        "candidate bench-evidence SHA-256 differs from its on-disk path"
    );
    let codegen = stdout
        .lines()
        .find(|line| line.starts_with("codegen_isa,"))
        .ok_or_else(|| anyhow!("candidate codegen ISA was not reported"))?;
    for required in [
        "target_arch=x86_64",
        "compile_sse4_2=true",
        "compile_avx2=true",
        "compile_fma=true",
    ] {
        ensure!(
            codegen.split(',').any(|field| field == required),
            "candidate is not the x86-64-v3 production ISA: missing {required}"
        );
    }
    let pgo_profile_sha256 = unique_prefixed_line(
        &stdout,
        "build_profile,pgo_profile_sha256=",
        "candidate PGO profile SHA-256",
    )?
    .to_owned();
    ensure!(
        is_sha256(&pgo_profile_sha256),
        "candidate is not a PGO production build: {pgo_profile_sha256}"
    );
    Ok(FfsBinaryIdentity {
        binary_sha256,
        pgo_profile_sha256,
    })
}

fn write_deterministic_payload(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create fixture payload {}", path.display()))?;
    let mut block = [0_u8; 4096];
    for (index, byte) in block.iter_mut().enumerate() {
        *byte = u8::try_from((index * 131 + 17) % 251).expect("fixture byte fits u8");
    }
    for _ in 0..(PAYLOAD_BYTES / block.len()) {
        file.write_all(&block)
            .with_context(|| format!("write fixture payload {}", path.display()))?;
    }
    file.sync_all()
        .with_context(|| format!("sync fixture payload {}", path.display()))
}

fn create_fixture_tree(run_dir: &Path) -> Result<PathBuf> {
    let root = run_dir.join("fixture-root");
    fs::create_dir(&root).with_context(|| format!("create {}", root.display()))?;
    write_deterministic_payload(&root.join("payload.bin"))?;
    let nested = root.join("nested");
    fs::create_dir(&nested).with_context(|| format!("create {}", nested.display()))?;
    fs::write(
        nested.join("sentinel.txt"),
        b"frankenfs-mounted-kernel-v1\n",
    )
    .context("write fixture sentinel")?;
    Ok(root)
}

fn create_sized_file(path: &Path, size_mib: u64) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create image {}", path.display()))?;
    file.set_len(size_mib * 1024 * 1024)
        .with_context(|| format!("size image {}", path.display()))
}

fn run_checked(command: &mut Command, label: &str) -> Result<()> {
    let status = command.status().with_context(|| format!("spawn {label}"))?;
    ensure!(status.success(), "{label} failed: {status}");
    Ok(())
}

fn create_base_image(
    kind: FilesystemKind,
    fixture_root: &Path,
    run_dir: &Path,
    size_mib: u64,
) -> Result<PathBuf> {
    let image = run_dir.join(format!("{}.base.img", kind.label()));
    create_sized_file(&image, size_mib)?;
    match kind {
        FilesystemKind::Ext4 => run_checked(
            Command::new("mke2fs")
                .args(["-t", "ext4", "-F", "-q", "-b", "4096"])
                .arg("-d")
                .arg(fixture_root)
                .arg(&image),
            "mke2fs ext4 fixture",
        )?,
        FilesystemKind::Btrfs => run_checked(
            Command::new("mkfs.btrfs")
                .args(["-f", "-q", "-r"])
                .arg(fixture_root)
                .arg(&image),
            "mkfs.btrfs fixture",
        )?,
    }
    validate_image(kind, &image)?;
    Ok(image)
}

fn validate_image(kind: FilesystemKind, image: &Path) -> Result<()> {
    match kind {
        FilesystemKind::Ext4 => {
            let status = Command::new("e2fsck")
                .args(["-fn"])
                .arg(image)
                .stdout(Stdio::null())
                .status()
                .with_context(|| format!("run e2fsck on {}", image.display()))?;
            ensure!(
                status.code() == Some(0),
                "e2fsck did not report clean image {}: {status}",
                image.display()
            );
        }
        FilesystemKind::Btrfs => run_checked(
            Command::new("btrfs")
                .args(["check", "--readonly"])
                .arg(image)
                .stdout(Stdio::null()),
            "btrfs check --readonly",
        )?,
    }
    Ok(())
}

fn clone_images(
    kind: FilesystemKind,
    base: &Path,
    run_dir: &Path,
) -> Result<BTreeMap<Arm, PathBuf>> {
    let expected_sha = file_sha256(base)?;
    let mut images = BTreeMap::new();
    for arm in [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB] {
        let path = run_dir.join(format!("{}.{}.img", kind.label(), arm.label()));
        fs::copy(base, &path)
            .with_context(|| format!("clone {} to {}", base.display(), path.display()))?;
        let actual_sha = file_sha256(&path)?;
        ensure!(
            actual_sha == expected_sha,
            "image clone digest mismatch for {}",
            path.display()
        );
        images.insert(arm, path);
    }
    Ok(images)
}

fn mountinfo_unescape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..=index + 3].iter().all(u8::is_ascii_digit)
        {
            let octal = (bytes[index + 1] - b'0') * 64
                + (bytes[index + 2] - b'0') * 8
                + (bytes[index + 3] - b'0');
            output.push(octal);
            index += 4;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn option_set(value: &str) -> BTreeSet<String> {
    value
        .split(',')
        .filter(|option| !option.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_mountinfo_line(line: &str) -> Result<MountInfo> {
    let (left, right) = line
        .split_once(" - ")
        .ok_or_else(|| anyhow!("mountinfo row has no separator"))?;
    let left_fields: Vec<&str> = left.split_ascii_whitespace().collect();
    let right_fields: Vec<&str> = right.split_ascii_whitespace().collect();
    ensure!(
        left_fields.len() >= 6 && right_fields.len() >= 3,
        "mountinfo row is too short"
    );
    Ok(MountInfo {
        major_minor: left_fields[2].to_owned(),
        root: mountinfo_unescape(left_fields[3]),
        mountpoint: PathBuf::from(mountinfo_unescape(left_fields[4])),
        mount_options: option_set(left_fields[5]),
        filesystem_type: right_fields[0].to_owned(),
        source: mountinfo_unescape(right_fields[1]),
        super_options: option_set(right_fields[2]),
    })
}

fn find_mount(mountpoint: &Path) -> Result<Option<MountInfo>> {
    let target = fs::canonicalize(mountpoint)
        .with_context(|| format!("canonicalize mountpoint {}", mountpoint.display()))?;
    let file = File::open("/proc/self/mountinfo").context("open /proc/self/mountinfo")?;
    for line in BufReader::new(file).lines() {
        let line = line.context("read /proc/self/mountinfo")?;
        let parsed = parse_mountinfo_line(&line)?;
        if parsed.mountpoint == target {
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn wait_for_mount(
    mountpoint: &Path,
    mut child: Option<&mut Child>,
    interrupted: &AtomicBool,
) -> Result<MountInfo> {
    let deadline = Instant::now() + MOUNT_READY_TIMEOUT;
    loop {
        ensure!(
            !interrupted.load(Ordering::Relaxed),
            "interrupted while waiting for mount"
        );
        if let Some(info) = find_mount(mountpoint)? {
            fs::metadata(mountpoint)
                .with_context(|| format!("stat ready mount {}", mountpoint.display()))?;
            return Ok(info);
        }
        if let Some(process) = child.as_deref_mut()
            && let Some(status) = process.try_wait().context("poll FUSE mount process")?
        {
            bail!("FUSE mount process exited before readiness: {status}");
        }
        ensure!(
            Instant::now() < deadline,
            "mount readiness timed out at {}",
            mountpoint.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_common_mount_options(info: &MountInfo, label: &str) -> Result<()> {
    for required in ["ro", "noatime", "nodev", "nosuid"] {
        ensure!(
            info.mount_options.contains(required) || info.super_options.contains(required),
            "{label} mount missing required option {required}: mount={:?} super={:?}",
            info.mount_options,
            info.super_options
        );
    }
    ensure!(
        !info.mount_options.contains("rw") && !info.super_options.contains("rw"),
        "{label} unexpectedly reports read-write mount options"
    );
    Ok(())
}

fn loop_backing_path(info: &MountInfo) -> Result<PathBuf> {
    let loop_name = Path::new(&info.source)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow!(
                "kernel source has no UTF-8 loop device name: {}",
                info.source
            )
        })?;
    let loop_index = loop_name
        .strip_prefix("loop")
        .ok_or_else(|| anyhow!("kernel source is not a loop device: {}", info.source))?;
    ensure!(
        !loop_index.is_empty() && loop_index.bytes().all(|byte| byte.is_ascii_digit()),
        "kernel source has invalid loop device name: {}",
        info.source
    );
    let path = PathBuf::from("/sys/class/block")
        .join(loop_name)
        .join("loop/backing_file");
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read loop backing file {}", path.display()))?;
    let trimmed = raw.trim();
    let absolute = if trimmed.starts_with('/') {
        PathBuf::from(trimmed)
    } else {
        PathBuf::from("/").join(trimmed)
    };
    fs::canonicalize(&absolute)
        .with_context(|| format!("canonicalize loop backing file {}", absolute.display()))
}

fn mount_kernel(
    kind: FilesystemKind,
    arm: Arm,
    image: &Path,
    mountpoint: &Path,
    interrupted: &AtomicBool,
) -> Result<MountedArm> {
    fs::create_dir(mountpoint)
        .with_context(|| format!("create kernel mountpoint {}", mountpoint.display()))?;
    let canonical_mountpoint = fs::canonicalize(mountpoint)
        .with_context(|| format!("canonicalize mountpoint {}", mountpoint.display()))?;
    let expected_image = fs::canonicalize(image)
        .with_context(|| format!("canonicalize image {}", image.display()))?;
    let options = match kind {
        FilesystemKind::Ext4 => "loop,ro,noload,noatime,nodev,nosuid",
        FilesystemKind::Btrfs => "loop,ro,noatime,nodev,nosuid",
    };
    run_checked(
        Command::new("sudo")
            .args(["-n", "mount", "-t", kind.label(), "-o", options])
            .arg(image)
            .arg(mountpoint),
        &format!("mount kernel {}", kind.label()),
    )?;
    let info = wait_for_mount(mountpoint, None, interrupted)?;
    let mounted = MountedArm {
        arm,
        mountpoint: canonical_mountpoint,
        image: expected_image,
        mount_info: info,
        kind: MountedArmKind::Kernel,
    };
    assert_common_mount_options(&mounted.mount_info, arm.label())?;
    ensure!(
        mounted.mount_info.filesystem_type == kind.label(),
        "{} incumbent identity mismatch: expected {}, observed {}",
        arm.label(),
        kind.label(),
        mounted.mount_info.filesystem_type
    );
    ensure!(
        mounted.mount_info.source.starts_with("/dev/loop"),
        "{} incumbent source is not a loop device: {}",
        arm.label(),
        mounted.mount_info.source
    );
    ensure!(
        loop_backing_path(&mounted.mount_info)? == mounted.image,
        "{} loop device does not reference its declared image",
        arm.label()
    );
    Ok(mounted)
}

fn parse_mount_self_report(log_path: &Path) -> Result<FfsBinaryIdentity> {
    let content = fs::read_to_string(log_path)
        .with_context(|| format!("read FUSE mount log {}", log_path.display()))?;
    let binary_sha256 = unique_prefixed_line(
        &content,
        "mount_bench_evidence,binary_sha256=",
        "FUSE mount executing ELF SHA-256",
    )?
    .to_owned();
    ensure!(
        is_sha256(&binary_sha256),
        "invalid FUSE mount ELF SHA-256: {binary_sha256}"
    );
    let pgo_profile_sha256 = unique_prefixed_line(
        &content,
        "mount_build_profile,pgo_profile_sha256=",
        "FUSE mount PGO profile SHA-256",
    )?
    .to_owned();
    ensure!(
        is_sha256(&pgo_profile_sha256),
        "FUSE mount is not running a PGO production build: {pgo_profile_sha256}"
    );
    Ok(FfsBinaryIdentity {
        binary_sha256,
        pgo_profile_sha256,
    })
}

// Keep the lifecycle linear: every identity check must remain visibly between
// daemon spawn and the cleanup guard that owns it.
#[allow(clippy::too_many_lines)]
fn mount_fuse(
    config: &Config,
    expected_identity: &FfsBinaryIdentity,
    arm: Arm,
    image: &Path,
    mountpoint: &Path,
    fuse_cpus: &[usize],
    interrupted: &AtomicBool,
) -> Result<MountedArm> {
    fs::create_dir(mountpoint)
        .with_context(|| format!("create FUSE mountpoint {}", mountpoint.display()))?;
    let canonical_mountpoint = fs::canonicalize(mountpoint)
        .with_context(|| format!("canonicalize mountpoint {}", mountpoint.display()))?;
    let canonical_image = fs::canonicalize(image)
        .with_context(|| format!("canonicalize image {}", image.display()))?;
    let stdout_log = mountpoint.with_extension("stdout.log");
    let stderr_log = mountpoint.with_extension("stderr.log");
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout_log)
        .with_context(|| format!("create {}", stdout_log.display()))?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr_log)
        .with_context(|| format!("create {}", stderr_log.display()))?;
    let cpu_list = fuse_cpus
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut child = Command::new("taskset")
        .args(["-c", &cpu_list])
        .arg(&config.ffs_cli)
        .arg("mount")
        .arg("--no-background-scrub")
        .arg(image)
        .arg(mountpoint)
        .env("FFS_AUTO_UNMOUNT", "0")
        .env("FFS_MOUNT_BENCH_EVIDENCE", "1")
        .env("RUST_LOG", "off")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("spawn FrankenFS FUSE arm {}", arm.label()))?;
    let info = wait_for_mount(mountpoint, Some(&mut child), interrupted).with_context(|| {
        let log = fs::read_to_string(&stderr_log).unwrap_or_default();
        format!("wait for {} FUSE mount; stderr={log}", arm.label())
    })?;
    let mut mounted = MountedArm {
        arm,
        mountpoint: canonical_mountpoint,
        image: canonical_image,
        mount_info: info,
        kind: MountedArmKind::Fuse {
            child,
            stdout_log,
            stderr_log,
            self_reported_sha256: String::new(),
            proc_exe_sha256: String::new(),
            pgo_profile_sha256: String::new(),
        },
    };
    assert_common_mount_options(&mounted.mount_info, arm.label())?;
    ensure!(
        mounted.mount_info.filesystem_type == "fuse.ffs",
        "{} FUSE identity mismatch: expected fuse.ffs, observed {}",
        arm.label(),
        mounted.mount_info.filesystem_type
    );
    ensure!(
        mounted.mount_info.source == "frankenfs",
        "{} FUSE source mismatch: expected frankenfs, observed {}",
        arm.label(),
        mounted.mount_info.source
    );
    ensure!(
        !mounted.mount_info.mount_options.contains("writeback_cache")
            && !mounted.mount_info.super_options.contains("writeback_cache"),
        "{} unexpectedly enabled FUSE writeback_cache",
        arm.label()
    );
    let (child_id, stderr_log) = match &mounted.kind {
        MountedArmKind::Fuse {
            child, stderr_log, ..
        } => (child.id(), stderr_log.clone()),
        MountedArmKind::Kernel => unreachable!("constructed FUSE mount"),
    };
    let self_report = parse_mount_self_report(&stderr_log)?;
    let proc_exe_sha256 = file_sha256(&PathBuf::from(format!("/proc/{child_id}/exe")))
        .with_context(|| format!("hash mapped FUSE executable for pid {child_id}"))?;
    ensure!(
        self_report.binary_sha256 == proc_exe_sha256,
        "{} self-reported ELF differs from /proc/{child_id}/exe",
        arm.label(),
    );
    ensure!(
        &self_report == expected_identity,
        "{} runtime daemon identity differs from the v3+PGO preflight",
        arm.label()
    );
    let MountedArmKind::Fuse {
        self_reported_sha256: reported,
        proc_exe_sha256: mapped,
        pgo_profile_sha256: pgo,
        ..
    } = &mut mounted.kind
    else {
        unreachable!("constructed FUSE mount");
    };
    *reported = self_report.binary_sha256;
    *mapped = proc_exe_sha256;
    *pgo = self_report.pgo_profile_sha256;
    Ok(mounted)
}

fn parity_witness(path: &Path) -> Result<ParityWitness> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(ParityWitness {
        file_sha256: file_sha256(path)?,
        len: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        nlink: metadata.nlink(),
    })
}

fn assert_independent_arms(mounts: &[MountedArm]) -> Result<()> {
    ensure!(mounts.len() == 4, "independence proof requires four mounts");
    let images: BTreeSet<PathBuf> = mounts.iter().map(|mount| mount.image.clone()).collect();
    let mountpoints: BTreeSet<PathBuf> = mounts
        .iter()
        .map(|mount| mount.mountpoint.clone())
        .collect();
    ensure!(
        images.len() == 4 && mountpoints.len() == 4,
        "mounted arms do not own four distinct images and mountpoints"
    );

    let kernel_devices: BTreeSet<String> = mounts
        .iter()
        .filter(|mount| matches!(&mount.kind, MountedArmKind::Kernel))
        .map(|mount| mount.mount_info.major_minor.clone())
        .collect();
    let kernel_sources: BTreeSet<String> = mounts
        .iter()
        .filter(|mount| matches!(&mount.kind, MountedArmKind::Kernel))
        .map(|mount| mount.mount_info.source.clone())
        .collect();
    ensure!(
        kernel_devices.len() == 2 && kernel_sources.len() == 2,
        "kernel A/A arms share a mounted superblock or loop source"
    );

    let fuse_devices: BTreeSet<String> = mounts
        .iter()
        .filter(|mount| matches!(&mount.kind, MountedArmKind::Fuse { .. }))
        .map(|mount| mount.mount_info.major_minor.clone())
        .collect();
    let fuse_pids: BTreeSet<u32> = mounts
        .iter()
        .filter_map(|mount| match &mount.kind {
            MountedArmKind::Fuse { child, .. } => Some(child.id()),
            MountedArmKind::Kernel => None,
        })
        .collect();
    ensure!(
        fuse_devices.len() == 2 && fuse_pids.len() == 2,
        "FUSE A/A arms share a mount device or daemon process"
    );
    Ok(())
}

fn stat_batch(path: &Path, operations: usize) -> Result<(u64, u64)> {
    let mut digest = 0x9E37_79B9_7F4A_7C15_u64;
    let started = Instant::now();
    for index in 0..operations {
        let metadata = fs::metadata(black_box(path))
            .with_context(|| format!("timed stat {}", path.display()))?;
        let row = metadata.len().wrapping_mul(0xD6E8_FEB8_6659_FD93)
            ^ u64::from(metadata.mode()).rotate_left(17)
            ^ metadata.nlink().rotate_left(31)
            ^ u64::try_from(index).unwrap_or(u64::MAX);
        digest = digest.rotate_left(9) ^ row;
    }
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    black_box(digest);
    Ok((elapsed, digest))
}

fn observe(path: &Path, config: &Config) -> Result<(u64, u64)> {
    let mut best = u64::MAX;
    let mut expected_digest = None;
    for _ in 0..config.observation_repeats {
        let (elapsed, digest) = stat_batch(path, config.operations)?;
        if let Some(expected) = expected_digest {
            ensure!(
                digest == expected,
                "timed workload digest changed within one arm"
            );
        } else {
            expected_digest = Some(digest);
        }
        best = best.min(elapsed);
    }
    Ok((best, expected_digest.unwrap_or(0)))
}

fn collect_samples(
    paths: &BTreeMap<Arm, PathBuf>,
    config: &Config,
    interrupted: &AtomicBool,
) -> Result<TimedSamples> {
    for arm in [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB] {
        let path = paths
            .get(&arm)
            .ok_or_else(|| anyhow!("missing workload path for {}", arm.label()))?;
        for _ in 0..2 {
            let (_, digest) = stat_batch(path, config.operations)?;
            black_box(digest);
        }
    }

    let mut values = BTreeMap::from([
        (Arm::KernelA, Vec::with_capacity(config.pairs)),
        (Arm::KernelB, Vec::with_capacity(config.pairs)),
        (Arm::FuseA, Vec::with_capacity(config.pairs)),
        (Arm::FuseB, Vec::with_capacity(config.pairs)),
    ]);
    let mut digests = BTreeMap::new();
    for round in 0..config.pairs {
        ensure!(
            !interrupted.load(Ordering::Relaxed),
            "interrupted during timed workload"
        );
        for arm in BALANCED_ORDERS[round % BALANCED_ORDERS.len()] {
            let path = paths
                .get(&arm)
                .ok_or_else(|| anyhow!("missing workload path for {}", arm.label()))?;
            let (elapsed, digest) = observe(path, config)?;
            values
                .get_mut(&arm)
                .expect("all arms initialized")
                .push(elapsed);
            if let Some(expected) = digests.insert(arm, digest) {
                ensure!(
                    expected == digest,
                    "{} workload digest changed across rounds",
                    arm.label()
                );
            }
        }
    }
    Ok(TimedSamples { values, digests })
}

fn median(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "median requires samples");
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        values[middle - 1].midpoint(values[middle])
    } else {
        values[middle]
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
    assert!(!log_ratios.is_empty(), "bootstrap requires samples");
    let mut state = seed ^ u64::try_from(log_ratios.len()).expect("sample count fits u64");
    let mut bootstrapped = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let mut sample = Vec::with_capacity(log_ratios.len());
        for _ in log_ratios {
            let draw =
                splitmix64(&mut state) % u64::try_from(log_ratios.len()).expect("length fits u64");
            sample.push(log_ratios[usize::try_from(draw).expect("draw fits usize")]);
        }
        bootstrapped.push(median(sample));
    }
    bootstrapped.sort_by(f64::total_cmp);
    let low_index = BOOTSTRAP_RESAMPLES * 25 / 1000;
    let high_index = (BOOTSTRAP_RESAMPLES * 975).div_ceil(1000).saturating_sub(1);
    BootstrapMedianCi {
        median: median(log_ratios.to_vec()).exp(),
        low: bootstrapped[low_index].exp(),
        high: bootstrapped[high_index].exp(),
    }
}

fn paired_log_ratios(numerator: &[u64], denominator: &[u64]) -> Result<Vec<f64>> {
    ensure!(
        numerator.len() == denominator.len() && !numerator.is_empty(),
        "paired ratio arms must be non-empty and equal length"
    );
    numerator
        .iter()
        .zip(denominator)
        .map(|(&num, &den)| {
            ensure!(num > 0 && den > 0, "timed samples must be positive");
            Ok((num as f64).ln() - (den as f64).ln())
        })
        .collect()
}

fn competitive_log_ratios(samples: &TimedSamples) -> Result<Vec<f64>> {
    let kernel_a = &samples.values[&Arm::KernelA];
    let kernel_b = &samples.values[&Arm::KernelB];
    let fuse_a = &samples.values[&Arm::FuseA];
    let fuse_b = &samples.values[&Arm::FuseB];
    ensure!(
        kernel_a.len() == kernel_b.len()
            && kernel_a.len() == fuse_a.len()
            && kernel_a.len() == fuse_b.len(),
        "competitive arms must have equal sample counts"
    );
    Ok(kernel_a
        .iter()
        .zip(kernel_b)
        .zip(fuse_a.iter().zip(fuse_b))
        .map(
            |((&kernel_left, &kernel_right), (&fuse_left, &fuse_right))| {
                0.5 * ((fuse_left as f64).ln() + (fuse_right as f64).ln()
                    - (kernel_left as f64).ln()
                    - (kernel_right as f64).ln())
            },
        )
        .collect())
}

fn read_cpu_ticks() -> Result<BTreeMap<usize, CpuTicks>> {
    let content = fs::read_to_string("/proc/stat").context("read /proc/stat")?;
    let mut cpus = BTreeMap::new();
    for line in content.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(label) = fields.next() else {
            continue;
        };
        let Some(suffix) = label.strip_prefix("cpu") else {
            continue;
        };
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let cpu = suffix.parse::<usize>().context("parse CPU index")?;
        let ticks = fields
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("parse /proc/stat ticks for cpu{cpu}"))?;
        ensure!(ticks.len() >= 5, "cpu{cpu} /proc/stat row is too short");
        let total = ticks.iter().copied().sum();
        let idle = ticks[3].saturating_add(ticks[4]);
        cpus.insert(cpu, CpuTicks { total, idle });
    }
    ensure!(!cpus.is_empty(), "no per-CPU rows in /proc/stat");
    Ok(cpus)
}

fn sample_cpu_busy() -> Result<BTreeMap<usize, f64>> {
    let before = read_cpu_ticks()?;
    thread::sleep(CPU_SAMPLE_INTERVAL);
    let after = read_cpu_ticks()?;
    let mut busy = BTreeMap::new();
    for (cpu, start) in before {
        let end = after
            .get(&cpu)
            .ok_or_else(|| anyhow!("cpu{cpu} disappeared during load sample"))?;
        let total = end.total.saturating_sub(start.total);
        let idle = end.idle.saturating_sub(start.idle);
        let fraction = if total == 0 {
            1.0
        } else {
            total.saturating_sub(idle) as f64 / total as f64
        };
        busy.insert(cpu, fraction);
    }
    Ok(busy)
}

fn parse_cpu_list(value: &str) -> Result<BTreeSet<usize>> {
    let mut cpus = BTreeSet::new();
    for range in value.trim().split(',').filter(|part| !part.is_empty()) {
        if let Some((start, end)) = range.split_once('-') {
            let start = start.parse::<usize>().context("parse CPU range start")?;
            let end = end.parse::<usize>().context("parse CPU range end")?;
            ensure!(start <= end, "descending CPU range: {range}");
            cpus.extend(start..=end);
        } else {
            cpus.insert(range.parse::<usize>().context("parse CPU index")?);
        }
    }
    ensure!(!cpus.is_empty(), "CPU list is empty");
    Ok(cpus)
}

fn thread_siblings(cpu: usize) -> Result<BTreeSet<usize>> {
    let path = PathBuf::from(format!(
        "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
    ));
    let value = fs::read_to_string(&path)
        .with_context(|| format!("read thread siblings {}", path.display()))?;
    parse_cpu_list(&value)
}

fn last_level_cache_siblings(cpu: usize) -> Result<BTreeSet<usize>> {
    let cache_root = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}/cache"));
    let mut highest: Option<(u32, BTreeSet<usize>)> = None;
    for entry in fs::read_dir(&cache_root)
        .with_context(|| format!("read CPU cache topology {}", cache_root.display()))?
    {
        let path = entry.context("read CPU cache topology entry")?.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("index"))
        {
            continue;
        }
        let cache_type = fs::read_to_string(path.join("type"))
            .with_context(|| format!("read cache type {}", path.display()))?;
        if !matches!(cache_type.trim(), "Unified" | "Data") {
            continue;
        }
        let level = fs::read_to_string(path.join("level"))
            .with_context(|| format!("read cache level {}", path.display()))?
            .trim()
            .parse::<u32>()
            .with_context(|| format!("parse cache level {}", path.display()))?;
        let shared = parse_cpu_list(
            &fs::read_to_string(path.join("shared_cpu_list"))
                .with_context(|| format!("read shared CPU list {}", path.display()))?,
        )?;
        if highest.as_ref().is_none_or(|(current, _)| level > *current) {
            highest = Some((level, shared));
        }
    }
    let (level, siblings) =
        highest.ok_or_else(|| anyhow!("cpu{cpu} exposes no data or unified cache topology"))?;
    ensure!(
        siblings.contains(&cpu),
        "cpu{cpu} is absent from its L{level} shared CPU list: {siblings:?}"
    );
    Ok(siblings)
}

fn select_cpu_placement() -> Result<CpuPlacement> {
    let busy = sample_cpu_busy()?;
    let mut ranked: Vec<(usize, f64)> = busy.iter().map(|(&cpu, &load)| (cpu, load)).collect();
    ranked.sort_by(|left, right| {
        left.1
            .total_cmp(&right.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    let mut driver = None;
    for &(cpu, load) in &ranked {
        let siblings = thread_siblings(cpu)?;
        if siblings.iter().all(|sibling| {
            busy.get(sibling)
                .is_some_and(|value| *value <= MAX_DRIVER_PREFLIGHT_BUSY)
        }) {
            driver = Some((cpu, load, siblings));
            break;
        }
    }
    let (driver_cpu, driver_busy, driver_guard_cpus) = driver.ok_or_else(|| {
        anyhow!("no physical core has every SMT thread below the driver contention limit")
    })?;
    ensure!(
        driver_busy <= MAX_DRIVER_PREFLIGHT_BUSY,
        "quietest driver CPU cpu{driver_cpu} was {:.1}% busy, above {:.1}% limit",
        driver_busy * 100.0,
        MAX_DRIVER_PREFLIGHT_BUSY * 100.0
    );
    let last_level_cache_cpus = last_level_cache_siblings(driver_cpu)?;
    let mut excluded = driver_guard_cpus.clone();
    let mut fuse_cpus = Vec::new();
    let mut fuse_guard_cpus = BTreeSet::new();
    for (cpu, load) in ranked {
        if !last_level_cache_cpus.contains(&cpu)
            || excluded.contains(&cpu)
            || load > MAX_FUSE_PREFLIGHT_BUSY
        {
            continue;
        }
        let siblings = thread_siblings(cpu)?;
        if siblings.iter().any(|sibling| {
            busy.get(sibling)
                .is_none_or(|value| *value > MAX_FUSE_PREFLIGHT_BUSY)
        }) {
            continue;
        }
        fuse_cpus.push(cpu);
        fuse_guard_cpus = siblings;
        excluded.extend(&fuse_guard_cpus);
        // Both identical FUSE daemons share one quiet physical CPU. The arms
        // execute serially, so this avoids cross-core scheduler asymmetry
        // without making the measured arms contend with each other. Requiring
        // the driver's LLC domain also avoids cross-CCD request/response bias.
        if fuse_cpus.len() == 1 {
            break;
        }
    }
    ensure!(
        !fuse_cpus.is_empty(),
        "no non-sibling CPU in the driver's last-level-cache domain has every SMT thread below the FUSE contention limit"
    );
    Ok(CpuPlacement {
        driver_cpu,
        fuse_cpus,
        driver_guard_cpus,
        fuse_guard_cpus,
        last_level_cache_cpus,
        busy_fractions: busy,
    })
}

fn pin_current_process(cpu: usize) -> Result<()> {
    run_checked(
        Command::new("taskset")
            .args(["-pc", &cpu.to_string(), &std::process::id().to_string()])
            .stdout(Stdio::null()),
        "pin mounted benchmark driver",
    )?;
    let status = fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    let allowed = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:\t"))
        .ok_or_else(|| anyhow!("Cpus_allowed_list missing from /proc/self/status"))?;
    ensure!(
        parse_cpu_list(allowed)? == BTreeSet::from([cpu]),
        "driver affinity did not resolve to cpu{cpu}: {allowed}"
    );
    Ok(())
}

fn free_bytes_on_data() -> Result<u64> {
    let output = Command::new("df")
        .args(["--output=avail", "-B1", "/data"])
        .output()
        .context("run df for /data")?;
    ensure!(output.status.success(), "df /data failed");
    let stdout = String::from_utf8(output.stdout).context("df output is not UTF-8")?;
    stdout
        .lines()
        .filter_map(|line| line.trim().parse::<u64>().ok())
        .next_back()
        .ok_or_else(|| anyhow!("could not parse available bytes from df"))
}

fn create_run_dir(root: &Path) -> Result<PathBuf> {
    ensure!(
        root.is_absolute() && root.starts_with("/data/tmp"),
        "artifact root must be an absolute path below /data/tmp"
    );
    fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_secs();
    let run_dir = root.join(format!("run_{epoch}_{}", std::process::id()));
    fs::create_dir(&run_dir).with_context(|| format!("create {}", run_dir.display()))?;
    Ok(run_dir)
}

fn create_mount_run_dir(artifact_run_dir: &Path) -> Result<PathBuf> {
    let run_name = artifact_run_dir
        .file_name()
        .ok_or_else(|| anyhow!("artifact run directory has no final component"))?;
    let mount_root = Path::new(MOUNT_ROOT);
    fs::create_dir_all(mount_root)
        .with_context(|| format!("create mount root {}", mount_root.display()))?;
    let mount_run_dir = mount_root.join(run_name);
    fs::create_dir(&mount_run_dir)
        .with_context(|| format!("create mount run directory {}", mount_run_dir.display()))?;
    Ok(mount_run_dir)
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context("poll child exit")? {
            ensure!(status.success(), "child exited unsuccessfully: {status}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait().context("wait after killing child")?;
            bail!("child did not exit after unmount; killed with status {status}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

// This is the auditable four-arm transaction boundary. Splitting its context
// across helper state would make mount ownership and teardown harder to verify.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn fs_report(
    kind: FilesystemKind,
    config: &Config,
    expected_identity: &FfsBinaryIdentity,
    run_dir: &Path,
    mount_run_dir: &Path,
    fixture_root: &Path,
    placement: &CpuPlacement,
    interrupted: &AtomicBool,
) -> Result<Value> {
    let fs_dir = run_dir.join(kind.label());
    fs::create_dir(&fs_dir).with_context(|| format!("create {}", fs_dir.display()))?;
    let mount_fs_dir = mount_run_dir.join(kind.label());
    fs::create_dir(&mount_fs_dir)
        .with_context(|| format!("create mount directory {}", mount_fs_dir.display()))?;
    let base = create_base_image(kind, fixture_root, &fs_dir, config.image_size_mib)?;
    let images = clone_images(kind, &base, &fs_dir)?;

    let mut mounts = Vec::with_capacity(4);
    for arm in [Arm::KernelA, Arm::KernelB] {
        mounts.push(mount_kernel(
            kind,
            arm,
            &images[&arm],
            &mount_fs_dir.join(arm.label()),
            interrupted,
        )?);
    }
    for arm in [Arm::FuseA, Arm::FuseB] {
        mounts.push(mount_fuse(
            config,
            expected_identity,
            arm,
            &images[&arm],
            &mount_fs_dir.join(arm.label()),
            &placement.fuse_cpus,
            interrupted,
        )?);
    }
    assert_independent_arms(&mounts)?;

    let fuse_shas: BTreeSet<String> = mounts
        .iter()
        .filter_map(|mount| match &mount.kind {
            MountedArmKind::Fuse {
                self_reported_sha256,
                ..
            } => Some(self_reported_sha256.clone()),
            MountedArmKind::Kernel => None,
        })
        .collect();
    ensure!(
        fuse_shas.len() == 1,
        "FUSE A/A arms executed different ELFs: {fuse_shas:?}"
    );

    let identities: Vec<Value> = mounts.iter().map(MountedArm::identity_json).collect();
    let mut parity = BTreeMap::new();
    let mut paths = BTreeMap::new();
    for mount in &mounts {
        let path = mount.workload_path();
        parity.insert(mount.arm, parity_witness(&path)?);
        paths.insert(mount.arm, path);
    }
    let expected_parity = parity
        .get(&Arm::KernelA)
        .cloned()
        .ok_or_else(|| anyhow!("kernel A parity witness missing"))?;
    ensure!(
        parity.values().all(|witness| witness == &expected_parity),
        "mounted parity mismatch for {}: {parity:?}",
        kind.label()
    );

    let contention = sample_cpu_busy()?;
    for &cpu in &placement.driver_guard_cpus {
        let load = contention
            .get(&cpu)
            .copied()
            .ok_or_else(|| anyhow!("driver guard cpu{cpu} disappeared before measurement"))?;
        ensure!(
            load <= MAX_DRIVER_PREFLIGHT_BUSY,
            "driver guard cpu{cpu} became {:.1}% busy before measurement",
            load * 100.0
        );
    }
    for &cpu in &placement.fuse_guard_cpus {
        let load = contention
            .get(&cpu)
            .copied()
            .ok_or_else(|| anyhow!("FUSE guard cpu{cpu} disappeared before measurement"))?;
        ensure!(
            load <= MAX_FUSE_PREFLIGHT_BUSY,
            "FUSE cpu{cpu} became {:.1}% busy before measurement",
            load * 100.0
        );
    }

    let samples = collect_samples(&paths, config, interrupted)?;
    let kernel_null = bootstrap_median_ci(
        &paired_log_ratios(
            &samples.values[&Arm::KernelA],
            &samples.values[&Arm::KernelB],
        )?,
        0x4B45_524E_454C_4141,
    );
    let fuse_null = bootstrap_median_ci(
        &paired_log_ratios(&samples.values[&Arm::FuseA], &samples.values[&Arm::FuseB])?,
        0x4655_5345_5F41_4141,
    );
    let fuse_over_kernel =
        bootstrap_median_ci(&competitive_log_ratios(&samples)?, 0x4B45_524E_454C_4142);
    let kernel_clear =
        kernel_null.contains_null() && kernel_null.symmetric_spread() <= config.maximum_null_ratio;
    let fuse_clear =
        fuse_null.contains_null() && fuse_null.symmetric_spread() <= config.maximum_null_ratio;
    let admitted = kernel_clear && fuse_clear;

    for arm in [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB] {
        println!(
            "mounted_kernel_arm,filesystem={},arm={},median_wall_ns={:.0},samples={}",
            kind.label(),
            arm.label(),
            median(
                samples.values[&arm]
                    .iter()
                    .map(|&value| value as f64)
                    .collect()
            ),
            samples.values[&arm].len(),
        );
    }
    println!(
        "mounted_kernel_identity,filesystem={},kernel_release={},kernel_module={},kernel_arms=2,fuse_arms=2,fuse_binary_sha256={},mount_identity=pass,independent_arms=pass,options=ro+noatime+nodev+nosuid,durability=read_only_no_mutation",
        kind.label(),
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim(),
        kind.kernel_module(),
        fuse_shas
            .iter()
            .next()
            .map_or("unavailable", String::as_str),
    );
    println!(
        "mounted_kernel_parity,filesystem={},arms=4,file_sha256={},len={},mode={:o},uid={},gid={},nlink={},verdict=pass",
        kind.label(),
        expected_parity.file_sha256,
        expected_parity.len,
        expected_parity.mode,
        expected_parity.uid,
        expected_parity.gid,
        expected_parity.nlink,
    );
    println!(
        "mounted_kernel_null,filesystem={},arm=kernel,median={:.6},ci_low={:.6},ci_high={:.6},symmetric_spread={:.6},maximum={:.6},clear={}",
        kind.label(),
        kernel_null.median,
        kernel_null.low,
        kernel_null.high,
        kernel_null.symmetric_spread(),
        config.maximum_null_ratio,
        kernel_clear,
    );
    println!(
        "mounted_kernel_null,filesystem={},arm=fuse,median={:.6},ci_low={:.6},ci_high={:.6},symmetric_spread={:.6},maximum={:.6},clear={}",
        kind.label(),
        fuse_null.median,
        fuse_null.low,
        fuse_null.high,
        fuse_null.symmetric_spread(),
        config.maximum_null_ratio,
        fuse_clear,
    );
    println!(
        "mounted_kernel_ratio,filesystem={},metric=wall_ns,workload=warm_stat,operations_per_observation={},pairs={},observation_reducer=min_of_{},fuse_over_kernel_median={:.6},ci_low={:.6},ci_high={:.6},admitted={},verdict={},gate_basis=bootstrap_median_ci,bootstrap_resamples={},cv_used=false,instructions_used=false",
        kind.label(),
        config.operations,
        config.pairs,
        config.observation_repeats,
        fuse_over_kernel.median,
        fuse_over_kernel.low,
        fuse_over_kernel.high,
        admitted,
        if admitted { "HONEST" } else { "BLOCKED_NULL" },
        BOOTSTRAP_RESAMPLES,
    );

    let raw_samples = samples
        .values
        .iter()
        .map(|(arm, values)| (arm.label().to_owned(), json!(values)))
        .collect::<serde_json::Map<_, _>>();
    let workload_digests = samples
        .digests
        .iter()
        .map(|(arm, digest)| (arm.label().to_owned(), json!(format!("{digest:016x}"))))
        .collect::<serde_json::Map<_, _>>();

    for mount in mounts.iter_mut().rev() {
        mount.unmount()?;
    }
    for image in images.values() {
        validate_image(kind, image)?;
    }

    Ok(json!({
        "filesystem": kind.label(),
        "workload": "warm_stat",
        "operations_per_observation": config.operations,
        "pairs": config.pairs,
        "observation_repeats": config.observation_repeats,
        "observation_reducer": "min",
        "identities": identities,
        "parity": {
            "verdict": "pass",
            "file_sha256": expected_parity.file_sha256,
            "len": expected_parity.len,
            "mode": expected_parity.mode,
            "uid": expected_parity.uid,
            "gid": expected_parity.gid,
            "nlink": expected_parity.nlink,
        },
        "pre_measurement_cpu_busy": contention,
        "raw_wall_ns": raw_samples,
        "workload_digests": workload_digests,
        "kernel_aa": {
            "median": kernel_null.median,
            "ci_low": kernel_null.low,
            "ci_high": kernel_null.high,
            "symmetric_spread": kernel_null.symmetric_spread(),
            "clear": kernel_clear,
        },
        "fuse_aa": {
            "median": fuse_null.median,
            "ci_low": fuse_null.low,
            "ci_high": fuse_null.high,
            "symmetric_spread": fuse_null.symmetric_spread(),
            "clear": fuse_clear,
        },
        "fuse_over_kernel": {
            "median": fuse_over_kernel.median,
            "ci_low": fuse_over_kernel.low,
            "ci_high": fuse_over_kernel.high,
        },
        "maximum_null_ratio": config.maximum_null_ratio,
        "gate_metric": "wall_ns",
        "gate_basis": "bootstrap_median_ci",
        "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
        "cv_used": false,
        "instructions_used": false,
        "admitted": admitted,
        "verdict": if admitted { "honest" } else { "blocked_null" },
        "post_unmount_validation": "clean",
    }))
}

// Top-level preflight and evidence emission intentionally remain in one
// straight-line routine so no benchmark can bypass a gate.
#[allow(clippy::too_many_lines)]
fn run() -> Result<Option<PathBuf>> {
    let Some(config) = parse_args()? else {
        return Ok(None);
    };
    let ffs_binary_identity = inspect_ffs_binary(&config.ffs_cli)?;
    let harness_sha = current_elf_sha256()?;
    println!("bench_evidence,binary_sha256={harness_sha}");
    println!(
        "candidate_identity,binary_sha256={},pgo_profile_sha256={},isa=x86-64-v3,verdict=pass",
        ffs_binary_identity.binary_sha256, ffs_binary_identity.pgo_profile_sha256
    );
    println!(
        "codegen_isa,target_arch={},compile_sse2={},compile_sse4_2={},compile_avx2={},compile_fma={},runtime_sse4_2={},runtime_avx2={},runtime_fma={}",
        env::consts::ARCH,
        cfg!(target_feature = "sse2"),
        cfg!(target_feature = "sse4.2"),
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "fma"),
        std::is_x86_feature_detected!("sse4.2"),
        std::is_x86_feature_detected!("avx2"),
        std::is_x86_feature_detected!("fma"),
    );

    let free_before = free_bytes_on_data()?;
    ensure!(
        free_before >= MIN_FREE_BYTES,
        "/data has {:.1} GiB free, below the 120 GiB abort floor",
        free_before as f64 / 1024.0_f64.powi(3)
    );
    let run_dir = create_run_dir(&config.artifact_root)?;
    let mount_run_dir = create_mount_run_dir(&run_dir)?;
    let output = config
        .output
        .clone()
        .unwrap_or_else(|| run_dir.join("mounted-kernel-report.json"));
    let fixture_root = create_fixture_tree(&run_dir)?;
    let placement = select_cpu_placement()?;
    pin_current_process(placement.driver_cpu)?;
    println!(
        "core_contention_preflight,driver_cpu={},driver_guard_cpus={},driver_busy_fraction={:.6},fuse_cpus={},fuse_guard_cpus={},fuse_busy_fractions={},same_llc=true,llc_cpus={},driver_limit={:.3},fuse_limit={:.3},verdict=clear",
        placement.driver_cpu,
        placement
            .driver_guard_cpus
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(":"),
        placement.busy_fractions[&placement.driver_cpu],
        placement
            .fuse_cpus
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(":"),
        placement
            .fuse_guard_cpus
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(":"),
        placement
            .fuse_cpus
            .iter()
            .map(|cpu| format!("{:.6}", placement.busy_fractions[cpu]))
            .collect::<Vec<_>>()
            .join(":"),
        placement
            .last_level_cache_cpus
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(":"),
        MAX_DRIVER_PREFLIGHT_BUSY,
        MAX_FUSE_PREFLIGHT_BUSY,
    );

    let interrupted = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&interrupted);
    ctrlc::set_handler(move || signal_flag.store(true, Ordering::Relaxed))
        .context("install SIGINT/SIGTERM handler")?;

    let requested = match config.filesystems {
        RequestedFilesystems::Ext4 => vec![FilesystemKind::Ext4],
        RequestedFilesystems::Btrfs => vec![FilesystemKind::Btrfs],
        RequestedFilesystems::Both => vec![FilesystemKind::Ext4, FilesystemKind::Btrfs],
    };
    let mut filesystem_reports = Vec::with_capacity(requested.len());
    let mut blocked_filesystems = Vec::new();
    for kind in requested {
        filesystem_reports.push(fs_report(
            kind,
            &config,
            &ffs_binary_identity,
            &run_dir,
            &mount_run_dir,
            &fixture_root,
            &placement,
            &interrupted,
        )?);
        let report = filesystem_reports
            .last()
            .expect("just pushed filesystem report");
        if report["admitted"].as_bool() != Some(true) {
            blocked_filesystems.push(kind.label());
        }
    }

    let free_after = free_bytes_on_data()?;
    let report = json!({
        "schema_version": 1,
        "harness": "ffs-mounted-kernel-bench",
        "harness_binary_sha256": harness_sha,
        "ffs_cli": fs::canonicalize(&config.ffs_cli)?,
        "ffs_binary_sha256": ffs_binary_identity.binary_sha256,
        "ffs_pgo_profile_sha256": ffs_binary_identity.pgo_profile_sha256,
        "kernel_release": fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
        "artifact_root": run_dir,
        "mount_root": mount_run_dir,
        "disk_free_before_bytes": free_before,
        "disk_free_after_bytes": free_after,
        "driver_cpu": placement.driver_cpu,
        "fuse_cpus": placement.fuse_cpus,
        "driver_guard_cpus": placement.driver_guard_cpus,
        "fuse_guard_cpus": placement.fuse_guard_cpus,
        "last_level_cache_cpus": placement.last_level_cache_cpus,
        "initial_cpu_busy_fractions": placement.busy_fractions,
        "mount_contract": {
            "kernel": "real kernel filesystem on read-only loop device",
            "candidate": "FrankenFS FUSE",
            "common": ["ro", "noatime", "nodev", "nosuid"],
            "ext4_kernel_only": ["noload"],
            "fuse_only": ["no_background_scrub", "writeback_cache_disabled"],
            "durability": "read_only_no_mutation",
        },
        "schedule": "balanced four-arm interleave with independent kernel and FUSE A/A",
        "filesystems": filesystem_reports,
    });
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create report parent {}", parent.display()))?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write report {}", output.display()))?;
    println!(
        "mounted_kernel_report,path={},disk_free_before_bytes={},disk_free_after_bytes={}",
        output.display(),
        free_before,
        free_after
    );
    ensure!(
        blocked_filesystems.is_empty(),
        "A/A null gate blocked filesystem(s) {}; report preserved at {}",
        blocked_filesystems.join(","),
        output.display()
    );
    Ok(Some(output))
}

fn main() -> ExitCode {
    match run() {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mounted_kernel_gate,error={error:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_orders_put_every_arm_in_every_position() {
        for arm in [Arm::KernelA, Arm::KernelB, Arm::FuseA, Arm::FuseB] {
            let positions: BTreeSet<usize> = BALANCED_ORDERS
                .iter()
                .flat_map(|order| {
                    order
                        .iter()
                        .enumerate()
                        .filter_map(move |(index, candidate)| (*candidate == arm).then_some(index))
                })
                .collect();
            assert_eq!(positions, BTreeSet::from([0, 1, 2, 3]));
        }
    }

    #[test]
    fn mountinfo_parser_preserves_runtime_identity() {
        let row = "42 31 7:3 / /data/tmp/run/mnt ro,nosuid,nodev,noatime shared:1 - ext4 /dev/loop3 ro,noload";
        let parsed = parse_mountinfo_line(row).expect("parse mountinfo");
        assert_eq!(parsed.major_minor, "7:3");
        assert_eq!(parsed.mountpoint, Path::new("/data/tmp/run/mnt"));
        assert_eq!(parsed.filesystem_type, "ext4");
        assert_eq!(parsed.source, "/dev/loop3");
        assert!(parsed.mount_options.contains("ro"));
        assert!(parsed.mount_options.contains("noatime"));
        assert!(parsed.super_options.contains("noload"));
    }

    #[test]
    fn mountinfo_unescapes_paths() {
        assert_eq!(
            mountinfo_unescape("/data/tmp/with\\040space"),
            "/data/tmp/with space"
        );
    }

    #[test]
    fn cpu_list_parser_handles_ranges() {
        assert_eq!(
            parse_cpu_list("0-2,8,10-11").expect("parse CPU list"),
            BTreeSet::from([0, 1, 2, 8, 10, 11])
        );
    }

    #[test]
    fn bootstrap_null_is_exact_for_identical_pairs() {
        let ratios = vec![0.0; 31];
        let ci = bootstrap_median_ci(&ratios, 7);
        assert_eq!(ci.median, 1.0);
        assert_eq!(ci.low, 1.0);
        assert_eq!(ci.high, 1.0);
        assert!(ci.contains_null());
        assert_eq!(ci.symmetric_spread(), 1.0);
    }

    #[test]
    fn narrow_but_biased_null_is_not_clear() {
        let ci = BootstrapMedianCi {
            median: 1.02,
            low: 1.01,
            high: 1.03,
        };
        assert!(!ci.contains_null());
    }

    #[test]
    fn competitive_ratio_uses_both_aa_arms() {
        let samples = TimedSamples {
            values: BTreeMap::from([
                (Arm::KernelA, vec![10, 10]),
                (Arm::KernelB, vec![10, 10]),
                (Arm::FuseA, vec![40, 40]),
                (Arm::FuseB, vec![40, 40]),
            ]),
            digests: BTreeMap::new(),
        };
        let ratios = competitive_log_ratios(&samples).expect("competitive ratios");
        assert!(ratios.iter().all(|ratio| (ratio.exp() - 4.0).abs() < 1e-12));
    }
}
