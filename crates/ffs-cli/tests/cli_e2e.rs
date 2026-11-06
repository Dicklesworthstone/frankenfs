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

fn run_native_companion_read_profile(profile: &str, binary: &str) {
    let root = tempfile::Builder::new()
        .prefix("ffs-companion-profile-")
        .tempdir()
        .unwrap()
        .keep();
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts")
        .join(profile);
    let mut command = Command::new("python3");
    command.arg(&script).arg("--binary").arg(binary);
    // Keep an isolated, provenance-checked mtools install local to this child.
    // The unchanged profile still requires and executes all its native tools.
    if let Some(bin) = std::env::var_os("FFS_NATIVE_ORACLE_BIN") {
        let mut paths = vec![PathBuf::from(bin)];
        if let Some(path) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&path));
        }
        command.env("PATH", std::env::join_paths(paths).unwrap());
    }
    fs::write(
        root.join("invocation.txt"),
        format!("script={}\nbinary={binary:?}\n", script.display()),
    )
    .unwrap();
    println!("retained companion profile output: {}", root.display());
    let output = command.output().expect("execute the native Python profile");
    fs::write(root.join("stdout"), &output.stdout).unwrap();
    fs::write(root.join("stderr"), &output.stderr).unwrap();
    fs::write(root.join("status"), output.status.to_string()).unwrap();
    println!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(
        output.status.success(),
        "native companion profile {profile} failed; see {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires dosfstools and mtools; retains native images and command evidence"]
fn native_companion_read_profile_fat() {
    run_native_companion_read_profile("verify_fat_read.py", env!("CARGO_BIN_EXE_ffs-fat"));
}

#[test]
#[ignore = "requires ntfs-3g tools; retains native images and command evidence"]
fn native_companion_read_profile_ntfs() {
    run_native_companion_read_profile("verify_ntfs_read.py", env!("CARGO_BIN_EXE_ffs-ntfs"));
}

#[test]
fn parity_default_reports_declarations_without_execution_credit() {
    let output = run_ffs_cli(&["parity", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["declared_contracts"]["overall_total"], 97);
    assert_eq!(report["evidence_backed_rows"], 0);
    assert_eq!(report["readiness_verified"], false);
    assert_eq!(report["runs"], serde_json::json!([]));
    assert_eq!(
        report["missing_evidence_rows"].as_array().unwrap().len() as u64,
        report["total_rows"].as_u64().unwrap()
    );

    for suite in ["ext4", "ext4-journal-extra", "../ext4-journal"] {
        let rejected = run_ffs_cli(&["parity", "--json", "--verify", suite]);
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("unknown parity suite"));
    }
}

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
    Command::new(env!("CARGO_BIN_EXE_ffs-cli"))
        .args(args)
        .output()
        .expect("failed to execute ffs-cli")
}

/// Native observation and its policy unit controls share this implementation.
/// The self-test exits before creating any filesystem or process resources.
const LIVE_TUI_PROFILE: &str = r"
import errno, hashlib, json, math, os, pathlib, pty, re, signal, subprocess, sys, time

def latest_scanned(data):
    values = re.findall(rb'Scanned:\s+([0-9]+)', data)
    assert values, 'scrub telemetry missing'
    return int(values[-1])

def classify_cpu(mode, cpu, start_scanned, end_scanned):
    assert math.isfinite(cpu) and cpu >= 0, 'CPU measurement invalid'
    assert start_scanned is not None and end_scanned is not None, 'scrub count missing'
    assert 0 <= start_scanned <= end_scanned, 'scrub count decreased'
    delta = end_scanned - start_scanned
    if mode == 'scrub':
        assert delta > 0, 'scrub made no progress during CPU measurement'
        return None, cpu, delta
    assert start_scanned == end_scanned == 0, 'idle window contained scrub work'
    assert cpu < 0.01, ('idle CPU target exceeded', cpu)
    return cpu, None, delta

def metrics_advanced(prior, current, require_payload):
    return current[1] > prior[1] and (not require_payload or current[2] > prior[2])

def mount_present(path, records=None):
    if records is None:
        records = pathlib.Path('/proc/thread-self/mountinfo').read_bytes()
    assert records.strip(b'\n'), 'mount table is empty'
    escapes = {9: b'\\011', 10: b'\\012', 32: b'\\040', 92: b'\\134'}
    encoded = b''.join(escapes.get(byte, bytes([byte])) for byte in os.fsencode(path))
    occupied = False
    for line in records.split(b'\n'):
        if not line:
            continue
        fields = line.split(b' ')
        assert len(fields) >= 10 and fields[3] and fields[4].startswith(b'/'), 'invalid mount record'
        assert b'-' in fields[6:] and fields[6:].index(b'-') + 10 == len(fields), 'invalid mount fields'
        occupied |= fields[4] == encoded
    return occupied

if sys.argv[1:] == ['--self-test']:
    cases = 0
    assert latest_scanned(b'Scanned: 7780\nScanned: 15560\n') == 15560
    cases += 1
    assert classify_cpu('captured', 0.005, 0, 0) == (0.005, None, 0)
    cases += 1
    assert classify_cpu('scrub', 0.06, 7780, 15560) == (None, 0.06, 7780)
    cases += 1
    for data in [b'', b'Scanned: unavailable']:
        try:
            latest_scanned(data)
        except AssertionError:
            cases += 1
        else:
            raise AssertionError('missing scrub telemetry admitted')
    for arguments in [
        ('captured', 0.01, 0, 0), ('captured', 0.02, 0, 0),
        ('captured', -0.001, 0, 0), ('captured', float('nan'), 0, 0),
        ('captured', float('inf'), 0, 0), ('captured', 0.005, None, 0),
        ('scrub', 0.06, 0, None), ('scrub', 0.06, 10, 10),
        ('scrub', 0.06, 20, 10), ('captured', 0.005, 10, 10),
        ('captured', 0.005, 0, 10), ('scrub', 0.06, -1, 1),
    ]:
        try:
            classify_cpu(*arguments)
        except AssertionError:
            cases += 1
        else:
            raise AssertionError(('invalid CPU observation admitted', arguments))
    for current, required, expected in [
        ((2000, 1, 0), True, False), ((2000, 2, 0), True, False),
        ((2000, 1, 65536), True, False), ((2000, 2, 65536), True, True),
        ((2000, 2, 0), False, True), ((2000, 1, 65536), False, False),
    ]:
        assert metrics_advanced((1000, 1, 0), current, required) == expected
        cases += 1
    records = (b'711 634 0:72 / /tmp/live ro - fuse.ffs frankenfs ro\n'
               b'712 634 0:73 / /tmp/live-child rw - tmpfs replacement rw\n'
               b'713 634 0:74 / /tmp/with\\040space\\011tab\\012line\\134040 rw - tmpfs replacement rw\n'
               b'714 634 0:75 / /tmp/vertical\x0bform\x0c\xff rw - tmpfs replacement rw\n'
               b'636 632 0:5 net:[4026533814] /run/docker/netns/17ccb5a24dfd rw - nsfs nsfs rw\n')
    for path, expected in [
        (b'/tmp/live', True), (b'/tmp/live-child', True),
        (b'/tmp/with space\ttab\nline\\040', True),
        (b'/tmp/vertical\x0bform\x0c\xff', True),
        (b'/run/docker/netns/17ccb5a24dfd', True),
        (b'/tmp/liv', False), (b'/tmp/live/', False), (b'/tmp', False),
    ]:
        assert mount_present(path, records) == expected
        cases += 1
    for invalid in [b'', b'\n', b'broken record\n', b'711 634 0:72 / /tmp/live ro - fuse.ffs\n',
                    b'711 634 0:72  /tmp/live ro - fuse.ffs frankenfs ro\n']:
        try:
            mount_present(b'/tmp/live', invalid)
        except AssertionError:
            cases += 1
        else:
            raise AssertionError('invalid mount table admitted')
    assert cases == 36
    print(json.dumps(dict(evidence_class='policy_unit', cases=cases)))
    sys.exit(0)

binary, image, root, mode, require_payload = sys.argv[1:]
require_payload = require_payload == 'true'
root = pathlib.Path(root).resolve(strict=True)
mount = root / ('live-' + mode)
mount.mkdir()
def digest():
    h = hashlib.sha256()
    with open(image, 'rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()
before_hash = digest()
stderr_path = root / (mode + '-stderr.log')
output = bytearray()
master = None
with open(stderr_path, 'wb') as errors:
    if mode == 'terminal':
        master, slave = pty.openpty()
        destination = slave
    else:
        destination = subprocess.PIPE
    arguments = [binary, 'tui', image, '--mountpoint', str(mount)]
    if mode == 'scrub':
        arguments.append('--scrub')
    if mode == 'fast':
        arguments.extend(['--refresh-ms', '250'])
    if mode == 'per-core':
        arguments = [binary, 'mount', image, str(mount), '--runtime-mode=per-core',
                     '--console-live', '--no-background-scrub']
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL, stdout=destination, stderr=errors,
        env=dict(os.environ, RUST_LOG='error,ffs_fuse=info'))
    if master is not None:
        os.close(slave)
        reader = master
    else:
        reader = process.stdout.fileno()
    os.set_blocking(reader, False)
    def collect():
        while reader is not None:
            try:
                block = os.read(reader, 65536)
                if not block:
                    break
                output.extend(block)
            except BlockingIOError:
                break
            except OSError as error:
                if master is not None and error.errno == errno.EIO:
                    break
                raise
    def samples():
        return [tuple(map(int, match)) for match in re.findall(
            rb'Sample: ([0-9]+) ms \| Requests: ([0-9]+) \| Read: ([0-9]+) bytes', output)]
    def until(predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while True:
            collect()
            if predicate():
                return
            if process.poll() is not None:
                raise AssertionError('TUI exited before completing live observations: ' + stderr_path.read_text())
            if time.monotonic() >= deadline:
                raise AssertionError('live TUI timed out: ' + stderr_path.read_text())
            time.sleep(0.01)
    def ticks():
        fields = pathlib.Path('/proc/' + str(process.pid) + '/stat').read_text().rsplit(') ', 1)[1].split()
        return int(fields[11]) + int(fields[12])
    idle_cpu = active_cpu = scanned_delta = None
    try:
        until(lambda: len(samples()) >= 2 and mount_present(mount))
        assert image.encode() in output, 'source identity missing'
        assert str(mount).encode() in output, 'mount identity missing'
        assert b'=== FrankenFS Live Telemetry ===' in output
        if mode == 'broken':
            process.stdout.close()
            reader = None
            result = process.wait(timeout=10)
            assert result != 0, 'closed reader was silently acknowledged'
            assert 'Broken pipe' in stderr_path.read_text(), stderr_path.read_text()
        else:
            start_scanned = latest_scanned(output)
            start_ticks = ticks()
            start_time = time.monotonic()
            count = len(samples())
            until(lambda: len(samples()) >= count + (20 if mode == 'fast' else 5))
            measured_cpu = (ticks() - start_ticks) / os.sysconf('SC_CLK_TCK') / (time.monotonic() - start_time)
            idle_cpu, active_cpu, scanned_delta = classify_cpu(
                mode, measured_cpu, start_scanned, latest_scanned(output))
            prior = samples()[-1]
            # These are actual filesystem calls through the mount. statvfs is
            # dispatched even when the kernel has cached directory attributes.
            for _ in range(4):
                os.statvfs(mount)
                list(mount.iterdir())
            payload = mount / 'payload.bin'
            if require_payload:
                assert payload.exists(), 'native payload missing from mounted namespace'
                assert payload.read_bytes() == bytes([0x5a]) * 65536
            try:
                fd = os.open(mount / 'must-stay-readonly', os.O_WRONLY | os.O_CREAT, 0o600)
            except OSError as error:
                assert error.errno == errno.EROFS, error
            else:
                os.close(fd)
                raise AssertionError('standalone TUI admitted a source mutation')
            until(lambda: metrics_advanced(prior, samples()[-1], require_payload))
            if require_payload:
                assert samples()[-1][2] > prior[2], 'real reads did not reach telemetry'
            if mode == 'scrub':
                scanned = re.findall(rb'Scanned:\s+([0-9]+)', output)
                assert scanned and max(map(int, scanned)) > 0, 'background scrub did not reach telemetry'
            if mode == 'external':
                unmount = subprocess.run(['fusermount3', '-u', str(mount)], capture_output=True, timeout=10)
                assert unmount.returncode == 0, unmount.stderr.decode()
            else:
                process.send_signal(signal.SIGINT)
            result = process.wait(timeout=10)
            collect()
            assert result == 0, stderr_path.read_text()
            elapsed = [sample[0] for sample in samples()]
            gaps = [later - earlier for earlier, later in zip(elapsed, elapsed[1:])]
            requested_ms = 250 if mode == 'fast' else 1000
            assert gaps and min(gaps) >= requested_ms - 1, gaps
            assert max(gaps) <= requested_ms + 100, ('refresh exceeded 100ms scheduling budget', gaps)
            if mode == 'fast':
                assert max(gaps) < 1000, ('live updates fell below 1Hz', gaps)
        assert not mount_present(mount), 'TUI left its mount active'
        assert 'unmount complete' in stderr_path.read_text(), 'dispatch join receipt missing'
        assert digest() == before_hash, 'read-only source bytes changed'
        assert (b'\x1b[H\x1b[2J' in output) == (mode == 'terminal')
        print(json.dumps(dict(
            mode=mode, argv=arguments, pid=process.pid, exit=result, samples=samples(),
            idle_cpu_fraction=idle_cpu, image_sha256=before_hash,
            active_cpu_fraction=active_cpu, scrub_blocks_scanned_delta=scanned_delta,
            executable_sha256=hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),
            image_unchanged=True, mount_active=False)))
    finally:
        try:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            if mount_present(mount):
                cleanup = subprocess.run(['fusermount3', '-u', str(mount)], capture_output=True, timeout=10)
                if cleanup.returncode:
                    print(cleanup.stderr.decode(), file=sys.stderr)
        finally:
            try:
                collect()
            finally:
                try:
                    (root / (mode + '-stdout.log')).write_bytes(output)
                finally:
                    if master is not None:
                        os.close(master)
";

/// Exercise one actual TUI process and its mounted filesystem. Python's stdlib
/// supplies the PTY and nonblocking output collection; no metrics are injected.
fn run_live_tui_profile(image: &Path, mode: &str, require_payload: bool) -> String {
    let root = image.parent().unwrap();
    let output = Command::new("python3")
        .args(["-c", LIVE_TUI_PROFILE, env!("CARGO_BIN_EXE_ffs-cli")])
        .arg(image)
        .arg(root)
        .arg(mode)
        .arg(require_payload.to_string())
        .output()
        .expect("execute actual live TUI profile");
    fs::write(root.join(format!("{mode}-profile.stdout")), &output.stdout).unwrap();
    fs::write(root.join(format!("{mode}-profile.stderr")), &output.stderr).unwrap();
    println!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(
        output.status.success(),
        "live TUI {mode} failed; retained {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn cli_live_tui_policy_rejects_unproven_observations() {
    let output = Command::new("python3")
        .args(["-c", LIVE_TUI_PROFILE, "--self-test"])
        .output()
        .expect("execute live observation policy unit controls");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report,
        serde_json::json!({"evidence_class": "policy_unit", "cases": 36})
    );
}

#[test]
fn cli_live_tui_one_process_observes_real_mounts_and_cleans_up() {
    let require = std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|value| value == "1");
    let available = Path::new("/dev/fuse").exists()
        && [
            "mkfs.ext4",
            "mkfs.btrfs",
            "debugfs",
            "e2fsck",
            "btrfs",
            "fusermount3",
            "python3",
        ]
        .iter()
        .all(|tool| command_available(tool));
    if !available {
        assert!(
            !require,
            "required live TUI/native prerequisites are missing"
        );
        emit_scenario_result(
            "cli_live_tui",
            "SKIP",
            Some("fuse_or_native_tools_unavailable"),
        );
        return;
    }
    let ext4_root = tempfile::Builder::new()
        .prefix("ffs-live-tui-ext4-")
        .tempdir()
        .unwrap()
        .keep();
    let ext4 = ext4_root.join("native.ext4");
    fs::File::create(&ext4)
        .unwrap()
        .set_len(32 * 1024 * 1024)
        .unwrap();
    let format = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-b", "4096"])
        .arg(&ext4)
        .output()
        .unwrap();
    println!("native ext4 producer: {format:?}");
    assert!(format.status.success(), "{format:?}");
    let payload = ext4_root.join("payload");
    fs::write(&payload, vec![0x5a; 65536]).unwrap();
    let populate = Command::new("debugfs")
        .args(["-w", "-R"])
        .arg(format!("write \"{}\" /payload.bin", payload.display()))
        .arg(&ext4)
        .output()
        .unwrap();
    assert!(populate.status.success(), "{populate:?}");
    println!("native ext4 population: {populate:?}");
    let check = Command::new("e2fsck")
        .arg("-fn")
        .arg(&ext4)
        .output()
        .unwrap();
    assert!(check.status.success(), "{check:?}");
    println!("native ext4 check: {check:?}");
    for mode in [
        "captured", "terminal", "external", "broken", "scrub", "per-core", "fast",
    ] {
        run_live_tui_profile(&ext4, mode, true);
    }
    let btrfs_root = tempfile::Builder::new()
        .prefix("ffs-live-tui-btrfs-")
        .tempdir()
        .unwrap()
        .keep();
    let btrfs = btrfs_root.join("native.btrfs");
    fs::File::create(&btrfs)
        .unwrap()
        .set_len(128 * 1024 * 1024)
        .unwrap();
    let source = btrfs_root.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("payload.bin"), vec![0x5a; 65536]).unwrap();
    let format = Command::new("mkfs.btrfs")
        .args(["-f", "-q", "--rootdir"])
        .arg(&source)
        .arg(&btrfs)
        .output()
        .unwrap();
    println!("native btrfs producer: {format:?}");
    assert!(format.status.success(), "{format:?}");
    let check = Command::new("btrfs")
        .args(["check", "--readonly"])
        .arg(&btrfs)
        .output()
        .unwrap();
    assert!(check.status.success(), "{check:?}");
    println!("native btrfs check: {check:?}");
    run_live_tui_profile(&btrfs, "captured", true);
    emit_scenario_result("cli_live_tui", "PASS", None);
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

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("format SHA-256");
    }
    encoded
}

fn run_cli_binary(binary: &Path, args: &[&str]) -> Output {
    Command::new(binary) // ubs:ignore[rust.security.command-executable] Ignored bd-b9dug benchmarks intentionally execute a trusted operator-selected baseline or Cargo-built candidate.
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
    if values.len().is_multiple_of(2) {
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

#[derive(Clone, Copy)]
struct ReadObservation {
    wall_us: f64,
    bytes: u64,
}

fn read_observation(
    binary: &Path,
    image: &Path,
    file_path: &str,
    expected_evidence: &CliEvidence,
) -> ReadObservation {
    let image = image.to_str().expect("read image path is UTF-8");
    let output = run_cli_binary(
        binary,
        &["read", image, file_path, "--discard", "--bench-evidence"],
    );
    assert!(
        output.status.success(),
        "read observation failed: binary={} status={:?}\nstdout:\n{}\nstderr:\n{}",
        binary.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("read observation stdout is UTF-8");
    let mut lines = stdout.lines().filter(|line| !line.trim().is_empty());
    assert_eq!(
        lines
            .next()
            .and_then(|line| line.strip_prefix("bench_evidence,binary_sha256=")),
        Some(expected_evidence.binary_sha256.as_str()),
        "timed read child executed an unexpected ELF"
    );
    assert_eq!(
        lines.next(),
        Some(expected_evidence.codegen_line.as_str()),
        "timed read child changed its compile/runtime ISA witness"
    );
    assert_eq!(
        lines
            .next()
            .and_then(|line| line.strip_prefix("build_profile,pgo_profile_sha256=")),
        Some(expected_evidence.pgo_profile_sha256.as_str()),
        "timed read child changed its consumed-profile identity"
    );
    let result = lines
        .next()
        .expect("timed read child emitted its observation");
    assert!(
        result.starts_with("bd_b9dug_read_observation,"),
        "unexpected timed read result: {result}"
    );
    assert!(
        lines.next().is_none(),
        "timed read child emitted unexpected stdout after its result"
    );
    let wall_us = csv_value(result, "duration_us=")
        .parse::<f64>()
        .expect("read duration is numeric");
    let bytes = csv_value(result, "bytes=")
        .parse::<u64>()
        .expect("read byte count is numeric");
    assert!(wall_us > 0.0, "read duration must be positive");
    ReadObservation { wall_us, bytes }
}

fn read_payload_signature(binary: &Path, image: &Path, file_path: &str) -> (usize, String) {
    let image = image.to_str().expect("read image path is UTF-8");
    let output = run_cli_binary(binary, &["read", image, file_path]);
    assert!(
        output.status.success(),
        "read parity run failed: binary={} status={:?}\nstderr:\n{}",
        binary.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    (output.stdout.len(), sha256_bytes(&output.stdout))
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

struct ReadSamples {
    anchor_us: Vec<f64>,
    repeat_us: Vec<f64>,
    candidate_us: Vec<f64>,
    raw_pairs: String,
}

fn collect_read_samples(
    generic: (&Path, &CliEvidence),
    pgo: (&Path, &CliEvidence),
    image: &Path,
    file_path: &str,
    expected_bytes: u64,
    pairs: usize,
) -> ReadSamples {
    let mut anchor_us = Vec::with_capacity(pairs);
    let mut repeat_us = Vec::with_capacity(pairs);
    let mut candidate_us = Vec::with_capacity(pairs);
    let mut raw_pairs = String::with_capacity(pairs.saturating_mul(64));
    for pair in 0..pairs {
        let observe_generic = || read_observation(generic.0, image, file_path, generic.1);
        let observe_pgo = || read_observation(pgo.0, image, file_path, pgo.1);
        let (anchor, repeat, candidate, order) = if pair % 2 == 0 {
            (observe_generic(), observe_generic(), observe_pgo(), "AAB")
        } else {
            let candidate = observe_pgo();
            let repeat = observe_generic();
            let anchor = observe_generic();
            (anchor, repeat, candidate, "BAA")
        };
        assert_eq!(
            anchor.bytes, expected_bytes,
            "generic anchor read was short"
        );
        assert_eq!(
            repeat.bytes, expected_bytes,
            "generic repeat read was short"
        );
        assert_eq!(
            candidate.bytes, expected_bytes,
            "v3+PGO candidate read was short"
        );
        anchor_us.push(anchor.wall_us);
        repeat_us.push(repeat.wall_us);
        candidate_us.push(candidate.wall_us);
        if pair > 0 {
            raw_pairs.push(';');
        }
        write!(
            &mut raw_pairs,
            "{order}:{:.3}:{:.3}:{:.3}",
            anchor.wall_us, repeat.wall_us, candidate.wall_us
        )
        .expect("format whole-binary read pair");
    }
    ReadSamples {
        anchor_us,
        repeat_us,
        candidate_us,
        raw_pairs,
    }
}

#[allow(clippy::too_many_arguments)]
fn report_read_gate(
    identity: &LookupIdentity<'_>,
    file_path: &str,
    input_image_sha256: &str,
    payload_bytes: usize,
    payload_sha256: &str,
    samples: ReadSamples,
    pairs: usize,
) {
    let (null, pgo_ratio, null_floor_ratio, twice_null_ratio) = paired_ratio_summaries(
        &samples.anchor_us,
        &samples.repeat_us,
        &samples.candidate_us,
    );
    let verdict = if null_floor_ratio >= 1.10 {
        "BLOCKED_NULL_FLOOR"
    } else if pgo_ratio.low > twice_null_ratio {
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
        "bd_b9dug_read_identity,generic_binary_sha256={},pgo_binary_sha256={},\
pgo_profile_sha256={},input_image={},input_image_sha256={input_image_sha256},\
file={file_path},payload_bytes={payload_bytes},payload_sha256={payload_sha256}",
        identity.generic.binary_sha256,
        identity.pgo.binary_sha256,
        identity.profile_sha256,
        identity.image.display()
    );
    println!(
        "bd_b9dug_read_pairs,pairs={pairs},format=order:generic_anchor_us:\
generic_repeat_us:pgo_us,values={}",
        samples.raw_pairs
    );
    println!(
        "bd_b9dug_whole_binary_read,generic_median_us={:.3},pgo_median_us={:.3},\
generic_aa_median={:.6},generic_aa_ci_low={:.6},generic_aa_ci_high={:.6},\
null_floor_ratio={null_floor_ratio:.6},twice_null_ratio={twice_null_ratio:.6},\
generic_over_pgo_median={:.6},generic_over_pgo_ci_low={:.6},\
generic_over_pgo_ci_high={:.6},verdict={verdict},same_invocation=true,\
binary_hash_in_every_timed_child=true,gate_metric=read_wall_us,\
gate_basis=bootstrap_median_ci,bootstrap_resamples=20000,cv_used=false,\
instructions_used=false",
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

    if let Some(read_image) = std::env::var_os("FFS_B9DUG_READ_IMAGE").map(PathBuf::from) {
        const READ_BLOCKS: usize = 8_192;
        const BLOCK_SIZE: usize = 4_096;
        const READ_FILE: &str = "/bd-b9dug-read.bin";

        assert!(
            !read_image.exists(),
            "refusing to overwrite read fixture {}",
            read_image.display()
        );
        fs::create_dir_all(read_image.parent().expect("read image has parent"))
            .expect("create read fixture directory");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/golden/ext4_dir_index_reference.ext4");
        fs::copy(&fixture, &read_image).unwrap_or_else(|error| {
            panic!(
                "copy read fixture {} -> {}: {error}",
                fixture.display(),
                read_image.display()
            )
        });
        let image = read_image.to_str().expect("read fixture path is UTF-8");
        run_cli_binary_checked(
            "prepare-read-fixture",
            source,
            &[
                "write-bench",
                image,
                READ_FILE,
                "--count",
                &READ_BLOCKS.to_string(),
                "--size",
                &BLOCK_SIZE.to_string(),
                "--create",
            ],
        );
        let (bytes, payload_sha256) = read_payload_signature(source, &read_image, READ_FILE);
        assert_eq!(
            bytes,
            READ_BLOCKS * BLOCK_SIZE,
            "prepared read fixture has the wrong file size"
        );
        println!(
            "bd_b9dug_read_fixture,path={},image_sha256={},file={READ_FILE},\
bytes={bytes},payload_sha256={payload_sha256}",
            read_image.display(),
            sha256_file(&read_image)
        );
    }
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

/// Production-shaped generic/PGO warm sequential-read decision. Every timed
/// child self-reports the ELF/ISA/profile it actually executes before measuring
/// one complete open/resolve/read, while this parent owns A/A and A/B ordering.
#[test]
#[ignore = "strict-remote bd-b9dug driver"]
fn bd_b9dug_whole_binary_read_gate() {
    const PAIRS: usize = 31;
    const READ_FILE: &str = "/bd-b9dug-read.bin";

    let generic = required_env_path("FFS_B9DUG_GENERIC_CLI");
    let pgo = Path::new(env!("CARGO_BIN_EXE_ffs-cli"));
    let image = required_env_path("FFS_B9DUG_READ_IMAGE");
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
    assert_create_gate_identity(&generic_evidence, &pgo_evidence, &expected_profile);
    let input_image_sha256 = sha256_file(&image);

    let (generic_bytes, generic_payload_sha256) =
        read_payload_signature(&generic, &image, READ_FILE);
    let (pgo_bytes, pgo_payload_sha256) = read_payload_signature(pgo, &image, READ_FILE);
    assert_eq!(
        generic_bytes, pgo_bytes,
        "generic and v3+PGO reads returned different byte counts"
    );
    assert_eq!(
        generic_payload_sha256, pgo_payload_sha256,
        "generic and v3+PGO reads returned different bytes"
    );
    let expected_bytes = u64::try_from(generic_bytes).expect("read payload length fits u64");

    for _ in 0..2 {
        let generic_warmup = read_observation(&generic, &image, READ_FILE, &generic_evidence);
        let pgo_warmup = read_observation(pgo, &image, READ_FILE, &pgo_evidence);
        assert_eq!(generic_warmup.bytes, expected_bytes);
        assert_eq!(pgo_warmup.bytes, expected_bytes);
    }
    let samples = collect_read_samples(
        (&generic, &generic_evidence),
        (pgo, &pgo_evidence),
        &image,
        READ_FILE,
        expected_bytes,
        PAIRS,
    );
    assert_eq!(
        sha256_file(&image),
        input_image_sha256,
        "read gate mutated its immutable input image"
    );
    report_read_gate(
        &LookupIdentity {
            generic: &generic_evidence,
            pgo: &pgo_evidence,
            profile_sha256: &expected_profile,
            image: &image,
        },
        READ_FILE,
        &input_image_sha256,
        generic_bytes,
        &generic_payload_sha256,
        samples,
        PAIRS,
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

/// `stat-bench` must divide by the getattrs it ACTUALLY issued, and adding
/// workers must not change how many that is (bd-3zx2x).
///
/// This is the assertion that makes the instrument trustworthy rather than
/// merely plausible. The two ways a threaded split goes wrong both produce a
/// believable-looking per-entry number and neither shows up in a wall-clock
/// check: give every worker the whole list and the bench does `threads x` the
/// work while reporting the same entry count (per-entry cost inflates), or
/// spawn workers over a stale chunk list and some entries are never stat'ed
/// (per-entry cost deflates). Requiring `stats_performed == entries * iters` at
/// BOTH thread counts catches duplication and truncation in the same assertion,
/// and requiring the same `entries` at both catches a split that changes the
/// measured set.
#[test]
fn cli_stat_bench_counts_the_getattrs_it_issues_at_every_thread_count() {
    const ITERS: u64 = 3;

    if !cli_prerequisites_available() {
        eprintln!("SKIP: mkfs.ext4 or debugfs not available");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let image = create_minimal_ext4_image(tmpdir.path(), 4);
    let image_arg = image.to_str().expect("image path is UTF-8");

    let observe = |threads: &str| -> (u64, u64) {
        let output = run_ffs_cli(&[
            "stat-bench",
            image_arg,
            "--dir",
            "/",
            "--iters",
            "3",
            "--warmup",
            "1",
            "--threads",
            threads,
            "--json",
        ]);
        assert!(
            output.status.success(),
            "stat-bench --threads {threads} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("stat-bench stdout is UTF-8");
        let line = stdout
            .lines()
            .find(|line| line.contains("\"stat_bench\""))
            .unwrap_or_else(|| panic!("stat-bench JSON line missing from:\n{stdout}"));
        let field = |key: &str| -> u64 {
            let needle = format!("\"{key}\":");
            let rest = line
                .split_once(needle.as_str())
                .unwrap_or_else(|| panic!("stat-bench JSON has no {key}: {line}"))
                .1;
            rest.split(|c: char| !c.is_ascii_digit())
                .find(|part| !part.is_empty())
                .unwrap_or_else(|| panic!("stat-bench {key} is not numeric: {line}"))
                .parse()
                .unwrap_or_else(|_| panic!("stat-bench {key} does not parse: {line}"))
        };
        (field("entries"), field("stats_performed"))
    };

    let (serial_entries, serial_stats) = observe("1");
    let (threaded_entries, threaded_stats) = observe("4");

    assert!(
        serial_entries > 0,
        "the fixture root must contain at least one stat-able entry"
    );
    assert_eq!(
        serial_entries, threaded_entries,
        "adding workers changed the measured entry set"
    );
    assert_eq!(
        serial_stats,
        serial_entries * ITERS,
        "serial stat-bench must issue exactly entries x iters getattrs"
    );
    assert_eq!(
        threaded_stats,
        threaded_entries * ITERS,
        "threaded stat-bench must issue exactly entries x iters getattrs — a chunk \
         handed to every worker inflates this, a dropped chunk deflates it, and both \
         silently rescale the reported per-entry cost"
    );
    emit_scenario_result(
        "cli_stat_bench_counts_the_getattrs_it_issues_at_every_thread_count",
        "PASS",
        None,
    );
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

/// Per-core mode must reach the real CPU-keyed FUSE transport rather than
/// retaining the former command-boundary rejection. A missing image therefore
/// fails during image open, just like the other mount modes.
///
/// This is intentionally a binary-level regression: it proves Clap parsing and
/// the public `ffs mount` surface admit the real routing path (bd-28mw2).
#[test]
fn cli_mount_per_core_reaches_image_open_before_mounting() {
    let tmpdir = tempfile::tempdir().expect("create temp dir");
    let missing_image = tmpdir.path().join("no_such.img");
    let mountpoint = tmpdir.path().join("mnt");
    fs::create_dir(&mountpoint).expect("create mountpoint dir");

    let output = run_ffs_cli(&[
        "mount",
        "--runtime-mode",
        "per-core",
        missing_image.to_str().expect("temp path is UTF-8"),
        mountpoint.to_str().expect("temp path is UTF-8"),
    ]);

    assert!(
        !output.status.success(),
        "a missing image must prevent a per-core mount from succeeding"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to open filesystem image"),
        "per-core mode must reach image open, got: {stderr}"
    );
    assert!(
        !stderr.contains("per-core runtime is unavailable"),
        "the stale inert-dispatcher rejection must stay gone, got: {stderr}"
    );
    emit_scenario_result("cli_mount_per_core_reaches_image_open", "PASS", None);
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

/// bd-dj725: the periodic commit is the only thing between an un-fsynced
/// write and its loss on a crash. Mount the real binary read-write, write
/// without fsync, wait past the commit interval, SIGKILL the daemon, then replay
/// the journal exactly as a kernel mount would (`e2fsck -E journal_only`): the
/// file must be there byte-exact on an `e2fsck -fn`-clean image.
///
/// The control arm disables the tick (`--commit-interval-secs 0`) and must NOT
/// keep the bytes — otherwise something other than the periodic commit made
/// them durable and the positive arm would prove nothing.
#[test]
fn cli_mount_periodic_commit_survives_sigkill_bd_dj725() {
    let require = std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|v| v == "1");
    let prerequisites = Path::new("/dev/fuse").exists()
        && ["mkfs.ext4", "e2fsck", "debugfs", "fusermount3"]
            .iter()
            .all(|tool| command_available(tool));
    if !prerequisites {
        assert!(
            !require,
            "FFS_REQUIRE_FUSE=1 but /dev/fuse, e2fsprogs or fusermount3 is missing"
        );
        emit_scenario_result(
            "cli_mount_periodic_commit_sigkill",
            "SKIP",
            Some("fuse_or_e2fsprogs_unavailable"),
        );
        return;
    }
    let payload: Vec<u8> = (0..65_536_u32).map(|i| (i % 251) as u8).collect();

    // Omit the option to exercise the actual default, then retain the explicit
    // override and disabled control. The default and control wait equally long.
    for interval_secs in [None, Some(1), Some(0)] {
        let kept = match periodic_commit_sigkill_arm(interval_secs, &payload, require) {
            SigkillArm::Skipped => return,
            SigkillArm::Missing => None,
            SigkillArm::Bytes(bytes) => Some(bytes),
        };
        if interval_secs == Some(0) {
            assert_ne!(
                kept.as_deref(),
                Some(payload.as_slice()),
                "disabled ext4 timer kept the bytes; this control cannot detect a missing tick"
            );
        } else {
            assert_eq!(
                kept.as_deref(),
                Some(payload.as_slice()),
                "ext4 writes older than the commit interval {interval_secs:?} must survive SIGKILL"
            );
        }
    }
    emit_scenario_result("cli_mount_periodic_commit_sigkill", "PASS", None);
}

/// The btrfs timer must publish un-fsynced mutations before a daemon crash.
/// The disabled-timer arm must lose them, and both images must remain clean.
#[test]
fn cli_mount_btrfs_periodic_commit_survives_sigkill_bd_dj725() {
    let require = std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|value| value == "1");
    if !Path::new("/dev/fuse").exists()
        || !["mkfs.btrfs", "btrfs", "fusermount3"]
            .iter()
            .all(|tool| command_available(tool))
    {
        assert!(
            !require,
            "FFS_REQUIRE_FUSE=1 but btrfs FUSE prerequisites are missing"
        );
        emit_scenario_result(
            "cli_mount_btrfs_periodic_commit_sigkill",
            "SKIP",
            Some("fuse_or_btrfs_tools_unavailable"),
        );
        return;
    }
    let payload: Vec<u8> = (0..65_536_u32).map(|i| (i % 251) as u8).collect();
    for interval_secs in [None, Some(1), Some(0)] {
        let kept =
            match btrfs_commit_sigkill_arm(interval_secs, &payload, require, None, None, false) {
                SigkillArm::Skipped => return,
                SigkillArm::Missing => None,
                SigkillArm::Bytes(bytes) => Some(bytes),
            };
        if interval_secs == Some(0) {
            assert_ne!(
                kept.as_deref(),
                Some(payload.as_slice()),
                "disabled btrfs timer kept the bytes; this control cannot detect a missing tick"
            );
        } else {
            assert_eq!(
                kept.as_deref(),
                Some(payload.as_slice()),
                "btrfs writes older than the commit interval {interval_secs:?} must survive SIGKILL"
            );
        }
    }
    emit_scenario_result("cli_mount_btrfs_periodic_commit_sigkill", "PASS", None);
}

#[test]
fn cli_mount_btrfs_pressure_commit_survives_sigkill_without_timer_bd_dj725() {
    let require = std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|value| value == "1");
    let prerequisites = Path::new("/dev/fuse").exists()
        && ["mkfs.btrfs", "btrfs", "fusermount3"]
            .iter()
            .all(|tool| command_available(tool));
    if !prerequisites {
        assert!(
            !require,
            "required FUSE/btrfs pressure prerequisites unavailable"
        );
        emit_scenario_result(
            "cli_mount_btrfs_pressure_sigkill",
            "SKIP",
            Some("fuse_unavailable"),
        );
        return;
    }
    let payload: Vec<u8> = (0..65_536_u32).map(|i| (i % 251) as u8).collect();
    for threshold in [1, u64::MAX] {
        let kept = match btrfs_commit_sigkill_arm(
            Some(0),
            &payload,
            require,
            Some(threshold),
            Some(2),
            false,
        ) {
            SigkillArm::Skipped => return,
            SigkillArm::Missing => None,
            SigkillArm::Bytes(bytes) => Some(bytes),
        };
        if threshold == 1 {
            assert_eq!(
                kept.as_deref(),
                Some(payload.as_slice()),
                "pressure must persist unsynced writes"
            );
        } else {
            assert_ne!(
                kept.as_deref(),
                Some(payload.as_slice()),
                "timer-off high-threshold control must detect missing pressure commits"
            );
        }
    }
    emit_scenario_result("cli_mount_btrfs_pressure_sigkill", "PASS", None);
}

#[test]
fn cli_mount_btrfs_sync_ioctl_survives_sigkill_bd_8u2a5() {
    let require = std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|value| value == "1");
    let prerequisites = Path::new("/dev/fuse").exists()
        && ["mkfs.btrfs", "btrfs", "fusermount3"]
            .iter()
            .all(|tool| command_available(tool));
    if !prerequisites {
        assert!(
            !require,
            "required FUSE/btrfs sync prerequisites unavailable"
        );
        emit_scenario_result(
            "cli_mount_btrfs_sync_ioctl_sigkill",
            "SKIP",
            Some("fuse_unavailable"),
        );
        return;
    }
    let payload: Vec<u8> = (0..65_536_u32).map(|i| (i % 251) as u8).collect();
    for sync_ioctl in [false, true] {
        let kept = match btrfs_commit_sigkill_arm(
            Some(0),
            &payload,
            require,
            Some(0),
            Some(0),
            sync_ioctl,
        ) {
            SigkillArm::Skipped => return,
            SigkillArm::Missing => None,
            SigkillArm::Bytes(bytes) => Some(bytes),
        };
        if sync_ioctl {
            assert_eq!(
                kept.as_deref(),
                Some(payload.as_slice()),
                "BTRFS_IOC_SYNC must persist every acknowledged byte before SIGKILL"
            );
        } else {
            assert_ne!(
                kept.as_deref(),
                Some(payload.as_slice()),
                "the omitted-ioctl control must detect the missing durability boundary"
            );
        }
    }
    emit_scenario_result("cli_mount_btrfs_sync_ioctl_sigkill", "PASS", None);
}

/// Own a freshly attached scratch loop until the mounted superblock takes over.
struct SyncfsTestLoop(Option<String>);

impl SyncfsTestLoop {
    fn attach(image: &Path) -> Self {
        let attached = Command::new("losetup")
            .args(["--find", "--show", "--nooverlap"])
            .arg(image)
            .output()
            .unwrap();
        assert!(
            attached.status.success(),
            "attach scratch loop: {attached:?}"
        );
        Self(Some(
            String::from_utf8(attached.stdout)
                .unwrap()
                .trim()
                .to_owned(),
        ))
    }

    fn device(&self) -> &str {
        self.0.as_deref().expect("owned scratch loop")
    }

    fn release_to_mount(&mut self) -> std::io::Result<()> {
        let detached = Command::new("losetup")
            .args(["--detach", self.device()])
            .output()?;
        if !detached.status.success() {
            return Err(std::io::Error::other(format!(
                "mark scratch loop autoclear: {detached:?}"
            )));
        }
        // The mounted block superblock and CLI hold references. Autoclear
        // releases the mapping after SIGKILL/unmount; never detach a reused ID.
        self.0 = None;
        Ok(())
    }
}

impl Drop for SyncfsTestLoop {
    fn drop(&mut self) {
        if let Some(device) = &self.0 {
            match Command::new("losetup").args(["--detach", device]).status() {
                Ok(status) if status.success() => {}
                result => eprintln!("scratch loop cleanup failed for {device}: {result:?}"),
            }
        }
    }
}

/// Keep a failed assertion from leaving this test's daemon or mount alive.
struct SyncfsTestMount {
    child: std::process::Child,
    mountpoint: PathBuf,
}

impl Drop for SyncfsTestMount {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // fuseblk is a privileged block mount; fusermount3 deliberately
        // rejects it. The test owns this mount in its private namespace.
        let unmounted = Command::new("umount")
            .arg(&self.mountpoint)
            .status()
            .is_ok_and(|status| status.success());
        if !unmounted {
            let _ = Command::new("umount")
                .arg("-l")
                .arg(&self.mountpoint)
                .status();
        }
    }
}

/// Linux syncfs must reach the native boundary through the fuseblk transport.
/// Run as root in a private mount namespace for the independent kernel readback.
#[test]
fn cli_mount_syncfs_survives_sigkill_bd_yek6e() {
    let require = std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|v| v == "1");
    let prerequisites = Path::new("/dev/fuse").exists()
        && Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|output| output.status.success() && output.stdout == b"0\n")
        && [
            "mkfs.ext4",
            "mkfs.btrfs",
            "mkfs.fat",
            "e2fsck",
            "btrfs",
            "fsck.fat",
            "mount",
            "umount",
            "sync",
            "losetup",
            "fusermount3",
        ]
        .iter()
        .all(|tool| command_available(tool));
    if !prerequisites {
        assert!(
            !require,
            "required syncfs mount/native oracle prerequisites missing"
        );
        emit_scenario_result(
            "cli_mount_syncfs_sigkill",
            "SKIP",
            Some("native_mount_prerequisites"),
        );
        return;
    }
    let root = tempfile::Builder::new()
        .prefix("ffs-syncfs-")
        .tempdir()
        .expect("retained syncfs evidence")
        .keep();
    println!("syncfs evidence: {}", root.display());
    println!(
        "CLI SHA256: {}",
        sha256_file(Path::new(env!("CARGO_BIN_EXE_ffs-cli")))
    );
    println!(
        "FAT CLI SHA256: {}",
        sha256_file(Path::new(env!("CARGO_BIN_EXE_ffs-fat")))
    );
    for tool in [
        "sync",
        "mkfs.ext4",
        "mkfs.btrfs",
        "mkfs.fat",
        "e2fsck",
        "btrfs",
        "fsck.fat",
        "mount",
        "umount",
        "fusermount3",
        "losetup",
    ] {
        let resolved = Command::new("which").arg(tool).output().unwrap();
        assert!(resolved.status.success(), "resolve {tool}");
        let path = PathBuf::from(String::from_utf8(resolved.stdout).unwrap().trim());
        println!("{tool} {} SHA256: {}", path.display(), sha256_file(&path));
    }
    let payload: Vec<u8> = (0..65_536_u32).map(|i| (i % 251) as u8).collect();
    for format in ["ext4", "btrfs", "fat16", "fat32"] {
        let is_fat = format.starts_with("fat");
        let binary = Path::new(if is_fat {
            env!("CARGO_BIN_EXE_ffs-fat")
        } else {
            env!("CARGO_BIN_EXE_ffs-cli")
        });
        // FAT already flushes each ordered mutation; an omitted-sync loss is
        // neither expected nor claimed for those two formats.
        let arms: &[bool] = if is_fat { &[true] } else { &[false, true] };
        for &do_sync in arms {
            let dir = root.join(format!("{format}-{do_sync}"));
            fs::create_dir(&dir).unwrap();
            let image = dir.join("volume.img");
            if format == "ext4" {
                format_ext4_owned_by_caller(&image, 64 << 20);
            } else {
                fs::File::create(&image)
                    .unwrap()
                    .set_len(256 << 20)
                    .unwrap();
                let mut command = if format == "btrfs" {
                    let mut command = Command::new("mkfs.btrfs");
                    command.args(["-f", "-q"]);
                    command
                } else {
                    let mut command = Command::new("mkfs.fat");
                    command.args(["-F", if format == "fat16" { "16" } else { "32" }]);
                    command
                };
                let output = command.arg(&image).output().unwrap();
                fs::write(dir.join("format.stdout"), &output.stdout).unwrap();
                fs::write(dir.join("format.stderr"), &output.stderr).unwrap();
                assert!(output.status.success(), "format {format}: {output:?}");
            }
            println!(
                "{format} sync={do_sync} input SHA256: {}",
                sha256_file(&image)
            );
            let mnt = dir.join("fuse");
            fs::create_dir(&mnt).unwrap();
            let mut loop_device = SyncfsTestLoop::attach(&image);
            let mut args = vec!["--rw", "--fuseblk-device", loop_device.device()];
            if is_fat {
                args.push("--offline-image");
            } else {
                args.extend(["--commit-interval-secs", "0"]);
            }
            let Some(child) = spawn_cli_mount_binary(
                binary,
                &image,
                &mnt,
                &dir.join("mount.log"),
                &args,
                &[
                    ("FFS_BTRFS_DIRTY_BYTES_THRESHOLD", "0"),
                    ("RUST_LOG", "info,fuser=debug"),
                ],
                ("cli_mount_syncfs_sigkill", require),
            ) else {
                return;
            };
            let mount = SyncfsTestMount {
                child,
                mountpoint: mnt.clone(),
            };
            let mountpoint = mnt.canonicalize().unwrap();
            let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap();
            fs::write(dir.join("mountinfo"), &mountinfo).unwrap();
            let block_mount = mountinfo.lines().any(|line| {
                line.split(' ').nth(4) == mountpoint.to_str()
                    && line.split_once(" - ").is_some_and(|(_, suffix)| {
                        suffix
                            .split(' ')
                            .next()
                            .is_some_and(|kind| kind == "fuseblk" || kind.starts_with("fuseblk."))
                    })
            });
            assert!(
                block_mount,
                "{format}: kernel did not mount the requested fuseblk transport"
            );
            loop_device
                .release_to_mount()
                .expect("scratch loop handoff");
            fs::write(mnt.join("durable.bin"), &payload).expect("mounted payload write");
            if do_sync {
                let synced = Command::new("sync").arg("-f").arg(&mnt).output();
                assert!(
                    synced.as_ref().is_ok_and(|output| output.status.success()),
                    "{format} syncfs failed: {synced:?}"
                );
                assert!(
                    fs::read_to_string(dir.join("mount.log"))
                        .unwrap()
                        .contains("SYNCFS nodeid"),
                    "{format}: returned syncfs must actually reach the userspace transport"
                );
            }
            drop(mount);
            let mut checker = match format {
                "ext4" => {
                    let mut c = Command::new("e2fsck");
                    c.arg("-fn");
                    c
                }
                "btrfs" => {
                    let mut c = Command::new("btrfs");
                    c.args(["check", "--readonly"]);
                    c
                }
                _ => {
                    let mut c = Command::new("fsck.fat");
                    c.arg("-n");
                    c
                }
            };
            let outcome = checker.arg(&image).output().unwrap();
            fs::write(dir.join("check.stdout"), &outcome.stdout).unwrap();
            fs::write(dir.join("check.stderr"), &outcome.stderr).unwrap();
            assert!(
                outcome.status.success(),
                "{format} native checker failed: {outcome:?}"
            );
            let native = dir.join("native");
            fs::create_dir(&native).unwrap();
            let options = match format {
                "ext4" => "loop,ro,noload",
                "btrfs" => "loop,ro,rescue=nologreplay",
                _ => "loop,ro",
            };
            let mounted = Command::new("mount")
                .args(["-o", options])
                .arg(&image)
                .arg(&native)
                .output()
                .unwrap();
            assert!(
                mounted.status.success(),
                "{format} native mount: {mounted:?}"
            );
            let native_bytes = fs::read(native.join("durable.bin"));
            let detached = Command::new("umount").arg(&native).output().unwrap();
            assert!(
                detached.status.success(),
                "native unmount failed: {detached:?}"
            );
            if do_sync {
                assert_eq!(
                    native_bytes.unwrap(),
                    payload,
                    "{format}: returned syncfs lost data"
                );
                let before = sha256_file(&image);
                let mut read_loop = SyncfsTestLoop::attach(&image);
                let mut read_args = vec!["--fuseblk-device", read_loop.device()];
                if is_fat {
                    read_args.push("--offline-image");
                }
                let Some(child) = spawn_cli_mount_binary(
                    binary,
                    &image,
                    &mnt,
                    &dir.join("remount.log"),
                    &read_args,
                    &[],
                    ("cli_mount_syncfs_sigkill_remount", require),
                ) else {
                    return;
                };
                let remounted = SyncfsTestMount {
                    child,
                    mountpoint: mnt.clone(),
                };
                read_loop
                    .release_to_mount()
                    .expect("read-only scratch loop handoff");
                let bytes = fs::read(mnt.join("durable.bin"));
                let synced = Command::new("sync").arg("-f").arg(&mnt).output();
                drop(remounted);
                assert_eq!(bytes.unwrap(), payload, "{format} FUSE readback");
                assert!(
                    synced.unwrap().status.success(),
                    "{format} read-only syncfs"
                );
                assert_eq!(
                    sha256_file(&image),
                    before,
                    "read-only syncfs wrote the image"
                );
            } else {
                let bytes = match native_bytes {
                    Ok(bytes) => Some(bytes),
                    Err(error) => {
                        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
                        None
                    }
                };
                assert_ne!(
                    bytes.as_deref(),
                    Some(payload.as_slice()),
                    "omitted syncfs did not expose the missing durability boundary for {format}"
                );
            }
            println!("{format} sync={do_sync}: PASS");
        }
    }
    emit_scenario_result("cli_mount_syncfs_sigkill", "PASS", None);
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn space_info_consumer_bounds_and_late_failures_do_not_emit_partial_json() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/ffs_space_info.py");
    let output = Command::new("python3")
        .arg("-c")
        .arg(r"
import contextlib, errno, fcntl, io, json, os, runpy, struct, sys, tempfile
from unittest.mock import patch
m = runpy.run_path(sys.argv[1])
with tempfile.TemporaryDirectory() as directory:
    def case(responses, success, expected_calls, diagnostic=None, native=False):
        calls = []
        def ioctl(fd, command, data, mutable):
            assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
            assert mutable
            slots = struct.unpack_from('<Q', data)[0]
            assert len(data) == 16 + slots * 24
            if native: assert command == 0xc0109414
            else: assert len(data) == ((command >> 16) & 0x3fff)
            calls.append(slots)
            response = responses[len(calls)-1]
            if isinstance(response, Exception): raise response
            if response == 'noop': return 0
            if response == 'nonzero': return 1
            total, records = response
            struct.pack_into('<QQ', data, 0, slots, total)
            for index, record in enumerate(records):
                struct.pack_into('<QQQ', data, 16 + index*24, *record)
            return 0
        out, err = io.StringIO(), io.StringIO()
        argv = ['ffs_space_info.py', directory] + (['--kernel-btrfs'] if native else [])
        with patch.object(fcntl, 'ioctl', ioctl), patch.object(sys, 'argv', argv), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = m['main']()
        assert len(calls) == expected_calls, calls
        if success:
            assert result == 0 and not err.getvalue()
            parsed = json.loads(out.getvalue())
            assert parsed['total_spaces'] == len(parsed['spaces'])
            return parsed
        assert result == 1 and out.getvalue() == '', (result, out.getvalue(), err.getvalue())
        assert diagnostic in err.getvalue(), err.getvalue()
    good = [(1, 4096, 1024), (4, 8192, 2048)]
    assert case([(2, []), (2, good)], True, 2)['spaces'][1]['used_bytes'] == 2048
    assert case([(0, []), (0, [])], True, 2)['spaces'] == []
    case([(2, []), (2, [good[0], (4, 8192, 8193)])], False, 2, 'more used')
    case([(2, []), (2, [good[0]])], False, 2, 'not completely returned')
    case(['noop'], False, 1, 'count is missing')
    case(['nonzero'], False, 1, 'nonzero result')
    case([(m['MAX_SLOTS'] + 1, [])], False, 1, 'bounded ioctl capacity')
    case([OSError(errno.ENOTTY, 'missing oracle')], False, 1, 'missing oracle')
    case([(1, []), (2, good[:1]), (3, good), (4, good + [(2, 16384, 0)])], False, 4, 'kept growing')
    assert case([(1, []), (1, good[:1]), (2, []), (2, good), (2, [])], True, 5, native=True)['total_spaces'] == 2
    case([(1, []), (1, good[:1]), (2, []), (2, good), (3, []), (3, good + [(2, 16384, 0)]), (4, [])], False, 7, 'kept growing', native=True)
    with patch.object(m['platform'], 'machine', lambda: 'ppc64le'):
        case([], False, 0, 'Linux x86_64')
print('consumer bounds and late-failure controls: PASS')
")
        .arg(&script)
        .output()
        .expect("run public space-info consumer fault controls");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("controls: PASS"));
}

/// Own only this test's native mount, including the failed-unmount path.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct SpaceInfoNativeMount(Option<PathBuf>);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for SpaceInfoNativeMount {
    fn drop(&mut self) {
        if let Some(path) = &self.0
            && !Command::new("umount")
                .arg(path)
                .status()
                .is_ok_and(|status| status.success())
        {
            let _ = Command::new("umount").arg("-l").arg(path).status();
        }
    }
}

/// Native durable block groups and real restricted-FUSE buffer lengths.
#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cli_mount_btrfs_space_info_records_bd_k3hon() {
    let require = std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|v| v == "1");
    let mount_capable = fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            .is_some_and(|capabilities| capabilities & (1 << 21) != 0)
    });
    let prerequisites = mount_capable
        && Path::new("/dev/fuse").exists()
        && Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|out| out.status.success() && out.stdout == b"0\n")
        && ["mkfs.btrfs", "btrfs", "mount", "umount", "python3", "which"]
            .iter()
            .all(|tool| command_available(tool));
    if !prerequisites {
        assert!(
            !require,
            "required mounted space-info/native oracle prerequisites missing"
        );
        emit_scenario_result(
            "cli_mount_btrfs_space_info",
            "SKIP",
            Some("native_mount_prerequisites"),
        );
        return;
    }
    let dir = tempfile::Builder::new()
        .prefix("ffs-space-info-")
        .tempdir()
        .unwrap()
        .keep();
    println!("space-info evidence: {}", dir.display());
    for tool in ["mkfs.btrfs", "btrfs", "mount", "umount", "python3"] {
        let resolved = Command::new("which").arg(tool).output().unwrap();
        assert!(resolved.status.success(), "resolve {tool}");
        let path = PathBuf::from(String::from_utf8(resolved.stdout).unwrap().trim());
        println!("{tool} {} SHA256: {}", path.display(), sha256_file(&path));
    }
    let image = dir.join("volume.img");
    fs::File::create(&image)
        .unwrap()
        .set_len(512 << 20)
        .unwrap();
    let formatted = Command::new("mkfs.btrfs")
        .args(["-f", "-q"])
        .arg(&image)
        .output()
        .unwrap();
    fs::write(dir.join("format.stdout"), &formatted.stdout).unwrap();
    fs::write(dir.join("format.stderr"), &formatted.stderr).unwrap();
    assert!(
        formatted.status.success(),
        "format native btrfs: {formatted:?}"
    );
    let native = dir.join("native");
    let mnt = dir.join("fuse");
    fs::create_dir(&native).unwrap();
    fs::create_dir(&mnt).unwrap();
    let baseline = sha256_file(&image);
    let mounted = Command::new("mount")
        .args(["-o", "loop,ro,rescue=nologreplay"])
        .arg(&image)
        .arg(&native)
        .output()
        .unwrap();
    assert!(
        mounted.status.success(),
        "native readonly mount: {mounted:?}"
    );
    let mut native_mount = SpaceInfoNativeMount(Some(native.clone()));
    let consumer = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/ffs_space_info.py");
    let native_query = Command::new("python3")
        .arg(&consumer)
        .arg("--kernel-btrfs")
        .arg(&native)
        .output();
    let detached = Command::new("umount").arg(&native).output().unwrap();
    assert!(detached.status.success(), "native unmount: {detached:?}");
    native_mount.0 = None;
    let native_query = native_query.unwrap();
    fs::write(dir.join("native.stdout"), &native_query.stdout).unwrap();
    fs::write(dir.join("native.stderr"), &native_query.stderr).unwrap();
    assert!(
        native_query.status.success(),
        "native consumer: {native_query:?}"
    );
    assert_eq!(
        sha256_file(&image),
        baseline,
        "native readonly query changed its input"
    );
    let dump = Command::new("btrfs")
        .args(["inspect-internal", "dump-tree", "-t", "extent"])
        .arg(&image)
        .output()
        .unwrap();
    fs::write(dir.join("extent-tree.stdout"), &dump.stdout).unwrap();
    fs::write(dir.join("extent-tree.stderr"), &dump.stderr).unwrap();
    assert!(
        dump.status.success(),
        "native durable block-group oracle: {dump:?}"
    );
    let block_groups = Command::new("python3").arg("-c").arg(r"
import json, re, sys
bits = dict(DATA=1, SYSTEM=2, METADATA=4, RAID0=8, RAID1=16, DUP=32, RAID10=64, RAID5=128, RAID6=256, RAID1C3=512, RAID1C4=1024, SINGLE=0)
groups, pending, count = {}, None, 0
for line in open(sys.argv[1], encoding='utf-8'):
    if 'BLOCK_GROUP_ITEM' in line:
        assert pending is None, 'missing final block-group body'
        key = re.search(r'key \((\d+) BLOCK_GROUP_ITEM (\d+)\)', line)
        assert key, line
        pending = int(key[2])
    elif pending is not None:
        body = re.search(r'block group used (\d+) chunk_objectid \d+ flags (\S+)', line)
        if body:
            flags = 0
            for name in body[2].upper().split('|'): flags |= bits[name]
            record = groups.setdefault(flags, dict(flags=flags, total_bytes=0, used_bytes=0))
            record['total_bytes'] += pending
            record['used_bytes'] += int(body[1])
            pending, count = None, count+1
assert pending is None and count >= 3, 'incomplete native block-group dump'
print(json.dumps(dict(total_spaces=len(groups), spaces=list(groups.values())), sort_keys=True))
").arg(dir.join("extent-tree.stdout")).output().unwrap();
    fs::write(dir.join("block-groups.json"), &block_groups.stdout).unwrap();
    fs::write(dir.join("block-groups.stderr"), &block_groups.stderr).unwrap();
    assert!(
        block_groups.status.success(),
        "parse the complete native block-group oracle: {block_groups:?}"
    );
    assert_eq!(
        sha256_file(&image),
        baseline,
        "native accounting oracle changed its input"
    );
    let Some(child) = spawn_cli_mount(
        &image,
        &mnt,
        &dir.join("mount.log"),
        &["--rw", "--commit-interval-secs", "0"],
        &[("FFS_BTRFS_DIRTY_BYTES_THRESHOLD", "0")],
        "cli_mount_btrfs_space_info",
        require,
    ) else {
        return;
    };
    let mount = SyncfsTestMount {
        child,
        mountpoint: mnt.clone(),
    };
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap();
    fs::write(dir.join("mountinfo"), &mountinfo).unwrap();
    assert!(mountinfo.lines().any(|line| {
        line.split(' ').nth(4) == mnt.to_str()
            && line
                .split_once(" - ")
                .is_some_and(|(_, suffix)| suffix.starts_with("fuse"))
    }));
    let mounted_hash = sha256_file(&image);
    let probe = Command::new("python3").arg("-c").arg(r"
import errno, fcntl, json, os, struct, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
def query(command, slots, size):
    data = bytearray(size)
    struct.pack_into('<QQ', data, 0, slots, 0)
    fcntl.ioctl(fd, command, data, True)
    return data
try:
    count = struct.unpack_from('<Q', query(0xc0109414, 0, 16), 8)[0]
    assert count > 1, count
    for command, slots, size, expected in [
        (0xc0109414, 8, 208, errno.EOVERFLOW),
        (0xc0289414, 8, 208, errno.EOVERFLOW),
        (0xc0119414, 0, 17, errno.EINVAL),
    ]:
        try: query(command, slots, size)
        except OSError as error: assert error.errno == expected, (error, expected)
        else: raise AssertionError('undersized query unexpectedly succeeded')
    partial = query(0xc0289414, 1, 40)
    assert struct.unpack_from('<Q', partial, 8)[0] == count
    assert struct.unpack_from('<Q', partial, 16)[0] != 0
    complete = query(0xc0d09414, 8, 208)
    assert struct.unpack_from('<Q', complete, 8)[0] == count
    assert count <= 8
    print(json.dumps({'total_spaces': count, 'spaces': [dict(zip(['flags','total_bytes','used_bytes'], struct.unpack_from('<QQQ', complete, 16+i*24))) for i in range(count)]}, sort_keys=True))
finally: os.close(fd)
").arg(&mnt).output().unwrap();
    fs::write(dir.join("probe.stdout"), &probe.stdout).unwrap();
    fs::write(dir.join("probe.stderr"), &probe.stderr).unwrap();
    let observed = Command::new("python3")
        .arg(&consumer)
        .arg(&mnt)
        .output()
        .unwrap();
    fs::write(dir.join("consumer.stdout"), &observed.stdout).unwrap();
    fs::write(dir.join("consumer.stderr"), &observed.stderr).unwrap();
    let query_hash = sha256_file(&image);
    drop(mount);
    assert!(
        probe.status.success(),
        "actual ioctl-window probe: {probe:?}"
    );
    assert!(
        observed.status.success(),
        "public consumer on FUSE: {observed:?}"
    );
    assert_eq!(
        query_hash, mounted_hash,
        "read queries changed the backing image"
    );
    let canonical = |bytes: &[u8]| {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let mut records = value["spaces"].as_array_mut().unwrap().clone();
        records.sort_by_key(|record| record["flags"].as_u64().unwrap());
        assert_eq!(
            records.len() as u64,
            value["total_spaces"].as_u64().unwrap()
        );
        records
    };
    assert_eq!(
        canonical(&observed.stdout),
        canonical(&block_groups.stdout),
        "complete records differ from the native durable block-group oracle"
    );
    assert_eq!(canonical(&probe.stdout), canonical(&block_groups.stdout));
    // Retain the entire kernel ioctl output, including its transient global
    // reserve, instead of filtering it into a false native-ABI parity claim.
    let native_records = canonical(&native_query.stdout);
    println!(
        "kernel ioctl full records: {}",
        String::from_utf8_lossy(&native_query.stdout)
    );
    println!(
        "FrankenFS allocator full records: {}",
        String::from_utf8_lossy(&observed.stdout)
    );
    println!(
        "native_ioctl_records_equal: {}",
        canonical(&observed.stdout) == native_records
    );
    let checked = Command::new("btrfs")
        .args(["check", "--readonly"])
        .arg(&image)
        .output()
        .unwrap();
    fs::write(dir.join("check.stdout"), &checked.stdout).unwrap();
    fs::write(dir.join("check.stderr"), &checked.stderr).unwrap();
    assert!(
        checked.status.success(),
        "native image checker: {checked:?}"
    );
    println!(
        "CLI SHA256: {}",
        sha256_file(Path::new(env!("CARGO_BIN_EXE_ffs-cli")))
    );
    println!("consumer SHA256: {}", sha256_file(&consumer));
    println!("input SHA256: {baseline}; mounted-before={mounted_hash}; mounted-after={query_hash}");
    emit_scenario_result("cli_mount_btrfs_space_info", "PASS", None);
}

/// Real mount ownership and cancellation of both idle background workers.
#[test]
fn cli_mount_background_workers_drain_on_unmount_bd_11a8t() {
    use std::time::{Duration, Instant};

    let require = std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|value| value == "1");
    if !Path::new("/dev/fuse").exists()
        || !["mkfs.ext4", "e2fsck", "debugfs", "fusermount3"]
            .iter()
            .all(|tool| command_available(tool))
    {
        assert!(
            !require,
            "FFS_REQUIRE_FUSE=1 but mount prerequisites are missing"
        );
        emit_scenario_result(
            "mount_worker_drain",
            "SKIP",
            Some("fuse_or_e2fsprogs_unavailable"),
        );
        return;
    }
    let dir = tempfile::tempdir().expect("test directory").keep();
    let image = dir.join("workers.ext4");
    format_ext4_owned_by_caller(&image, 32 << 20);
    let mnt = dir.join("mnt");
    fs::create_dir(&mnt).unwrap();
    let log = dir.join("mount.log");
    let Some(mut child) = spawn_cli_mount(
        &image,
        &mnt,
        &log,
        &[
            "--rw",
            "--background-scrub",
            "--background-scrub-interval-secs",
            "3600",
            "--commit-interval-secs",
            "3600",
        ],
        &[("RUST_LOG", "info")],
        "mount_worker_drain",
        require,
    ) else {
        return;
    };
    let activity = (|| -> std::io::Result<()> {
        fs::write(mnt.join("sentinel"), b"durable before worker shutdown")?;
        fs::File::open(mnt.join("sentinel"))?.sync_all()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let output = fs::read_to_string(&log)?;
            if output.contains("scrub_round_complete") && output.contains("periodic_commit_started")
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "background workers did not complete startup and a scrub round",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    // Both workers have hour-long intervals. Normal unmount must cancel their
    // idle waits, drain actual I/O, and exit successfully without force/lazy detach.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut unmount = Command::new("fusermount3")
        .arg("-u")
        .arg(&mnt)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    while unmount.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            unmount.kill().expect("stop only the failed test unmounter");
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let unmount = unmount.wait_with_output().unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill().expect("stop only the failed test daemon");
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !unmount.status.success() || status.is_none() {
        // Failure-only cleanup of this test's dead mount. This cannot satisfy
        // the normal-unmount assertions below or extend their original deadline.
        if let Ok(mut cleanup) = Command::new("fusermount3")
            .args(["-u", "-z"])
            .arg(&mnt)
            .spawn()
        {
            let cleanup_deadline = Instant::now() + Duration::from_secs(5);
            while !matches!(cleanup.try_wait(), Ok(Some(_))) {
                if Instant::now() >= cleanup_deadline {
                    let _ = cleanup.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = cleanup.wait();
        }
    }
    let output = fs::read_to_string(&log).unwrap();
    assert!(
        unmount.status.success(),
        "{}",
        String::from_utf8_lossy(&unmount.stderr)
    );
    assert!(
        status.is_some_and(|status| status.success()),
        "daemon did not drain cleanly: {output}"
    );
    activity.expect("mounted write and a real scrub round must succeed");
    assert!(output.contains("mount_background_scrub_stop"), "{output}");
    assert!(output.contains("periodic_commit_started"), "{output}");
    let check = Command::new("e2fsck")
        .arg("-fn")
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    let readback = Command::new("debugfs")
        .args(["-R", "cat /sentinel"])
        .arg(&image)
        .output()
        .unwrap();
    assert!(readback.status.success());
    assert_eq!(readback.stdout, b"durable before worker shutdown");
    emit_scenario_result(
        "mount_worker_drain",
        "PASS",
        Some(&dir.display().to_string()),
    );
}

/// Outcome of one SIGKILL arm.
enum SigkillArm {
    /// The mount could not start (a SKIP, only allowed without `FFS_REQUIRE_FUSE=1`).
    Skipped,
    /// After crash + journal replay the file does not exist on the image.
    Missing,
    /// The file's bytes after crash + journal replay.
    Bytes(Vec<u8>),
}

/// One SIGKILL arm of [`cli_mount_periodic_commit_survives_sigkill_bd_dj725`].
/// Spawn `ffs mount <extra_args> image mnt` and wait for it to appear in
/// mountinfo. `None` is a SKIP (the mount could not start), which is a
/// failure under `FFS_REQUIRE_FUSE=1`.
fn spawn_cli_mount(
    image: &Path,
    mnt: &Path,
    log_path: &Path,
    extra_args: &[&str],
    envs: &[(&str, &str)],
    scenario: &str,
    require: bool,
) -> Option<std::process::Child> {
    spawn_cli_mount_binary(
        Path::new(env!("CARGO_BIN_EXE_ffs-cli")),
        image,
        mnt,
        log_path,
        extra_args,
        envs,
        (scenario, require),
    )
}

fn spawn_cli_mount_binary(
    binary: &Path,
    image: &Path,
    mnt: &Path,
    log_path: &Path,
    extra_args: &[&str],
    envs: &[(&str, &str)],
    expectation: (&str, bool),
) -> Option<std::process::Child> {
    use std::time::{Duration, Instant};

    let (scenario, require) = expectation;

    let mnt_key = mnt
        .canonicalize()
        .expect("canonical mountpoint")
        .to_string_lossy()
        .into_owned();
    // A file, not a pipe: an unread pipe would block a chatty daemon.
    let mut child = Command::new(binary)
        .arg("mount")
        .args(extra_args)
        .arg(image)
        .arg(mnt)
        // auto_unmount routes through fusermount3 even as root, and some CI
        // workers deny it; callers unmount the (dead) mount themselves.
        .env("FFS_AUTO_UNMOUNT", "0")
        .envs(envs.iter().copied())
        .stdout(std::process::Stdio::null())
        .stderr(fs::File::create(log_path).expect("create mount log"))
        .spawn()
        .expect("spawn `ffs mount`");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mounted = fs::read_to_string("/proc/self/mountinfo")
            .unwrap_or_default()
            .lines()
            .any(|line| line.split(' ').nth(4) == Some(mnt_key.as_str()));
        if mounted {
            return Some(child);
        }
        if let Some(status) = child.try_wait().expect("poll mount daemon") {
            let stderr = fs::read_to_string(log_path).unwrap_or_default();
            assert!(
                !require,
                "FFS_REQUIRE_FUSE=1 but `ffs mount` exited {status}: {stderr}"
            );
            emit_scenario_result(scenario, "SKIP", Some("mount_failed"));
            return None;
        }
        if Instant::now() > deadline {
            sigkill_cli_mount(&mut child, mnt);
            panic!("`ffs mount` did not appear in mountinfo within 30s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Size and format `image` as ext4 with the root directory owned by THIS
/// process: CI runs tests as an unprivileged user, and a root-owned 0755 root
/// directory makes every create through a `default_permissions` mount EACCES
/// (the rch workers run as root, which hid it).
fn format_ext4_owned_by_caller(image: &Path, size: u64) {
    use std::os::unix::fs::MetadataExt as _;

    fs::File::create(image)
        .and_then(|file| file.set_len(size))
        .expect("size image");
    let me = fs::metadata(image).expect("stat image");
    let root_owner = format!("root_owner={}:{}", me.uid(), me.gid());
    let format = Command::new("mkfs.ext4")
        .args(["-F", "-q", "-b", "4096", "-E", &root_owner])
        .arg(image)
        .output()
        .expect("run mkfs.ext4");
    assert!(
        format.status.success(),
        "mkfs.ext4 failed: {}",
        String::from_utf8_lossy(&format.stderr)
    );
}

/// SIGKILL a CLI mount daemon and detach its now-dead mount.
fn sigkill_cli_mount(child: &mut std::process::Child, mnt: &Path) {
    child.kill().expect("SIGKILL the mount daemon");
    let _ = child.wait();
    let unmounted = Command::new("fusermount3")
        .args(["-u", "-z"])
        .arg(mnt)
        .status()
        .is_ok_and(|status| status.success());
    if !unmounted {
        let _ = Command::new("umount").arg("-l").arg(mnt).status();
    }
}

/// bd-dj725 memory bound, measured on the real daemon: 2 GiB written through
/// `ffs mount --rw` without any fsync. The absolute ceiling defaults to 1 GiB
/// (half the workload) and can be configured with `FFS_TEST_MAX_DAEMON_RSS_MIB`.
/// VmHWM measures the process peak; sampled VmRSS retains the growth comparison
/// against the control with durable MVCC eviction disabled.
#[test]
fn cli_mount_rss_stays_bounded_without_fsync_bd_dj725() {
    use std::io::Write as _;

    let max_rss_mib = match std::env::var("FFS_TEST_MAX_DAEMON_RSS_MIB") {
        Ok(raw) => raw
            .parse::<u64>()
            .expect("FFS_TEST_MAX_DAEMON_RSS_MIB must be an integer"),
        Err(std::env::VarError::NotPresent) => 1024,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("FFS_TEST_MAX_DAEMON_RSS_MIB must be valid UTF-8");
        }
    };
    assert!(max_rss_mib > 0, "RSS ceiling must be nonzero");
    let ceiling_kib = max_rss_mib
        .checked_mul(1024)
        .expect("RSS ceiling exceeds the KiB measurement range");
    let require = std::env::var_os("FFS_REQUIRE_FUSE").is_some_and(|v| v == "1");
    let prerequisites = Path::new("/dev/fuse").exists()
        && ["mkfs.ext4", "fusermount3"]
            .iter()
            .all(|tool| command_available(tool));
    if !prerequisites {
        assert!(
            !require,
            "FFS_REQUIRE_FUSE=1 but FUSE prerequisites are missing"
        );
        emit_scenario_result("cli_mount_rss_bound", "SKIP", Some("fuse_unavailable"));
        return;
    }
    // One arm: write 2 GiB without fsync; return the two sampled VmRSS peaks
    // and the kernel's whole-process VmHWM, all in KiB.
    let arm = |envs: &[(&str, &str)]| -> Option<([u64; 2], u64)> {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let image = tmp.path().join("rss.ext4");
        format_ext4_owned_by_caller(&image, 4 << 30);
        let mnt = tmp.path().join("mnt");
        fs::create_dir(&mnt).expect("create mountpoint");
        let mut child = spawn_cli_mount(
            &image,
            &mnt,
            &tmp.path().join("mount.log"),
            &["--rw"],
            envs,
            "cli_mount_rss_bound",
            require,
        )?;
        let status_kib = |pid: u32, field: &str| -> u64 {
            fs::read_to_string(format!("/proc/{pid}/status"))
                .unwrap_or_default()
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
                .unwrap_or(0)
        };
        let pid = child.id();
        let chunk: Vec<u8> = (0..1024 * 1024_u32).map(|i| (i % 253) as u8).collect();
        // Peak VmRSS over the first and second GiB written.
        let mut halves = [0_u64; 2];
        {
            let mut file = fs::File::create(mnt.join("big.bin")).unwrap_or_else(|error| {
                sigkill_cli_mount(&mut child, &mnt);
                panic!("create big.bin: {error}");
            });
            for mib in 0..2048_u32 {
                file.write_all(&chunk).unwrap_or_else(|error| {
                    sigkill_cli_mount(&mut child, &mnt);
                    panic!("write MiB {mib}: {error}");
                });
                if mib % 16 == 15 {
                    let half = usize::from(mib >= 1024);
                    halves[half] = halves[half].max(status_kib(pid, "VmRSS:"));
                }
            }
        }
        let peak_kib = status_kib(pid, "VmHWM:");
        sigkill_cli_mount(&mut child, &mnt);
        assert!(
            halves[0] > 0 && halves[1] > 0 && peak_kib >= halves[0].max(halves[1]),
            "could not measure daemon VmRSS/VmHWM: halves={halves:?}, peak={peak_kib} KiB"
        );
        Some((halves, peak_kib))
    };

    let Some(([bounded_first, bounded_second], bounded_peak)) = arm(&[]) else {
        return;
    };
    // Control: eviction disabled. It must show the growth the bound prevents,
    // or this test could pass without measuring anything.
    let Some(([unbounded_first, unbounded_second], unbounded_peak)) =
        arm(&[("FFS_MVCC_RESIDENT_CAP_BLOCKS", "18446744073709551615")])
    else {
        return;
    };
    eprintln!(
        "RSS_BOUND|written_mib=2048|default_cap_kib={bounded_first},{bounded_second}\
         |no_eviction_kib={unbounded_first},{unbounded_second}\
         |default_peak_kib={bounded_peak}|no_eviction_peak_kib={unbounded_peak}\
         |ceiling_kib={ceiling_kib}"
    );
    assert!(
        bounded_peak <= ceiling_kib,
        "daemon peak RSS {bounded_peak} KiB exceeded the configured ceiling \
         {ceiling_kib} KiB during 2 GiB written without fsync"
    );
    // Also check that memory stops growing with the data written. Measured
    // 2026-09-25: ~0.5 GiB with the default cap vs ~1.9 GiB without eviction
    // for the same 1 GiB in the original control. Per-block overhead, transient
    // block copies and allocator retention make the absolute level workload-
    // and allocator-dependent, so retain the growth trend as an independent
    // check alongside the absolute peak ceiling. Exercise the full 2 GiB
    // workload, comparing growth over the same second GiB in both arms:
    // 13 runs on identical daemon code (2026-09-25) grew
    // 33..139 MiB with eviction, so a 64 MiB bound failed ~40% of runs on
    // noise, while the control grew ~650 MiB.
    let bounded_growth = bounded_second.saturating_sub(bounded_first);
    let unbounded_growth = unbounded_second.saturating_sub(unbounded_first);
    assert!(
        unbounded_growth > 512 * 1024,
        "control arm (no eviction) did not grow ({unbounded_first} -> {unbounded_second} \
         KiB): the test is not detecting the growth eviction prevents"
    );
    assert!(
        bounded_growth * 3 < unbounded_growth,
        "daemon RSS kept growing with the default resident cap: +{bounded_growth} KiB over \
         the second GiB vs +{unbounded_growth} KiB without eviction \
         ({bounded_first} -> {bounded_second} KiB)"
    );
    assert!(
        bounded_second * 2 < unbounded_second,
        "eviction must at least halve the daemon's memory for 2 GiB written: \
         {bounded_second} KiB vs {unbounded_second} KiB without it"
    );
    emit_scenario_result("cli_mount_rss_bound", "PASS", None);
}

fn btrfs_commit_sigkill_arm(
    interval_secs: Option<u64>,
    payload: &[u8],
    require: bool,
    pressure_bytes: Option<u64>,
    wait_override_secs: Option<u64>,
    sync_ioctl: bool,
) -> SigkillArm {
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    let tmp = tempfile::tempdir().expect("create temp dir");
    let seed_root = tmp.path().join("seed_root");
    fs::create_dir(&seed_root).expect("create btrfs seed root");
    fs::set_permissions(&seed_root, fs::Permissions::from_mode(0o777))
        .expect("make seeded root writable for unprivileged mounts");
    let image = tmp.path().join("commit.btrfs");
    fs::File::create(&image)
        .and_then(|file| file.set_len(256 << 20))
        .expect("size btrfs image");
    let made = Command::new("mkfs.btrfs")
        .args(["-f", "-q", "--rootdir"])
        .arg(&seed_root)
        .arg(&image)
        .output()
        .expect("run mkfs.btrfs");
    assert!(
        made.status.success(),
        "mkfs.btrfs failed: {}",
        String::from_utf8_lossy(&made.stderr)
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir(&mnt).expect("create mountpoint");
    let interval = interval_secs.map(|secs| secs.to_string());
    let mut args = vec!["--rw", "--log-format", "json"];
    if let Some(interval) = &interval {
        args.extend(["--commit-interval-secs", interval.as_str()]);
    }
    let threshold = pressure_bytes.map(|bytes| bytes.to_string());
    let mut envs = vec![("RUST_LOG", "info")];
    if let Some(threshold) = &threshold {
        envs.push(("FFS_BTRFS_DIRTY_BYTES_THRESHOLD", threshold.as_str()));
    }
    let Some(mut child) = spawn_cli_mount(
        &image,
        &mnt,
        &tmp.path().join("mount.log"),
        &args,
        &envs,
        "cli_mount_btrfs_periodic_commit_sigkill",
        require,
    ) else {
        return SigkillArm::Skipped;
    };
    if let Err(error) = fs::write(mnt.join("durable.bin"), payload) {
        sigkill_cli_mount(&mut child, &mnt);
        panic!("write unsynced btrfs payload: {error}");
    }
    if sync_ioctl {
        // btrfs-progs issues BTRFS_IOC_SYNC directly. Ordinary FUSE mounts do
        // not deliver syncfs(2); its separate regression uses fuseblk.
        let synced = Command::new("btrfs")
            .args(["filesystem", "sync"])
            .arg(&mnt)
            .output();
        if !synced.as_ref().is_ok_and(|output| output.status.success()) {
            sigkill_cli_mount(&mut child, &mnt);
            panic!("BTRFS_IOC_SYNC failed: {synced:?}");
        }
    }
    // The disabled control waits as long as the 30 s default arm, so an
    // unrelated delayed flush cannot masquerade as the default commit timer.
    let wait_secs = wait_override_secs
        .unwrap_or_else(|| interval_secs.filter(|secs| *secs != 0).unwrap_or(30) + 1);
    std::thread::sleep(Duration::from_secs(wait_secs));
    sigkill_cli_mount(&mut child, &mnt);
    if pressure_bytes == Some(1) {
        let logs = fs::read_to_string(tmp.path().join("mount.log")).expect("read pressure log");
        assert!(
            logs.lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|event| event["message"] == "btrfs_pressure_commit"
                    && event["committed"].as_bool() == Some(true)),
            "timer-off writes must cross a real pressure durability boundary: {logs}"
        );
        assert!(
            !logs.contains("periodic_commit_started"),
            "pressure proof must run with the periodic timer disabled: {logs}"
        );
    }
    if interval_secs != Some(0) {
        let logs = fs::read_to_string(tmp.path().join("mount.log")).expect("read daemon log");
        assert!(
            logs.lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|event| event["message"] == "periodic_commit_started"
                    && event["interval_secs"].as_u64() == Some(interval_secs.unwrap_or(30))),
            "btrfs timer must start with the requested or default interval: {logs}"
        );
    }
    let checked = Command::new("btrfs")
        .args(["check", "--readonly"])
        .arg(&image)
        .output()
        .expect("run btrfs check");
    assert!(
        checked.status.success(),
        "btrfs image is inconsistent after SIGKILL (interval={interval_secs:?}): {} {}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    let Some(mut remounted) = spawn_cli_mount(
        &image,
        &mnt,
        &tmp.path().join("remount.log"),
        &[],
        &[],
        "cli_mount_btrfs_periodic_commit_sigkill_remount",
        require,
    ) else {
        return SigkillArm::Skipped;
    };
    let mounted_bytes = fs::read(mnt.join("durable.bin"));
    sigkill_cli_mount(&mut remounted, &mnt);
    match mounted_bytes {
        Ok(bytes) => SigkillArm::Bytes(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => SigkillArm::Missing,
        Err(error) => panic!("read btrfs payload after remount: {error}"),
    }
}

fn periodic_commit_sigkill_arm(
    interval_secs: Option<u64>,
    payload: &[u8],
    require: bool,
) -> SigkillArm {
    use std::time::Duration;

    let tmp = tempfile::tempdir().expect("create temp dir");
    let image = tmp.path().join("commit.ext4");
    format_ext4_owned_by_caller(&image, 64 << 20);
    let mnt = tmp.path().join("mnt");
    fs::create_dir(&mnt).expect("create mountpoint");
    let interval = interval_secs.map(|secs| secs.to_string());
    let mut args = vec!["--rw", "--log-format", "json"];
    if let Some(interval) = &interval {
        args.extend(["--commit-interval-secs", interval.as_str()]);
    }
    let Some(mut child) = spawn_cli_mount(
        &image,
        &mnt,
        &tmp.path().join("mount.log"),
        &args,
        &[("RUST_LOG", "info")],
        "cli_mount_periodic_commit_sigkill",
        require,
    ) else {
        return SigkillArm::Skipped;
    };

    // No fsync, no close-time flush semantics relied on: fs::write only closes.
    if let Err(error) = fs::write(mnt.join("durable.bin"), payload) {
        sigkill_cli_mount(&mut child, &mnt);
        panic!("write through the mount: {error}");
    }
    // The disabled control waits as long as the 5 s default arm.
    let wait_secs = interval_secs.filter(|secs| *secs != 0).unwrap_or(5) + 1;
    std::thread::sleep(Duration::from_secs(wait_secs));
    sigkill_cli_mount(&mut child, &mnt);

    if interval_secs != Some(0) {
        let logs = fs::read_to_string(tmp.path().join("mount.log")).expect("read daemon log");
        assert!(
            logs.lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|event| event["message"] == "periodic_commit_started"
                    && event["interval_secs"].as_u64() == Some(interval_secs.unwrap_or(5))),
            "ext4 timer must start with the requested or default interval: {logs}"
        );
        let commits: Vec<serde_json::Value> = logs
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["message"] == "ext4_journal_checkpoint_durable")
            .collect();
        assert!(
            !commits.is_empty(),
            "periodic commit must report the completed journal boundary: {logs}"
        );
        for commit in commits {
            assert!(commit["journal_sequence"].as_u64().is_some(), "{commit}");
            assert!(
                commit["checkpoint_blocks"]
                    .as_u64()
                    .is_some_and(|blocks| blocks > 0),
                "{commit}"
            );
            assert!(commit["duration_us"].as_u64().is_some(), "{commit}");
        }
    }

    let replay = Command::new("e2fsck")
        .args(["-E", "journal_only", "-y"])
        .arg(&image)
        .output()
        .expect("run e2fsck journal replay");
    assert!(
        replay.status.code().is_some_and(|code| code <= 1),
        "journal replay must succeed after SIGKILL (interval {interval_secs:?}): {}{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    let check = Command::new("e2fsck")
        .arg("-fn")
        .arg(&image)
        .output()
        .expect("run e2fsck -fn");
    assert!(
        check.status.success(),
        "image must be e2fsck-clean after SIGKILL + replay (interval {interval_secs:?}):\n{}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );

    let cat = Command::new("debugfs")
        .args(["-R", "cat /durable.bin"])
        .arg(&image)
        .output()
        .expect("run debugfs cat");
    let stderr = String::from_utf8_lossy(&cat.stderr);
    if stderr.contains("not found") {
        return SigkillArm::Missing;
    }
    if interval_secs != Some(0) {
        let Some(mut remounted) = spawn_cli_mount(
            &image,
            &mnt,
            &tmp.path().join("remount.log"),
            &[],
            &[],
            "cli_mount_periodic_commit_sigkill_remount",
            require,
        ) else {
            return SigkillArm::Skipped;
        };
        let mounted_bytes = fs::read(mnt.join("durable.bin"));
        sigkill_cli_mount(&mut remounted, &mnt);
        assert_eq!(
            mounted_bytes.expect("read durable data after FUSE remount"),
            cat.stdout,
            "FUSE remount must expose the same durable bytes as native debugfs"
        );
    }
    SigkillArm::Bytes(cat.stdout)
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

fn build_gate7_ext4_image() -> Vec<u8> {
    const BLOCK_SIZE: usize = 4096;
    const IMAGE_SIZE: usize = 256 * 1024; // 64 blocks
    const SB_OFF: usize = 1024;
    let mut image = vec![0_u8; IMAGE_SIZE];

    // Superblock
    image[SB_OFF..SB_OFF + 4].copy_from_slice(&128_u32.to_le_bytes()); // s_inodes_count
    image[SB_OFF + 0x04..SB_OFF + 0x08].copy_from_slice(&64_u32.to_le_bytes()); // s_blocks_count_lo
    image[SB_OFF + 0x0C..SB_OFF + 0x10].copy_from_slice(&50_u32.to_le_bytes()); // s_free_blocks_count_lo
    image[SB_OFF + 0x10..SB_OFF + 0x14].copy_from_slice(&117_u32.to_le_bytes()); // s_free_inodes_count
    image[SB_OFF + 0x14..SB_OFF + 0x18].copy_from_slice(&0_u32.to_le_bytes()); // s_first_data_block
    image[SB_OFF + 0x18..SB_OFF + 0x1C].copy_from_slice(&2_u32.to_le_bytes()); // s_log_block_size (4K)
    image[SB_OFF + 0x20..SB_OFF + 0x24].copy_from_slice(&64_u32.to_le_bytes()); // s_blocks_per_group
    image[SB_OFF + 0x28..SB_OFF + 0x2C].copy_from_slice(&128_u32.to_le_bytes()); // s_inodes_per_group
    image[SB_OFF + 0x38..SB_OFF + 0x3A].copy_from_slice(&0xEF53_u16.to_le_bytes()); // s_magic
    image[SB_OFF + 0x3A..SB_OFF + 0x3C].copy_from_slice(&1_u16.to_le_bytes()); // s_state = EXT4_VALID_FS
    image[SB_OFF + 0x4C..SB_OFF + 0x50].copy_from_slice(&1_u32.to_le_bytes()); // s_rev_level
    image[SB_OFF + 0x54..SB_OFF + 0x58].copy_from_slice(&11_u32.to_le_bytes()); // s_first_ino
    image[SB_OFF + 0x58..SB_OFF + 0x5A].copy_from_slice(&256_u16.to_le_bytes()); // s_inode_size
    let incompat: u32 = 0x0002 | 0x0040; // FILETYPE | EXTENTS
    image[SB_OFF + 0x60..SB_OFF + 0x64].copy_from_slice(&incompat.to_le_bytes());
    image[SB_OFF + 0xFE..SB_OFF + 0x100].copy_from_slice(&32_u16.to_le_bytes()); // s_desc_size

    // Group descriptor at block 1
    let gd_off = BLOCK_SIZE;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes()); // block_bitmap
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes()); // inode_bitmap
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes()); // inode_table
    image[gd_off + 0x0C..gd_off + 0x0E].copy_from_slice(&50_u16.to_le_bytes()); // free_blocks_count
    image[gd_off + 0x0E..gd_off + 0x10].copy_from_slice(&117_u16.to_le_bytes()); // free_inodes_count
    image[gd_off + 0x10..gd_off + 0x12].copy_from_slice(&1_u16.to_le_bytes()); // used_dirs_count

    // Block bitmap at block 2: mark blocks 0..=13 allocated
    let bbm = 2 * BLOCK_SIZE;
    image[bbm] = 0xFF;
    image[bbm + 1] = 0x3F;

    // Inode bitmap at block 3: mark inodes 1..=11 allocated
    let ibm = 3 * BLOCK_SIZE;
    image[ibm] = 0xFF;
    image[ibm + 1] = 0x07;

    // Inode #2 (root dir) -> extent at block 12
    let ino2 = 4 * BLOCK_SIZE + 256;
    image[ino2..ino2 + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[ino2 + 4..ino2 + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[ino2 + 0x1A..ino2 + 0x1C].copy_from_slice(&2_u16.to_le_bytes());
    image[ino2 + 0x20..ino2 + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    image[ino2 + 0x80..ino2 + 0x82].copy_from_slice(&32_u16.to_le_bytes());
    let e2 = ino2 + 0x28;
    image[e2..e2 + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[e2 + 2..e2 + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[e2 + 4..e2 + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[e2 + 6..e2 + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[e2 + 12..e2 + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[e2 + 16..e2 + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[e2 + 18..e2 + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[e2 + 20..e2 + 24].copy_from_slice(&12_u32.to_le_bytes());

    // Inode #11 (regular file) -> extent at block 13
    let ino11 = 4 * BLOCK_SIZE + 10 * 256;
    image[ino11..ino11 + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[ino11 + 4..ino11 + 8].copy_from_slice(&6_u32.to_le_bytes());
    image[ino11 + 0x1A..ino11 + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino11 + 0x20..ino11 + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    image[ino11 + 0x80..ino11 + 0x82].copy_from_slice(&32_u16.to_le_bytes());
    let e11 = ino11 + 0x28;
    image[e11..e11 + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[e11 + 2..e11 + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[e11 + 4..e11 + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[e11 + 6..e11 + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[e11 + 12..e11 + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[e11 + 16..e11 + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[e11 + 18..e11 + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[e11 + 20..e11 + 24].copy_from_slice(&13_u32.to_le_bytes());

    // Block 12: root directory entries ".", "..", "hello.txt"
    let d = 12 * BLOCK_SIZE;
    image[d..d + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[d + 4..d + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[d + 6] = 1;
    image[d + 7] = 2;
    image[d + 8] = b'.';

    let d = d + 12;
    image[d..d + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[d + 4..d + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[d + 6] = 2;
    image[d + 7] = 2;
    image[d + 8..d + 10].copy_from_slice(b"..");

    let d = d + 12;
    image[d..d + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[d + 4..d + 6].copy_from_slice(&4072_u16.to_le_bytes());
    image[d + 6] = 9;
    image[d + 7] = 1;
    image[d + 8..d + 17].copy_from_slice(b"hello.txt");

    let b13 = 13 * BLOCK_SIZE;
    image[b13..b13 + 6].copy_from_slice(b"hello\n");

    image
}

#[test]
#[ignore = "canonical spec §22.1 Gate 7: full conformance and user-facing tools"]
fn gate7_full_conformance_and_tools() {
    let tmpdir = tempfile::Builder::new()
        .prefix("ffs-gate7-")
        .tempdir()
        .expect("create temp dir")
        .keep();
    let image = tmpdir.join("gate7.ext4");
    fs::write(&image, build_gate7_ext4_image()).expect("write gate7 ext4 image");
    let image_str = image.to_str().expect("utf-8 path");

    // 1. Inspect (JSON)
    let inspect = run_ffs_cli(&["inspect", "--json", image_str]);
    assert!(
        inspect.status.success(),
        "ffs inspect --json failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_json: serde_json::Value =
        serde_json::from_slice(&inspect.stdout).expect("inspect JSON");
    assert_eq!(inspect_json["filesystem"], "ext4");

    // 2. Info + MVCC info
    let info_out = run_ffs_cli(&["info", "--mvcc", image_str]);
    assert!(
        info_out.status.success(),
        "ffs info --mvcc failed: {}",
        String::from_utf8_lossy(&info_out.stderr)
    );

    // 3. Scrub / fsck (JSON)
    let fsck = run_ffs_cli(&["fsck", "--json", image_str]);
    assert!(
        fsck.status.success(),
        "ffs fsck --json failed: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
    let fsck_json: serde_json::Value = serde_json::from_slice(&fsck.stdout).expect("fsck JSON");
    assert_eq!(fsck_json["outcome"], "clean");
    assert_eq!(fsck_json["exit_code"], 0);

    // 4. Offline JSON plus one continuous mounted TUI process at nominal 1Hz.
    let tui_json_out = run_ffs_cli(&["tui", image_str, "--scrub", "--snapshot-json"]);
    assert!(
        tui_json_out.status.success(),
        "ffs tui --snapshot-json failed: {}",
        String::from_utf8_lossy(&tui_json_out.stderr)
    );
    let tui_snap: serde_json::Value =
        serde_json::from_slice(&tui_json_out.stdout).expect("tui snapshot JSON");
    assert_eq!(tui_snap["fs_type"], "ext4");
    assert!(tui_snap["cache_capacity"].as_u64().unwrap_or(0) > 0);
    assert!(tui_snap["scrub_blocks_scanned"].as_u64().unwrap_or(0) > 0);

    let tui_live = run_live_tui_profile(&image, "captured", false);
    assert!(tui_live.contains("\"image_unchanged\": true"));

    // 5. User-facing error diagnostics and parity declarations
    cli_inspect_empty_file_reports_error();
    cli_inspect_nonexistent_file_returns_error();
    parity_default_reports_declarations_without_execution_credit();
}
