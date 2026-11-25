use super::*;
use ffs_repair::sidecar::{SidecarOptions, protect};
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Condvar;
use tempfile::TempDir;

// A spawned child holds a copy of every open descriptor of this process
// until it execs, and a flock belongs to the open file description: a
// sibling test's mkfs/debugfs child could still hold an image or sidecar
// lock a test had just released, and its re-open failed with WouldBlock
// (flaky on CI and locally). Spawns are counted until the child has exited
// (see `command`); re-opens wait until none is in progress. Spawns never
// wait, so a test holding a device can still run a command.
static SPAWNS_IN_PROGRESS: Mutex<usize> = Mutex::new(0);
static SPAWNS_DONE: Condvar = Condvar::new();

fn wait_for_spawns() {
    let mut count = SPAWNS_IN_PROGRESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while *count > 0 {
        count = SPAWNS_DONE
            .wait(count)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
}

/// Retry a reopen briefly if an external helper (such as `fusermount3` forked
/// inside `fuser::Session::new` on a sibling test thread) momentarily holds an
/// inherited open-file-description `flock` between `fork` and `execve`.
fn retry_transient_flock_ffs<T>(
    mut op: impl FnMut() -> ffs_error::Result<T>,
) -> ffs_error::Result<T> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        wait_for_spawns();
        match op() {
            Err(ffs_error::FfsError::Io(ref err))
                if err.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            other => return other,
        }
    }
}

/// `prepare`, after any in-flight child spawn has exec'd (see above).
pub fn prepare(cx: &Cx, args: &Args) -> Result<Prepared> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        wait_for_spawns();
        match super::prepare(cx, args) {
            Err(err)
                if err
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                    .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::WouldBlock)
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            other => return other,
        }
    }
}

/// Core-only fixtures must select the variant explicitly. Production dispatch
/// stays on `FsOps` and cannot implicitly coerce a native reader into `OpenFs`.
fn core(prepared: &Prepared) -> &OpenFs {
    match prepared.fs.as_ref() {
        ProtectedFs::Core(fs) => Some(fs.as_ref()),
        ProtectedFs::Fat { .. } | ProtectedFs::Ntfs(_) | ProtectedFs::Zfs(_) => None,
    }
    .expect("this fixture requires the ext4/btrfs engine")
}

/// `ffs_repair::sidecar::verify`, after any in-flight child spawn has exec'd.
pub fn verify(
    cx: &Cx,
    image: &Path,
    sidecar: &Path,
) -> ffs_error::Result<ffs_repair::sidecar::SidecarReport> {
    retry_transient_flock_ffs(|| ffs_repair::sidecar::verify(cx, image, sidecar))
}

/// `SidecarImageDevice::open`, after any in-flight child spawn has exec'd.
pub fn open_device(cx: &Cx, image: &Path, sidecar: &Path) -> ffs_error::Result<SidecarImageDevice> {
    retry_transient_flock_ffs(|| SidecarImageDevice::open(cx, image, sidecar))
}

fn check_args(image: &Path, sidecar: &Path) -> Args {
    Args {
        image: image.to_owned(),
        sidecar: sidecar.to_owned(),
        mountpoint: None,
        scrub: scrub::Options::default(),
        set: SetOptions::default(),
        authority: Authority {
            exclusive_image: true,
            allow_repair: true,
        },
        check: true,
        rw: false,
        commit_interval_secs: None,
        allow_other: false,
    }
}

pub fn command_unchecked(command: &mut Command) -> std::io::Result<Output> {
    *SPAWNS_IN_PROGRESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
    let output = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(std::process::Child::wait_with_output);
    // Released only once the child has EXITED: `spawn` returns when execve
    // releases the parent (exec_mmap), before the kernel closes the child's
    // close-on-exec descriptors, so for a moment after `spawn` the child
    // can still hold a sibling test's just-released lock (bd-hi96g).
    {
        let mut count = SPAWNS_IN_PROGRESS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count -= 1;
        if *count == 0 {
            SPAWNS_DONE.notify_all();
        }
    }
    output
}

pub fn command(command: &mut Command) -> Output {
    let output = command_unchecked(command).expect("required filesystem oracle must be installed");
    assert!(
        output.status.success(),
        "oracle failed: {command:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

struct Fixture {
    dir: TempDir,
    image: PathBuf,
    sidecar: PathBuf,
    payload: Vec<u8>,
}

impl Fixture {
    fn ext4() -> Self {
        Self::ext4_with_journal(false)
    }

    fn ext4_with_journal(journalled: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image.ext4");
        let sidecar = dir.path().join("image.ffs-rq");
        File::create(&image)
            .unwrap()
            .set_len(if journalled { 32 } else { 8 } * 1024 * 1024)
            .unwrap();
        command(
            Command::new("mkfs.ext4")
                .args([
                    "-q",
                    "-F",
                    "-b",
                    "4096",
                    "-O",
                    if journalled {
                        "has_journal"
                    } else {
                        "^has_journal"
                    },
                ])
                .arg(&image),
        );
        let payload: Vec<u8> = (0_u32..12_288)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let source = dir.path().join("payload.bin");
        std::fs::write(&source, &payload).unwrap();
        let output = command(
            Command::new("debugfs")
                .args(["-w", "-R"])
                .arg(format!("write {} /payload", source.display()))
                .arg(&image),
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Allocated inode"));
        protect(
            &Cx::for_testing(),
            &image,
            &sidecar,
            SidecarOptions {
                block_size: 4096,
                group_blocks: 16,
                repair_symbols: 4,
            },
        )
        .expect("protect formatted image");
        Self {
            dir,
            image,
            sidecar,
            payload,
        }
    }

    fn args(&self) -> Args {
        check_args(&self.image, &self.sidecar)
    }

    fn first_block(&self, path: &str) -> u64 {
        let output = command(
            Command::new("debugfs")
                .arg("-R")
                .arg(format!("blocks {path}"))
                .arg(&self.image),
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .expect("file must have a physical block")
            .parse()
            .unwrap()
    }

    fn read_block(&self, block: u64) -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        File::open(&self.image)
            .unwrap()
            .read_exact_at(&mut bytes, block * 4096)
            .unwrap();
        bytes
    }

    fn damage_block(&self, block: u64) {
        // Deliberate media-fault injection after admission. Normal operators
        // must never bypass the protected device like this.
        let file = File::options().write(true).open(&self.image).unwrap();
        file.write_all_at(&[0xE7; 4096], block * 4096).unwrap();
        file.sync_all().unwrap();
    }

    fn assert_healthy(&self) {
        assert!(
            verify(&Cx::for_testing(), &self.image, &self.sidecar)
                .unwrap()
                .is_healthy()
        );
        command(Command::new("e2fsck").arg("-fn").arg(&self.image));
    }
}

// This additional lane uses the production CLI and the kernel. The ordinary
// owning suite keeps its direct FsOps checks; CI explicitly requires all three
// mounted results. Fixtures and logs are retained even if a mount cannot retire.
const MOUNTED_REPAIR: &str = r"
import hashlib, json, os, pathlib, shutil, signal, subprocess, sys, time

binary, source, directory, filesystem, first, second = sys.argv[1:]
directory = pathlib.Path(directory)
image, archive = directory / 'image', directory / 'sidecar'
mount = directory / 'mount'
expected = (directory / 'expected').read_bytes()
blocks = [int(first), int(second)]
assert len(set(blocks)) == 2
assert pathlib.Path(binary).is_file() and os.access(binary, os.X_OK)
assert source and pathlib.Path('/dev/fuse').exists()
assert shutil.which('fusermount3') and shutil.which('timeout')
binary_hash = hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()
escapes = {9: b'\\011', 10: b'\\012', 32: b'\\040', 92: b'\\134'}
mount_key = b''.join(escapes.get(b, bytes([b])) for b in os.fsencode(mount))

def mount_id():
    records = pathlib.Path('/proc/self/mountinfo').read_bytes()
    assert records.strip(), 'empty mount table'
    matches = []
    for line in records.split(b'\n'):
        if not line:
            continue
        fields = line.split(b' ')
        assert len(fields) >= 10 and b'-' in fields[6:], 'invalid mount table'
        if fields[4] == mount_key:
            split = fields.index(b'-', 6)
            assert fields[split + 1] == b'fuse.ffs', fields
            matches.append(int(fields[0]))
    assert len(matches) <= 1, 'stacked mounts are not owned by this test'
    return matches[0] if matches else None

def identity(pid):
    try:
        fields = pathlib.Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()
        return fields[19]
    except (FileNotFoundError, ProcessLookupError):
        return None

def helpers(process):
    found = {}
    for task in pathlib.Path('/proc', str(process.pid), 'task').iterdir():
        try:
            children = (task / 'children').read_text().split()
        except FileNotFoundError:
            continue
        for pid in children:
            try:
                name = pathlib.Path('/proc', pid, 'comm').read_text().strip()
                start = identity(pid)
            except FileNotFoundError:
                continue
            if name in ('fusermount', 'fusermount3') and start is not None:
                found[int(pid)] = start
    assert found, 'automatic-unmount helper was not observed'
    return found

client_number = 0
def run(arguments):
    global client_number
    client_number += 1
    stdout = directory / ('client-' + str(client_number) + '.stdout')
    stderr = directory / ('client-' + str(client_number) + '.stderr')
    # Files avoid waiting for pipe EOF if a stuck FUSE client outlives timeout.
    with stdout.open('xb') as out, stderr.open('xb') as err:
        result = subprocess.run(['timeout', '--kill-after=5s', '30s', *map(str, arguments)],
                                stdout=out, stderr=err, timeout=40)
    errors = stderr.read_bytes()
    assert result.returncode == 0, (arguments, result.returncode, errors)
    assert not errors, (arguments, errors)
    return stdout.read_bytes()

def cycle(phase, writable, action):
    assert mount_id() is None
    logfile = directory / (phase + '.log')
    with logfile.open('wb') as output:
        args = [binary, str(image), str(archive), str(mount), '--exclusive-image', '--allow-repair']
        if writable:
            args += ['--rw', '--commit-interval-secs', '0']
        process = subprocess.Popen(args, stdout=output, stderr=output)
        owned = None
        observed = {}
        try:
            deadline = time.monotonic() + 30
            while True:
                assert process.poll() is None, logfile.read_text()
                statuses = []
                for line in logfile.read_text().splitlines():
                    try:
                        statuses.append(json.loads(line))
                    except ValueError:
                        pass
                owned = mount_id()
                if owned is not None and any(s.get('event') == 'mounted' and
                        s.get('filesystem') == filesystem and s.get('read_only') == (not writable)
                        for s in statuses):
                    break
                assert time.monotonic() < deadline, ('mount startup timed out', logfile.read_text())
                time.sleep(0.02)
            observed = helpers(process)
            action()
        finally:
            try:
                # External unmount is the declared shutdown for this lane,
                # including assertion failures. Never rescue a failed automatic
                # cleanup, lazy-detach, or operate on a replacement mount.
                current = mount_id()
                if current is not None:
                    assert owned is not None and current == owned, 'mount identity changed'
                    run(['fusermount3', '-u', mount])
                elif process.poll() is None:
                    process.send_signal(signal.SIGINT)
                assert process.wait(timeout=60) == 0, logfile.read_text()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            assert mount_id() is None, 'owned mount remains attached'
            deadline = time.monotonic() + 10
            while any(identity(pid) == start for pid, start in observed.items()):
                assert time.monotonic() < deadline, ('helper remains', observed)
                time.sleep(0.02)
        print('PROTECTED_MOUNT_PHASE|' + filesystem + '|' + phase + '|PASS|' +
              json.dumps({'source': source, 'binary_sha256': binary_hash,
                          'mount_id': owned, 'observed_helpers': observed}), flush=True)

def repair():
    with image.open('r+b', buffering=0) as raw:
        original = [os.pread(raw.fileno(), 4096, block * 4096) for block in blocks]
        assert all(len(block) == 4096 for block in original)
        for block, before in zip(blocks, original):
            assert os.pwrite(raw.fileno(), bytes([0xE7]) * 4096, block * 4096) == 4096
            assert os.pread(raw.fileno(), 4096, block * 4096) != before
        os.fsync(raw.fileno())
        assert run(['cat', mount / 'payload.bin']) == expected
        assert [os.pread(raw.fileno(), 4096, block * 4096) for block in blocks] == original
        os.fsync(raw.fileno())
        print('PROTECTED_MOUNT_REPAIR|' + json.dumps({
            'filesystem': filesystem, 'blocks': blocks,
            'restored_block_sha256': [hashlib.sha256(block).hexdigest() for block in original],
            'application_sha256': hashlib.sha256(expected).hexdigest()}), flush=True)

cycle('read-repair', False, repair)
if filesystem == 'fat32':
    written = bytes([0xA3]) * 16385
    (directory / 'new-payload').write_bytes(written)
    def write_and_capture():
        # Keep the client descriptor open through capture: neither close/flush
        # nor CLI finalization may rescue a missing fsync publication.
        client = '''
import hashlib, json, os, pathlib, shutil, sys
directory, mount = map(pathlib.Path, sys.argv[1:])
data = (directory / 'new-payload').read_bytes()
with (mount / 'kernel-written.bin').open('wb') as target:
    assert target.write(data) == len(data)
    target.flush()
    os.fsync(target.fileno())
    paths = [directory / 'image', directory / 'sidecar']
    before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    for path, name in zip(paths, ['fsync.image', 'fsync.sidecar']):
        shutil.copyfile(path, directory / name)
    assert [hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ['fsync.image', 'fsync.sidecar']] == before
    assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths] == before
    print('PROTECTED_MOUNT_FSYNC_CAPTURE|' + json.dumps(before), flush=True)
'''
        print(run(['python3', '-c', client, directory, mount]).decode(), end='', flush=True)
        assert run(['cat', mount / 'kernel-written.bin']) == written
    cycle('write-fsync', True, write_and_capture)
    def reopen():
        assert run(['cat', mount / 'kernel-written.bin']) == written
        assert run(['cat', mount / 'payload.bin']) == expected
    cycle('fresh-reopen', False, reopen)
";

fn assert_mounted_repair(fixture: &Fixture, filesystem: &str, blocks: [u64; 2]) {
    if std::env::var_os("FFS_PROTECTED_MOUNT_E2E").as_deref() != Some(OsStr::new("1")) {
        return;
    }
    let binary = std::env::var_os("FFS_PROTECTED_MOUNT_BIN")
        .expect("mounted repair requires the source-bound production CLI");
    let source = std::env::var("FFS_CLI_SOURCE_STAMP")
        .expect("mounted repair requires the production CLI source identity");
    let artifacts = std::env::var_os("FFS_CLI_ARTIFACT_DIR")
        .expect("mounted repair requires a retained artifact directory");
    let directory = tempfile::Builder::new()
        .prefix("ffs-protected-mount-")
        .tempdir_in(artifacts)
        .unwrap()
        .keep();
    println!("PROTECTED_MOUNT_ARTIFACTS|{}", directory.display());
    let image = directory.join("image");
    let archive = directory.join("sidecar");
    // The owning test has finished and verified this pair. Copy both inputs;
    // the new CLI independently admits them without inheriting warmed caches.
    std::fs::copy(&fixture.image, &image).unwrap();
    std::fs::copy(&fixture.sidecar, &archive).unwrap();
    std::fs::write(directory.join("expected"), &fixture.payload).unwrap();
    std::fs::create_dir(directory.join("mount")).unwrap();
    let cx = Cx::for_testing();
    let output = command(
        Command::new("python3")
            .args(["-c", MOUNTED_REPAIR])
            .arg(&binary)
            .arg(&source)
            .arg(&directory)
            .arg(filesystem)
            .arg(blocks[0].to_string())
            .arg(blocks[1].to_string()),
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(verify(&cx, &image, &archive).unwrap().is_healthy());
    if filesystem == "fat32" {
        assert!(
            verify(
                &cx,
                &directory.join("fsync.image"),
                &directory.join("fsync.sidecar"),
            )
            .unwrap()
            .is_healthy(),
            "the capture before CLI shutdown must already have current protection"
        );
        assert_fat_cli_refresh(&directory, &binary, &source);
    }
    println!("PROTECTED_MOUNT_RESULT|{filesystem}|PASS");
}

fn assert_fat_cli_refresh(directory: &Path, protected: &OsStr, source: &str) {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let binary = std::env::var_os("FFS_FAT_BIN")
        .expect("FAT refresh requires the source-bound production CLI");
    let digest = Sha256::digest(std::fs::read(&binary).unwrap());
    let mut binary_hash = String::with_capacity(64);
    for byte in &digest[..] {
        write!(&mut binary_hash, "{byte:02x}").unwrap();
    }
    let image = directory.join("image");
    let archive = directory.join("sidecar");
    let cx = Cx::for_testing();
    // A healthy old image/archive pair is insufficient. Independently read the
    // pre-shutdown capture to prove it contains the acknowledged kernel write.
    for (path, expected) in [
        ("kernel-written.bin", vec![0xA3; 16_385]),
        (
            "payload.bin",
            std::fs::read(directory.join("expected")).unwrap(),
        ),
    ] {
        let output = command(
            Command::new(&binary)
                .arg("cat")
                .arg(directory.join("fsync.image"))
                .arg(path)
                .arg("--sidecar")
                .arg(directory.join("fsync.sidecar")),
        );
        assert_eq!(output.stdout, expected);
    }
    let mutate = |label: &str, operation: &str, paths: &[&str], input: Option<&str>, create| {
        let mut cmd = Command::new(&binary);
        cmd.arg(operation)
            .arg(&image)
            .args(paths)
            .arg("--offline-image")
            .arg("--sidecar")
            .arg(&archive);
        if let Some(input) = input {
            cmd.arg("--source").arg(directory.join(input));
        }
        if create {
            cmd.arg("--create");
        }
        let output = command(&mut cmd);
        std::fs::write(directory.join(format!("cli-{label}.json")), &output.stdout).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["sidecar_refreshed"], true);
        assert!(verify(&cx, &image, &archive).unwrap().is_healthy());
        println!("PROTECTED_FAT_CLI_RESULT|{label}|PASS|source={source}|sha256={binary_hash}");
    };
    let read = |path: &str| {
        command(
            Command::new(&binary)
                .arg("cat")
                .arg(&image)
                .arg(path)
                .arg("--sidecar")
                .arg(&archive),
        )
        .stdout
    };
    mutate("mkdir", "mkdir", &["/cli-dir"], None, false);
    mutate(
        "create",
        "replace",
        &["/cli-dir/created.bin"],
        Some("new-payload"),
        true,
    );
    assert_eq!(read("/cli-dir/created.bin"), vec![0xA3; 16_385]);
    mutate(
        "replace",
        "replace",
        &["/cli-dir/created.bin"],
        Some("expected"),
        false,
    );
    let expected = std::fs::read(directory.join("expected")).unwrap();
    assert_eq!(read("/cli-dir/created.bin"), expected);
    mutate(
        "rename",
        "rename",
        &["/cli-dir/created.bin", "/cli-renamed.bin"],
        None,
        false,
    );
    assert_eq!(read("/cli-renamed.bin"), expected);
    mutate("unlink", "unlink", &["/cli-renamed.bin"], None, false);
    mutate("rmdir", "rmdir", &["/cli-dir"], None, false);
    let volume = fat::reader::FatVolume::open(&cx, &image, 0, None).unwrap();
    for path in ["/cli-dir", "/cli-renamed.bin"] {
        assert!(
            matches!(volume.resolve(&cx, path), Err(FfsError::NotFound(name))
                if name == path.trim_start_matches('/')),
            "removed FAT path must report its exact missing name: {path}"
        );
    }
    drop(volume);
    let checked = command(Command::new("fsck.fat").arg("-n").arg(&image));
    std::fs::write(directory.join("native-fat32.stdout"), &checked.stdout).unwrap();
    std::fs::write(directory.join("native-fat32.stderr"), &checked.stderr).unwrap();

    let formatted = directory.join("formatted.fat16");
    let formatted_archive = directory.join("formatted.sidecar");
    let output = command(
        Command::new(&binary)
            .arg("format")
            .arg(&formatted)
            .args(["--kind", "fat16", "--size-mib", "8", "--sidecar"])
            .arg(&formatted_archive),
    );
    std::fs::write(directory.join("cli-format.json"), &output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["sidecar_refreshed"], true);
    assert!(
        verify(&cx, &formatted, &formatted_archive)
            .unwrap()
            .is_healthy()
    );
    let checked = command(Command::new("fsck.fat").arg("-n").arg(&formatted));
    std::fs::write(directory.join("native-fat16.stdout"), &checked.stdout).unwrap();
    std::fs::write(directory.join("native-fat16.stderr"), &checked.stderr).unwrap();
    let output = command(
        Command::new(protected)
            .arg(&formatted)
            .arg(&formatted_archive)
            .args(["--check", "--exclusive-image", "--allow-repair"]),
    );
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["event"], "checked_not_mounted");
    assert_eq!(status["filesystem"], "fat16");
    assert_eq!(status["read_only"], true);
    println!("PROTECTED_FAT_CLI_RESULT|format|PASS|source={source}|sha256={binary_hash}");
}

#[test]
fn command_requires_authority_and_a_single_execution_mode() {
    let base = ["ffs-protected-mount", "image", "archive", "--check"];
    assert!(Args::try_parse_from(base).is_err());
    assert!(Args::try_parse_from(base.into_iter().chain(["--exclusive-image"])).is_err());
    assert!(Args::try_parse_from(base.into_iter().chain(["--allow-repair"])).is_err());
    let args = Args::try_parse_from(
        base.into_iter()
            .chain(["--exclusive-image", "--allow-repair"]),
    )
    .unwrap();
    assert!(args.check);
    let options = mount_options(&args);
    assert!(options.read_only);
    assert!(!options.allow_other);
    assert!(options.auto_unmount);
    assert!(!options.writeback_cache.is_enabled());
    assert!(
        Args::try_parse_from([
            "ffs-protected-mount",
            "image",
            "archive",
            "mountpoint",
            "--check",
            "--exclusive-image",
            "--allow-repair",
        ])
        .is_err()
    );
}

#[test]
fn invalid_mountpoint_is_rejected_before_device_admission() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("image");
    let sidecar = dir.path().join("archive");
    std::fs::write(&image, b"not an image").unwrap();
    std::fs::write(&sidecar, b"not an archive").unwrap();
    let mut args = check_args(&image, &sidecar);
    args.check = false;
    args.mountpoint = Some(image.clone());
    let error = prepare(&Cx::for_testing(), &args).err().unwrap();
    assert!(error.to_string().contains("not a directory"));
    assert_eq!(std::fs::read(image).unwrap(), b"not an image");
    assert_eq!(std::fs::read(sidecar).unwrap(), b"not an archive");
}

#[test]
fn filesystem_read_repairs_corrupt_data_before_returning_it() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let block = fixture.first_block("/payload");
    let prepared = prepare(&cx, &fixture.args()).expect("open protected filesystem");
    // Select the core variant explicitly; `FsOps` has scope-taking methods.
    let inode = OpenFs::lookup(core(&prepared), &cx, InodeNumber(2), OsStr::new("payload"))
        .unwrap()
        .ino;
    let original = fixture.read_block(block);
    fixture.damage_block(block);
    assert_ne!(fixture.read_block(block), original);
    assert_eq!(
        OpenFs::read(
            core(&prepared),
            &cx,
            inode,
            0,
            u32::try_from(fixture.payload.len()).unwrap()
        )
        .unwrap(),
        fixture.payload,
    );
    assert_eq!(
        fixture.read_block(block),
        original,
        "repair must reach physical storage"
    );
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn filesystem_lookup_repairs_directory_metadata_before_parsing_it() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let block = fixture.first_block("/");
    let prepared = prepare(&cx, &fixture.args()).unwrap();
    let original = fixture.read_block(block);
    fixture.damage_block(block);
    let attr = OpenFs::lookup(core(&prepared), &cx, InodeNumber(2), OsStr::new("payload")).unwrap();
    assert_eq!(attr.size, u64::try_from(fixture.payload.len()).unwrap());
    assert_eq!(fixture.read_block(block), original);
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn startup_difference_is_not_silently_rolled_back() {
    let fixture = Fixture::ext4();
    fixture.damage_block(fixture.first_block("/payload"));
    let damaged = std::fs::read(&fixture.image).unwrap();
    let archive = std::fs::read(&fixture.sidecar).unwrap();
    let error = prepare(&Cx::for_testing(), &fixture.args()).err().unwrap();
    assert!(format!("{error:#}").contains("refusing implicit rollback"));
    assert_eq!(std::fs::read(&fixture.image).unwrap(), damaged);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
}

#[test]
fn pending_epoch_is_not_admitted_or_relabelled_clean() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let device = open_device(&cx, &fixture.image, &fixture.sidecar).unwrap();
    device
        .write_all_at(&cx, ByteOffset(device.len_bytes() - 4096), &[0x5A; 4096])
        .unwrap();
    drop(device);
    let damaged = std::fs::read(&fixture.image).unwrap();
    let pending = std::fs::read(&fixture.sidecar).unwrap();
    let error = prepare(&cx, &fixture.args()).err().unwrap();
    assert!(format!("{error:#}").contains("unfinished write epoch"));
    assert_eq!(std::fs::read(&fixture.image).unwrap(), damaged);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), pending);
}

#[test]
fn readonly_filesystem_and_adapter_cannot_write_caller_data() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.args()).unwrap();
    let before = std::fs::read(&fixture.image).unwrap();
    let device = ProtectedDevice {
        inner: Arc::clone(&prepared.device),
        writable: false,
    };
    assert!(matches!(
        device.write_all_at(&cx, ByteOffset(4096), &[1]),
        Err(FfsError::ReadOnly)
    ));
    let error = OpenFs::create(
        core(&prepared),
        &cx,
        InodeNumber(2),
        OsStr::new("no-write"),
        0o600,
        0,
        0,
    )
    .unwrap_err();
    assert_eq!(error.to_errno(), libc::EROFS);
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(matches!(
        device.write_all_at(&cancelled, ByteOffset(4096), &[1]),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(std::fs::read(&fixture.image).unwrap(), before);
    drop(device);
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn unfinished_dispatch_cannot_be_reported_as_completed_shutdown() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.args()).unwrap();
    let in_flight = Arc::clone(&prepared.fs);
    let error = prepared.finish(&cx).unwrap_err();
    assert!(error.to_string().contains("shutdown is incomplete"));
    assert!(open_device(&cx, &fixture.image, &fixture.sidecar).is_err());
    drop(in_flight);
    let device = open_device(&cx, &fixture.image, &fixture.sidecar).unwrap();
    device.sync(&cx).unwrap();
}

impl Fixture {
    fn writable_args(&self) -> Args {
        let mountpoint = self.dir.path().join("mountpoint");
        std::fs::create_dir_all(&mountpoint).unwrap();
        let mut args = self.args();
        args.check = false;
        args.rw = true;
        args.mountpoint = Some(mountpoint);
        args
    }

    fn btrfs() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image.btrfs");
        let sidecar = dir.path().join("image.ffs-rq");
        File::create(&image)
            .unwrap()
            .set_len(128 * 1024 * 1024)
            .unwrap();
        command(
            Command::new("mkfs.btrfs")
                .args([
                    "-q", "-f", "-n", "16384", "-s", "4096", "-m", "single", "-d", "single",
                ])
                .arg(&image),
        );
        protect(
            &Cx::for_testing(),
            &image,
            &sidecar,
            SidecarOptions {
                block_size: 4096,
                group_blocks: 64,
                repair_symbols: 4,
            },
        )
        .expect("protect btrfs image");
        Self {
            dir,
            image,
            sidecar,
            payload: Vec::new(),
        }
    }
}

fn create_written(prepared: &Prepared, cx: &Cx, parent: InodeNumber, data: &[u8]) -> InodeNumber {
    let inode = OpenFs::create(
        core(prepared),
        cx,
        parent,
        OsStr::new("written"),
        0o600,
        0,
        0,
    )
    .unwrap()
    .ino;
    let written = OpenFs::write(core(prepared), cx, inode, 0, data).unwrap();
    assert_eq!(usize::try_from(written).unwrap(), data.len());
    inode
}

fn assert_file(prepared: &Prepared, cx: &Cx, parent: InodeNumber, name: &str, data: &[u8]) {
    let attr = OpenFs::lookup(core(prepared), cx, parent, OsStr::new(name)).unwrap();
    assert_eq!(attr.size, u64::try_from(data.len()).unwrap());
    assert_eq!(
        OpenFs::read(
            core(prepared),
            cx,
            attr.ino,
            0,
            u32::try_from(data.len()).unwrap(),
        )
        .unwrap(),
        data,
    );
}

/// Capture the pair only AFTER the synchronous filesystem barrier has returned,
/// with no other thread mutating it. Reopening an independent copy bypasses the
/// original process's MVCC and block caches and tests archive publication timing.
fn assert_published(fixture: &Fixture, parent: InodeNumber, data: &[u8]) {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("captured.image");
    let sidecar = dir.path().join("captured.ffsrq");
    std::fs::copy(&fixture.image, &image).unwrap();
    std::fs::copy(&fixture.sidecar, &sidecar).unwrap();
    let cx = Cx::for_testing();
    assert!(verify(&cx, &image, &sidecar).unwrap().is_healthy());
    let reopened = prepare(&cx, &check_args(&image, &sidecar)).expect("admit captured protection");
    assert_file(&reopened, &cx, parent, "written", data);
    reopened.finish(&cx).unwrap();
}

#[test]
fn rw_requires_a_mount_and_keeps_kernel_writeback_disabled() {
    let args = Args::try_parse_from([
        "ffs-protected-mount",
        "image",
        "archive",
        "mountpoint",
        "--rw",
        "--exclusive-image",
        "--allow-repair",
    ])
    .unwrap();
    assert!(args.rw);
    let options = mount_options(&args);
    assert!(!options.read_only);
    assert!(options.auto_unmount);
    assert!(!options.writeback_cache.is_enabled());
    assert!(
        Args::try_parse_from([
            "ffs-protected-mount",
            "image",
            "archive",
            "--check",
            "--rw",
            "--exclusive-image",
            "--allow-repair",
        ])
        .is_err()
    );
    let mut direct = check_args(Path::new("absent-image"), Path::new("absent-sidecar"));
    direct.rw = true;
    assert!(
        checked_paths(&direct)
            .unwrap_err()
            .to_string()
            .contains("--check")
    );
}

#[test]
fn periodic_commit_options_require_writable_mount() {
    let base = [
        "ffs-protected-mount",
        "image",
        "archive",
        "mount",
        "--exclusive-image",
        "--allow-repair",
    ];
    for seconds in ["0", "1", "30"] {
        assert!(
            Args::try_parse_from(base.into_iter().chain(["--commit-interval-secs", seconds,]))
                .is_err()
        );
        let args = Args::try_parse_from(base.into_iter().chain([
            "--rw",
            "--commit-interval-secs",
            seconds,
        ]))
        .unwrap();
        assert_eq!(args.commit_interval_secs, Some(seconds.parse().unwrap()));
    }
    let defaults = Args::try_parse_from(base.into_iter().chain(["--rw"])).unwrap();
    assert!(defaults.commit_interval_secs.is_none());
    assert!(
        Args::try_parse_from(
            base.into_iter()
                .chain(["--rw", "--commit-interval-secs", "-1",])
        )
        .is_err()
    );
}

#[test]
fn disabled_periodic_commit_retains_no_filesystem_owner() {
    let fixture = Fixture::ext4();
    let runtime = mount_worker::mount_background_runtime().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    let worker = mount_worker::start_periodic_commit(
        &cx,
        &runtime,
        &prepared.fs,
        Some(std::time::Duration::ZERO),
        "disabled-test",
    )
    .unwrap();
    assert!(worker.is_none());
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn stopped_periodic_commit_releases_filesystem_before_final_checkpoint() {
    let fixture = Fixture::ext4();
    let runtime = mount_worker::mount_background_runtime().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    let mut worker = mount_worker::start_periodic_commit(
        &cx,
        &runtime,
        &prepared.fs,
        Some(std::time::Duration::from_hours(24)),
        "stop-test",
    )
    .unwrap()
    .unwrap();
    let written = [0x57; 8193];
    create_written(&prepared, &cx, InodeNumber(2), &written);
    worker.request_stop().unwrap();
    worker.stop().unwrap();
    prepared
        .finish(&cx)
        .expect("stopped worker must not retain the filesystem");
    assert_published(&fixture, InodeNumber(2), &written);
    fixture.assert_healthy();
}

#[test]
fn writable_ext4_finish_persists_noninline_data_and_namespace() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let before = std::fs::read(&fixture.sidecar).unwrap();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    assert!(prepared.fs.is_writable());
    let data: Vec<u8> = (0_u32..65_553)
        .map(|index| u8::try_from(index % 239).unwrap())
        .collect();
    create_written(&prepared, &cx, InodeNumber(2), &data);
    // No caller fsync: shutdown must drain the filesystem, not just the device.
    prepared.finish(&cx).unwrap();
    assert_ne!(std::fs::read(&fixture.sidecar).unwrap(), before);
    fixture.assert_healthy();
    assert_published(&fixture, InodeNumber(2), &data);
    let reopened = prepare(&cx, &fixture.args()).unwrap();
    assert_file(&reopened, &cx, InodeNumber(2), "payload", &fixture.payload);
    reopened.finish(&cx).unwrap();
}

#[test]
fn protected_journalled_ext4_uses_internal_writer_and_publishes_fsync_bd_7zjfh() {
    let fixture = Fixture::ext4_with_journal(true);
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    assert!(
        core(&prepared)
            .ext4_superblock()
            .unwrap()
            .has_compat(ffs_ondisk::Ext4CompatFeatures::HAS_JOURNAL)
    );
    assert!(
        core(&prepared).has_jbd2_writer(),
        "protected journalled ext4 must not bypass the ordinary journal durability rule"
    );
    let data: Vec<u8> = (0_u32..65_553)
        .map(|index| u8::try_from(index % 239).unwrap())
        .collect();
    let inode = create_written(&prepared, &cx, InodeNumber(2), &data);
    FsOps::fsync(
        prepared.fs.as_ref(),
        &cx,
        &mut RequestScope::empty(),
        inode,
        0,
        false,
    )
    .unwrap();
    assert_published(&fixture, InodeNumber(2), &data);
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
    let reopened = prepare(&cx, &fixture.args()).unwrap();
    assert_file(&reopened, &cx, InodeNumber(2), "written", &data);
    assert_file(&reopened, &cx, InodeNumber(2), "payload", &fixture.payload);
    reopened.finish(&cx).unwrap();
}

#[test]
fn protected_journalled_ext4_refuses_missing_or_empty_journal_bd_7zjfh() {
    for (mutation, diagnostic) in [
        (
            "set_super_value journal_inum 0",
            "no JBD2 writer is attached",
        ),
        (
            "set_inode_field <8> block[0] 0x0000f30a",
            "no JBD2 writer is attached",
        ),
    ] {
        let mut fixture = Fixture::ext4_with_journal(true);
        let cx = Cx::for_testing();
        let original = prepare(&cx, &fixture.args()).unwrap();
        assert_eq!(core(&original).ext4_superblock().unwrap().journal_inum, 8);
        let original_inode = core(&original).read_inode(&cx, InodeNumber(8)).unwrap();
        assert_ne!(original_inode.flags & ffs_types::EXT4_EXTENTS_FL, 0);
        let (original_header, _) =
            ffs_ondisk::parse_extent_tree(&original_inode.extent_bytes).unwrap();
        assert_eq!(original_header.depth, 0);
        assert!(original_header.entries > 0);
        original.finish(&cx).unwrap();
        command(
            Command::new("debugfs")
                .args(["-w", "-R", mutation])
                .arg(&fixture.image),
        );
        // Preserve a valid leaf header while clearing eh_entries. An invalid
        // magic fails earlier during read-only fast-commit inspection, even
        // with replay skipped; this empty mapping must reach the writer guard.
        // Fresh protection makes the missing journal, not stale parity, the
        // reason write admission refuses this filesystem.
        fixture.sidecar = fixture.dir.path().join("invalid-journal.ffsrq");
        protect(
            &Cx::for_testing(),
            &fixture.image,
            &fixture.sidecar,
            SidecarOptions {
                block_size: 4096,
                group_blocks: 16,
                repair_symbols: 4,
            },
        )
        .unwrap();
        let source = std::fs::read(&fixture.image).unwrap();
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        let readonly = prepare(&cx, &fixture.args()).unwrap();
        if mutation == "set_super_value journal_inum 0" {
            assert_eq!(core(&readonly).ext4_superblock().unwrap().journal_inum, 0);
        } else {
            assert_eq!(core(&readonly).ext4_superblock().unwrap().journal_inum, 8);
            let inode = core(&readonly).read_inode(&cx, InodeNumber(8)).unwrap();
            let (header, tree) = ffs_ondisk::parse_extent_tree(&inode.extent_bytes).unwrap();
            assert_eq!(header.magic, original_header.magic);
            assert_eq!(header.max_entries, original_header.max_entries);
            assert_eq!(header.depth, 0);
            assert_eq!(header.entries, 0, "debugfs must clear the journal mapping");
            assert_eq!(tree, ffs_ondisk::ExtentTree::Leaf(Vec::new()));
        }
        assert_file(&readonly, &cx, InodeNumber(2), "payload", &fixture.payload);
        readonly.finish(&cx).unwrap();
        let error = prepare(&Cx::for_testing(), &fixture.writable_args())
            .err()
            .expect("journalled write admission must fail");
        assert!(format!("{error:#}").contains(diagnostic), "{error:#}");
        assert_eq!(std::fs::read(&fixture.image).unwrap(), source);
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
        let cx = Cx::for_testing();
        let readonly = prepare(&cx, &fixture.args()).unwrap();
        assert_file(&readonly, &cx, InodeNumber(2), "payload", &fixture.payload);
        readonly.finish(&cx).unwrap();
        assert_eq!(std::fs::read(&fixture.image).unwrap(), source);
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
    }
}

#[test]
fn filesystem_fsync_and_fdatasync_publish_each_new_protection_point() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    let inode = create_written(&prepared, &cx, InodeNumber(2), &[0; 8193]);
    for (datasync, byte) in [(false, 0x37), (true, 0x92)] {
        let data = vec![byte; 8193];
        let written = OpenFs::write(core(&prepared), &cx, inode, 0, &data).unwrap();
        assert_eq!(usize::try_from(written).unwrap(), data.len());
        FsOps::fsync(
            prepared.fs.as_ref(),
            &cx,
            &mut RequestScope::empty(),
            inode,
            0,
            datasync,
        )
        .unwrap();
        // This must work BEFORE finish(), which would otherwise hide a missing
        // sidecar refresh at the actual filesystem fsync boundary.
        assert_published(&fixture, InodeNumber(2), &data);
    }
    prepared.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn refreshed_protection_repairs_new_file_bytes_after_reopen() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    let data = vec![0x6D; 65_553];
    create_written(&prepared, &cx, InodeNumber(2), &data);
    prepared.finish(&cx).unwrap();
    let block = fixture.first_block("/written");
    let original = fixture.read_block(block);
    let reopened = prepare(&cx, &fixture.args()).unwrap();
    fixture.damage_block(block);
    assert_file(&reopened, &cx, InodeNumber(2), "written", &data);
    assert_eq!(fixture.read_block(block), original);
    reopened.finish(&cx).unwrap();
    fixture.assert_healthy();
}

#[test]
fn rw_still_refuses_startup_mismatch_and_pending_epochs_without_mutation() {
    for pending in [false, true] {
        let fixture = Fixture::ext4();
        let cx = Cx::for_testing();
        let block = fixture.first_block("/payload");
        if pending {
            let device = open_device(&cx, &fixture.image, &fixture.sidecar).unwrap();
            device
                .write_all_at(&cx, ByteOffset(block * 4096), &[0x5A; 4096])
                .unwrap();
        } else {
            fixture.damage_block(block);
        }
        let image = std::fs::read(&fixture.image).unwrap();
        let archive = std::fs::read(&fixture.sidecar).unwrap();
        let error = prepare(&cx, &fixture.writable_args()).err().unwrap();
        let expected = if pending {
            "unfinished write epoch"
        } else {
            "refusing implicit rollback"
        };
        assert!(format!("{error:#}").contains(expected));
        assert_eq!(std::fs::read(&fixture.image).unwrap(), image);
        assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
    }
}

#[test]
fn shutdown_uses_an_uncancelled_capability_to_persist_writes() {
    let fixture = Fixture::ext4();
    let startup = Cx::for_testing();
    let prepared = prepare(&startup, &fixture.writable_args()).unwrap();
    let data = vec![0x47; 16_385];
    create_written(&prepared, &startup, InodeNumber(2), &data);
    startup.set_cancel_requested(true);
    prepared.finish(&Cx::for_testing()).unwrap();
    fixture.assert_healthy();
    assert_published(&fixture, InodeNumber(2), &data);
}

#[test]
fn archive_publication_failure_is_a_failed_filesystem_shutdown() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    create_written(&prepared, &cx, InodeNumber(2), &[0x4B; 8193]);
    // Deliberately obstruct atomic archive replacement after admission. This
    // is fault injection, not a supported operator namespace change.
    let retained = fixture.dir.path().join("retained.ffsrq");
    std::fs::rename(&fixture.sidecar, &retained).unwrap();
    std::fs::create_dir(&fixture.sidecar).unwrap();
    let error = prepared.finish(&cx).unwrap_err();
    assert!(format!("{error:#}").contains("checkpoint protected filesystem"));
    assert!(open_device(&cx, &fixture.image, &retained).is_err());
}

#[test]
fn writable_shutdown_does_not_flush_while_dispatch_still_owns_the_filesystem() {
    let fixture = Fixture::ext4();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    create_written(&prepared, &cx, InodeNumber(2), &[0x51; 8193]);
    let image = std::fs::read(&fixture.image).unwrap();
    let archive = std::fs::read(&fixture.sidecar).unwrap();
    let in_flight = Arc::clone(&prepared.fs);
    let error = prepared.finish(&cx).unwrap_err();
    assert!(error.to_string().contains("shutdown is incomplete"));
    assert_eq!(std::fs::read(&fixture.image).unwrap(), image);
    assert_eq!(std::fs::read(&fixture.sidecar).unwrap(), archive);
    assert!(open_device(&cx, &fixture.image, &fixture.sidecar).is_err());
    // The surviving dispatcher, not finish(), owns any subsequent persistence.
    FsOps::fsyncdir(
        in_flight.as_ref(),
        &cx,
        &mut RequestScope::empty(),
        InodeNumber(1),
        0,
        false,
    )
    .unwrap();
    drop(in_flight);
    fixture.assert_healthy();
}

#[test]
fn writable_btrfs_finish_publishes_data_roots_and_matching_protection() {
    let fixture = Fixture::btrfs();
    let cx = Cx::for_testing();
    let prepared = prepare(&cx, &fixture.writable_args()).unwrap();
    assert_eq!(prepared.filesystem, "btrfs");
    assert!(prepared.fs.is_writable());
    let data: Vec<u8> = (0_u32..65_553)
        .map(|index| u8::try_from(index % 241).unwrap())
        .collect();
    create_written(&prepared, &cx, InodeNumber(1), &data);
    prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
    command(
        Command::new("btrfs")
            .args(["check", "--readonly"])
            .arg(&fixture.image),
    );
    assert_published(&fixture, InodeNumber(1), &data);
}

#[test]
fn protected_mount_fat32_repairs_multi_block_corruption_and_refreshes_on_rw_bd_q19uk() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("image.fat32");
    let sidecar = dir.path().join("image.ffs-rq");
    let cx = Cx::for_testing();
    File::create(&image)
        .unwrap()
        .set_len(36 * 1024 * 1024)
        .unwrap();
    command(
        Command::new("mkfs.fat")
            .args(["-F", "32", "-S", "512", "-s", "1"])
            .arg(&image),
    );
    let payload: Vec<u8> = (0_u32..16_384).map(|i| (i % 251) as u8).collect();
    {
        let volume = fat::reader::replacement::open_volume(
            &cx,
            &fat::reader::ImageArgs {
                image: image.clone(),
                offset: 0,
                length: None,
                oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii,
                sidecar: None,
            },
            true,
        )
        .unwrap();
        fat::reader::replacement::create_in_volume(
            &cx,
            &volume,
            "/payload.bin",
            &payload,
            1_700_000_000,
            false,
        )
        .unwrap();
    }
    protect(
        &cx,
        &image,
        &sidecar,
        SidecarOptions {
            block_size: 4096,
            group_blocks: 16,
            repair_symbols: 4,
        },
    )
    .expect("protect fat32 image");

    let fixture = Fixture {
        dir,
        image,
        sidecar,
        payload,
    };

    // Find physical 4096-byte blocks of /payload.bin
    let data_block_0 = {
        let vol = fat::reader::FatVolume::open(&cx, &fixture.image, 0, None).unwrap();
        let entry = vol.resolve(&cx, "/payload.bin").unwrap().unwrap();
        let chain = vol.file_chain(&cx, &entry).unwrap();
        assert!(chain.clusters.len() >= 2);
        let offset = fixture.read_block(0);
        let _ = offset;
        let bpb =
            ffs_ondisk::fat::FatGeometry::parse(&fixture.read_block(0)[..512], 64 * 1024 * 1024)
                .unwrap();
        bpb.cluster_offset(chain.clusters[0]).unwrap() / 4096
    };
    let data_block_1 = data_block_0 + 1;
    let orig_0 = fixture.read_block(data_block_0);
    let orig_1 = fixture.read_block(data_block_1);

    let prepared = prepare(&cx, &fixture.args()).expect("admit protected fat32");
    assert_eq!(prepared.filesystem, "fat32");
    // Inject multi-block corruption (2 blocks in the same group!)
    fixture.damage_block(data_block_0);
    fixture.damage_block(data_block_1);
    assert_ne!(fixture.read_block(data_block_0), orig_0);
    assert_ne!(fixture.read_block(data_block_1), orig_1);

    let mut scope = RequestScope::empty();
    let attr = FsOps::lookup(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        InodeNumber(1),
        OsStr::new("payload.bin"),
    )
    .unwrap();
    let read_back = FsOps::read(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        attr.ino,
        0,
        u32::try_from(fixture.payload.len()).unwrap(),
    )
    .unwrap();
    assert_eq!(read_back, fixture.payload);
    assert_eq!(
        fixture.read_block(data_block_0),
        orig_0,
        "block 0 must be self-healed on disk"
    );
    assert_eq!(
        fixture.read_block(data_block_1),
        orig_1,
        "block 1 must be self-healed on disk"
    );
    prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );

    // Enable writable FsOps, write a new file, and verify protection on finish.
    let rw_prepared = prepare(&cx, &fixture.writable_args()).expect("admit writable fat32");
    assert!(rw_prepared.fs.is_writable());
    let new_data = vec![0xA7_u8; 12_288];
    let created = FsOps::create(
        rw_prepared.fs.as_ref(),
        &cx,
        &mut scope,
        InodeNumber(1),
        OsStr::new("written.bin"),
        0o644,
        0,
        0,
    )
    .unwrap();
    let written = FsOps::write(
        rw_prepared.fs.as_ref(),
        &cx,
        &mut scope,
        created.ino,
        0,
        &new_data,
    )
    .unwrap();
    assert_eq!(written as usize, new_data.len());
    rw_prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
    assert_mounted_repair(&fixture, "fat32", [data_block_0, data_block_1]);
}

#[test]
fn protected_mount_ntfs_repairs_multi_block_corruption_on_read_bd_q19uk() {
    let dir = tempfile::tempdir().unwrap();
    let image_path = dir.path().join("image.ntfs");
    let sidecar_path = dir.path().join("image.ffs-rq");
    let cx = Cx::for_testing();

    // Construct a 1 MiB NTFS 3.1 fixture with 512-byte sectors/clusters and a
    // 12 KiB non-resident file.
    let length = 1024 * 1024_usize;
    let mut image = vec![0_u8; length];
    let boot = &mut image[..512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = 1;
    boot[21] = 0xF8;
    boot[40..48].copy_from_slice(&2047_u64.to_le_bytes());
    boot[48..56].copy_from_slice(&4_u64.to_le_bytes());
    boot[56..64].copy_from_slice(&128_u64.to_le_bytes());
    boot[64] = 0xF6;
    boot[68] = 0xF4;
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);

    let resident = |kind: u32, id: u16, name: &str, value: &[u8]| -> Vec<u8> {
        let name: Vec<_> = name.encode_utf16().collect();
        let start = (24 + name.len() * 2).next_multiple_of(8);
        let len = (start + value.len()).next_multiple_of(8);
        let mut attr = vec![0; len];
        attr[..4].copy_from_slice(&kind.to_le_bytes());
        attr[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        attr[9] = name.len() as u8;
        attr[10..12].copy_from_slice(&24_u16.to_le_bytes());
        attr[14..16].copy_from_slice(&id.to_le_bytes());
        attr[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        attr[20..22].copy_from_slice(&(start as u16).to_le_bytes());
        for (idx, unit) in name.iter().enumerate() {
            attr[24 + idx * 2..26 + idx * 2].copy_from_slice(&unit.to_le_bytes());
        }
        attr[start..start + value.len()].copy_from_slice(value);
        attr
    };
    let mapped = |pairs: &[u8], clusters: u64, size: u64| -> Vec<u8> {
        let start = 64_usize;
        let len = (start + pairs.len()).next_multiple_of(8);
        let mut attr = vec![0; len];
        attr[..4].copy_from_slice(&0x80_u32.to_le_bytes());
        attr[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        attr[8] = 1;
        attr[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
        attr[32..34].copy_from_slice(&(start as u16).to_le_bytes());
        attr[40..48].copy_from_slice(&(clusters * 512).to_le_bytes());
        attr[48..56].copy_from_slice(&size.to_le_bytes());
        attr[56..64].copy_from_slice(&size.to_le_bytes());
        attr[start..start + pairs.len()].copy_from_slice(pairs);
        attr
    };
    let mut std_info = [0_u8; 72];
    for i in 0..4 {
        std_info[i * 8..i * 8 + 8].copy_from_slice(&116_444_736_000_000_000_u64.to_le_bytes());
    }
    let standard = resident(0x10, 500, "", &std_info);
    let filename = |parent: u64, name: &str, ns: u8| -> Vec<u8> {
        let units: Vec<_> = name.encode_utf16().collect();
        let mut bytes = vec![0; 66 + units.len() * 2];
        bytes[..8].copy_from_slice(&((7_u64 << 48) | parent).to_le_bytes());
        bytes[64] = units.len() as u8;
        bytes[65] = ns;
        for (i, u) in units.iter().enumerate() {
            bytes[66 + i * 2..68 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        bytes
    };
    let make_record = |number: u32, directory: bool, links: u16, attrs: &[Vec<u8>]| -> Vec<u8> {
        let mut raw = vec![0; 1024];
        raw[..4].copy_from_slice(b"FILE");
        raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
        raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
        raw[16..18].copy_from_slice(&7_u16.to_le_bytes());
        raw[18..20].copy_from_slice(&links.to_le_bytes());
        raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
        raw[22..24].copy_from_slice(&(if directory { 3_u16 } else { 1 }).to_le_bytes());
        raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
        raw[44..48].copy_from_slice(&number.to_le_bytes());
        let mut at = 56;
        for attr in attrs {
            raw[at..at + attr.len()].copy_from_slice(attr);
            at += attr.len();
        }
        raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        raw[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
        raw[48..50].copy_from_slice(&0x1234_u16.to_le_bytes());
        for part in 1..=2 {
            let saved = [raw[part * 512 - 2], raw[part * 512 - 1]];
            raw[48 + part * 2..50 + part * 2].copy_from_slice(&saved);
            raw[part * 512 - 2..part * 512].copy_from_slice(&0x1234_u16.to_le_bytes());
        }
        raw
    };
    let put = |img: &mut [u8], number: u32, bytes: &[u8]| {
        let at = 4 * 512 + number as usize * 1024;
        img[at..at + 1024].copy_from_slice(bytes);
    };
    let mft = make_record(
        0,
        false,
        1,
        &[
            mapped(&[0x11, 80, 4, 0], 80, 40960),
            resident(0xB0, 1, "", &[0xFF, 0, 0, 0x01, 0]),
        ],
    );
    put(&mut image, 0, &mft);
    image[128 * 512..130 * 512].copy_from_slice(&mft);
    // Supply the native journal required by clean-only NTFS admission. Its
    // fully initialized erased bytes are disjoint from MFT, mirror, UpCase
    // and the protected file payload; no recovery bypass is involved.
    put(
        &mut image,
        2,
        &make_record(
            2,
            false,
            1,
            &[
                standard.clone(),
                mapped(&[0x21, 64, 0xC0, 0, 0], 64, 32_768),
            ],
        ),
    );
    image[192 * 512..256 * 512].fill(0xFF);
    let mut vol_info = [0_u8; 12];
    vol_info[8..10].copy_from_slice(&[3, 1]);
    put(
        &mut image,
        3,
        &make_record(3, false, 1, &[resident(0x70, 0, "", &vol_info)]),
    );
    let mut root_idx = vec![0_u8; 32];
    root_idx[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root_idx[4..8].copy_from_slice(&1_u32.to_le_bytes());
    root_idx[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    root_idx[12] = 8;
    root_idx[16..20].copy_from_slice(&16_u32.to_le_bytes());
    {
        let val = filename(5, "payload.bin", 1);
        let len = (16 + val.len()).next_multiple_of(8);
        let mut entry = vec![0_u8; len];
        entry[..8].copy_from_slice(&((7_u64 << 48) | 0x0018).to_le_bytes());
        entry[8..10].copy_from_slice(&(len as u16).to_le_bytes());
        entry[10..12].copy_from_slice(&(val.len() as u16).to_le_bytes());
        entry[16..16 + val.len()].copy_from_slice(&val);
        root_idx.extend(entry);
    }
    let mut last_entry = [0_u8; 16];
    last_entry[8] = 16;
    last_entry[12] = 2;
    root_idx.extend(last_entry);
    let used = root_idx.len() as u32 - 16;
    root_idx[20..24].copy_from_slice(&used.to_le_bytes());
    root_idx[24..28].copy_from_slice(&used.to_le_bytes());
    put(
        &mut image,
        5,
        &make_record(
            5,
            true,
            1,
            &[
                standard.clone(),
                // Native root name: self-reference in the Win32/DOS namespace.
                resident(0x30, 501, "", &filename(5, ".", 3)),
                resident(0x90, 40, "$I30", &root_idx),
            ],
        ),
    );
    put(
        &mut image,
        6,
        &make_record(6, false, 1, &[resident(0x80, 0, "", &[0xFF; 256])]),
    );
    // $UpCase at LCN 300 (256 sectors = 128 KiB)
    put(
        &mut image,
        10,
        &make_record(
            10,
            false,
            1,
            &[mapped(&[0x22, 0, 1, 44, 1, 0], 256, 131_072)],
        ),
    );
    for unit in 0..=u16::MAX {
        let upper = if (97..=122).contains(&unit) {
            unit - 32
        } else {
            unit
        };
        let at = 300 * 512 + usize::from(unit) * 2;
        image[at..at + 2].copy_from_slice(&upper.to_le_bytes());
    }
    // Record 24: non-resident 12 KiB file at LCN 640 (byte offset 327,680 = 4096-block 80)
    // Mapping pairs for 24 clusters starting at LCN 640 (0x0280): [0x21, 24, 0x80, 0x02, 0]
    let payload: Vec<u8> = (0_u32..12_288).map(|i| (i % 241) as u8).collect();
    image[640 * 512..640 * 512 + payload.len()].copy_from_slice(&payload);
    put(
        &mut image,
        24,
        &make_record(
            24,
            false,
            1,
            &[
                standard,
                mapped(&[0x21, 24, 0x80, 0x02, 0], 24, payload.len() as u64),
                resident(0x30, 2, "", &filename(5, "payload.bin", 1)),
            ],
        ),
    );

    std::fs::write(&image_path, &image).unwrap();
    protect(
        &cx,
        &image_path,
        &sidecar_path,
        SidecarOptions {
            block_size: 4096,
            group_blocks: 16,
            repair_symbols: 4,
        },
    )
    .expect("protect ntfs image");

    let fixture = Fixture {
        dir,
        image: image_path,
        sidecar: sidecar_path,
        payload,
    };

    // Refuse --rw for NTFS
    assert!(prepare(&cx, &fixture.writable_args()).is_err());

    let prepared = prepare(&cx, &fixture.args()).expect("admit protected ntfs");
    assert_eq!(prepared.filesystem, "ntfs");
    assert_eq!(
        std::fs::read(&fixture.image).unwrap(),
        image,
        "clean NTFS preparation must not alter the native journal or backing bytes"
    );

    // Corrupt TWO 4096-byte blocks in the file's data region (blocks 80 and 81)
    let orig_80 = fixture.read_block(80);
    let orig_81 = fixture.read_block(81);
    fixture.damage_block(80);
    fixture.damage_block(81);
    assert_ne!(fixture.read_block(80), orig_80);
    assert_ne!(fixture.read_block(81), orig_81);

    let mut scope = RequestScope::empty();
    let attr = FsOps::lookup(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        InodeNumber(1),
        OsStr::new("payload.bin"),
    )
    .unwrap();
    let read_back = FsOps::read(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        attr.ino,
        0,
        u32::try_from(fixture.payload.len()).unwrap(),
    )
    .unwrap();
    assert_eq!(read_back, fixture.payload);
    assert_eq!(
        fixture.read_block(80),
        orig_80,
        "NTFS block 80 must be self-healed on disk"
    );
    assert_eq!(
        fixture.read_block(81),
        orig_81,
        "NTFS block 81 must be self-healed on disk"
    );
    prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
    assert_mounted_repair(&fixture, "ntfs", [80, 81]);
}

#[test]
fn protected_mount_zfs_repairs_multi_block_corruption_on_read_bd_q19uk() {
    use ffs_ondisk::zfs::{
        DATA_OFFSET, Endian, LABEL_BYTES, LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET,
        UBERBLOCK_RING_OFFSET, checksum, label_offsets,
    };
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let image_path = dir.path().join("image.zfs");
    let sidecar_path = dir.path().join("image.ffs-rq");
    let cx = Cx::for_testing();

    let length = 8 * 1024 * 1024_usize;
    let order = Endian::Little;
    let mut image = vec![0_u8; length];

    let u16put = |raw: &mut [u8], at: usize, value: u16| {
        raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
    };
    let bp = |raw: &[u8], at: u64, kind: u8, level: u8, birth: u64| -> Vec<u8> {
        let mut words = [0_u64; 16];
        words[0] = raw.len() as u64 / 512;
        words[1] = (at - DATA_OFFSET) / 512;
        words[6] = (raw.len() as u64 / 512 - 1)
            | ((raw.len() as u64 / 512 - 1) << 16)
            | (2 << 32)
            | (7 << 40)
            | (u64::from(kind) << 48)
            | (u64::from(level) << 56)
            | (1_u64 << 63);
        words[10] = birth;
        words[12..].copy_from_slice(&checksum(raw, 7, order).unwrap());
        words.into_iter().flat_map(|w| order.encode(w)).collect()
    };
    let node =
        |kind: u8, block: usize, levels: u8, max: u64, bonus: &[u8], bonus_type: u8| -> Vec<u8> {
            let mut raw = vec![0_u8; 512];
            raw[0] = kind;
            raw[1] = 12;
            raw[2] = levels;
            raw[3] = 1;
            raw[4] = bonus_type;
            raw[7] = 1;
            u16put(&mut raw, 8, (block / 512) as u16);
            u16put(&mut raw, 10, bonus.len() as u16);
            raw[16..24].copy_from_slice(&order.encode(max));
            raw[192..192 + bonus.len()].copy_from_slice(bonus);
            raw
        };
    let legacy = |mode: u64, size: u64, parent: u64| -> Vec<u8> {
        let mut raw = vec![0_u8; 264];
        for (at, value) in [
            (0, 1_700_000_000),
            (8, 123),
            (64, 10),
            (72, mode),
            (80, size),
            (88, parent),
            (96, 2),
            (128, 1000),
            (136, 100),
        ] {
            raw[at..at + 8].copy_from_slice(&order.encode(value));
        }
        raw
    };
    let micro = |entries: &[(&[u8], u64)]| -> Vec<u8> {
        let mut raw = vec![0_u8; 512];
        raw[..8].copy_from_slice(&order.encode((1 << 63) + 3));
        for (i, (name, value)) in entries.iter().enumerate() {
            let at = 64 + i * 64;
            raw[at..at + 8].copy_from_slice(&order.encode(*value));
            raw[at + 14..at + 14 + name.len()].copy_from_slice(name);
        }
        raw
    };

    let mos_at = DATA_OFFSET + 0x10000;
    let pool_map_at = DATA_OFFSET + 0x14000;
    let os_at = DATA_OFFSET + 0x18000;
    let table_at = DATA_OFFSET + 0x20000;
    let master_at = DATA_OFFSET + 0x25000;
    let root_map_at = DATA_OFFSET + 0x26000;
    let file_blk0_at = DATA_OFFSET + 0x28000;
    let file_blk1_at = DATA_OFFSET + 0x29000;
    let indirect_at = DATA_OFFSET + 0x2e000;

    let mut table = vec![0_u8; 16_384];
    let master = micro(&[(b"ROOT", 2), (b"VERSION", 4)]);
    image[master_at as usize..master_at as usize + 512].copy_from_slice(&master);
    let mut master_node = node(21, 512, 1, 0, &[], 0);
    master_node[64..192].copy_from_slice(&bp(&master, master_at, 21, 0, 20));
    table[512..1024].copy_from_slice(&master_node);

    let root_dir = micro(&[(b"payload.bin", (8 << 60) | 3)]);
    image[root_map_at as usize..root_map_at as usize + 512].copy_from_slice(&root_dir);
    let mut root_dn = node(20, 512, 1, 0, &legacy(0o040_755, 2, 2), 17);
    root_dn[64..192].copy_from_slice(&bp(&root_dir, root_map_at, 20, 0, 20));
    table[2 * 512..3 * 512].copy_from_slice(&root_dn);

    let blk0: Vec<u8> = (0_u32..4096).map(|i| (i % 239) as u8).collect();
    let blk1: Vec<u8> = (0_u32..4096).map(|i| ((i + 77) % 239) as u8).collect();
    let mut payload = blk0.clone();
    payload.extend_from_slice(&blk1);
    image[file_blk0_at as usize..file_blk0_at as usize + 4096].copy_from_slice(&blk0);
    image[file_blk1_at as usize..file_blk1_at as usize + 4096].copy_from_slice(&blk1);

    let mut indirect = vec![0_u8; 4096];
    indirect[..128].copy_from_slice(&bp(&blk0, file_blk0_at, 19, 0, 20));
    indirect[128..256].copy_from_slice(&bp(&blk1, file_blk1_at, 19, 0, 20));
    image[indirect_at as usize..indirect_at as usize + 4096].copy_from_slice(&indirect);

    let mut file_dn = node(
        19,
        4096,
        2,
        1,
        &legacy(0o100_644, payload.len() as u64, 2),
        17,
    );
    file_dn[24..32].copy_from_slice(&order.encode(8192));
    file_dn[64..192].copy_from_slice(&bp(&indirect, indirect_at, 19, 1, 30));
    table[3 * 512..4 * 512].copy_from_slice(&file_dn);
    image[table_at as usize..table_at as usize + table.len()].copy_from_slice(&table);

    let mut os = vec![0_u8; 1024];
    let mut os_meta = node(10, 16_384, 1, 0, &[], 0);
    os_meta[64..192].copy_from_slice(&bp(&table, table_at, 10, 0, 40));
    os[..512].copy_from_slice(&os_meta);
    os[704..712].copy_from_slice(&order.encode(2));
    image[os_at as usize..os_at as usize + 1024].copy_from_slice(&os);

    let mut mos_table = vec![0_u8; 16_384];
    let pool_zap = micro(&[
        (b"root_dataset", 2),
        (b"features_for_read", 29),
        (b"features_for_write", 30),
        (b"feature_descriptions", 31),
    ]);
    image[pool_map_at as usize..pool_map_at as usize + 512].copy_from_slice(&pool_zap);
    let mut pool_dn = node(1, 512, 1, 0, &[], 0);
    pool_dn[64..192].copy_from_slice(&bp(&pool_zap, pool_map_at, 1, 0, 20));
    mos_table[512..1024].copy_from_slice(&pool_dn);
    let mut dir_bonus = vec![0_u8; 256];
    dir_bonus[8..16].copy_from_slice(&order.encode(3));
    mos_table[1024..1536].copy_from_slice(&node(12, 512, 1, 0, &dir_bonus, 12));
    let mut ds_bonus = vec![0_u8; 320];
    for (at, value) in [(0, 2), (56, 5), (112, 987), (120, 4)] {
        ds_bonus[at..at + 8].copy_from_slice(&order.encode(value));
    }
    ds_bonus[128..256].copy_from_slice(&bp(&os, os_at, 11, 0, 45));
    mos_table[1536..2048].copy_from_slice(&node(16, 512, 1, 0, &ds_bonus, 16));
    // Version 5000 requires distinct native MOS feature catalogs, even when
    // this uncompressed fixture enables no features. These blocks occupy the
    // unused gap after the pool directory and before the dataset object set.
    for (object, at) in [
        (29, DATA_OFFSET + 0x14400),
        (30, DATA_OFFSET + 0x14600),
        (31, DATA_OFFSET + 0x14800),
    ] {
        let catalog = micro(&[]);
        image[at as usize..at as usize + catalog.len()].copy_from_slice(&catalog);
        let mut catalog_dn = node(196, 512, 1, 0, &[], 0);
        catalog_dn[64..192].copy_from_slice(&bp(&catalog, at, 196, 0, 20));
        mos_table[object * 512..(object + 1) * 512].copy_from_slice(&catalog_dn);
    }
    image[mos_at as usize..mos_at as usize + mos_table.len()].copy_from_slice(&mos_table);

    let mut mos_os = vec![0_u8; 1024];
    let mut mos_meta = node(10, 16_384, 1, 0, &[], 0);
    mos_meta[64..192].copy_from_slice(&bp(&mos_table, mos_at, 10, 0, 50));
    mos_os[..512].copy_from_slice(&mos_meta);
    mos_os[704..712].copy_from_slice(&order.encode(1));
    let mos_os_at = DATA_OFFSET + 0x1000;
    image[mos_os_at as usize..mos_os_at as usize + 1024].copy_from_slice(&mos_os);

    let mut ub = vec![0_u8; 1024];
    for (at, value) in [
        (0, 0x00ba_b10c),
        (8, 5000),
        (16, 50),
        (24, 1122),
        (32, 1_700_000_000),
    ] {
        ub[at..at + 8].copy_from_slice(&order.encode(value));
    }
    ub[40..168].copy_from_slice(&bp(&mos_os, mos_os_at, 11, 0, 50));

    let xstring = |value: &str| -> Vec<u8> {
        let mut bytes = (value.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(value.as_bytes());
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes
    };
    let pair = |name: &str, kind: u32, data: &[u8]| -> Vec<u8> {
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(&xstring(name));
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(data);
        let len = bytes.len() as u32;
        bytes[..4].copy_from_slice(&len.to_be_bytes());
        bytes[4..8].copy_from_slice(&64_u32.to_be_bytes());
        bytes
    };
    let uint = |name: &str, value: u64| pair(name, 8, &value.to_be_bytes());
    let list = |pairs: &[Vec<u8>]| -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 0, 0, 0, 0, 1];
        for p in pairs {
            bytes.extend_from_slice(p);
        }
        bytes.extend_from_slice(&[0; 8]);
        bytes
    };
    let vdev_tree = list(&[
        pair("type", 9, &xstring("file")),
        uint("id", 0),
        uint("guid", 999),
        uint("ashift", 9),
        uint("asize", length as u64 - DATA_OFFSET - 2 * LABEL_BYTES),
        uint("is_log", 0),
    ]);
    let mut cfg = vec![1, 1, 0, 0];
    cfg.extend_from_slice(&list(&[
        uint("version", 5000),
        uint("state", 1),
        uint("txg", 50),
        uint("pool_guid", 123),
        uint("guid", 999),
        uint("top_guid", 999),
        uint("vdev_children", 1),
        pair("name", 9, &xstring("tank")),
        pair("vdev_tree", 19, &vdev_tree),
        pair("features_for_read", 19, &list(&[])),
    ]));
    let stamp = |bytes: &mut [u8], offset: u64| {
        let at = bytes.len() - 40;
        bytes[at..at + 8].copy_from_slice(&order.encode(0x0210_da7a_b10c_7a11));
        bytes[at + 8..].fill(0);
        bytes[at + 8..at + 16].copy_from_slice(&order.encode(offset));
        let digest = Sha256::digest(&*bytes);
        for i in 0..4 {
            let word = u64::from_be_bytes(std::array::from_fn(|n| digest[i * 8 + n]));
            bytes[at + 8 + i * 8..at + 16 + i * 8].copy_from_slice(&order.encode(word));
        }
    };
    for label in label_offsets(length as u64).unwrap() {
        let cfg_off = label + LABEL_CONFIG_OFFSET;
        let mut cfg_blk = vec![0_u8; LABEL_CONFIG_BYTES];
        cfg_blk[..cfg.len()].copy_from_slice(&cfg);
        stamp(&mut cfg_blk, cfg_off);
        image[cfg_off as usize..cfg_off as usize + LABEL_CONFIG_BYTES].copy_from_slice(&cfg_blk);

        let ub_off = label + UBERBLOCK_RING_OFFSET;
        let mut ub_blk = ub.clone();
        stamp(&mut ub_blk, ub_off);
        image[ub_off as usize..ub_off as usize + ub_blk.len()].copy_from_slice(&ub_blk);
    }

    std::fs::write(&image_path, &image).unwrap();
    protect(
        &cx,
        &image_path,
        &sidecar_path,
        SidecarOptions {
            block_size: 4096,
            group_blocks: 16,
            repair_symbols: 4,
        },
    )
    .expect("protect zfs image");

    let fixture = Fixture {
        dir,
        image: image_path,
        sidecar: sidecar_path,
        payload,
    };

    // Refuse --rw for ZFS
    assert!(prepare(&cx, &fixture.writable_args()).is_err());

    let prepared = prepare(&cx, &fixture.args()).expect("admit protected zfs");
    assert_eq!(prepared.filesystem, "zfs");
    assert_eq!(std::fs::read(&fixture.image).unwrap(), image);

    // Corrupt TWO 4096-byte blocks in the same group (file_blk0_at and file_blk1_at)
    let blk_a = file_blk0_at / 4096;
    let blk_b = file_blk1_at / 4096;
    let orig_a = fixture.read_block(blk_a);
    let orig_b = fixture.read_block(blk_b);
    fixture.damage_block(blk_a);
    fixture.damage_block(blk_b);
    assert_ne!(fixture.read_block(blk_a), orig_a);
    assert_ne!(fixture.read_block(blk_b), orig_b);

    let mut scope = RequestScope::empty();
    let attr = FsOps::lookup(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        InodeNumber(1),
        OsStr::new("payload.bin"),
    )
    .unwrap();
    let read_back = FsOps::read(
        prepared.fs.as_ref(),
        &cx,
        &mut scope,
        attr.ino,
        0,
        u32::try_from(fixture.payload.len()).unwrap(),
    )
    .unwrap();
    assert_eq!(read_back, fixture.payload);
    assert_eq!(
        fixture.read_block(blk_a),
        orig_a,
        "ZFS block A must be self-healed on disk"
    );
    assert_eq!(
        fixture.read_block(blk_b),
        orig_b,
        "ZFS block B must be self-healed on disk"
    );
    prepared.finish(&cx).unwrap();
    assert!(
        verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
    assert_mounted_repair(&fixture, "zfs", [blk_a, blk_b]);
}

mod bd_tqrnc {
    use super::*;
    use ffs_core::{SetAttrRequest, XattrSetMode};
    use ffs_ondisk::ntfs::index::NtfsFileName;
    use ffs_ondisk::ntfs::{
        DATA, NtfsFileRecord, NtfsReference, NtfsRun, VOLUME_INFORMATION, encode_mapping_pairs,
    };
    use ffs_ondisk::zfs::{
        BlockPointer, DATA_OFFSET, Dva, Endian, LABEL_BYTES, LABEL_CONFIG_BYTES,
        LABEL_CONFIG_OFFSET, RegularBlockSpec, UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET,
        Uberblock, label_offsets, stamp_label_checksum,
    };
    use ffs_ondisk::zfs_dmu::space_map::{
        AllocationMap, Header as SpaceMapHeader, MapType, Record as SpaceMapRecord,
        extent_records_for_range,
    };
    use ffs_ondisk::zfs_dmu::{
        DMU_OT_DNODE, DMU_OT_OBJECT_DIRECTORY, DMU_OT_OBJSET, DNODE_BLOCK_BYTES, DNODE_BYTES,
        DNODE_FLAG_USED_BYTES, Dnode, DnodeSpec, ObjectSet, ZapEntry, ZilHeader, encode_microzap,
        write_dnode_at,
    };
    use ffs_ondisk::zfs_zap::{Entry as RawZapEntry, encode_fatzap_with_flags};
    use ffs_ondisk::zfs_zpl::{Kind, Metadata, SaRegistry, Timestamp};
    use ffs_repair::evidence::parse_evidence_ledger;
    use ffs_repair::por::PorKey;
    use ffs_repair::sidecar::live::{
        StorageSetMemberSpec, StorageSetProtectRequest, protect_storage_set, verify_storage_set,
    };
    use ffs_repair::sidecar::{
        MemberRole, NativeCommitBinding, ProtectedViewIdentity, StorageSetManifest,
        StorageSetTopology, TrustPolicy,
    };
    use std::collections::BTreeMap;

    const NTFS_SECTOR_BYTES: usize = 512;
    const NTFS_CLUSTER_BYTES: usize = 4096;
    const NTFS_RECORD_BYTES: usize = 1024;
    const NTFS_INDEX_BYTES: usize = 4096;
    const NTFS_DEFAULT_FILETIME: u64 = 133_500_000_000_000_000;

    const ZFS_POOL_GUID: u64 = 0x5A46_535F_5445_5354;
    const ZFS_TOP_SINGLE_GUID: u64 = 0x1111_2222_3333_4444;
    const ZFS_TOP_MIRROR_GUID: u64 = 0x7777_8888_9999_AAAA;
    const ZFS_CHILD_GUIDS: [u64; 2] = [0x1001_0000_0000_0001, 0x1002_0000_0000_0002];
    const ZFS_INITIAL_TXG: u64 = 20;
    const ZFS_SLAB_SHIFT: u64 = 22;

    fn protect_ntfs_record(mut raw: Vec<u8>, token: u16) -> Vec<u8> {
        let usa = usize::from(u16::from_le_bytes([raw[4], raw[5]]));
        let count = usize::from(u16::from_le_bytes([raw[6], raw[7]]));
        raw[usa..usa + 2].copy_from_slice(&token.to_le_bytes());
        for sector in 1..count {
            let end = sector * NTFS_SECTOR_BYTES;
            let saved = [raw[end - 2], raw[end - 1]];
            raw[usa + sector * 2..usa + sector * 2 + 2].copy_from_slice(&saved);
            raw[end - 2..end].copy_from_slice(&token.to_le_bytes());
        }
        raw
    }

    fn ntfs_resident_attr(kind: u32, id: u16, name: &[u16], indexed: bool, val: &[u8]) -> Vec<u8> {
        let name_bytes = name.len() * 2;
        let val_off = (24 + name_bytes + 7) & !7;
        let total = (val_off + val.len() + 7) & !7;
        let mut out = vec![0_u8; total];
        out[0..4].copy_from_slice(&kind.to_le_bytes());
        out[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        out[9] = u8::try_from(name.len()).unwrap();
        out[10..12].copy_from_slice(&24_u16.to_le_bytes());
        out[14..16].copy_from_slice(&id.to_le_bytes());
        out[16..20].copy_from_slice(&(val.len() as u32).to_le_bytes());
        out[20..22].copy_from_slice(&(val_off as u16).to_le_bytes());
        out[22] = u8::from(indexed);
        for (i, &ch) in name.iter().enumerate() {
            let at = 24 + i * 2;
            out[at..at + 2].copy_from_slice(&ch.to_le_bytes());
        }
        out[val_off..val_off + val.len()].copy_from_slice(val);
        out
    }

    fn ntfs_nonresident_attr(
        kind: u32,
        id: u16,
        name: &[u16],
        lcn: u64,
        clusters: u64,
        logical_size: u64,
        total_clusters: u64,
    ) -> Vec<u8> {
        let run = NtfsRun {
            vcn: 0,
            clusters,
            lcn: Some(lcn),
        };
        let (pairs, last_vcn) = encode_mapping_pairs(&[run], 0, total_clusters).unwrap();
        let name_bytes = name.len() * 2;
        let map_off = (64 + name_bytes + 7) & !7;
        let total = (map_off + pairs.len() + 7) & !7;
        let alloc_bytes = clusters * (NTFS_CLUSTER_BYTES as u64);
        let mut out = vec![0_u8; total];
        out[0..4].copy_from_slice(&kind.to_le_bytes());
        out[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        out[8] = 1;
        out[9] = u8::try_from(name.len()).unwrap();
        out[10..12].copy_from_slice(&64_u16.to_le_bytes());
        out[14..16].copy_from_slice(&id.to_le_bytes());
        out[24..32].copy_from_slice(&last_vcn.to_le_bytes());
        out[32..34].copy_from_slice(&(map_off as u16).to_le_bytes());
        out[40..48].copy_from_slice(&alloc_bytes.to_le_bytes());
        out[48..56].copy_from_slice(&logical_size.to_le_bytes());
        out[56..64].copy_from_slice(&logical_size.to_le_bytes());
        for (i, &ch) in name.iter().enumerate() {
            let at = 64 + i * 2;
            out[at..at + 2].copy_from_slice(&ch.to_le_bytes());
        }
        out[map_off..map_off + pairs.len()].copy_from_slice(&pairs);
        out
    }

    fn ntfs_file_record(
        number: u32,
        sequence: u16,
        hard_links: u16,
        is_dir: bool,
        attrs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut raw = vec![0_u8; NTFS_RECORD_BYTES];
        raw[0..4].copy_from_slice(b"FILE");
        raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
        raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
        raw[16..18].copy_from_slice(&sequence.to_le_bytes());
        raw[18..20].copy_from_slice(&hard_links.to_le_bytes());
        raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
        let flags: u16 = if is_dir { 0x0003 } else { 0x0001 };
        raw[22..24].copy_from_slice(&flags.to_le_bytes());
        raw[28..32].copy_from_slice(&(NTFS_RECORD_BYTES as u32).to_le_bytes());
        raw[40..42].copy_from_slice(&u16::try_from(attrs.len()).unwrap().to_le_bytes());
        raw[44..48].copy_from_slice(&number.to_le_bytes());
        let mut pos = 56;
        for a in attrs {
            raw[pos..pos + a.len()].copy_from_slice(a);
            pos += a.len();
        }
        raw[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        raw[24..28].copy_from_slice(&((pos + 8) as u32).to_le_bytes());
        let protected = protect_ntfs_record(raw, 0x2468);
        NtfsFileRecord::parse(&protected).expect("valid synthetic NTFS FILE record");
        protected
    }

    fn build_clean_writable_ntfs_image(
        total_clusters: u64,
        log_pages: u64,
        serial: u64,
    ) -> Vec<u8> {
        let mft_lcn = 1_u64;
        let mirr_lcn = 9_u64;
        let log_lcn = 10_u64;
        let bm_lcn = 10 + log_pages;
        let upcase_lcn = 11 + log_pages;
        let used_clusters = upcase_lcn + 32;
        assert!(total_clusters >= used_clusters + 16);

        let volume_bytes = total_clusters * (NTFS_CLUSTER_BYTES as u64);
        let mut img = vec![0_u8; usize::try_from(volume_bytes).unwrap() + NTFS_SECTOR_BYTES];
        {
            let boot = &mut img[0..NTFS_SECTOR_BYTES];
            boot[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
            boot[3..11].copy_from_slice(b"NTFS    ");
            boot[11..13].copy_from_slice(&(NTFS_SECTOR_BYTES as u16).to_le_bytes());
            boot[13] = u8::try_from(NTFS_CLUSTER_BYTES / NTFS_SECTOR_BYTES).unwrap();
            boot[21] = 0xF8;
            boot[24..26].copy_from_slice(&63_u16.to_le_bytes());
            boot[26..28].copy_from_slice(&255_u16.to_le_bytes());
            boot[36] = 0x80;
            boot[38] = 0x80;
            let total_sectors = volume_bytes / (NTFS_SECTOR_BYTES as u64);
            boot[40..48].copy_from_slice(&total_sectors.to_le_bytes());
            boot[48..56].copy_from_slice(&mft_lcn.to_le_bytes());
            boot[56..64].copy_from_slice(&mirr_lcn.to_le_bytes());
            boot[64] = 0xF6;
            boot[68] = 1;
            boot[72..80].copy_from_slice(&serial.to_le_bytes());
            boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        }
        let boot_copy = img[0..NTFS_SECTOR_BYTES].to_vec();
        let vol_end = usize::try_from(volume_bytes).unwrap();
        img[vol_end..vol_end + NTFS_SECTOR_BYTES].copy_from_slice(&boot_copy);

        let log_off = usize::try_from(log_lcn).unwrap() * NTFS_CLUSTER_BYTES;
        let logfile_byte_len = usize::try_from(log_pages).unwrap() * NTFS_CLUSTER_BYTES;
        img[log_off..log_off + logfile_byte_len].fill(0xFF);

        let up_off = usize::try_from(upcase_lcn).unwrap() * NTFS_CLUSTER_BYTES;
        for cp in 0_u32..65_536 {
            let mapped = if (u32::from(b'a')..=u32::from(b'z')).contains(&cp) {
                u16::try_from(cp - 32).unwrap()
            } else {
                u16::try_from(cp).unwrap()
            };
            let at = up_off + (cp as usize) * 2;
            img[at..at + 2].copy_from_slice(&mapped.to_le_bytes());
        }

        let bm_logical = usize::try_from(total_clusters.div_ceil(8)).unwrap();
        let bm_off = usize::try_from(bm_lcn).unwrap() * NTFS_CLUSTER_BYTES;
        for c in 0..used_clusters {
            img[bm_off + usize::try_from(c / 8).unwrap()] |= 1_u8 << (c % 8);
        }

        let mut mft_bm = [0_u8; 8];
        for slot in [0_u64, 1, 2, 3, 5, 6, 7, 10] {
            mft_bm[usize::try_from(slot / 8).unwrap()] |= 1_u8 << (slot % 8);
        }
        let rec0 = ntfs_file_record(
            0,
            1,
            0,
            false,
            &[
                ntfs_nonresident_attr(
                    DATA,
                    0,
                    &[],
                    mft_lcn,
                    8,
                    32 * NTFS_RECORD_BYTES as u64,
                    total_clusters,
                ),
                ntfs_resident_attr(0xB0, 1, &[], false, &mft_bm),
            ],
        );
        let rec1 = ntfs_file_record(
            1,
            1,
            0,
            false,
            &[ntfs_nonresident_attr(
                DATA,
                0,
                &[],
                mirr_lcn,
                1,
                4 * NTFS_RECORD_BYTES as u64,
                total_clusters,
            )],
        );
        let rec2 = ntfs_file_record(
            2,
            1,
            0,
            false,
            &[ntfs_nonresident_attr(
                DATA,
                0,
                &[],
                log_lcn,
                log_pages,
                log_pages * NTFS_CLUSTER_BYTES as u64,
                total_clusters,
            )],
        );
        let mut vol_info = [0_u8; 12];
        vol_info[8..10].copy_from_slice(&[3, 1]);
        let rec3 = ntfs_file_record(
            3,
            1,
            0,
            false,
            &[ntfs_resident_attr(
                VOLUME_INFORMATION,
                0,
                &[],
                false,
                &vol_info,
            )],
        );

        let mut std5 = [0_u8; 48];
        for off in [0_usize, 8, 16, 24] {
            std5[off..off + 8].copy_from_slice(&NTFS_DEFAULT_FILETIME.to_le_bytes());
        }
        let root_fn = NtfsFileName {
            parent: NtfsReference {
                record: 5,
                sequence: 5,
            },
            namespace: 3,
            name: vec![u16::from(b'.')],
        }
        .encode(
            NTFS_DEFAULT_FILETIME,
            NTFS_DEFAULT_FILETIME,
            NTFS_DEFAULT_FILETIME,
            NTFS_DEFAULT_FILETIME,
            0,
            0,
            0x1000_0000,
            0,
        )
        .unwrap();
        let mut sd = vec![0_u8; 52];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
        sd[4..8].copy_from_slice(&20_u32.to_le_bytes());
        sd[8..12].copy_from_slice(&32_u32.to_le_bytes());
        sd[16..20].copy_from_slice(&44_u32.to_le_bytes());
        let sid = [1_u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        sd[20..32].copy_from_slice(&sid);
        sd[32..44].copy_from_slice(&sid);
        sd[44] = 2;
        sd[46..48].copy_from_slice(&8_u16.to_le_bytes());

        let mut empty_i30 = vec![0_u8; 48];
        empty_i30[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
        empty_i30[4..8].copy_from_slice(&1_u32.to_le_bytes());
        empty_i30[8..12].copy_from_slice(&(NTFS_INDEX_BYTES as u32).to_le_bytes());
        empty_i30[12] = 1;
        empty_i30[16..20].copy_from_slice(&16_u32.to_le_bytes());
        empty_i30[20..24].copy_from_slice(&32_u32.to_le_bytes());
        empty_i30[24..28].copy_from_slice(&32_u32.to_le_bytes());
        empty_i30[40..42].copy_from_slice(&16_u16.to_le_bytes());
        empty_i30[44..48].copy_from_slice(&2_u32.to_le_bytes());
        let i30_name = [
            u16::from(b'$'),
            u16::from(b'I'),
            u16::from(b'3'),
            u16::from(b'0'),
        ];
        let rec5 = ntfs_file_record(
            5,
            5,
            1,
            true,
            &[
                ntfs_resident_attr(0x10, 0, &[], false, &std5),
                ntfs_resident_attr(0x30, 1, &[], true, &root_fn),
                ntfs_resident_attr(0x50, 2, &[], false, &sd),
                ntfs_resident_attr(0x90, 3, &i30_name, false, &empty_i30),
            ],
        );
        let rec6 = ntfs_file_record(
            6,
            1,
            0,
            false,
            &[ntfs_nonresident_attr(
                DATA,
                0,
                &[],
                bm_lcn,
                1,
                bm_logical as u64,
                total_clusters,
            )],
        );
        let rec7 = ntfs_file_record(
            7,
            1,
            0,
            false,
            &[ntfs_nonresident_attr(
                DATA,
                0,
                &[],
                0,
                1,
                NTFS_CLUSTER_BYTES as u64,
                total_clusters,
            )],
        );
        let upcase_rec = ntfs_file_record(
            10,
            1,
            0,
            false,
            &[ntfs_nonresident_attr(
                DATA,
                0,
                &[],
                upcase_lcn,
                32,
                131_072,
                total_clusters,
            )],
        );
        let mft_base = usize::try_from(mft_lcn).unwrap() * NTFS_CLUSTER_BYTES;
        for (slot, bytes) in [
            (0_usize, &rec0),
            (1, &rec1),
            (2, &rec2),
            (3, &rec3),
            (5, &rec5),
            (6, &rec6),
            (7, &rec7),
            (10, &upcase_rec),
        ] {
            let off = mft_base + slot * NTFS_RECORD_BYTES;
            img[off..off + NTFS_RECORD_BYTES].copy_from_slice(bytes);
        }
        let mirr_base = usize::try_from(mirr_lcn).unwrap() * NTFS_CLUSTER_BYTES;
        let first4 = img[mft_base..mft_base + 4 * NTFS_RECORD_BYTES].to_vec();
        img[mirr_base..mirr_base + 4 * NTFS_RECORD_BYTES].copy_from_slice(&first4);
        img
    }

    // ── Clean ZFS v5000 single-leaf / 2-way mirror pool builder ──────────────

    fn xdr_string(value: &str) -> Vec<u8> {
        let mut bytes = u32::try_from(value.len()).unwrap().to_be_bytes().to_vec();
        bytes.extend_from_slice(value.as_bytes());
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes
    }

    fn nv_pair(name: &str, kind: u32, count: u32, data: &[u8], dec_val_bytes: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; 8];
        bytes.extend_from_slice(&xdr_string(name));
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(data);
        let len = u32::try_from(bytes.len()).unwrap();
        let dec_sz = u32::try_from(
            (16 + name.len() + 1).next_multiple_of(8) + dec_val_bytes.next_multiple_of(8),
        )
        .unwrap();
        bytes[0..4].copy_from_slice(&len.to_be_bytes());
        bytes[4..8].copy_from_slice(&dec_sz.to_be_bytes());
        bytes
    }

    fn nv_u64(name: &str, value: u64) -> Vec<u8> {
        nv_pair(name, 8, 1, &value.to_be_bytes(), 8)
    }

    fn nv_str(name: &str, value: &str) -> Vec<u8> {
        nv_pair(name, 9, 1, &xdr_string(value), value.len() + 1)
    }

    fn nv_bool(name: &str) -> Vec<u8> {
        nv_pair(name, 1, 0, &[], 0)
    }

    fn nv_list_body(pairs: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 0, 0, 0, 0, 1];
        for p in pairs {
            bytes.extend_from_slice(p);
        }
        bytes.extend_from_slice(&[0_u8; 8]);
        bytes
    }

    fn nv_embedded(name: &str, pairs: &[Vec<u8>]) -> Vec<u8> {
        nv_pair(name, 19, 1, &nv_list_body(pairs), 24)
    }

    fn nv_list_array(name: &str, items: &[Vec<Vec<u8>>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for item in items {
            payload.extend_from_slice(&nv_list_body(item));
        }
        nv_pair(
            name,
            20,
            u32::try_from(items.len()).unwrap(),
            &payload,
            items.len() * 32,
        )
    }

    fn pack_xdr_nvlist(pairs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![1, 1, 0, 0];
        out.extend_from_slice(&nv_list_body(pairs));
        out
    }

    struct ZfsArena {
        sector: u64,
        cursor: u64,
        limit: u64,
        blocks: BTreeMap<u64, Vec<u8>>,
        alloc_map: AllocationMap,
    }

    impl ZfsArena {
        fn new(asize: u64, ashift: u8) -> Self {
            let sector = 1_u64 << ashift;
            Self {
                sector,
                cursor: sector * 8,
                limit: asize,
                blocks: BTreeMap::new(),
                alloc_map: AllocationMap::new(0, asize, ashift, 262_144).unwrap(),
            }
        }

        fn alloc_block(
            &mut self,
            payload: &[u8],
            object_type: u8,
            level: u8,
            birth: u64,
            order: Endian,
        ) -> BlockPointer {
            let min_blk = usize::try_from(self.sector).unwrap().max(512);
            let lsize = payload.len().max(min_blk).next_multiple_of(512);
            let mut buf = payload.to_vec();
            buf.resize(lsize, 0);
            let asize = (lsize as u64).next_multiple_of(self.sector);
            let dva_off = self.cursor;
            assert!(dva_off + asize <= self.limit);
            self.cursor += asize;
            self.alloc_map
                .apply(MapType::Allocate, dva_off..(dva_off + asize))
                .unwrap();
            let mut disk_bytes = buf.clone();
            disk_bytes.resize(usize::try_from(asize).unwrap(), 0);
            self.blocks.insert(dva_off, disk_bytes);
            let fill = if object_type == DMU_OT_DNODE {
                buf.as_chunks::<DNODE_BYTES>()
                    .0
                    .iter()
                    .filter(|slot| slot[0] != 0)
                    .count() as u64
            } else if object_type == DMU_OT_OBJSET {
                ObjectSet::parse(&buf, order).unwrap().meta_fill()
            } else {
                1
            };
            BlockPointer::new_regular(&RegularBlockSpec {
                dvas: &[Dva {
                    vdev: 0,
                    offset: dva_off,
                    allocated_bytes: asize,
                    gang: false,
                }],
                logical_bytes: lsize,
                physical: &buf,
                compression: 2,
                checksum_type: 7,
                object_type,
                level,
                payload_order: order,
                birth,
                fill,
            })
            .unwrap()
        }
    }

    fn bp_allocated_bytes(bp: &BlockPointer) -> u64 {
        bp.regular_dvas()
            .map_or(0, |dvas| dvas.iter().map(|d| d.allocated_bytes).sum())
    }

    fn mzap(pairs: &[(&[u8], u64)], salt: u64, order: Endian) -> Vec<u8> {
        let entries: Vec<ZapEntry> = pairs
            .iter()
            .map(|&(name, value)| ZapEntry {
                name: name.to_vec(),
                value,
                collision: 0,
            })
            .collect();
        encode_microzap(&entries, 4096, salt, order).unwrap()
    }

    fn make_dnode(
        object_type: u8,
        data_bytes: usize,
        pointers: Vec<BlockPointer>,
        bonus_type: u8,
        bonus: Vec<u8>,
        order: Endian,
    ) -> Dnode {
        let used_bytes: u64 = pointers
            .iter()
            .filter(|bp| !bp.hole())
            .map(bp_allocated_bytes)
            .sum();
        let max_block = if pointers.is_empty() || pointers.iter().all(BlockPointer::hole) {
            0
        } else {
            (pointers.len() as u64) - 1
        };
        let nblkptr = if bonus_type == 44 {
            1
        } else {
            ((DNODE_BYTES - 64 - bonus.len()) / 128).clamp(1, 3)
        };
        let mut ptrs = pointers;
        ptrs.resize(nblkptr, BlockPointer::hole_pointer());
        Dnode::from_spec(DnodeSpec {
            object_type,
            bonus_type,
            checksum_type: 0,
            compress_type: 0,
            flags: DNODE_FLAG_USED_BYTES,
            order,
            levels: 1,
            indirect_shift: 17,
            data_bytes,
            max_block,
            used_bytes,
            slots: 1,
            pointers: ptrs,
            bonus,
            spill: None,
        })
        .unwrap()
    }

    fn build_zpl_v5_dataset(
        arena: &mut ZfsArena,
        birth: u64,
        order: Endian,
    ) -> (BlockPointer, u64) {
        let mut table = vec![0_u8; DNODE_BLOCK_BYTES];
        let reg_entries = vec![
            RawZapEntry {
                name: b"ZPL_ATIME".to_vec(),
                integer_bytes: 8,
                values: vec![16_u64 << 24],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_MTIME".to_vec(),
                integer_bytes: 8,
                values: vec![(16_u64 << 24) | 1],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_CTIME".to_vec(),
                integer_bytes: 8,
                values: vec![(16_u64 << 24) | 2],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_CRTIME".to_vec(),
                integer_bytes: 8,
                values: vec![(16_u64 << 24) | 3],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_GEN".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 4],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_MODE".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 5],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_SIZE".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 6],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_PARENT".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 7],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_LINKS".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 8],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_RDEV".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 0x0a],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_FLAGS".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 0x0b],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_UID".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 0x0c],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_GID".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 0x0d],
                collision: 0,
            },
            RawZapEntry {
                name: b"ZPL_DACL_COUNT".to_vec(),
                integer_bytes: 8,
                values: vec![(8_u64 << 24) | 0x10],
                collision: 0,
            },
            // Real OpenZFS `sa_bswap_type_t`: SA_ACL == 4 (variable length 0)!
            RawZapEntry {
                name: b"ZPL_DACL_ACES".to_vec(),
                integer_bytes: 8,
                values: vec![(4_u64 << 16) | 0x11],
                collision: 0,
            },
        ];
        let lay_entries = vec![RawZapEntry {
            name: b"2".to_vec(),
            integer_bytes: 2,
            values: vec![5, 6, 4, 12, 13, 7, 11, 0, 1, 2, 3, 8],
            collision: 0,
        }];
        let sa_reg = SaRegistry::from_zaps(&reg_entries, &lay_entries).unwrap();
        let sa_master_bp = arena.alloc_block(
            &mzap(&[(b"REGISTRY", 9), (b"LAYOUTS", 10)], 0x1234, order),
            45,
            0,
            birth,
            order,
        );
        let sa_master_bytes = bp_allocated_bytes(&sa_master_bp);
        write_dnode_at(
            &mut table,
            8,
            &make_dnode(
                45,
                sa_master_bp.logical_bytes(),
                vec![sa_master_bp],
                0,
                Vec::new(),
                order,
            ),
        )
        .unwrap();
        let reg_blocks =
            encode_fatzap_with_flags(&reg_entries, 4096, 0x2345, false, order).unwrap();
        let reg_ptrs: Vec<_> = reg_blocks
            .iter()
            .map(|b| arena.alloc_block(b, 46, 0, birth, order))
            .collect();
        let reg_bytes: u64 = reg_ptrs.iter().map(bp_allocated_bytes).sum();
        write_dnode_at(
            &mut table,
            9,
            &make_dnode(46, 4096, reg_ptrs, 0, Vec::new(), order),
        )
        .unwrap();
        let lay_blocks =
            encode_fatzap_with_flags(&lay_entries, 4096, 0x3456, false, order).unwrap();
        let lay_ptrs: Vec<_> = lay_blocks
            .iter()
            .map(|b| arena.alloc_block(b, 47, 0, birth, order))
            .collect();
        let lay_bytes: u64 = lay_ptrs.iter().map(bp_allocated_bytes).sum();
        write_dnode_at(
            &mut table,
            10,
            &make_dnode(47, 4096, lay_ptrs, 0, Vec::new(), order),
        )
        .unwrap();

        let master_bp = arena.alloc_block(
            &mzap(
                &[
                    (b"VERSION", 5),
                    (b"ROOT", 2),
                    (b"DELETE_QUEUE", 3),
                    (b"SA_ATTRS", 8),
                ],
                0x55,
                order,
            ),
            21,
            0,
            birth,
            order,
        );
        let master_bytes = bp_allocated_bytes(&master_bp);
        write_dnode_at(
            &mut table,
            1,
            &make_dnode(
                21,
                master_bp.logical_bytes(),
                vec![master_bp],
                0,
                Vec::new(),
                order,
            ),
        )
        .unwrap();
        let delq_bp = arena.alloc_block(&mzap(&[], 0x66, order), 22, 0, birth, order);
        let delq_bytes = bp_allocated_bytes(&delq_bp);
        write_dnode_at(
            &mut table,
            3,
            &make_dnode(
                22,
                delq_bp.logical_bytes(),
                vec![delq_bp],
                0,
                Vec::new(),
                order,
            ),
        )
        .unwrap();

        let ts = Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        };
        let root_meta = Metadata {
            kind: Kind::Directory,
            mode: (Kind::Directory.to_tag() << 12) | 0o755,
            size: 2,
            links: 2,
            parent: 2,
            uid: 0,
            gid: 0,
            flags: 0x408,
            generation: birth,
            times: [ts; 4],
            inline_symlink: None,
        };
        let mut tmpl = vec![0_u8; 136];
        tmpl[0..4].copy_from_slice(&[0x5a, 0x50, 0x2f, 0x00]);
        tmpl[4..6].copy_from_slice(&((1_u16 << 10) | 2_u16).to_le_bytes());
        let root_bonus = sa_reg.encode_new_from_template(&tmpl, &root_meta).unwrap();
        let root_bp = arena.alloc_block(&mzap(&[], 0x88, order), 20, 0, birth, order);
        let root_bytes = bp_allocated_bytes(&root_bp);
        write_dnode_at(
            &mut table,
            2,
            &make_dnode(
                20,
                root_bp.logical_bytes(),
                vec![root_bp],
                44,
                root_bonus,
                order,
            ),
        )
        .unwrap();

        let table_bp = arena.alloc_block(&table, DMU_OT_DNODE, 0, birth, order);
        let table_bytes = bp_allocated_bytes(&table_bp);
        let meta_dn = make_dnode(
            DMU_OT_DNODE,
            DNODE_BLOCK_BYTES,
            vec![table_bp],
            0,
            Vec::new(),
            order,
        );
        let os_obj = ObjectSet::new(2, 0, meta_dn, ZilHeader::empty(), 1024).unwrap();
        let encoded_os = os_obj.encode(order).unwrap();
        let os_bp = arena.alloc_block(&encoded_os, DMU_OT_OBJSET, 0, birth, order);
        let referenced = sa_master_bytes
            + reg_bytes
            + lay_bytes
            + master_bytes
            + delq_bytes
            + root_bytes
            + table_bytes
            + bp_allocated_bytes(&os_bp);
        (os_bp, referenced)
    }

    fn encode_dsl_dir_bonus(
        head_obj: u64,
        parent_dir_obj: u64,
        origin_obj: u64,
        child_dir_zapobj: u64,
        props_zapobj: u64,
        used_bytes: u64,
        order: Endian,
    ) -> Vec<u8> {
        let mut raw = vec![0_u8; 256];
        for (at, val) in [
            (0, 1_700_000_000_u64),
            (8, head_obj),
            (16, parent_dir_obj),
            (24, origin_obj),
            (32, child_dir_zapobj),
            (40, used_bytes),
            (48, used_bytes),
            (56, used_bytes),
            (80, props_zapobj),
        ] {
            raw[at..at + 8].copy_from_slice(&order.encode(val));
        }
        raw
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_dsl_dataset_bonus(
        dir_obj: u64,
        prev_snap_obj: u64,
        prev_snap_txg: u64,
        next_snap_obj: u64,
        snapnames_zapobj: u64,
        num_children: u64,
        creation_txg: u64,
        deadlist_obj: u64,
        referenced_bytes: u64,
        guid: u64,
        next_clones_obj: u64,
        os_bp: &BlockPointer,
        order: Endian,
    ) -> Vec<u8> {
        let mut raw = vec![0_u8; 320];
        for (at, val) in [
            (0, dir_obj),
            (8, prev_snap_obj),
            (16, prev_snap_txg),
            (24, next_snap_obj),
            (32, snapnames_zapobj),
            (40, num_children),
            (48, 1_700_000_000 + creation_txg),
            (56, creation_txg),
            (64, deadlist_obj),
            (72, referenced_bytes),
            (80, referenced_bytes),
            (88, referenced_bytes),
            (96, referenced_bytes),
            (104, guid ^ 0x55AA),
            (112, guid),
            (120, 0),
            (256, next_clones_obj),
        ] {
            raw[at..at + 8].copy_from_slice(&order.encode(val));
        }
        raw[128..256].copy_from_slice(&os_bp.encode(order));
        raw
    }

    fn build_clean_writable_zfs_pool(mirror_width: usize) -> (Vec<Vec<u8>>, u64) {
        let image_bytes = 16 * 1024 * 1024_u64;
        let ashift = 9_u8;
        let order = Endian::Little;
        let asize =
            (image_bytes - DATA_OFFSET - 2 * LABEL_BYTES) & !((1_u64 << ZFS_SLAB_SHIFT) - 1);
        let num_slabs = usize::try_from(asize >> ZFS_SLAB_SHIFT).unwrap();
        let mut arena = ZfsArena::new(asize, ashift);

        let (root_os_bp, root_ref_bytes) =
            build_zpl_v5_dataset(&mut arena, ZFS_INITIAL_TXG - 1, order);
        let (data_os_bp, data_ref_bytes) =
            build_zpl_v5_dataset(&mut arena, ZFS_INITIAL_TXG - 1, order);

        let sm_base_id = 40_usize;
        let slots_per_dnode_blk = DNODE_BLOCK_BYTES / DNODE_BYTES;
        let mos_table_blocks = (sm_base_id + num_slabs).div_ceil(slots_per_dnode_blk);
        let mut mos_tables = vec![vec![0_u8; DNODE_BLOCK_BYTES]; mos_table_blocks];
        let set_mos = |tables: &mut [Vec<u8>], id: usize, dn: &Dnode| {
            write_dnode_at(
                &mut tables[id / slots_per_dnode_blk],
                id % slots_per_dnode_blk,
                dn,
            )
            .unwrap();
        };

        let r_snaps_bp = arena.alloc_block(&mzap(&[], 0x101, order), 14, 0, ZFS_INITIAL_TXG, order);
        set_mos(
            &mut mos_tables,
            4,
            &make_dnode(
                14,
                r_snaps_bp.logical_bytes(),
                vec![r_snaps_bp],
                0,
                Vec::new(),
                order,
            ),
        );
        let child_zap_bp = arena.alloc_block(
            &mzap(
                &[
                    (b"$FREE", 14),
                    (b"$MOS", 9),
                    (b"$ORIGIN", 24),
                    (b"data", 17),
                ],
                0x102,
                order,
            ),
            13,
            0,
            ZFS_INITIAL_TXG,
            order,
        );
        set_mos(
            &mut mos_tables,
            15,
            &make_dnode(
                13,
                child_zap_bp.logical_bytes(),
                vec![child_zap_bp],
                0,
                Vec::new(),
                order,
            ),
        );

        for (id, kind, salt) in [
            (16_usize, 15_u8, 0x103_u64),
            (19, 13, 0x104),
            (20, 15, 0x105),
            (30, 15, 0x110),
            (31, 15, 0x111),
            (32, 15, 0x112),
            (33, 13, 0x113),
            (34, 13, 0x114),
            (35, 13, 0x115),
        ] {
            let bp = arena.alloc_block(&mzap(&[], salt, order), kind, 0, ZFS_INITIAL_TXG, order);
            set_mos(
                &mut mos_tables,
                id,
                &make_dnode(kind, bp.logical_bytes(), vec![bp], 0, Vec::new(), order),
            );
        }
        for bpobj_id in [7_usize, 8, 13, 36, 37, 38] {
            set_mos(
                &mut mos_tables,
                bpobj_id,
                &make_dnode(5, 4096, Vec::new(), 6, vec![0_u8; 48], order),
            );
        }
        for (special_dir_id, child_id, props_id) in [(9_usize, 33_u64, 30_u64), (14, 34, 31)] {
            set_mos(
                &mut mos_tables,
                special_dir_id,
                &make_dnode(
                    12,
                    512,
                    Vec::new(),
                    12,
                    encode_dsl_dir_bonus(0, 2, 0, child_id, props_id, 0, order),
                    order,
                ),
            );
        }
        set_mos(
            &mut mos_tables,
            24,
            &make_dnode(
                12,
                512,
                Vec::new(),
                12,
                encode_dsl_dir_bonus(25, 2, 0, 35, 32, 0, order),
                order,
            ),
        );
        let origin_snaps_bp = arena.alloc_block(
            &mzap(&[(b"$ORIGIN", 26)], 0x10C, order),
            14,
            0,
            ZFS_INITIAL_TXG,
            order,
        );
        set_mos(
            &mut mos_tables,
            27,
            &make_dnode(
                14,
                origin_snaps_bp.logical_bytes(),
                vec![origin_snaps_bp],
                0,
                Vec::new(),
                order,
            ),
        );
        let origin_hole_bp = BlockPointer::hole_pointer();
        set_mos(
            &mut mos_tables,
            25,
            &make_dnode(
                16,
                512,
                Vec::new(),
                16,
                encode_dsl_dataset_bonus(
                    24,
                    26,
                    1,
                    0,
                    27,
                    0,
                    1,
                    36,
                    0,
                    0xABCD_0025,
                    0,
                    &origin_hole_bp,
                    order,
                ),
                order,
            ),
        );
        let origin_clones_bp = arena.alloc_block(
            &mzap(&[(b"3", 3), (b"12", 18)], 0x10D, order),
            37,
            0,
            ZFS_INITIAL_TXG,
            order,
        );
        set_mos(
            &mut mos_tables,
            28,
            &make_dnode(
                37,
                origin_clones_bp.logical_bytes(),
                vec![origin_clones_bp],
                0,
                Vec::new(),
                order,
            ),
        );
        set_mos(
            &mut mos_tables,
            26,
            &make_dnode(
                16,
                512,
                Vec::new(),
                16,
                encode_dsl_dataset_bonus(
                    24,
                    0,
                    0,
                    25,
                    0,
                    3,
                    1,
                    13,
                    0,
                    0xABCD_0026,
                    28,
                    &origin_hole_bp,
                    order,
                ),
                order,
            ),
        );

        let d_snaps_bp = arena.alloc_block(&mzap(&[], 0x107, order), 14, 0, ZFS_INITIAL_TXG, order);
        set_mos(
            &mut mos_tables,
            22,
            &make_dnode(
                14,
                d_snaps_bp.logical_bytes(),
                vec![d_snaps_bp],
                0,
                Vec::new(),
                order,
            ),
        );
        set_mos(
            &mut mos_tables,
            3,
            &make_dnode(
                16,
                512,
                Vec::new(),
                16,
                encode_dsl_dataset_bonus(
                    2,
                    26,
                    1,
                    0,
                    4,
                    0,
                    10,
                    37,
                    root_ref_bytes,
                    0xABCD_0003,
                    0,
                    &root_os_bp,
                    order,
                ),
                order,
            ),
        );
        set_mos(
            &mut mos_tables,
            18,
            &make_dnode(
                16,
                512,
                Vec::new(),
                16,
                encode_dsl_dataset_bonus(
                    17,
                    26,
                    1,
                    0,
                    22,
                    0,
                    12,
                    38,
                    data_ref_bytes,
                    0xABCD_0018,
                    0,
                    &data_os_bp,
                    order,
                ),
                order,
            ),
        );
        set_mos(
            &mut mos_tables,
            17,
            &make_dnode(
                12,
                512,
                Vec::new(),
                12,
                encode_dsl_dir_bonus(18, 2, 26, 19, 20, data_ref_bytes, order),
                order,
            ),
        );
        set_mos(
            &mut mos_tables,
            2,
            &make_dnode(
                12,
                512,
                Vec::new(),
                12,
                encode_dsl_dir_bonus(3, 0, 26, 15, 16, root_ref_bytes + data_ref_bytes, order),
                order,
            ),
        );

        let rf_bp = arena.alloc_block(
            &mzap(
                &[
                    (b"org.illumos:lz4_compress", 1),
                    (b"com.delphix:hole_birth", 1),
                    (b"com.delphix:extensible_dataset", 0),
                ],
                0x108,
                order,
            ),
            196,
            0,
            ZFS_INITIAL_TXG,
            order,
        );
        set_mos(
            &mut mos_tables,
            10,
            &make_dnode(
                196,
                rf_bp.logical_bytes(),
                vec![rf_bp],
                0,
                Vec::new(),
                order,
            ),
        );
        let wf_bp = arena.alloc_block(
            &mzap(
                &[
                    (b"com.delphix:async_destroy", 0),
                    (b"com.delphix:empty_bpobj", 1),
                    (b"com.delphix:enabled_txg", 1),
                    (b"com.delphix:spacemap_histogram", 1),
                    (b"com.delphix:spacemap_v2", 1),
                ],
                0x109,
                order,
            ),
            196,
            0,
            ZFS_INITIAL_TXG,
            order,
        );
        set_mos(
            &mut mos_tables,
            11,
            &make_dnode(
                196,
                wf_bp.logical_bytes(),
                vec![wf_bp],
                0,
                Vec::new(),
                order,
            ),
        );
        let fd_bp = arena.alloc_block(&mzap(&[], 0x10A, order), 196, 0, ZFS_INITIAL_TXG, order);
        set_mos(
            &mut mos_tables,
            12,
            &make_dnode(
                196,
                fd_bp.logical_bytes(),
                vec![fd_bp],
                0,
                Vec::new(),
                order,
            ),
        );

        let top_guid = if mirror_width == 1 {
            ZFS_TOP_SINGLE_GUID
        } else {
            ZFS_TOP_MIRROR_GUID
        };
        let top_vdev_pairs = if mirror_width == 1 {
            vec![
                nv_str("type", "file"),
                nv_u64("id", 0),
                nv_u64("guid", top_guid),
                nv_str("path", "/dev/ffs-member-0"),
                nv_u64("metaslab_array", 6),
                nv_u64("metaslab_shift", ZFS_SLAB_SHIFT),
                nv_u64("ashift", u64::from(ashift)),
                nv_u64("asize", asize),
                nv_u64("is_log", 0),
            ]
        } else {
            let children: Vec<Vec<Vec<u8>>> = (0..mirror_width)
                .map(|idx| {
                    vec![
                        nv_str("type", "file"),
                        nv_u64("id", idx as u64),
                        nv_u64("guid", ZFS_CHILD_GUIDS[idx]),
                        nv_str("path", &format!("/dev/ffs-member-{idx}")),
                    ]
                })
                .collect();
            vec![
                nv_str("type", "mirror"),
                nv_u64("id", 0),
                nv_u64("guid", top_guid),
                nv_u64("metaslab_array", 6),
                nv_u64("metaslab_shift", ZFS_SLAB_SHIFT),
                nv_u64("ashift", u64::from(ashift)),
                nv_u64("asize", asize),
                nv_u64("is_log", 0),
                nv_list_array("children", &children),
            ]
        };
        let mos_cfg_packed = pack_xdr_nvlist(&[
            nv_u64("version", 5000),
            nv_str("name", "ffstestpool"),
            nv_u64("state", 1),
            nv_u64("txg", ZFS_INITIAL_TXG),
            nv_u64("pool_guid", ZFS_POOL_GUID),
            nv_u64("hostid", 1),
            nv_str("hostname", "frankenfs"),
            nv_u64("vdev_children", 1),
            nv_embedded(
                "vdev_tree",
                &[
                    nv_str("type", "root"),
                    nv_u64("id", 0),
                    nv_u64("guid", ZFS_POOL_GUID),
                    nv_list_array("children", std::slice::from_ref(&top_vdev_pairs)),
                ],
            ),
            nv_embedded("features_for_read", &[nv_bool("com.delphix:hole_birth")]),
        ]);
        let cfg_len = mos_cfg_packed.len() as u64;
        let mut cfg_padded = mos_cfg_packed;
        cfg_padded.resize(cfg_padded.len().max(4096).next_multiple_of(4096), 0);
        let cfg_bp = arena.alloc_block(&cfg_padded, 3, 0, ZFS_INITIAL_TXG, order);
        set_mos(
            &mut mos_tables,
            5,
            &make_dnode(
                3,
                cfg_padded.len(),
                vec![cfg_bp],
                4,
                order.encode(cfg_len).to_vec(),
                order,
            ),
        );

        let fet_bp = arena.alloc_block(
            &mzap(
                &[
                    (b"com.delphix:enabled_txg", 1),
                    (b"com.delphix:hole_birth", 1),
                ],
                0x10E,
                order,
            ),
            196,
            0,
            ZFS_INITIAL_TXG,
            order,
        );
        set_mos(
            &mut mos_tables,
            29,
            &make_dnode(
                196,
                fet_bp.logical_bytes(),
                vec![fet_bp],
                0,
                Vec::new(),
                order,
            ),
        );
        let obj_dir_bp = arena.alloc_block(
            &mzap(
                &[
                    (b"root_dataset", 2),
                    (b"config", 5),
                    (b"sync_bplist", 7),
                    (b"free_bpobj", 8),
                    (b"features_for_read", 10),
                    (b"features_for_write", 11),
                    (b"feature_descriptions", 12),
                    (b"empty_bpobj", 13),
                    (b"feature_enabled_txg", 29),
                ],
                0x10B,
                order,
            ),
            DMU_OT_OBJECT_DIRECTORY,
            0,
            ZFS_INITIAL_TXG,
            order,
        );
        set_mos(
            &mut mos_tables,
            1,
            &make_dnode(
                DMU_OT_OBJECT_DIRECTORY,
                obj_dir_bp.logical_bytes(),
                vec![obj_dir_bp],
                0,
                Vec::new(),
                order,
            ),
        );

        let mut ms_arr = vec![0_u8; (num_slabs * 8).max(4096).next_multiple_of(512)];
        ms_arr[0..8].copy_from_slice(&order.encode(sm_base_id as u64));
        let ms_arr_bp = arena.alloc_block(&ms_arr, 2, 0, ZFS_INITIAL_TXG, order);
        set_mos(
            &mut mos_tables,
            6,
            &make_dnode(2, ms_arr.len(), vec![ms_arr_bp], 0, Vec::new(), order),
        );

        let sector = 1_u64 << ashift;
        let sm_block_bytes = 4096_u64;
        let mos_table_bytes = DNODE_BLOCK_BYTES as u64;
        let mos_root_lsize = 1024_usize.max(usize::try_from(sector).unwrap());
        let mos_root_alloc_bytes = (mos_root_lsize as u64).next_multiple_of(sector);

        let sm0_off = arena.cursor;
        arena.cursor += sm_block_bytes;
        arena
            .alloc_map
            .apply(MapType::Allocate, sm0_off..(sm0_off + sm_block_bytes))
            .unwrap();

        let mut mos_table_offs = Vec::with_capacity(mos_table_blocks);
        for _ in 0..mos_table_blocks {
            let off = arena.cursor;
            arena.cursor += mos_table_bytes;
            arena
                .alloc_map
                .apply(MapType::Allocate, off..(off + mos_table_bytes))
                .unwrap();
            mos_table_offs.push(off);
        }
        let mos_root_off = arena.cursor;
        arena.cursor += mos_root_alloc_bytes;
        arena
            .alloc_map
            .apply(
                MapType::Allocate,
                mos_root_off..(mos_root_off + mos_root_alloc_bytes),
            )
            .unwrap();

        let slab_size = 1_u64 << ZFS_SLAB_SHIFT;
        let mut slab_map = AllocationMap::new(0, slab_size, ashift, 262_144).unwrap();
        let mut records = Vec::new();
        for r in arena.alloc_map.ranges() {
            let ov_end = r.end.min(slab_size);
            if r.start < ov_end {
                slab_map.apply(MapType::Allocate, r.start..ov_end).unwrap();
                records.extend(
                    extent_records_for_range(
                        MapType::Allocate,
                        r.start..ov_end,
                        0,
                        slab_size,
                        ashift,
                    )
                    .unwrap(),
                );
            }
        }
        let mut cur = Vec::with_capacity(4096);
        let pad = SpaceMapRecord::padding_word().encode(order, true).unwrap();
        for rec in &records {
            let encoded = rec.encode(order, true).unwrap();
            assert!(cur.len() + encoded.len() <= 4096);
            cur.extend_from_slice(&encoded);
        }
        let stream_len = cur.len() as u64;
        while cur.len() < 4096 {
            cur.extend_from_slice(&pad);
        }
        cur.truncate(4096);
        arena.blocks.insert(sm0_off, cur.clone());
        let sm_bp = BlockPointer::new_regular(&RegularBlockSpec {
            dvas: &[Dva {
                vdev: 0,
                offset: sm0_off,
                allocated_bytes: sm_block_bytes,
                gang: false,
            }],
            logical_bytes: 4096,
            physical: &cur,
            compression: 2,
            checksum_type: 7,
            object_type: 8,
            level: 0,
            payload_order: order,
            birth: ZFS_INITIAL_TXG,
            fill: 1,
        })
        .unwrap();
        let hist = slab_map.free_histogram(ashift).unwrap();
        let hdr = SpaceMapHeader {
            length: stream_len,
            allocated: i64::try_from(slab_map.allocated_bytes()).unwrap(),
            histogram: Some(hist),
        };
        let sm_dn = make_dnode(
            8,
            4096,
            vec![sm_bp],
            7,
            hdr.encode(320, 0, order).unwrap(),
            order,
        );
        write_dnode_at(
            &mut mos_tables[sm_base_id / slots_per_dnode_blk],
            sm_base_id % slots_per_dnode_blk,
            &sm_dn,
        )
        .unwrap();

        let mut mos_table_bps = Vec::with_capacity(mos_table_blocks);
        for (tbl_blk, tbl_off) in mos_tables.into_iter().zip(mos_table_offs) {
            let fill = tbl_blk
                .as_chunks::<DNODE_BYTES>()
                .0
                .iter()
                .filter(|slot| slot[0] != 0)
                .count() as u64;
            let bp = BlockPointer::new_regular(&RegularBlockSpec {
                dvas: &[Dva {
                    vdev: 0,
                    offset: tbl_off,
                    allocated_bytes: mos_table_bytes,
                    gang: false,
                }],
                logical_bytes: DNODE_BLOCK_BYTES,
                physical: &tbl_blk,
                compression: 2,
                checksum_type: 7,
                object_type: DMU_OT_DNODE,
                level: 0,
                payload_order: order,
                birth: ZFS_INITIAL_TXG,
                fill,
            })
            .unwrap();
            arena.blocks.insert(tbl_off, tbl_blk);
            mos_table_bps.push(bp);
        }
        let mos_meta_dn = make_dnode(
            DMU_OT_DNODE,
            DNODE_BLOCK_BYTES,
            mos_table_bps,
            0,
            Vec::new(),
            order,
        );
        let mos_os = ObjectSet::new(1, 0, mos_meta_dn, ZilHeader::empty(), mos_root_lsize).unwrap();
        let mos_os_bytes = mos_os.encode(order).unwrap();
        let mut mos_os_disk = mos_os_bytes.clone();
        mos_os_disk.resize(usize::try_from(mos_root_alloc_bytes).unwrap(), 0);
        arena.blocks.insert(mos_root_off, mos_os_disk);
        let mos_root_bp = BlockPointer::new_regular(&RegularBlockSpec {
            dvas: &[Dva {
                vdev: 0,
                offset: mos_root_off,
                allocated_bytes: mos_root_alloc_bytes,
                gang: false,
            }],
            logical_bytes: mos_root_lsize,
            physical: &mos_os_bytes,
            compression: 2,
            checksum_type: 7,
            object_type: DMU_OT_OBJSET,
            level: 0,
            payload_order: order,
            birth: ZFS_INITIAL_TXG,
            fill: mos_os.meta_fill(),
        })
        .unwrap();

        let slot_bytes = (1_usize << ashift).clamp(1024, 8192);
        let slots_per_label = UBERBLOCK_RING_BYTES / slot_bytes;
        let initial_slot = (ZFS_INITIAL_TXG as usize) % slots_per_label;
        let guid_sum = if mirror_width == 1 {
            ZFS_POOL_GUID.wrapping_add(top_guid)
        } else {
            (0..mirror_width).fold(ZFS_POOL_GUID.wrapping_add(top_guid), |acc, i| {
                acc.wrapping_add(ZFS_CHILD_GUIDS[i])
            })
        };
        let ub = Uberblock {
            order,
            version: 5000,
            txg: ZFS_INITIAL_TXG,
            guid_sum,
            timestamp: 1_700_000_000,
            root: mos_root_bp,
            checkpoint_txg: 0,
            raidz_reflow_info: 0,
        };
        let l_offsets = label_offsets(image_bytes).unwrap();
        let mut members = Vec::with_capacity(mirror_width);
        for &child_guid in ZFS_CHILD_GUIDS.iter().take(mirror_width) {
            let mut img = vec![0_u8; usize::try_from(image_bytes).unwrap()];
            for (&dva_off, blk) in &arena.blocks {
                let start = usize::try_from(DATA_OFFSET + dva_off).unwrap();
                img[start..start + blk.len()].copy_from_slice(blk);
            }
            let member_guid = if mirror_width == 1 {
                top_guid
            } else {
                child_guid
            };
            let lbl_packed = pack_xdr_nvlist(&[
                nv_u64("version", 5000),
                nv_str("name", "ffstestpool"),
                nv_u64("state", 1),
                nv_u64("txg", ZFS_INITIAL_TXG),
                nv_u64("pool_guid", ZFS_POOL_GUID),
                nv_u64("hostid", 1),
                nv_str("hostname", "frankenfs"),
                nv_u64("top_guid", top_guid),
                nv_u64("guid", member_guid),
                nv_u64("vdev_children", 1),
                nv_embedded("vdev_tree", &top_vdev_pairs),
                nv_embedded("features_for_read", &[nv_bool("com.delphix:hole_birth")]),
            ]);
            for &lbl_base in &l_offsets {
                let cfg_vdev_off = lbl_base + LABEL_CONFIG_OFFSET;
                let mut cfg_blk = vec![0_u8; LABEL_CONFIG_BYTES];
                cfg_blk[..lbl_packed.len()].copy_from_slice(&lbl_packed);
                stamp_label_checksum(&mut cfg_blk, cfg_vdev_off, order).unwrap();
                let c_start = usize::try_from(cfg_vdev_off).unwrap();
                img[c_start..c_start + LABEL_CONFIG_BYTES].copy_from_slice(&cfg_blk);

                let ub_vdev_off =
                    lbl_base + UBERBLOCK_RING_OFFSET + ((initial_slot * slot_bytes) as u64);
                let ub_blk = ub.encode(slot_bytes, ub_vdev_off).unwrap();
                let u_start = usize::try_from(ub_vdev_off).unwrap();
                img[u_start..u_start + slot_bytes].copy_from_slice(&ub_blk);
            }
            members.push(img);
        }
        (members, ZFS_POOL_GUID)
    }

    fn fuse_device_available() -> bool {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")
            .is_ok()
    }

    fn fuse_mount_tempdir() -> tempfile::TempDir {
        if Path::new("/tmp").is_dir() {
            tempfile::tempdir_in("/tmp").unwrap()
        } else {
            tempfile::tempdir().unwrap()
        }
    }

    fn verify_set(
        cx: &Cx,
        manifest: &Path,
        members: &[(PathBuf, PathBuf)],
        policy: TrustPolicy,
    ) -> ffs_error::Result<ffs_repair::sidecar::live::StorageSetVerifyReport> {
        wait_for_spawns();
        verify_storage_set(cx, manifest, members, policy)
    }

    fn exercise_live_fuse_mount(
        args: &Args,
        prepared: &Prepared,
        work: impl FnOnce(&Path),
    ) -> bool {
        let require_e2e =
            std::env::var_os("FFS_PROTECTED_MOUNT_E2E").as_deref() == Some(OsStr::new("1"));
        if !fuse_device_available() {
            assert!(
                !require_e2e,
                "/dev/fuse must be available when FFS_PROTECTED_MOUNT_E2E=1"
            );
            return false;
        }
        let mountpoint = prepared
            .mountpoint
            .as_ref()
            .expect("mountpoint required for live FUSE exercise")
            .clone();
        let runtime = mount_worker::mount_background_runtime().expect("mount runtime");
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let stopped = Arc::new(AtomicBool::new(false));
        let shutdown: Arc<Mutex<Option<Arc<AtomicBool>>>> = Arc::new(Mutex::new(None));

        let mounted = std::thread::scope(|scope| {
            let serve_rt = &runtime;
            let serve_stopped = Arc::clone(&stopped);
            struct ScopeShutdownGuard<'a> {
                stopped: &'a AtomicBool,
                shutdown: &'a Mutex<Option<Arc<AtomicBool>>>,
                mountpoint: PathBuf,
                armed: bool,
            }
            impl Drop for ScopeShutdownGuard<'_> {
                fn drop(&mut self) {
                    if !self.armed {
                        return;
                    }
                    self.stopped.store(true, Ordering::Release);
                    if let Some(flag) = self.shutdown.lock().unwrap().as_ref() {
                        flag.store(true, Ordering::Release);
                    }
                    let _ = command_unchecked(
                        std::process::Command::new("fusermount3")
                            .args(["-u", "-z"])
                            .arg(&self.mountpoint),
                    );
                    let _ = command_unchecked(
                        std::process::Command::new("umount")
                            .arg("-l")
                            .arg(&self.mountpoint),
                    );
                }
            }

            let serve_shutdown = Arc::clone(&shutdown);
            let worker = scope.spawn(move || {
                super::serve(
                    &cx,
                    Some(serve_rt),
                    args,
                    prepared,
                    &serve_stopped,
                    &serve_shutdown,
                )
            });
            let mut scope_guard = ScopeShutdownGuard {
                stopped: &stopped,
                shutdown: &shutdown,
                mountpoint: mountpoint.clone(),
                armed: true,
            };

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            let mut last_rd_err: Option<std::io::Error> = None;
            loop {
                if shutdown.lock().unwrap().is_some() {
                    match std::fs::read_dir(&mountpoint) {
                        Ok(_) => break,
                        Err(err) => last_rd_err = Some(err),
                    }
                }
                if worker.is_finished() {
                    scope_guard.armed = false;
                    let res = worker.join().expect("join serve thread");
                    if !require_e2e
                        && let Err(ref err) = res
                        && (format!("{err:#}")
                            .contains("fusermount3: mount failed: Permission denied")
                            || format!("{err:#}").contains("Operation not permitted"))
                    {
                        return false;
                    }
                    panic!("serve exited before mount became ready: {res:?}");
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "timed out waiting for live /dev/fuse protected mount at {} (last read_dir err: {last_rd_err:?})",
                    mountpoint.display()
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }

            let work_done = Arc::new(AtomicBool::new(false));
            let wd_done = Arc::clone(&work_done);
            let wd_shutdown = Arc::clone(&shutdown);
            let wd_mnt = mountpoint.clone();
            let watchdog = scope.spawn(move || {
                let wd_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while !wd_done.load(Ordering::Acquire) {
                    if std::time::Instant::now() >= wd_deadline {
                        eprintln!(
                            "WATCHDOG: live FUSE work exceeded 30s at {}; forcing unmount",
                            wd_mnt.display()
                        );
                        if let Some(flag) = wd_shutdown.lock().unwrap().as_ref() {
                            flag.store(true, Ordering::Release);
                        }
                        let _ = command_unchecked(
                            std::process::Command::new("fusermount3")
                                .args(["-u", "-z"])
                                .arg(&wd_mnt),
                        );
                        let _ = command_unchecked(
                            std::process::Command::new("umount").arg("-l").arg(&wd_mnt),
                        );
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            });

            let work_outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&mountpoint)));
            work_done.store(true, Ordering::Release);
            let _ = watchdog.join();

            stopped.store(true, Ordering::Release);
            if let Some(flag) = shutdown.lock().unwrap().as_ref() {
                flag.store(true, Ordering::Release);
            }
            let serve_outcome = worker.join().expect("join serve thread");
            scope_guard.armed = false;
            if let Err(payload) = work_outcome {
                std::panic::resume_unwind(payload);
            }
            serve_outcome.expect("clean serve shutdown");
            true
        });
        assert!(
            !require_e2e || mounted,
            "FFS_PROTECTED_MOUNT_E2E=1 requires live /dev/fuse mount execution"
        );
        mounted
    }

    #[test]
    fn bd_tqrnc_completeness_refuses_partial_zfs_mirror_external_ext4_journal_and_wrong_member_guid()
     {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().unwrap();
        let (members, pool_guid) = build_clean_writable_zfs_pool(2);

        let m0_img = dir.path().join("m0.zfs");
        let m0_rq = dir.path().join("m0.ffsrq");
        let m1_img = dir.path().join("m1.zfs");
        let m1_rq = dir.path().join("m1.ffsrq");
        std::fs::write(&m0_img, &members[0]).unwrap();
        std::fs::write(&m1_img, &members[1]).unwrap();

        let sidecar_opts = SidecarOptions {
            block_size: 4096,
            group_blocks: 16,
            repair_symbols: 4,
        };
        protect(&cx, &m0_img, &m0_rq, sidecar_opts).unwrap();

        // 1. One member's archive CANNOT qualify 2-way ZFS mirror protection (read-only OR --rw)!
        let single_ro = check_args(&m0_img, &m0_rq);
        let ro_err = prepare(&cx, &single_ro)
            .err()
            .expect("single-leg archive on 2-way ZFS mirror must be refused");
        assert!(
            format!("{ro_err:#}").contains("multi-member")
                || format!("{ro_err:#}").contains("storage-set")
        );

        let mut partial_writable = check_args(&m0_img, &m0_rq);
        partial_writable.check = false;
        partial_writable.rw = true;
        let mnt = dir.path().join("mnt");
        std::fs::create_dir(&mnt).unwrap();
        partial_writable.mountpoint = Some(mnt);
        assert!(prepare(&cx, &partial_writable).is_err());

        // 2. External log/special member flags are explicitly refused until native split-device recovery exists.
        let manifest_path = dir.path().join("mirror.ffsrqset");
        let key: PorKey = [0x61; 32];
        let key_file = dir.path().join("trust.key");
        std::fs::write(&key_file, key).unwrap();

        let mut wrong_id0 = [0_u8; 16];
        wrong_id0[..8].copy_from_slice(&0xDEAD_BEEF_CAFE_BABE_u64.to_le_bytes());
        let mut id1 = [0_u8; 16];
        id1[..8].copy_from_slice(&ZFS_CHILD_GUIDS[1].to_le_bytes());

        protect_storage_set(
            &cx,
            &StorageSetProtectRequest {
                manifest_path: manifest_path.clone(),
                filesystem: "zfs".to_owned(),
                topology: StorageSetTopology::ZfsMirror { width: 2 },
                view: ProtectedViewIdentity::default(),
                native_binding: NativeCommitBinding::UninterpretedRaw,
                members: vec![
                    StorageSetMemberSpec {
                        role: MemberRole::Data,
                        image_path: m0_img.clone(),
                        sidecar_path: m0_rq.clone(),
                        native_member_id: wrong_id0,
                        offset: 0,
                        length: None,
                    },
                    StorageSetMemberSpec {
                        role: MemberRole::Data,
                        image_path: m1_img.clone(),
                        sidecar_path: m1_rq.clone(),
                        native_member_id: id1,
                        offset: 0,
                        length: None,
                    },
                ],
                options: sidecar_opts,
                signing_key: Some(key),
            },
        )
        .unwrap();

        // 3. Manifest binding wrong physical ZFS member GUID is refused!
        let mut wrong_guid_args = check_args(&m0_img, &m0_rq);
        wrong_guid_args.set.manifest = Some(manifest_path);
        wrong_guid_args.set.extra_members = vec![m1_img, m1_rq];
        wrong_guid_args.set.pool_guid = Some(pool_guid);
        wrong_guid_args.set.trust_key_file = Some(key_file);
        wrong_guid_args.set.require_trusted_root = true;
        let guid_err = prepare(&cx, &wrong_guid_args)
            .err()
            .expect("wrong physical ZFS member GUID in manifest must be refused");
        assert!(
            format!("{guid_err:#}").contains("GUID disagrees"),
            "{guid_err:#}"
        );

        // 4. External-journal Ext4 (HAS_JOURNAL with journal_inum == 0 and non-zero journal_uuid)
        // is refused on single-member mount!
        let ext4_fix = Fixture::ext4_with_journal(true);
        command(
            Command::new("debugfs")
                .args(["-w", "-R", "set_super_value journal_inum 0"])
                .arg(&ext4_fix.image),
        );
        command(
            Command::new("debugfs")
                .args([
                    "-w",
                    "-R",
                    "set_super_value journal_uuid 11223344-5566-7788-99aa-bbccddeeff00",
                ])
                .arg(&ext4_fix.image),
        );
        let ext4_ext_rq = ext4_fix.dir.path().join("ext-jnl.ffsrq");
        protect(&cx, &ext4_fix.image, &ext4_ext_rq, sidecar_opts).unwrap();
        let ext4_err = prepare(&cx, &check_args(&ext4_fix.image, &ext4_ext_rq))
            .err()
            .expect("external-journal ext4 without journal member must be refused");
        assert!(
            format!("{ext4_err:#}").contains("external journal"),
            "{ext4_err:#}"
        );
    }

    #[test]
    fn bd_tqrnc_protected_writable_ntfs_binds_lsn_survives_cancelled_rename_heals_and_mounts_fuse()
    {
        let cx = Cx::for_testing();
        let dir = tempfile::tempdir().unwrap();
        let ntfs_img = dir.path().join("volume.ntfs");
        let ntfs_rq = dir.path().join("volume.ffsrq");
        let manifest_path = dir.path().join("ntfs.ffsrqset");
        let ledger_path = dir.path().join("ntfs-evidence.jsonl");
        let key: PorKey = [0x73; 32];
        let key_file = dir.path().join("ntfs.key");
        std::fs::write(&key_file, key).unwrap();

        let serial = 0xBEEF_CAFE_2026_1117_u64;
        let raw_ntfs = build_clean_writable_ntfs_image(128, 50, serial);
        std::fs::write(&ntfs_img, &raw_ntfs).unwrap();

        let sidecar_opts = SidecarOptions {
            block_size: 4096,
            group_blocks: 16,
            repair_symbols: 4,
        };
        protect_storage_set(
            &cx,
            &StorageSetProtectRequest {
                manifest_path: manifest_path.clone(),
                filesystem: "ntfs".to_owned(),
                topology: StorageSetTopology::SingleData,
                view: ProtectedViewIdentity::default(),
                native_binding: NativeCommitBinding::UninterpretedRaw,
                members: vec![StorageSetMemberSpec {
                    role: MemberRole::Data,
                    image_path: ntfs_img.clone(),
                    sidecar_path: ntfs_rq.clone(),
                    native_member_id: [0_u8; 16],
                    offset: 0,
                    length: None,
                }],
                options: sidecar_opts,
                signing_key: Some(key),
            },
        )
        .expect("protect clean NTFS storage set");

        let mnt_holder = fuse_mount_tempdir();
        let mnt_dir = mnt_holder.path().join("mnt-ntfs");
        std::fs::create_dir(&mnt_dir).unwrap();
        let make_args = |rw: bool, check: bool| -> Args {
            Args {
                image: ntfs_img.clone(),
                sidecar: ntfs_rq.clone(),
                mountpoint: (!check).then(|| mnt_dir.clone()),
                scrub: scrub::Options::default(),
                set: SetOptions {
                    manifest: Some(manifest_path.clone()),
                    trust_key_file: Some(key_file.clone()),
                    require_trusted_root: true,
                    evidence_ledger: Some(ledger_path.clone()),
                    ..SetOptions::default()
                },
                authority: Authority {
                    exclusive_image: true,
                    allow_repair: true,
                },
                check,
                rw,
                commit_interval_secs: None,
                allow_other: false,
            }
        };

        // Phase 1: In-process writable FsOps + LSN manifest sealing + cancelled-retry rename non-duplication.
        let rw_args = make_args(true, false);
        let prepared = prepare(&cx, &rw_args).expect("admit writable protected NTFS");
        assert_eq!(prepared.filesystem, "ntfs");
        assert!(prepared.fs.is_writable());

        let mut scope = RequestScope::empty();
        let sub = FsOps::mkdir(
            prepared.fs.as_ref(),
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("docs"),
            0o755,
            0,
            0,
        )
        .unwrap();
        let created = FsOps::create(
            prepared.fs.as_ref(),
            &cx,
            &mut scope,
            sub.ino,
            OsStr::new("draft.bin"),
            0o644,
            0,
            0,
        )
        .unwrap();
        let payload: Vec<u8> = (0_u32..16_385)
            .map(|i| u8::try_from((i * 5 + 1) % 251).unwrap())
            .collect();
        let written = FsOps::write(
            prepared.fs.as_ref(),
            &cx,
            &mut scope,
            created.ino,
            0,
            &payload,
        )
        .unwrap();
        assert_eq!(written as usize, payload.len());
        FsOps::fsync(prepared.fs.as_ref(), &cx, &mut scope, created.ino, 0, false).unwrap();

        // Mid-mount fsync must already seal the StorageSetManifest with a non-zero $LogFile commit_lsn!
        let mid_manifest = StorageSetManifest::decode(
            &std::fs::read(&manifest_path).unwrap(),
            TrustPolicy::RequireTrustedRoot { key },
        )
        .expect("mid-mount fsync must seal signed NTFS manifest");
        assert!(mid_manifest.generation >= 2);
        match mid_manifest.native_binding {
            NativeCommitBinding::Ntfs {
                volume_serial,
                commit_lsn,
                ..
            } => {
                assert_eq!(volume_serial, serial);
                assert!(commit_lsn > 0, "committed NTFS $LogFile LSN must be > 0");
            }
            other => panic!("expected NativeCommitBinding::Ntfs, got {other:?}"),
        }

        // Commit rename (`draft.bin` -> `committed.bin`), then simulate client retry after post-commit
        // reply loss/cancellation: retrying `draft.bin` -> `committed.bin` must fail cleanly with NotFound
        // and NEVER duplicate or corrupt `committed.bin`!
        FsOps::rename(
            prepared.fs.as_ref(),
            &cx,
            &mut scope,
            sub.ino,
            OsStr::new("draft.bin"),
            sub.ino,
            OsStr::new("committed.bin"),
        )
        .unwrap();
        let retry_err = FsOps::rename(
            prepared.fs.as_ref(),
            &cx,
            &mut scope,
            sub.ino,
            OsStr::new("draft.bin"),
            sub.ino,
            OsStr::new("committed.bin"),
        )
        .expect_err("retrying an already-committed rename must fail with NotFound");
        assert!(matches!(retry_err, FfsError::NotFound(_)), "{retry_err:?}");

        prepared.finish(&cx).expect("clean NTFS finish");

        let members = vec![(ntfs_img.clone(), ntfs_rq.clone())];
        let verified = verify_set(
            &cx,
            &manifest_path,
            &members,
            TrustPolicy::RequireTrustedRoot { key },
        )
        .unwrap();
        assert!(verified.is_healthy());

        // Independent native NTFS engine reopen verifies structural + $LogFile consistency!
        let data_lcn = {
            wait_for_spawns();
            let engine = ntfs::transaction::NtfsTransactionEngine::open(
                &cx,
                &ntfs_img,
                0,
                None,
                ntfs::NtfsWriteOptions {
                    offline_image: true,
                    allow_write: true,
                    recover_dirty: false,
                },
            )
            .expect("native NtfsTransactionEngine clean reopen");
            assert!(engine.last_recovery().is_none());
            drop(engine);

            let vol = ntfs::reader::NtfsVolume::open(&cx, &ntfs_img, 0, None).unwrap();
            let rec = vol.resolve(&cx, "/docs/committed.bin").unwrap();
            let stream = vol.data_stream(&cx, &rec, &[]).unwrap();
            assert_eq!(vol.read(&cx, &stream, 0, payload.len()).unwrap(), payload);
            let raw_disk = std::fs::read(&ntfs_img).unwrap();
            raw_disk
                .as_chunks::<4096>()
                .0
                .iter()
                .position(|blk| blk == &payload[..4096])
                .expect("allocated non-resident LCN") as u64
        };

        // Phase 2: Inject 2-block media corruption in `committed.bin`'s physical clusters and prove read self-healing!
        let orig_b0 = {
            let mut b = vec![0_u8; 4096];
            File::open(&ntfs_img)
                .unwrap()
                .read_exact_at(&mut b, data_lcn * 4096)
                .unwrap();
            b
        };
        let orig_b1 = {
            let mut b = vec![0_u8; 4096];
            File::open(&ntfs_img)
                .unwrap()
                .read_exact_at(&mut b, (data_lcn + 1) * 4096)
                .unwrap();
            b
        };
        let ro_prepared = prepare(&cx, &make_args(false, true)).expect("reopen protected NTFS");
        {
            let f = File::options().write(true).open(&ntfs_img).unwrap();
            f.write_all_at(&[0xEE; 8192], data_lcn * 4096).unwrap();
            f.sync_all().unwrap();
        }
        let docs_attr = FsOps::lookup(
            ro_prepared.fs.as_ref(),
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("docs"),
        )
        .unwrap();
        let file_attr = FsOps::lookup(
            ro_prepared.fs.as_ref(),
            &cx,
            &mut scope,
            docs_attr.ino,
            OsStr::new("committed.bin"),
        )
        .unwrap();
        let healed = FsOps::read(
            ro_prepared.fs.as_ref(),
            &cx,
            &mut scope,
            file_attr.ino,
            0,
            u32::try_from(payload.len()).unwrap(),
        )
        .unwrap();
        assert_eq!(healed, payload);
        let mut disk_b0 = vec![0_u8; 4096];
        let mut disk_b1 = vec![0_u8; 4096];
        File::open(&ntfs_img)
            .unwrap()
            .read_exact_at(&mut disk_b0, data_lcn * 4096)
            .unwrap();
        File::open(&ntfs_img)
            .unwrap()
            .read_exact_at(&mut disk_b1, (data_lcn + 1) * 4096)
            .unwrap();
        assert_eq!(disk_b0, orig_b0);
        assert_eq!(disk_b1, orig_b1);
        ro_prepared.finish(&cx).unwrap();

        // Phase 3: Real Linux `/dev/fuse` kernel-mounted `--rw` writes + native reopen!
        let fuse_args = make_args(true, false);
        let fuse_prepared = prepare(&cx, &fuse_args).expect("prepare NTFS for live FUSE");
        let fuse_payload = vec![0x9C_u8; 10_000];
        let mounted = exercise_live_fuse_mount(&fuse_args, &fuse_prepared, |mnt| {
            assert_eq!(
                std::fs::read(mnt.join("docs/committed.bin")).unwrap(),
                payload
            );
            let draft_path = mnt.join("docs/fuse-draft.bin");
            let final_path = mnt.join("docs/fuse-final.bin");
            {
                let mut f = File::create(&draft_path).unwrap();
                f.write_all(&fuse_payload).unwrap();
                f.sync_all().unwrap();
            }
            std::fs::rename(&draft_path, &final_path).unwrap();
            assert_eq!(std::fs::read(&final_path).unwrap(), fuse_payload);
        });
        fuse_prepared
            .finish(&cx)
            .expect("finish live FUSE NTFS mount");
        assert!(
            verify_set(
                &cx,
                &manifest_path,
                &members,
                TrustPolicy::RequireTrustedRoot { key }
            )
            .unwrap()
            .is_healthy()
        );
        if mounted {
            let vol = ntfs::reader::NtfsVolume::open(&cx, &ntfs_img, 0, None).unwrap();
            let rec = vol.resolve(&cx, "/docs/fuse-final.bin").unwrap();
            let stream = vol.data_stream(&cx, &rec, &[]).unwrap();
            assert_eq!(
                vol.read(&cx, &stream, 0, fuse_payload.len()).unwrap(),
                fuse_payload
            );
        }

        let ledger_records = parse_evidence_ledger(&std::fs::read(&ledger_path).unwrap());
        assert!(ledger_records.iter().any(|r| {
            r.protected_repair_gate
                .as_ref()
                .is_some_and(|g| g.authorized)
        }));
        assert!(ledger_records.iter().any(|r| {
            r.protected_commit_ack
                .as_ref()
                .is_some_and(|a| a.protected_durable)
        }));
    }

    #[test]
    fn bd_tqrnc_protected_writable_zfs_single_and_mirror_bind_txg_heal_and_mount_fuse() {
        for mirror_width in [1_usize, 2_usize] {
            let cx = Cx::for_testing();
            let dir = tempfile::tempdir().unwrap();
            let (raw_members, pool_guid) = build_clean_writable_zfs_pool(mirror_width);

            let manifest_path = dir.path().join("zfs.ffsrqset");
            let ledger_path = dir.path().join("zfs-evidence.jsonl");
            let key: PorKey = [0x84; 32];
            let key_file = dir.path().join("zfs.key");
            std::fs::write(&key_file, key).unwrap();

            let mut specs = Vec::with_capacity(mirror_width);
            let mut member_pairs = Vec::with_capacity(mirror_width);
            for (idx, raw) in raw_members.iter().enumerate() {
                let img = dir.path().join(format!("m{idx}.zfs"));
                let rq = dir.path().join(format!("m{idx}.ffsrq"));
                std::fs::write(&img, raw).unwrap();
                let guid = if mirror_width == 1 {
                    ZFS_TOP_SINGLE_GUID
                } else {
                    ZFS_CHILD_GUIDS[idx]
                };
                let mut native_id = [0_u8; 16];
                native_id[..8].copy_from_slice(&guid.to_le_bytes());
                specs.push(StorageSetMemberSpec {
                    role: MemberRole::Data,
                    image_path: img.clone(),
                    sidecar_path: rq.clone(),
                    native_member_id: native_id,
                    offset: 0,
                    length: None,
                });
                member_pairs.push((img, rq));
            }

            let topology = if mirror_width == 1 {
                StorageSetTopology::ZfsSingleLeaf
            } else {
                StorageSetTopology::ZfsMirror { width: 2 }
            };
            protect_storage_set(
                &cx,
                &StorageSetProtectRequest {
                    manifest_path: manifest_path.clone(),
                    filesystem: "zfs".to_owned(),
                    topology,
                    view: ProtectedViewIdentity {
                        partition_selector: None,
                        zfs_dataset: vec!["data".to_owned()],
                        btrfs_subvolume_id: None,
                    },
                    native_binding: NativeCommitBinding::UninterpretedRaw,
                    members: specs,
                    options: SidecarOptions {
                        block_size: 4096,
                        group_blocks: 16,
                        repair_symbols: 4,
                    },
                    signing_key: Some(key),
                },
            )
            .expect("protect ZFS storage set");

            let mnt_holder = fuse_mount_tempdir();
            let mnt_dir = mnt_holder.path().join("mnt-zfs");
            std::fs::create_dir(&mnt_dir).unwrap();
            let extra_members: Vec<PathBuf> = member_pairs[1..]
                .iter()
                .flat_map(|(i, r)| [i.clone(), r.clone()])
                .collect();

            let make_args = |rw: bool, check: bool| -> Args {
                Args {
                    image: member_pairs[0].0.clone(),
                    sidecar: member_pairs[0].1.clone(),
                    mountpoint: (!check).then(|| mnt_dir.clone()),
                    scrub: scrub::Options::default(),
                    set: SetOptions {
                        manifest: Some(manifest_path.clone()),
                        extra_members: extra_members.clone(),
                        zfs_dataset: Some("data".to_owned()),
                        pool_guid: Some(pool_guid),
                        trust_key_file: Some(key_file.clone()),
                        require_trusted_root: true,
                        evidence_ledger: Some(ledger_path.clone()),
                        ..SetOptions::default()
                    },
                    authority: Authority {
                        exclusive_image: true,
                        allow_repair: true,
                    },
                    check,
                    rw,
                    commit_interval_secs: None,
                    allow_other: false,
                }
            };

            // Phase 1: Writable FsOps (mkdir, create, write, chmod setattr, setxattr, rename, fsync)
            let rw_args = make_args(true, false);
            let prepared = prepare(&cx, &rw_args).expect("admit writable protected ZFS");
            assert_eq!(prepared.filesystem, "zfs");
            assert!(prepared.fs.is_writable());

            let mount_user = nix::unistd::geteuid().as_raw();
            let mount_group = nix::unistd::getegid().as_raw();
            let mut scope = RequestScope::empty();
            let sub = FsOps::mkdir(
                prepared.fs.as_ref(),
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("work"),
                0o755,
                mount_user,
                mount_group,
            )
            .unwrap();
            let created = FsOps::create(
                prepared.fs.as_ref(),
                &cx,
                &mut scope,
                sub.ino,
                OsStr::new("temp.bin"),
                0o644,
                mount_user,
                mount_group,
            )
            .unwrap();
            let payload: Vec<u8> = (0_u32..12_345)
                .map(|i| u8::try_from((i * 9 + mirror_width as u32) % 251).unwrap())
                .collect();
            assert_eq!(
                FsOps::write(
                    prepared.fs.as_ref(),
                    &cx,
                    &mut scope,
                    created.ino,
                    0,
                    &payload
                )
                .unwrap() as usize,
                payload.len()
            );
            // Exercises ZPL v5 SA `chmod` (`ZPL_DACL_ACES` SA_ACL swap=4 compatibility)!
            FsOps::setattr(
                prepared.fs.as_ref(),
                &cx,
                &mut scope,
                created.ino,
                &SetAttrRequest {
                    mode: Some(0o600),
                    uid: Some(mount_user),
                    gid: Some(mount_group),
                    size: None,
                    atime: None,
                    mtime: None,
                },
            )
            .unwrap();
            FsOps::setxattr(
                prepared.fs.as_ref(),
                &cx,
                &mut scope,
                created.ino,
                "user.tag",
                b"protected-zfs",
                XattrSetMode::Set,
            )
            .unwrap();
            FsOps::rename(
                prepared.fs.as_ref(),
                &cx,
                &mut scope,
                sub.ino,
                OsStr::new("temp.bin"),
                sub.ino,
                OsStr::new("sealed.bin"),
            )
            .unwrap();
            FsOps::fsync(prepared.fs.as_ref(), &cx, &mut scope, created.ino, 0, false).unwrap();

            // Verify mid-mount fsync already sealed StorageSetManifest with committed_txg > 20!
            let mid_manifest = StorageSetManifest::decode(
                &std::fs::read(&manifest_path).unwrap(),
                TrustPolicy::RequireTrustedRoot { key },
            )
            .unwrap();
            assert!(mid_manifest.generation >= 2);
            let sealed_txg = match mid_manifest.native_binding {
                NativeCommitBinding::Zfs {
                    pool_guid: pg,
                    member_guids,
                    committed_txg,
                    ..
                } => {
                    assert_eq!(pg, pool_guid);
                    assert_eq!(member_guids.len(), mirror_width);
                    assert!(committed_txg > ZFS_INITIAL_TXG);
                    committed_txg
                }
                other => panic!("expected NativeCommitBinding::Zfs, got {other:?}"),
            };

            prepared.finish(&cx).expect("finish writable protected ZFS");
            let verified = verify_set(
                &cx,
                &manifest_path,
                &member_pairs,
                TrustPolicy::RequireTrustedRoot { key },
            )
            .unwrap();
            assert!(verified.is_healthy());
            assert_eq!(verified.member_reports.len(), mirror_width);

            // Independent native ZfsTransactionEngine reopen across all members verifies space maps + Uberblocks!
            {
                wait_for_spawns();
                let img_paths: Vec<&Path> = member_pairs.iter().map(|(i, _)| i.as_path()).collect();
                let (lbl, slot) = {
                    let leaves: Vec<_> = img_paths
                        .iter()
                        .map(|p| zfs::reader::Leaf::open(&cx, p, 0, None).unwrap())
                        .collect();
                    let pool = zfs::reader::Pool::from_leaves(leaves).unwrap();
                    let (l, s, _) = pool.import_active(&cx, Some(pool_guid)).unwrap();
                    (l, s)
                };
                wait_for_spawns();
                let engine = zfs::ZfsTransactionEngine::open_files(
                    &cx,
                    &img_paths,
                    zfs::ZfsWriteOptions {
                        offline_image: true,
                        allow_write: true,
                        pool_guid,
                        label: lbl,
                        slot,
                        reconcile_torn_uberblocks: false,
                    },
                )
                .expect("native ZfsTransactionEngine clean reopen across all members");
                assert!(engine.committed_txg() >= sealed_txg);
            }

            // Phase 2: Corrupt physical Uberblock/data region on EVERY member and prove RaptorQ self-healing!
            let saved_m0_block = {
                let mut b = vec![0_u8; 4096];
                File::open(&member_pairs[0].0)
                    .unwrap()
                    .read_exact_at(&mut b, DATA_OFFSET + 4096)
                    .unwrap();
                b
            };
            let ro_prepared = prepare(&cx, &make_args(false, true)).expect("reopen protected ZFS");
            for (img, _) in &member_pairs {
                let f = File::options().write(true).open(img).unwrap();
                f.write_all_at(&[0xEE; 4096], DATA_OFFSET + 4096).unwrap();
                f.sync_all().unwrap();
            }
            let work_attr = FsOps::lookup(
                ro_prepared.fs.as_ref(),
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("work"),
            )
            .unwrap();
            let sealed_attr = FsOps::lookup(
                ro_prepared.fs.as_ref(),
                &cx,
                &mut scope,
                work_attr.ino,
                OsStr::new("sealed.bin"),
            )
            .unwrap();
            // Read-only ZfsFs exposes sandboxed extraction permissions (0o444) while preserving xattrs/data;
            // native mode/uid/gid (0o600, 1234, 5678) are verified on the writable reopen below!
            assert_eq!(sealed_attr.perm & 0o777, 0o444);
            assert_eq!(
                FsOps::getxattr(ro_prepared.fs.as_ref(), &cx, sealed_attr.ino, "user.tag")
                    .unwrap()
                    .as_deref(),
                Some(b"protected-zfs".as_slice())
            );
            let read_back = FsOps::read(
                ro_prepared.fs.as_ref(),
                &cx,
                &mut scope,
                sealed_attr.ino,
                0,
                u32::try_from(payload.len()).unwrap(),
            )
            .unwrap();
            assert_eq!(read_back, payload);

            // Force read of the corrupted block on member 0 via primary_device to verify writeback healing
            let mut healed_b = vec![0_u8; 4096];
            ro_prepared
                .device
                .read_exact_at(&cx, ByteOffset(DATA_OFFSET + 4096), &mut healed_b)
                .unwrap();
            assert_eq!(healed_b, saved_m0_block);
            if mirror_width == 2 {
                let mut healed_m1 = vec![0_u8; 4096];
                ro_prepared.storage_set.members()[1]
                    .device
                    .read_exact_at(&cx, ByteOffset(DATA_OFFSET + 4096), &mut healed_m1)
                    .unwrap();
            }
            ro_prepared.finish(&cx).unwrap();

            // Phase 3: Writable reopen verifies persisted ZPL v5 SA chmod/chown + live `/dev/fuse` writes!
            let fuse_args = make_args(true, false);
            let fuse_prepared = prepare(&cx, &fuse_args).expect("prepare ZFS for live FUSE");
            let rw_work = FsOps::lookup(
                fuse_prepared.fs.as_ref(),
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("work"),
            )
            .unwrap();
            let rw_sealed = FsOps::lookup(
                fuse_prepared.fs.as_ref(),
                &cx,
                &mut scope,
                rw_work.ino,
                OsStr::new("sealed.bin"),
            )
            .unwrap();
            assert_eq!(rw_sealed.perm & 0o777, 0o600);
            assert_eq!(rw_sealed.uid, mount_user);
            assert_eq!(rw_sealed.gid, mount_group);
            let fuse_payload = vec![0x5D_u8; 9_000];
            let mounted = exercise_live_fuse_mount(&fuse_args, &fuse_prepared, |mnt| {
                assert_eq!(std::fs::read(mnt.join("work/sealed.bin")).unwrap(), payload);
                let draft = mnt.join("work/fuse-zfs-draft.bin");
                let committed = mnt.join("work/fuse-zfs-final.bin");
                {
                    let mut f = File::create(&draft).unwrap();
                    f.write_all(&fuse_payload).unwrap();
                    f.sync_all().unwrap();
                }
                std::fs::rename(&draft, &committed).unwrap();
                assert_eq!(std::fs::read(&committed).unwrap(), fuse_payload);
            });
            fuse_prepared
                .finish(&cx)
                .expect("finish live FUSE ZFS mount");
            let post_fuse_verify = verify_set(
                &cx,
                &manifest_path,
                &member_pairs,
                TrustPolicy::RequireTrustedRoot { key },
            )
            .unwrap();
            assert!(post_fuse_verify.is_healthy());

            if mounted {
                let reopen_check = prepare(&cx, &make_args(false, true)).unwrap();
                let w_attr = FsOps::lookup(
                    reopen_check.fs.as_ref(),
                    &cx,
                    &mut scope,
                    InodeNumber(1),
                    OsStr::new("work"),
                )
                .unwrap();
                let f_attr = FsOps::lookup(
                    reopen_check.fs.as_ref(),
                    &cx,
                    &mut scope,
                    w_attr.ino,
                    OsStr::new("fuse-zfs-final.bin"),
                )
                .unwrap();
                assert_eq!(
                    FsOps::read(
                        reopen_check.fs.as_ref(),
                        &cx,
                        &mut scope,
                        f_attr.ino,
                        0,
                        u32::try_from(fuse_payload.len()).unwrap(),
                    )
                    .unwrap(),
                    fuse_payload
                );
                reopen_check.finish(&cx).unwrap();
            }
        }
    }
}
