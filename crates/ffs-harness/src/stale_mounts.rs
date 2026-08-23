//! Reap stale FrankenFS FUSE mounts left behind by crashed or killed test runs.
//!
//! Background (ts1 incident, 2026-06-03): the FUSE e2e/conformance tests mount
//! images at `<tempdir>/mnt`. When a test process dies without unmounting —
//! SIGKILL, OOM, or a wedged server thread that never closes `/dev/fuse` — the
//! mount outlives the run. `MountOption::AutoUnmount` only fires when the
//! session fd closes, so a *wedged-alive* server leaks its mount indefinitely.
//! Dead FUSE mounts are toxic well beyond the leak itself: any tool that
//! statfs's the whole mount table (uutils `stat`/`df` on Ubuntu 25.10, the
//! login MOTD release-upgrade check, parts of `ps`) hangs forever on the first
//! corpse it touches. 27 such corpses accumulated on ts1 and wedged the host.
//!
//! The fix is self-healing rather than best-effort teardown: before mounting
//! anything, each test process sweeps the mount table for FrankenFS mounts
//! under the system temp dirs, probes each one for liveness with a *bounded
//! external* probe (so healthy mounts belonging to concurrently running test
//! binaries are never touched), and lazily unmounts only the dead ones.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};
use std::time::Duration;

/// Outcome of one reap sweep.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReapReport {
    /// FrankenFS mounts found under the temp dirs.
    pub candidates: usize,
    /// Candidates that answered the liveness probe (left alone).
    pub live: usize,
    /// Dead candidates successfully (lazily) unmounted.
    pub reaped: usize,
    /// Dead candidates we failed to unmount.
    pub failed: usize,
}

/// Sweep once per process. Cheap to call from every mount helper.
pub fn reap_stale_frankenfs_mounts_once() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let report = reap_stale_frankenfs_mounts();
        if report.reaped > 0 || report.failed > 0 {
            eprintln!(
                "stale_mounts: reaped {} dead FrankenFS mount(s), {} failed, {} live left alone",
                report.reaped, report.failed, report.live
            );
        }
    });
}

/// Find and lazily unmount dead FrankenFS FUSE mounts under the temp dirs.
///
/// A mount is considered FrankenFS when its `/proc/mounts` source is
/// `frankenfs` or its fstype is `fuse.ffs` / `fuse.frankenfs` (see
/// `build_mount_options` in `ffs-fuse`: `FSName("frankenfs")` +
/// `Subtype("ffs")`). Only mountpoints under [`temp_roots`] are eligible, so
/// a deliberately mounted FrankenFS volume elsewhere is never touched.
#[cfg(target_os = "linux")]
#[must_use]
pub fn reap_stale_frankenfs_mounts() -> ReapReport {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return ReapReport::default();
    };
    reap_from_mounts_table(&mounts)
}

/// Non-Linux stub: `/proc/mounts` (and the leak mechanism) is Linux-specific.
#[cfg(not(target_os = "linux"))]
pub fn reap_stale_frankenfs_mounts() -> ReapReport {
    ReapReport::default()
}

#[cfg(target_os = "linux")]
fn reap_from_mounts_table(mounts: &str) -> ReapReport {
    let mut report = ReapReport::default();
    let roots = temp_roots();
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (Some(source), Some(mountpoint_raw), Some(fstype)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !is_frankenfs_mount(source, fstype) {
            continue;
        }
        let mountpoint = unescape_mounts_field(mountpoint_raw);
        if !roots.iter().any(|root| mountpoint.starts_with(root)) {
            continue;
        }
        report.candidates += 1;
        match probe_liveness(&mountpoint, Duration::from_millis(1500)) {
            Liveness::Live => report.live += 1,
            Liveness::Dead => {
                if lazy_unmount(&mountpoint) {
                    report.reaped += 1;
                } else {
                    report.failed += 1;
                }
            }
        }
    }
    report
}

/// Roots under which test mounts may live. `std::env::temp_dir()` honours
/// `TMPDIR`, but the *reaping* process may run with a different `TMPDIR` than
/// the *leaking* one did, so the conventional locations are always included.
fn temp_roots() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/tmp"), PathBuf::from("/data/tmp")];
    let env_tmp = std::env::temp_dir();
    if !roots.contains(&env_tmp) {
        roots.push(env_tmp);
    }
    roots
}

/// Markers FrankenFS mounts carry in the mount table.
fn is_frankenfs_mount(source: &str, fstype: &str) -> bool {
    source == "frankenfs" || fstype == "fuse.ffs" || fstype == "fuse.frankenfs"
}

/// Decode the octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash) used in `/proc/mounts` path fields.
#[allow(clippy::items_after_statements)]
fn unescape_mounts_field(field: &str) -> PathBuf {
    let mut out = Vec::with_capacity(field.len());
    let bytes = field.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && let Some(val) = octal3(&bytes[i + 1..])
        {
            out.push(val);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_vec(out))
}

/// Parse exactly three octal digits, if present.
fn octal3(bytes: &[u8]) -> Option<u8> {
    if bytes.len() < 3 {
        return None;
    }
    let mut val: u32 = 0;
    for &b in &bytes[..3] {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        val = val * 8 + u32::from(b - b'0');
    }
    u8::try_from(val).ok()
}

#[cfg(target_os = "linux")]
enum Liveness {
    Live,
    Dead,
}

/// Probe a mountpoint without risking a hang in *this* process.
///
/// The probe must touch only the candidate path: `stat`/`df` from uutils
/// coreutils statfs the whole mount table and would hang on *other* corpses,
/// so a plain `ls <mnt>` child is used instead. Outcomes:
///
/// * exits 0 quickly        → healthy mount (possibly a concurrent test's) — skip
/// * hangs past the timeout → wedged-alive server (the toxic case) — reap
/// * exits non-zero         → re-check inline (safe: it did not hang) and reap
///   only on `ENOTCONN` (dead transport); permission errors etc. are skipped
#[cfg(target_os = "linux")]
#[allow(clippy::items_after_statements)]
fn probe_liveness(mountpoint: &Path, timeout: Duration) -> Liveness {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let Ok(mut child) = Command::new("ls")
        .arg(mountpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        // Cannot probe: be conservative and leave the mount alone.
        return Liveness::Live;
    };

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Liveness::Live;
                }
                // `ls` failed fast. Distinguish a dead transport from e.g. a
                // permission error; this read_dir cannot hang (ls just proved
                // the mount answers promptly).
                const ENOTCONN: i32 = 107;
                return match std::fs::read_dir(mountpoint) {
                    Err(e) if e.raw_os_error() == Some(ENOTCONN) => Liveness::Dead,
                    _ => Liveness::Live,
                };
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    // Wedged in uninterruptible sleep on the dead mount; the
                    // lazy unmount below unblocks and reaps it eventually.
                    let _ = child.kill();
                    return Liveness::Dead;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return Liveness::Live,
        }
    }
}

/// Lazily detach a dead mount: `fusermount3 -uz`, then `fusermount -uz`,
/// then `umount -l`, and finally — for a server thread wedged so hard the
/// lazy detach cannot drain it — abort the FUSE connection directly via
/// `/sys/fs/fuse/connections/<id>/abort`. Returns whether the mountpoint
/// left the mount table.
///
/// Idempotent: safe to call on an already-unmounted path (every step no-ops
/// when the mount is gone, and the final truth check reads `/proc/mounts`).
#[cfg(target_os = "linux")]
fn lazy_unmount(mountpoint: &Path) -> bool {
    use std::process::{Command, Stdio};

    for (cmd, args) in [
        ("fusermount3", &["-uz"][..]),
        ("fusermount", &["-uz"][..]),
        ("umount", &["-l"][..]),
    ] {
        let status = Command::new(cmd)
            .args(args)
            .arg(mountpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if matches!(status, Ok(s) if s.success()) {
            break;
        }
    }

    if !still_mounted(mountpoint) {
        return true;
    }

    // A lazy detach alone cannot reclaim a connection whose server thread is
    // wedged inside `/dev/fuse` (the toxic D-state case): the device fd never
    // closes, so the kernel keeps the FUSE worker threads alive indefinitely.
    // Aborting the connection forces every outstanding/future request to fail
    // with ENOTCONN, releasing those threads so the lazy detach can complete.
    // This is the manual `echo 1 > .../abort` recovery, expressed in code.
    abort_fuse_connection(mountpoint);

    !still_mounted(mountpoint)
}

/// Whether `mountpoint` is still present in `/proc/mounts`. Truth comes from
/// the live mount table, never from a command's exit code.
#[cfg(target_os = "linux")]
fn still_mounted(mountpoint: &Path) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        // If we cannot read the table, assume the mount is gone rather than
        // spinning on it: the caller treats `false` as "nothing left to do".
        return false;
    };
    mounts.lines().any(|line| {
        line.split_whitespace()
            .nth(1)
            .is_some_and(|mp| unescape_mounts_field(mp) == mountpoint)
    })
}

/// Locate the FUSE connection id backing `mountpoint` (the device *minor* from
/// `/proc/self/mountinfo`) and write `1` to
/// `/sys/fs/fuse/connections/<id>/abort` to tear down a wedged connection.
///
/// Best-effort: silently no-ops when mountinfo is unreadable, the mount is
/// already gone, or the sysfs node is not writable (unprivileged sandbox).
#[cfg(target_os = "linux")]
fn abort_fuse_connection(mountpoint: &Path) {
    use std::io::Write;

    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return;
    };
    let Some(minor) = fuse_connection_minor(&mountinfo, mountpoint) else {
        return;
    };
    let abort = PathBuf::from("/sys/fs/fuse/connections")
        .join(minor)
        .join("abort");
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&abort) {
        let _ = f.write_all(b"1");
    }
}

/// Extract the FUSE connection id (the *minor* of the `major:minor` field) for
/// `mountpoint` from `/proc/self/mountinfo` contents. The connection directory
/// under `/sys/fs/fuse/connections/<id>` is named by this device minor.
///
/// mountinfo field layout: `id parent major:minor root mountpoint ...`.
#[cfg(target_os = "linux")]
fn fuse_connection_minor(mountinfo: &str, mountpoint: &Path) -> Option<String> {
    for line in mountinfo.lines() {
        let mut fields = line.split_whitespace();
        // Skip id, parent; capture major:minor; skip root; capture mountpoint.
        let (_id, _parent, majmin, _root, mp_raw) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        );
        let (Some(majmin), Some(mp_raw)) = (majmin, mp_raw) else {
            continue;
        };
        if unescape_mounts_field(mp_raw) != mountpoint {
            continue;
        }
        if let Some(minor) = majmin.split(':').nth(1) {
            return Some(minor.to_owned());
        }
    }
    None
}

// ── RAII teardown guard ──────────────────────────────────────────────────────

/// Registry of live FUSE mountpoints owned by [`MountGuard`]s in this process,
/// consulted by the signal handler (where no `Drop` runs) so it can reclaim
/// guard-tracked mounts even before the proactive mount-table sweep.
#[cfg(target_os = "linux")]
static LIVE_MOUNTS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// RAII guard owning a background FUSE session and its mountpoint.
///
/// On `Drop` — normal return, `?` propagation, **panic unwind**, or an explicit
/// `drop()` — it first drops the inner `fuser::BackgroundSession`, performing
/// the clean happy-path unmount (which leaves the mountpoint immediately free
/// for the remount tests), and then escalates to the robust lazy-detach +
/// connection-abort path *only if the mount is still present* (a busy or wedged
/// server the clean unmount could not drain). The `Drop` covers every normal
/// and unwinding exit; the process-wide SIGINT/SIGTERM handler installed by
/// [`install_teardown_hooks`] covers the abrupt-kill exits where no `Drop`
/// runs. Together they reclaim the mount on every reachable exit path short of
/// `SIGKILL` (which the proactive [`reap_stale_frankenfs_mounts_once`] sweep
/// covers on the next run).
#[cfg(target_os = "linux")]
pub struct MountGuard {
    session: Option<fuser::BackgroundSession>,
    mountpoint: PathBuf,
}

#[cfg(target_os = "linux")]
impl MountGuard {
    /// Wrap a live background session, registering its mountpoint for
    /// signal-driven teardown and installing the process-wide hooks once.
    #[must_use]
    pub fn new(session: fuser::BackgroundSession, mountpoint: &Path) -> Self {
        install_teardown_hooks();
        if let Ok(mut live) = LIVE_MOUNTS.lock() {
            live.push(mountpoint.to_path_buf());
        }
        Self {
            session: Some(session),
            mountpoint: mountpoint.to_path_buf(),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for MountGuard {
    fn drop(&mut self) {
        // 1. Clean happy-path unmount first (frees the mountpoint for remount).
        drop(self.session.take());
        // 2. Escalate only if a wedged/busy server kept the mount alive. The
        //    lazy path never panics, so it is safe to run during unwind.
        if still_mounted(&self.mountpoint) {
            let _ = lazy_unmount(&self.mountpoint);
        }
        // 3. Deregister so the signal handler does not chase a freed mount.
        if let Ok(mut live) = LIVE_MOUNTS.lock()
            && let Some(idx) = live.iter().position(|p| p == &self.mountpoint)
        {
            live.swap_remove(idx);
        }
    }
}

/// Non-Linux stub: the mount-leak mechanism (and `/proc`, `/sys/fs/fuse`) is
/// Linux-specific, so the guard just owns the session and drops it normally.
#[cfg(not(target_os = "linux"))]
pub struct MountGuard {
    session: Option<fuser::BackgroundSession>,
}

#[cfg(not(target_os = "linux"))]
impl MountGuard {
    #[must_use]
    pub fn new(session: fuser::BackgroundSession, _mountpoint: &Path) -> Self {
        Self {
            session: Some(session),
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for MountGuard {
    fn drop(&mut self) {
        drop(self.session.take());
    }
}

/// Reclaim every leaked FrankenFS mount on an abrupt (signal) exit, where no
/// `Drop` runs. Must not panic or block for long (it runs from the `ctrlc`
/// handler thread and from the panic hook).
///
/// Coverage is deliberately broader than the [`LIVE_MOUNTS`] registry: it
/// drains every guard-tracked mount *and* runs the same proactive mount-table
/// sweep used at startup, so mounts created through callsites that were not
/// wrapped in a [`MountGuard`] are reclaimed too. The sweep only touches
/// FrankenFS mounts under the temp roots and probes liveness first, so a
/// healthy mount belonging to a concurrent test binary is never disturbed.
#[cfg(target_os = "linux")]
fn reap_all_live_mounts() {
    let tracked: Vec<PathBuf> = LIVE_MOUNTS
        .lock()
        .map(|live| live.clone())
        .unwrap_or_default();
    for mountpoint in tracked {
        let _ = lazy_unmount(&mountpoint);
    }
    // Backstop: reclaim any leaked-but-untracked FrankenFS mount this process
    // is responsible for (the unconverted inline `mount_background` callsites).
    let _ = reap_stale_frankenfs_mounts();
}

/// Install — exactly once per process — a SIGINT/SIGTERM handler and a panic
/// hook so a leaked FUSE mount is reclaimed before the process tears down.
///
/// * Signals (Ctrl+C, timeout-kill): `ctrlc` (with the `termination` feature
///   covering SIGTERM too) runs the teardown on its own thread — so the work
///   does not execute in async-signal context — then re-exits with the
///   conventional 128+signo code so the runner still observes a killed binary.
///   This is the path the registry exists for: on an abrupt kill no `Drop`
///   runs, so the handler must reclaim every live mount itself.
/// * Panic: on the default `panic = "unwind"` build, `MountGuard::drop` already
///   performs the teardown as the stack unwinds, and a panic may legitimately
///   be caught (`catch_unwind`) by a still-running test — so the hook here must
///   **not** force-unmount; it only chains the previous (default) hook for the
///   message. The signal path is what covers the genuinely-fatal exits. (A
///   `panic = "abort"` build would skip `Drop`, but the harness uses the
///   default unwind profile, and an aborting panic typically still drives the
///   runner to send a follow-up signal that the handler above catches.)
#[cfg(target_os = "linux")]
fn install_teardown_hooks() {
    static HOOKS: Once = Once::new();
    HOOKS.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // Do NOT reap here: `Drop` already unmounts on unwind, and a caught
            // panic must not have its still-healthy mount torn out from under it.
            prev(info);
        }));

        // `ctrlc::set_handler` may be called at most once per process; this is
        // the sole installer in the harness test binaries. The handler body
        // runs on a dedicated thread, not in async-signal context.
        let _ = ctrlc::set_handler(|| {
            reap_all_live_mounts();
            // Re-exit so the runner sees the binary as terminated; 130 is the
            // conventional 128+SIGINT code shells use for an interrupted child.
            std::process::exit(130);
        });
    });
}

/// Non-Linux stub: nothing to install where the leak mechanism does not exist.
#[cfg(not(target_os = "linux"))]
fn install_teardown_hooks() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frankenfs_mount_markers_match() {
        assert!(is_frankenfs_mount("frankenfs", "fuse"));
        assert!(is_frankenfs_mount("frankenfs", "fuse.ffs"));
        assert!(is_frankenfs_mount("anything", "fuse.ffs"));
        assert!(is_frankenfs_mount("anything", "fuse.frankenfs"));
        assert!(!is_frankenfs_mount("ext4", "ext4"));
        assert!(!is_frankenfs_mount("sshfs", "fuse.sshfs"));
        assert!(!is_frankenfs_mount("/dev/sda1", "fuse"));
    }

    #[test]
    fn mounts_field_octal_unescape() {
        assert_eq!(
            unescape_mounts_field("/tmp/.tmpAbC123/mnt"),
            PathBuf::from("/tmp/.tmpAbC123/mnt")
        );
        assert_eq!(
            unescape_mounts_field("/tmp/with\\040space/mnt"),
            PathBuf::from("/tmp/with space/mnt")
        );
        assert_eq!(
            unescape_mounts_field("/tmp/back\\134slash"),
            PathBuf::from("/tmp/back\\slash")
        );
        // Non-octal escape sequences pass through untouched.
        assert_eq!(
            unescape_mounts_field("/tmp/\\zz"),
            PathBuf::from("/tmp/\\zz")
        );
    }

    #[test]
    fn temp_roots_include_conventional_locations() {
        let roots = temp_roots();
        assert!(roots.contains(&PathBuf::from("/tmp")));
        assert!(roots.contains(&PathBuf::from("/data/tmp")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_connection_minor_extracts_device_minor() {
        // Real-shaped mountinfo lines: `id parent major:minor root mp ...`.
        let mountinfo = "\
36 35 0:32 / /proc rw,nosuid shared:5 - proc proc rw
99 24 0:74 / /tmp/.tmpXyz/mnt rw,nosuid,relatime shared:1 - fuse.ffs frankenfs rw
101 24 0:81 / /data/tmp/.tmpAbc/mnt rw shared:2 - fuse.frankenfs frankenfs rw
";
        assert_eq!(
            fuse_connection_minor(mountinfo, &PathBuf::from("/tmp/.tmpXyz/mnt")),
            Some("74".to_owned())
        );
        assert_eq!(
            fuse_connection_minor(mountinfo, &PathBuf::from("/data/tmp/.tmpAbc/mnt")),
            Some("81".to_owned())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_connection_minor_handles_escaped_and_missing_paths() {
        // Octal-escaped space in the mountpoint field must round-trip.
        let mountinfo =
            "120 24 0:90 / /tmp/with\\040space/mnt rw shared:9 - fuse.ffs frankenfs rw\n";
        assert_eq!(
            fuse_connection_minor(mountinfo, &PathBuf::from("/tmp/with space/mnt")),
            Some("90".to_owned())
        );
        // A path that is not present yields None rather than a wrong id.
        assert_eq!(
            fuse_connection_minor(mountinfo, &PathBuf::from("/tmp/absent/mnt")),
            None
        );
        // Malformed (truncated) lines are skipped, not panicked on.
        assert_eq!(
            fuse_connection_minor("36 35 0:32\n", &PathBuf::from("/x")),
            None
        );
    }
}
