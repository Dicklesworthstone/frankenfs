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
use std::sync::Once;
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
fn unescape_mounts_field(field: &str) -> PathBuf {
    let mut out = Vec::with_capacity(field.len());
    let bytes = field.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if let Some(val) = octal3(&bytes[i + 1..]) {
                out.push(val);
                i += 4;
                continue;
            }
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
/// then `umount -l`. Returns whether the mountpoint left the mount table.
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

    // Verify against the live mount table rather than trusting exit codes.
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return false;
    };
    !mounts.lines().any(|line| {
        line.split_whitespace()
            .nth(1)
            .is_some_and(|mp| unescape_mounts_field(mp) == mountpoint)
    })
}

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
}
