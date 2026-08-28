//! Worker-side head-to-head on the COUNTED scale: blocking FUSE crossings per
//! operation, FrankenFS against a LIVE kernel btrfs mount, both arms in one
//! invocation on one worker.
//!
//! Why this exists beside `h2h_worker`. The six-arm comparator refuses to run on the
//! rch worker because it cannot read `/sys/devices/system/cpu/*/cpufreq` — and that
//! refusal is CORRECT: it certifies wall-time ratios, and this campaign has recorded
//! a FUSE A/A null failing at 1.256x purely from a `powersave` governor. Relaxing
//! that gate is forbidden and would be wrong.
//!
//! So measure something the governor cannot distort. A blocking crossing is a
//! VOLUNTARY CONTEXT SWITCH: the client sleeps until the daemon replies. CPU
//! frequency changes how LONG each one takes; it cannot change HOW MANY there are.
//! Across this campaign these counts reproduced bit-exactly or to ±1 run over run,
//! including in windows where wall-time rows had to be voided for load. This is not
//! a weaker substitute for the gated measurement — it is a different quantity, with
//! its own validity argument, and it is reported as a count and never as a ratio of
//! performance.
//!
//! Counts come from `/proc/self/status voluntary_ctxt_switches`, so no `unsafe` and
//! no C are involved. Everything is printed to stderr because that is what rch
//! returns.

use std::path::{Path, PathBuf};
use std::process::Command;

const OPS: usize = 20_000;

fn sh(cmd: &str) -> (bool, String) {
    let out = Command::new("sh").arg("-c").arg(cmd).output();
    match out {
        Ok(o) => (
            o.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
        ),
        Err(e) => (false, e.to_string()),
    }
}

/// Voluntary context switches for THIS process: the count of times it blocked
/// waiting for something, which for a FUSE client is one per crossing it waits on.
fn voluntary_ctxt_switches() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("voluntary_ctxt_switches:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Repeatedly `stat` one warm file and report blocking crossings per operation.
/// No I/O, no directory work: what it isolates is the per-request round trip.
fn measure_warm_stat(mount: &Path) -> (f64, u64) {
    let path = mount.join("payload.bin");
    // Warm outside the counted region so first-touch is not charged per-op.
    for _ in 0..64 {
        let _ = std::fs::metadata(&path);
    }
    let before = voluntary_ctxt_switches();
    let mut acc = 0_u64;
    for _ in 0..OPS {
        if let Ok(md) = std::fs::metadata(&path) {
            acc = acc.wrapping_add(md.len());
        }
    }
    let delta = voluntary_ctxt_switches() - before;
    (delta as f64 / OPS as f64, acc)
}

fn main() {
    let host = sh("hostname").1.trim().to_owned();
    eprintln!("h2h_counted: host={host}");

    let exe = std::env::current_exe().expect("current_exe");
    let release = exe.parent().and_then(Path::parent).expect("release dir");
    let ffs_cli = release.join("ffs-cli");
    if !ffs_cli.exists() {
        eprintln!("h2h_counted: building ffs-cli on the worker");
        let (ok, log) = sh(&format!(
            "cd {} && cargo build --release -p ffs-cli --bin ffs-cli 2>&1 | tail -3",
            env!("CARGO_MANIFEST_DIR")
        ));
        eprintln!("h2h_counted: build ok={ok} {}", log.trim());
    }
    let (_, sha) = sh(&format!("{} bench-evidence 2>/dev/null | grep binary_sha256", ffs_cli.display()));
    eprintln!("h2h_counted: candidate {}", sha.trim());

    let work = PathBuf::from("/tmp/ffs-h2h-counted");
    let _ = std::fs::create_dir_all(&work);
    let base = work.join("base.btrfs");

    // Fixture: one small file, laid out THROUGH A KERNEL MOUNT so btrfs writes its
    // own inode item rather than any FrankenFS write path.
    let seed = work.join("seed");
    let _ = std::fs::create_dir_all(&seed);
    let mkfs = format!(
        "rm -f {img} && truncate -s 512M {img} && $(command -v mkfs.btrfs) -q -f {img} && \
         sudo -n mount -o loop {img} {seed} && sudo -n chown $(id -u):$(id -g) {seed} && \
         dd if=/dev/urandom of={seed}/payload.bin bs=64K count=1 status=none && sync && \
         sudo -n umount {seed}",
        img = base.display(),
        seed = seed.display()
    );
    let (ok, log) = sh(&mkfs);
    if !ok {
        eprintln!("h2h_counted: FIXTURE FAILED: {}", log.trim());
        std::process::exit(2);
    }

    // Three arms: two kernel mounts (the A/A null) and one FrankenFS mount.
    let mut per_arm: Vec<(String, f64, u64)> = Vec::new();
    let mut cleanup: Vec<String> = Vec::new();

    for arm in ["k1", "k2"] {
        let img = work.join(format!("{arm}.btrfs"));
        let mnt = work.join(format!("m-{arm}"));
        let _ = std::fs::create_dir_all(&mnt);
        let (ok, log) = sh(&format!(
            "cp {base} {img} && sudo -n mount -o ro,loop {img} {mnt}",
            base = base.display(),
            img = img.display(),
            mnt = mnt.display()
        ));
        if !ok {
            eprintln!("h2h_counted: kernel arm {arm} mount failed: {}", log.trim());
            std::process::exit(2);
        }
        cleanup.push(format!("sudo -n umount {}", mnt.display()));
        let (per_op, digest) = measure_warm_stat(&mnt);
        per_arm.push((format!("kernel-{arm}"), per_op, digest));
    }

    {
        let img = work.join("f.btrfs");
        let mnt = work.join("m-f");
        let _ = std::fs::create_dir_all(&mnt);
        let (ok, log) = sh(&format!(
            "cp {base} {img} && nohup {cli} mount {img} {mnt} >/tmp/ffs-h2h-counted/fuse.log 2>&1 & \
             for i in $(seq 1 200); do mountpoint -q {mnt} && break; sleep 0.1; done; mountpoint -q {mnt}",
            base = base.display(),
            img = img.display(),
            mnt = mnt.display(),
            cli = ffs_cli.display()
        ));
        if !ok {
            eprintln!("h2h_counted: FUSE arm never mounted: {}", log.trim());
            // Diagnose rather than guess: an unprivileged FUSE mount needs a setuid
            // fusermount3 (or user_allow_other), and a container can have /dev/fuse
            // present while still refusing the mount.
            eprintln!("h2h_counted: fusermount3 = {}", sh("ls -l $(command -v fusermount3) 2>&1").1.trim());
            eprintln!("h2h_counted: fuse_conf   = {}", sh("cat /etc/fuse.conf 2>&1 | tr '\n' ' '").1.trim());
            eprintln!("h2h_counted: dev_fuse    = {}", sh("ls -l /dev/fuse 2>&1").1.trim());
            for line in sh("grep -aiE 'error|refus|denied|permission|panic' /tmp/ffs-h2h-counted/fuse.log 2>&1 | tail -8").1.lines() {
                eprintln!("h2h_counted: fuse.log! {line}");
            }
            for line in sh("tail -4 /tmp/ffs-h2h-counted/fuse.log 2>&1").1.lines() {
                eprintln!("h2h_counted: fuse.log  {}", &line[..line.len().min(160)]);
            }
            for c in &cleanup {
                let _ = sh(c);
            }
            std::process::exit(2);
        }
        cleanup.push(format!("fusermount3 -u {}", mnt.display()));
        let (per_op, digest) = measure_warm_stat(&mnt);
        per_arm.push(("frankenfs".to_owned(), per_op, digest));
    }

    for c in cleanup.iter().rev() {
        let _ = sh(c);
    }

    eprintln!("h2h_counted: workload = {OPS} warm stat() of one file, single thread");
    for (name, per_op, digest) in &per_arm {
        eprintln!("h2h_counted:   {name:<12} blocking_crossings_per_op={per_op:.4} digest={digest}");
    }
    let k1 = per_arm[0].1;
    let k2 = per_arm[1].1;
    let f = per_arm[2].1;
    let digests_agree = per_arm[0].2 == per_arm[1].2 && per_arm[1].2 == per_arm[2].2;
    eprintln!("h2h_counted: A/A null kernel-k1 vs kernel-k2 = {k1:.4} vs {k2:.4}");
    eprintln!("h2h_counted: digest parity across all arms = {digests_agree}");
    eprintln!(
        "h2h_counted: RESULT frankenfs={f:.4} blocking crossings/op against a live kernel btrfs arm at {:.4}",
        (k1 + k2) / 2.0
    );
}
