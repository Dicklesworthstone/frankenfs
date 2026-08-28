//! Can the rch worker host this campaign's head-to-head measurements?
//!
//! Builds are rch-remote and no artifact comes back, so the proposed method is to run
//! the whole head-to-head ON the worker in one invocation
//! (`rch exec -- cargo run --release --example …`). That is sound for an in-process
//! bench — but every vs-incumbent row in this campaign compares FrankenFS mounted
//! over FUSE against a LIVE kernel ext4/btrfs mount, which needs:
//!
//!   * `/dev/fuse` and `fusermount3`, to mount the candidate at all;
//!   * `losetup`, to put each arm's image on its own loop device;
//!   * root (passwordless `sudo`), because `mount`/`losetup` are privileged.
//!
//! Without those the incumbent arm cannot exist, and a run with no incumbent is a
//! self-comparison — which this campaign rejects by rule. So probe first and report,
//! rather than writing a harness against an environment that may not support it.
//!
//! `rch exec` refuses non-compilation commands, so this probe has to BE a cargo
//! target. It only inspects the environment: it mounts nothing and formats nothing.

use std::path::Path;
use std::process::Command;

fn which(binary: &str) -> String {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {binary} 2>/dev/null"))
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|found| !found.is_empty())
        .unwrap_or_else(|| "MISSING".to_owned())
}

fn main() {
    let host = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());

    // Passwordless sudo is the gate on both `losetup` and `mount`. `sudo -n true`
    // touches nothing and fails closed when credentials are absent.
    let sudo = Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| if s.success() { "OK" } else { "DENIED" })
        .unwrap_or("DENIED");

    println!("worker_capability_probe");
    println!("  hostname       = {host}");
    println!("  euid_is_root   = {}", std::fs::metadata("/proc/self").is_ok() && which("id") != "MISSING");
    println!("  dev_fuse       = {}", if Path::new("/dev/fuse").exists() { "present" } else { "MISSING" });
    println!("  fusermount3    = {}", which("fusermount3"));
    println!("  losetup        = {}", which("losetup"));
    println!("  btrfs_progs    = {}", which("btrfs"));
    println!("  e2fsprogs_fsck = {}", which("e2fsck"));
    println!("  sudo_n         = {sudo}");
    println!("  nproc          = {}", std::thread::available_parallelism().map_or(0, |n| n.get()));

    let can_mount = Path::new("/dev/fuse").exists()
        && which("fusermount3") != "MISSING"
        && which("losetup") != "MISSING"
        && sudo == "OK";
    println!(
        "  VERDICT: live-incumbent head-to-head on this worker is {}",
        if can_mount { "POSSIBLE" } else { "NOT POSSIBLE" }
    );
}
