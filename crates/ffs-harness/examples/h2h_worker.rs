//! Run the campaign's six-arm head-to-head ENTIRELY ON THE WORKER, in one
//! `rch exec -- cargo run --release --example h2h_worker` invocation.
//!
//! Builds are rch-remote and no artifact is retrievable, so nothing can be measured
//! by building there and running here. Running both arms on the worker sidesteps
//! that: the FUSE candidate and the LIVE kernel incumbent are mounted on the same
//! machine, in the same invocation, and only the numbers travel back.
//!
//! Why an example rather than invoking the comparator directly: it needs
//! `--ffs-cli PATH`, and rch rewrites `CARGO_TARGET_DIR` to a generated
//! worker-scoped directory (`.rch-target-<worker>-pool-<hash>`) that must never be
//! hardcoded. An example runs from `<target>/release/examples/`, so
//! `std::env::current_exe()` gives the target directory for free on any worker.
//!
//! Everything is printed to STDERR because that is what rch returns.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn release_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    // <target>/release/examples/h2h_worker -> <target>/release
    exe.parent()
        .and_then(|examples| examples.parent())
        .map(PathBuf::from)
        .ok_or_else(|| format!("cannot derive release dir from {}", exe.display()))
}

/// `cargo run --example` builds the example and its dependencies, NOT the other
/// binaries in the workspace, so the two the comparator needs may be absent. Build
/// them explicitly; cargo has released the target lock by the time an example runs.
fn ensure_binaries(release: &PathBuf) -> Result<(), String> {
    let needed = ["ffs-cli", "ffs-mounted-kernel-bench"];
    if needed.iter().all(|b| release.join(b).exists()) {
        eprintln!("h2h_worker: both binaries already present in {}", release.display());
        return Ok(());
    }
    eprintln!("h2h_worker: building ffs-cli + ffs-mounted-kernel-bench on the worker");
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "build",
            "--release",
            "-p",
            "ffs-cli",
            "--bin",
            "ffs-cli",
            "-p",
            "ffs-harness",
            "--bin",
            "ffs-mounted-kernel-bench",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("spawn cargo build: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build failed: {status}"));
    }
    for b in needed {
        if !release.join(b).exists() {
            return Err(format!("{} still missing after build", release.join(b).display()));
        }
    }
    Ok(())
}

fn main() {
    let release = match release_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("h2h_worker: {e}");
            std::process::exit(2);
        }
    };
    eprintln!("h2h_worker: hostname={}", hostname());
    eprintln!("h2h_worker: target release dir = {}", release.display());

    if let Err(e) = ensure_binaries(&release) {
        eprintln!("h2h_worker: {e}");
        std::process::exit(2);
    }

    let ffs_cli = release.join("ffs-cli");
    let bench = release.join("ffs-mounted-kernel-bench");

    // Arguments come from the caller so one runner serves every row; the defaults
    // pick the campaign's WORST measured cell (ext4 xattr-get-list-report) and the
    // transport that makes both arms cross the same block layer.
    let passthrough: Vec<String> = std::env::args().skip(1).collect();
    let mut args: Vec<String> = if passthrough.is_empty() {
        [
            "--filesystem", "ext4",
            "--workload", "xattr-get-list-report",
            "--pairs", "12",
            "--fuse-transport", "loop",
            // No PGO profile exists on a worker build; the gate is explicit about
            // recording such a candidate as non-production rather than silently
            // accepting it.
            "--allow-non-pgo-candidate",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    } else {
        passthrough
    };
    args.push("--ffs-cli".into());
    args.push(ffs_cli.display().to_string());
    // The comparator refuses to run without knowing which machine built the ELF
    // (`--harness-builder`), because this campaign has been burned by rows compared
    // across workers with no identity recorded. The runner supplies it from the
    // machine it is actually executing on, so provenance is self-reported rather
    // than asserted by whoever typed the command.
    // Both the harness ELF and the candidate ELF were built by THIS worker in this
    // invocation, so both provenance flags name it.
    for flag in ["--harness-builder", "--candidate-builder"] {
        if !args.iter().any(|a| a == flag) {
            args.push(flag.into());
            args.push(hostname());
        }
    }

    eprintln!("h2h_worker: {} {}", bench.display(), args.join(" "));
    // CAPTURE rather than inherit. A first run had the comparator exit 2 with no
    // visible message at all: inherited streams did not survive back through rch,
    // so a refusal (this comparator fails CLOSED on its ISA and PGO gates) was
    // indistinguishable from a crash. Re-emitting both streams on stderr makes the
    // reason travel, which is the whole point of running out here.
    let out = Command::new(&bench).args(&args).output();
    match out {
        Ok(o) => {
            for (name, buf) in [("stdout", &o.stdout), ("stderr", &o.stderr)] {
                for line in String::from_utf8_lossy(buf).lines() {
                    eprintln!("h2h[{name}] {line}");
                }
            }
            eprintln!("h2h_worker: comparator exited {}", o.status);
            std::process::exit(o.status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("h2h_worker: spawn comparator: {e}");
            std::process::exit(2);
        }
    }
}

fn hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".into())
}
