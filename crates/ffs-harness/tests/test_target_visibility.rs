//! Every `.rs` file under a `tests/` directory must be visible to git.
//!
//! Cargo compiles every `.rs` directly under a crate's `tests/` directory as its
//! own integration-test target, and it does that whether or not git can see the
//! file. A gitignored probe therefore becomes a REAL test target that:
//!
//!   * `git status` does not show,
//!   * review never sees, because it is not in any diff, and
//!   * aborts `cargo test -p <crate>` for everyone if it stops compiling.
//!
//! The failure is maximally confusing: the crate's test run dies on a file that
//! does not appear to exist, and `--lib` runs stay green because they never build
//! the integration targets at all.
//!
//! frankenfs is exposed to this by construction: `.gitignore:83` carries a blanket
//! `repro_*.rs`, so any scratch reproducer dropped into a `tests/` directory is
//! hidden by default rather than by choice. At the time this guard was written
//! `crates/ffs-core/tests/repro_create.rs` was exactly that — gitignored,
//! untracked, and compiled into `cargo test -p ffs-core`. It happened to compile,
//! so nothing was broken; that is luck, not a property.
//!
//! Reported by frankenlibc, who hit the broken-probe version of this.
//!
//! FIXING A FAILURE: either track the file (if it is a real test) or move it out
//! of `tests/` (if it is a scratch probe — `examples/`, a `#[ignore]`d unit test,
//! or somewhere outside the crate). Do NOT widen the ignore rule; that is the
//! mechanism, not the fix.

use std::path::{Path, PathBuf};
use std::process::Command;

/// `tests/` directories that belong to this workspace. Vendored and third-party
/// trees are excluded: their visibility is their upstream's business, and
/// `third_party/` is deliberately not built by our test runs.
fn workspace_test_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let workspace_tests = root.join("tests");
    if workspace_tests.is_dir() {
        dirs.push(workspace_tests);
    }
    for parent in ["crates", "tools"] {
        let Ok(entries) = std::fs::read_dir(root.join(parent)) else {
            continue;
        };
        for entry in entries.flatten() {
            let candidate = entry.path().join("tests");
            if candidate.is_dir() {
                dirs.push(candidate);
            }
        }
    }
    dirs
}

/// Only files DIRECTLY under `tests/` become targets; nested modules do not, so
/// this deliberately does not recurse.
fn direct_rs_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    files.sort();
    files
}

#[test]
fn no_gitignored_rs_file_becomes_an_invisible_test_target() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root is two levels above crates/ffs-harness")
        .to_path_buf();

    // Absence of git is a skip, not a failure: this guard is about repository
    // hygiene, and a source tree without git has no ignore rules to violate.
    let Ok(probe) = Command::new("git").arg("--version").output() else {
        eprintln!("git unavailable; skipping test-target visibility check");
        return;
    };
    if !probe.status.success() {
        eprintln!("git unusable; skipping test-target visibility check");
        return;
    }

    let mut hidden: Vec<String> = Vec::new();
    for dir in workspace_test_dirs(&root) {
        for file in direct_rs_files(&dir) {
            let Ok(output) = Command::new("git")
                .arg("-C")
                .arg(&root)
                .arg("check-ignore")
                .arg("--quiet")
                .arg(&file)
                .status()
            else {
                continue;
            };
            // check-ignore exits 0 when the path IS ignored.
            if output.success() {
                hidden.push(
                    file.strip_prefix(&root)
                        .unwrap_or(&file)
                        .display()
                        .to_string(),
                );
            }
        }
    }

    assert!(
        hidden.is_empty(),
        "these files are gitignored but cargo still compiles each as an integration \
         test target, so they run in CI while being invisible to git status and to \
         review — and if one stops compiling it aborts the whole crate's test run:\n  \
         {}\n\
         Fix by tracking the file if it is a real test, or moving it out of tests/ if \
         it is a scratch probe. Do not widen the ignore rule.",
        hidden.join("\n  ")
    );
}
