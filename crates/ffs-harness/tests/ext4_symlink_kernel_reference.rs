//! Conformance harness: ext4 symlink targets read by
//! `Ext4ImageReader::read_symlink` must agree with what e2fsprogs
//! (`debugfs stat` / `debugfs dump`) reports for the same inode.
//!
//! ext4 stores short targets (≤ 60 bytes) inside `i_block` (the "fast
//! symlink" optimisation, with `i_blocks` zeroed and no `EXTENTS_FL`),
//! and longer targets in extent-mapped data blocks. The two paths are
//! handled by completely different read code, so a regression in either
//! one would otherwise survive every other test (`fuzz_ext4_image_reader`
//! exercises the parser, but never against a kernel-written image).
//!
//! Strategy:
//!   * Use `debugfs symlink` to plant a corpus of short and long targets
//!     covering both branches plus 1-byte / boundary / multi-segment paths
//!     and non-ASCII bytes.
//!   * For each link, read the target two ways:
//!       - via `Ext4ImageReader::read_symlink` (the FFS path),
//!       - via `debugfs stat` (`Fast link dest: "..."`) for fast links and
//!         `debugfs dump` for extent-mapped links (the e2fsprogs path).
//!   * Assert byte-for-byte equality, plus structural invariants
//!     (`is_fast_symlink()` matches the size threshold; non-fast symlinks
//!     have the EXTENTS flag set).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ffs_ondisk::Ext4ImageReader;

const FAST_SYMLINK_MAX: usize = 60;

/// Printable, space-free ASCII used to fill the heterogeneous symlink target.
/// Excludes NUL (terminates C strings), space and tab (split debugfs argv),
/// `'`/`"`/backslash (debugfs quoting), and `/` runs (would conflict with
/// some downstream consumers' path normalisation).
const SAFE_CHARS: &[u8] =
    b"!#$%&()*+,-.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}~";

fn has_command(name: &str) -> bool {
    Command::new(name)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn ext4_tools_available() -> bool {
    has_command("mkfs.ext4") && has_command("debugfs")
}

fn unique_temp_path(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("ffs_symlink_{tag}_{pid}_{nanos}.ext4"))
}

fn run_debugfs_w(image: &Path, cmd: &str) {
    let st = Command::new("debugfs")
        .args(["-w", "-R", cmd])
        .arg(image)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn debugfs");
    assert!(st.success(), "debugfs -w -R {cmd:?} failed");
}

/// Extract the literal text inside `Fast link dest: "..."` from `debugfs
/// stat` output. e2fsprogs emits the target verbatim (no escaping) on a
/// single line, so a substring match suffices.
fn capture_fast_link_dest(image: &Path, link_name: &str) -> Vec<u8> {
    let out = Command::new("debugfs")
        .args(["-R", &format!("stat {link_name}")])
        .arg(image)
        .stderr(Stdio::null())
        .output()
        .expect("spawn debugfs");
    assert!(out.status.success(), "debugfs stat {link_name} failed");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = text
        .lines()
        .find(|l| l.contains("Fast link dest:"))
        .unwrap_or_else(|| {
            panic!("debugfs stat {link_name}: no 'Fast link dest:' line in:\n{text}")
        });
    let start = line
        .find('"')
        .unwrap_or_else(|| panic!("malformed Fast link dest line: {line}"));
    let end = line.rfind('"').expect("trailing quote present");
    assert!(end > start, "malformed Fast link dest line: {line}");
    line.as_bytes()[start + 1..end].to_vec()
}

/// Use `debugfs dump <link> <out>` to extract an extent-mapped link's
/// target bytes from the on-disk data block. Empirically this works
/// for symlinks even though they are not regular files.
fn capture_dumped_link(image: &Path, link_name: &str) -> Vec<u8> {
    let scratch = std::env::temp_dir().join(format!(
        "ffs_symlink_dump_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
        link_name
    ));
    let st = Command::new("debugfs")
        .args(["-R", &format!("dump {link_name} {}", scratch.display())])
        .arg(image)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn debugfs");
    assert!(st.success(), "debugfs dump {link_name} failed");
    let bytes = std::fs::read(&scratch).expect("read dumped symlink target");
    std::fs::remove_file(&scratch).ok();
    bytes
}

#[derive(Debug, Clone)]
struct SymlinkCase {
    name: &'static str,
    target: Vec<u8>,
}

fn corpus() -> Vec<SymlinkCase> {
    let mixed: Vec<u8> = (0..120usize)
        .map(|i| SAFE_CHARS[i % SAFE_CHARS.len()])
        .collect();
    vec![
        SymlinkCase {
            name: "fast_one_byte",
            target: b"x".to_vec(),
        },
        SymlinkCase {
            name: "fast_short",
            target: b"a/b/c".to_vec(),
        },
        SymlinkCase {
            name: "fast_relative",
            target: b"../../sibling/file".to_vec(),
        },
        SymlinkCase {
            name: "fast_absolute",
            target: b"/etc/passwd".to_vec(),
        },
        SymlinkCase {
            name: "fast_dotted",
            target: b"./.hidden/.dotfile".to_vec(),
        },
        SymlinkCase {
            name: "fast_max_minus_one",
            target: vec![b'A'; FAST_SYMLINK_MAX - 1],
        },
        SymlinkCase {
            name: "fast_at_max",
            target: vec![b'B'; FAST_SYMLINK_MAX],
        },
        // First size that pushes the symlink off the fast path.
        SymlinkCase {
            name: "extent_just_over",
            target: vec![b'C'; FAST_SYMLINK_MAX + 1],
        },
        SymlinkCase {
            name: "extent_medium",
            target: vec![b'D'; 200],
        },
        SymlinkCase {
            name: "extent_long",
            target: vec![b'E'; 1024],
        },
        // Heterogeneous payload to catch byte-equality regressions that
        // monotonic fills would hide.
        SymlinkCase {
            name: "extent_heterogeneous",
            target: mixed,
        },
    ]
}

#[test]
fn ext4_symlink_kernel_reference_targets_match_debugfs() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let path = unique_temp_path("corpus");
    let f = std::fs::File::create(&path).expect("create image file");
    f.set_len(16 * 1024 * 1024).expect("set image length");
    drop(f);
    let st = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-O", "^has_journal", "-b", "4096"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 failed");

    let cases = corpus();

    // debugfs's `symlink` command takes the target as a literal trailing
    // argument; embedded spaces get split. Restrict the corpus to
    // space-free targets and stage each link.
    for case in &cases {
        let target_str =
            std::str::from_utf8(&case.target).expect("corpus entries are UTF-8 by construction");
        assert!(
            !target_str.contains(' '),
            "corpus targets must not contain spaces (debugfs symlink quoting)"
        );
        run_debugfs_w(
            &path,
            &format!("symlink {name} {target_str}", name = case.name),
        );
    }

    let image = std::fs::read(&path).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse ext4 image");

    let mut fast_count = 0_usize;
    let mut extent_count = 0_usize;
    for case in &cases {
        let (_ino, inode) = reader
            .resolve_path(&image, &format!("/{}", case.name))
            .unwrap_or_else(|err| panic!("resolve /{}: {err:?}", case.name));

        assert!(
            inode.is_symlink(),
            "/{}: i_mode does not classify as a symlink",
            case.name
        );

        let ffs_target = reader
            .read_symlink(&image, &inode)
            .unwrap_or_else(|err| panic!("read_symlink /{}: {err:?}", case.name));
        assert_eq!(
            ffs_target, case.target,
            "/{}: FFS read_symlink returned wrong bytes",
            case.name
        );

        // Cross-check against e2fsprogs: fast symlinks expose the target in
        // `debugfs stat`; extent-mapped ones must be dumped from data blocks.
        let kernel_target = if inode.is_fast_symlink(&reader.sb) {
            fast_count += 1;
            assert_eq!(
                inode.size,
                u64::try_from(case.target.len()).expect("target length fits u64"),
                "/{}: fast-symlink i_size mismatch",
                case.name
            );
            // Fast links MUST NOT have the EXTENTS flag — they have no data
            // blocks at all.
            assert!(
                !inode.uses_extents(),
                "/{}: fast symlink should not have EXTENTS flag",
                case.name
            );
            capture_fast_link_dest(&path, case.name)
        } else {
            extent_count += 1;
            assert!(
                inode.uses_extents(),
                "/{}: extent-mapped symlink missing EXTENTS flag",
                case.name
            );
            capture_dumped_link(&path, case.name)
        };

        assert_eq!(
            kernel_target, case.target,
            "/{}: e2fsprogs view of target diverges from corpus expectation",
            case.name
        );
    }

    // The corpus is intentionally sized so we exercise both branches.
    assert!(
        fast_count >= 4 && extent_count >= 3,
        "corpus must exercise both fast (got {fast_count}) and extent (got {extent_count}) paths"
    );

    std::fs::remove_file(&path).ok();
}
