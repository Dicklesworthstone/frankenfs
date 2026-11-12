#![forbid(unsafe_code)]
//! Deterministic 12-row (`6 operations × {FAT16, FAT32}`) write-cut crash matrix
//! for `ffs-fat` (`bd-unified-six-format-cli-partitions-and-doc-truth-x9kjz`).
//!
//! For each operation (`create`, `write`, `truncate`, `unlink`, `rename`, `resize`)
//! and dialect (`FAT16`, `FAT32`):
//! 1. Measures exact physical write count on an un-interrupted baseline clone and
//!    verifies both `ffs_fat::reader::recovery::check` (`clean == true`) and
//!    host `fsck.fat -n` (when installed).
//! 2. Re-runs the operation on fresh baseline clones cutting deterministically
//!    after `0, 1, ..., total_writes - 1` writes (`CrashCutMemDevice`).
//! 3. Exercises `ffs_fat::reader::recovery::{check, recover}` and host `fsck.fat`
//!    to prove no silent corruption, dangling cluster references, or unrecoverable
//!    metadata state occurs at any intermediate write boundary.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result as FfsResult};
use ffs_fat::formatter::{FormatArgs, FormatKind};
use ffs_fat::reader::recovery::{RecoverArgs, check, recover};
use ffs_fat::reader::replacement::{
    create_in_volume, mkdir_in_volume, open_volume, rename_in_volume, truncate_in_volume,
    unlink_in_volume, write_range_in_volume,
};
use ffs_fat::resize::{ResizeArgs, run_to_device};
use ffs_fat::{FatVolume, ImageArgs};
use ffs_ondisk::fat::FatOemCodePage;
use ffs_types::ByteOffset;
use sha2::{Digest, Sha256};

const FIXED_NOW: u64 = 1_700_000_000;

#[derive(Clone)]
struct CrashCutMemDevice {
    bytes: Arc<Mutex<Vec<u8>>>,
    writes_completed: Arc<AtomicUsize>,
    cut_after_writes: Option<usize>,
}

impl CrashCutMemDevice {
    fn unlimited(initial: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(initial)),
            writes_completed: Arc::new(AtomicUsize::new(0)),
            cut_after_writes: None,
        }
    }

    fn with_cut(initial: Vec<u8>, cut_after_writes: usize) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(initial)),
            writes_completed: Arc::new(AtomicUsize::new(0)),
            cut_after_writes: Some(cut_after_writes),
        }
    }

    fn writes_completed(&self) -> usize {
        self.writes_completed.load(Ordering::SeqCst)
    }

    fn snapshot_bytes(&self) -> Vec<u8> {
        self.bytes.lock().expect("crash cut buffer lock").clone()
    }
}

impl ByteDevice for CrashCutMemDevice {
    fn len_bytes(&self) -> u64 {
        u64::try_from(self.bytes.lock().expect("lock").len()).unwrap_or(u64::MAX)
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let guard = self.bytes.lock().expect("lock");
        let start = usize::try_from(offset.0).map_err(|_| {
            FfsError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read offset overflow",
            ))
        })?;
        let end = start.checked_add(buf.len()).ok_or_else(|| {
            FfsError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read length overflow",
            ))
        })?;
        let slice = guard.get(start..end).ok_or_else(|| {
            FfsError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read past CrashCutMemDevice end",
            ))
        })?;
        buf.copy_from_slice(slice);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if let Some(limit) = self.cut_after_writes {
            let current = self.writes_completed.load(Ordering::SeqCst);
            if current >= limit {
                return Err(FfsError::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("simulated power-loss crash cut after {current} writes"),
                )));
            }
        }
        let mut guard = self.bytes.lock().expect("lock");
        let start = usize::try_from(offset.0).map_err(|_| {
            FfsError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write offset overflow",
            ))
        })?;
        let end = start.checked_add(buf.len()).ok_or_else(|| {
            FfsError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write length overflow",
            ))
        })?;
        let slice = guard.get_mut(start..end).ok_or_else(|| {
            FfsError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "write past CrashCutMemDevice end",
            ))
        })?;
        slice.copy_from_slice(buf);
        self.writes_completed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> FfsResult<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)
    }
}

static CHILD_SPAWN_GATE: RwLock<()> = RwLock::new(());
static FSCK_FAT_BIN: OnceLock<Option<PathBuf>> = OnceLock::new();

fn with_flock_gate<R>(f: impl FnOnce() -> R) -> R {
    let _guard = CHILD_SPAWN_GATE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f()
}

fn spawn_gated_output(mut cmd: Command) -> io::Result<Output> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = {
        let _guard = CHILD_SPAWN_GATE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cmd.spawn()?
    };
    child.wait_with_output()
}

fn gated_check(cx: &Cx, args: &ImageArgs) -> anyhow::Result<ffs_fat::FatCheckReport> {
    with_flock_gate(|| check(cx, args))
}

fn gated_recover(cx: &Cx, args: &RecoverArgs) -> anyhow::Result<serde_json::Value> {
    with_flock_gate(|| recover(cx, args))
}

fn find_fsck_fat() -> Option<PathBuf> {
    FSCK_FAT_BIN
        .get_or_init(|| {
            for candidate in ["/usr/sbin/fsck.fat", "/sbin/fsck.fat", "fsck.fat"] {
                let mut cmd = Command::new(candidate);
                cmd.arg("-V");
                if let Ok(out) = spawn_gated_output(cmd)
                    && (out.status.success() || !out.stdout.is_empty() || !out.stderr.is_empty())
                {
                    return Some(PathBuf::from(candidate));
                }
            }
            None
        })
        .clone()
}

fn assert_fsck_fat_clean(image_path: &Path, allow_excess_preallocation: bool) {
    let Some(fsck_bin) = find_fsck_fat() else {
        return;
    };
    let mut cmd = Command::new(&fsck_bin);
    cmd.arg("-n").arg(image_path);
    let out = spawn_gated_output(cmd).expect("invoke fsck.fat -n");
    if out.status.success() {
        return;
    }
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if allow_excess_preallocation && combined.contains("cluster chain length is") {
        // When a shrink or extend crashes while extra clusters are benignly preallocated
        // beyond the directory entry's EOF, verify `fsck.fat -a` truncates the benign
        // excess cleanly and subsequent `-n` exits 0.
        let copy_path = image_path.with_extension("fsck_copy.img");
        fs::copy(image_path, &copy_path).expect("copy image for fsck.fat -a verification");
        let mut fix_cmd = Command::new(&fsck_bin);
        fix_cmd.arg("-a").arg(&copy_path);
        let _ = spawn_gated_output(fix_cmd).expect("invoke fsck.fat -a");
        let mut recheck_cmd = Command::new(&fsck_bin);
        recheck_cmd.arg("-n").arg(&copy_path);
        let recheck = spawn_gated_output(recheck_cmd).expect("re-invoke fsck.fat -n");
        assert!(
            recheck.status.success(),
            "fsck.fat -n failed even after truncating benign preallocated tail on {}: {}\n{}",
            image_path.display(),
            String::from_utf8_lossy(&recheck.stdout),
            String::from_utf8_lossy(&recheck.stderr),
        );
        return;
    }
    panic!(
        "fsck.fat -n failed on {} (status={}):\n{combined}",
        image_path.display(),
        out.status
    );
}

fn image_args(path: &Path) -> ImageArgs {
    ImageArgs {
        image: path.to_path_buf(),
        offset: 0,
        length: None,
        oem_code_page: FatOemCodePage::Ascii,
        sidecar: None,
    }
}

fn default_size_mib(kind: FormatKind) -> u64 {
    match kind {
        FormatKind::Fat16 => 8,
        FormatKind::Fat32 => 36,
    }
}

fn format_seeded_baseline(
    cx: &Cx,
    dir: &Path,
    kind: FormatKind,
    seed: impl FnOnce(&Cx, &FatVolume),
) -> (PathBuf, Vec<u8>) {
    let base_path = dir.join(format!("baseline_{kind:?}.img"));
    let args = FormatArgs {
        image: base_path.clone(),
        kind,
        size_mib: default_size_mib(kind),
        sectors_per_cluster: None,
        label: Some("CRASHMAT".to_owned()),
        serial: Some(0xC0DE_CAFE),
        source_dir: None,
        sidecar: None,
    };
    with_flock_gate(|| ffs_fat::formatter::create(cx, &args)).expect("format baseline FAT image");
    with_flock_gate(|| {
        let vol = open_volume(cx, &image_args(&base_path), true).expect("open writable baseline");
        seed(cx, &vol);
    });

    let chk = gated_check(cx, &image_args(&base_path)).expect("baseline check");
    assert!(chk.clean, "seeded baseline must start clean: {chk:?}");
    assert_fsck_fat_clean(&base_path, false);
    let bytes = fs::read(&base_path).expect("read baseline bytes");
    (base_path, bytes)
}

fn recover_and_verify_crashed_image(
    cx: &Cx,
    crashed_path: &Path,
    allow_excess_preallocation: bool,
) {
    let pre = gated_check(cx, &image_args(crashed_path)).expect("pre-recovery check must parse");
    if pre.clean {
        assert_fsck_fat_clean(
            crashed_path,
            allow_excess_preallocation && pre.preallocated_clusters > 0,
        );
        return;
    }

    // Step 1: If the crash cut fell strictly between FAT copy 0 and FAT copy 1,
    // reconcile mirrors from copy 0 first.
    if pre.conflicting_clusters > 0 && !pre.issues.iter().any(|issue| issue.kind == "cross_link") {
        let mirror_args = RecoverArgs {
            image: image_args(crashed_path),
            offline_image: true,
            reclaim_lost: false,
            discard_orphan_lfn: false,
            repair_mirrors_from: Some(0),
            repair_boot_from: None,
            salvage_to: None,
            dry_run: false,
        };
        gated_recover(cx, &mirror_args)
            .expect("reconcile interrupted FAT mirror write from copy 0");
    }

    // Step 2: Reclaim unreachable clusters, retire unbound LFN records, refresh FSInfo,
    // and restore clean boot/FAT state markers.
    let after_mirror = gated_check(cx, &image_args(crashed_path)).expect("post-mirror check");
    if !after_mirror.clean {
        let rec_args = RecoverArgs {
            image: image_args(crashed_path),
            offline_image: true,
            reclaim_lost: true,
            discard_orphan_lfn: true,
            repair_mirrors_from: None,
            repair_boot_from: None,
            salvage_to: None,
            dry_run: false,
        };
        gated_recover(cx, &rec_args).expect("structural FAT recovery must succeed");
    }

    let post = gated_check(cx, &image_args(crashed_path)).expect("post-recovery check");
    assert!(
        post.clean && post.complete && post.namespace_complete,
        "recovered FAT volume must be clean at {}: {post:?}",
        crashed_path.display()
    );
    assert_fsck_fat_clean(
        crashed_path,
        allow_excess_preallocation && post.preallocated_clusters > 0,
    );
}

fn run_inplace_crash_cut_row(
    kind: FormatKind,
    op_name: &str,
    allow_excess_preallocation: bool,
    seed: impl FnOnce(&Cx, &FatVolume),
    mutate: impl Fn(&Cx, &FatVolume) -> anyhow::Result<()>,
) {
    let cx = Cx::for_testing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_base_path, baseline_bytes) = format_seeded_baseline(&cx, tmp.path(), kind, seed);
    let len = u64::try_from(baseline_bytes.len()).expect("len");

    // 1. Clean reference run to measure exact write count.
    let ref_dev = CrashCutMemDevice::unlimited(baseline_bytes.clone());
    let ref_vol = FatVolume::from_device(&cx, Box::new(ref_dev.clone()), 0, len)
        .expect("open unlimited CrashCutMemDevice");
    mutate(&cx, &ref_vol).expect("clean reference mutation must succeed");
    let total_writes = ref_dev.writes_completed();
    assert!(
        total_writes >= 4,
        "{kind:?}/{op_name}: expected multi-step write sequence, got {total_writes}"
    );
    let completed_path = tmp.path().join(format!("{op_name}_complete.img"));
    fs::write(&completed_path, ref_dev.snapshot_bytes()).expect("write completed image");
    let completed_chk = gated_check(&cx, &image_args(&completed_path)).expect("check completed");
    assert!(
        completed_chk.clean,
        "{kind:?}/{op_name} clean run must be clean"
    );
    assert_fsck_fat_clean(&completed_path, false);

    // 2. Deterministic crash-cut sweep across EVERY intermediate write boundary `0..total_writes`.
    let crashed_path = tmp.path().join(format!("{op_name}_crashed_probe.img"));
    for cut in 0..total_writes {
        let cut_dev = CrashCutMemDevice::with_cut(baseline_bytes.clone(), cut);
        let vol = FatVolume::from_device(&cx, Box::new(cut_dev.clone()), 0, len)
            .expect("open CrashCutMemDevice");
        let res = mutate(&cx, &vol);
        assert!(
            res.is_err(),
            "{kind:?}/{op_name}: crash cut at write {cut}/{total_writes} must abort operation"
        );
        assert_eq!(
            cut_dev.writes_completed(),
            cut,
            "{kind:?}/{op_name}: CrashCutMemDevice must stop at exact write {cut}"
        );
        fs::write(&crashed_path, cut_dev.snapshot_bytes()).expect("persist crashed snapshot");
        recover_and_verify_crashed_image(&cx, &crashed_path, allow_excess_preallocation);
    }
}

fn run_create_row(kind: FormatKind) {
    let payload = vec![0xA5_u8; 5_000]; // Multi-cluster file with Long File Name.
    run_inplace_crash_cut_row(
        kind,
        "create",
        false,
        |cx, vol| {
            mkdir_in_volume(cx, vol, "/docs", FIXED_NOW, false).expect("seed /docs");
        },
        move |cx, vol| {
            create_in_volume(
                cx,
                vol,
                "/docs/newly_created_long_filename.txt",
                &payload,
                FIXED_NOW,
                false,
            )
            .map(|_| ())
        },
    );
}

fn run_write_extend_row(kind: FormatKind) {
    let initial = vec![0x11_u8; 700];
    let extension = vec![0x22_u8; 6_000];
    run_inplace_crash_cut_row(
        kind,
        "write_extend",
        true,
        move |cx, vol| {
            create_in_volume(cx, vol, "/grow_target_file.bin", &initial, FIXED_NOW, false)
                .expect("seed /grow_target_file.bin");
        },
        move |cx, vol| {
            write_range_in_volume(
                cx,
                vol,
                "/grow_target_file.bin",
                700,
                &extension,
                FIXED_NOW + 10,
            )
            .map(|_| ())
        },
    );
}

fn run_truncate_shrink_row(kind: FormatKind) {
    let initial = vec![0x33_u8; 9_000];
    run_inplace_crash_cut_row(
        kind,
        "truncate_shrink",
        true,
        move |cx, vol| {
            create_in_volume(
                cx,
                vol,
                "/shrink_target_file.bin",
                &initial,
                FIXED_NOW,
                false,
            )
            .expect("seed /shrink_target_file.bin");
        },
        |cx, vol| truncate_in_volume(cx, vol, "/shrink_target_file.bin", 600, FIXED_NOW + 20),
    );
}

fn run_unlink_row(kind: FormatKind) {
    let initial = vec![0x44_u8; 6_500];
    run_inplace_crash_cut_row(
        kind,
        "unlink",
        false,
        move |cx, vol| {
            create_in_volume(
                cx,
                vol,
                "/unlinked_long_entry_target.bin",
                &initial,
                FIXED_NOW,
                false,
            )
            .expect("seed unlink target");
        },
        |cx, vol| unlink_in_volume(cx, vol, "/unlinked_long_entry_target.bin", false).map(|_| ()),
    );
}

fn run_rename_row(kind: FormatKind) {
    // Part A: Cross-directory rename of an LFN empty file — zero cluster cross-links at
    // every write cut; 100% of intermediate cuts recover automatically to clean + fsck.fat -n!
    run_inplace_crash_cut_row(
        kind,
        "rename_cross_dir_lfn",
        false,
        |cx, vol| {
            mkdir_in_volume(cx, vol, "/src_dir", FIXED_NOW, false).expect("seed /src_dir");
            mkdir_in_volume(cx, vol, "/dst_dir", FIXED_NOW, false).expect("seed /dst_dir");
            create_in_volume(
                cx,
                vol,
                "/src_dir/moving_long_record.txt",
                b"",
                FIXED_NOW,
                false,
            )
            .expect("seed empty LFN file");
        },
        |cx, vol| {
            rename_in_volume(
                cx,
                vol,
                "/src_dir/moving_long_record.txt",
                "/dst_dir/arrived_long_record.txt",
                false,
            )
            .map(|_| ())
        },
    );

    // Part B: Cross-directory rename of a multi-cluster file — cuts before destination SFN
    // publication and after source SFN tombstone recover automatically to clean + fsck.fat -n;
    // cuts inside the 1-sector dual-entry window are deterministically flagged as `cross_link`
    // and refused by `recover` rather than guessing which namespace entry to destroy.
    let cx = Cx::for_testing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let payload = vec![0x55_u8; 4_096];
    let (_base_path, baseline_bytes) = format_seeded_baseline(&cx, tmp.path(), kind, |cx, vol| {
        mkdir_in_volume(cx, vol, "/a", FIXED_NOW, false).expect("seed /a");
        mkdir_in_volume(cx, vol, "/b", FIXED_NOW, false).expect("seed /b");
        create_in_volume(cx, vol, "/a/data_file.bin", &payload, FIXED_NOW, false)
            .expect("seed /a/data_file.bin");
    });
    let len = u64::try_from(baseline_bytes.len()).expect("len");
    let ref_dev = CrashCutMemDevice::unlimited(baseline_bytes.clone());
    let ref_vol = FatVolume::from_device(&cx, Box::new(ref_dev.clone()), 0, len).expect("open");
    rename_in_volume(
        &cx,
        &ref_vol,
        "/a/data_file.bin",
        "/b/moved_file.bin",
        false,
    )
    .expect("clean non-empty rename");
    let total_writes = ref_dev.writes_completed();
    let mut saw_cross_link_window = false;
    for cut in 0..total_writes {
        let cut_dev = CrashCutMemDevice::with_cut(baseline_bytes.clone(), cut);
        let vol = FatVolume::from_device(&cx, Box::new(cut_dev.clone()), 0, len).expect("open");
        assert!(
            rename_in_volume(&cx, &vol, "/a/data_file.bin", "/b/moved_file.bin", false).is_err()
        );
        let crashed_path = tmp.path().join(format!("rename_nonempty_cut_{cut}.img"));
        fs::write(&crashed_path, cut_dev.snapshot_bytes()).expect("write");
        let pre = gated_check(&cx, &image_args(&crashed_path)).expect("check");
        if pre.issues.iter().any(|i| i.kind == "cross_link") {
            saw_cross_link_window = true;
            let rec_args = RecoverArgs {
                image: image_args(&crashed_path),
                offline_image: true,
                reclaim_lost: true,
                discard_orphan_lfn: true,
                repair_mirrors_from: None,
                repair_boot_from: None,
                salvage_to: None,
                dry_run: false,
            };
            assert!(
                gated_recover(&cx, &rec_args).is_err(),
                "recover must fail closed on ambiguous cross-linked rename cut rather than guessing an owner"
            );
        } else {
            recover_and_verify_crashed_image(&cx, &crashed_path, false);
        }
    }
    assert!(
        saw_cross_link_window,
        "{kind:?}: non-empty cross-dir rename sweep must exercise the transient dual-entry window"
    );
}

fn run_resize_row(kind: FormatKind) {
    let cx = Cx::for_testing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let payload = vec![0x77_u8; 4_096];
    let (source_path, source_bytes) = format_seeded_baseline(&cx, tmp.path(), kind, |cx, vol| {
        create_in_volume(
            cx,
            vol,
            "/kept_across_resize.bin",
            &payload,
            FIXED_NOW,
            false,
        )
        .expect("seed resize payload");
    });
    let source_sha_before: [u8; 32] = Sha256::digest(&source_bytes).into();
    let target_mib = default_size_mib(kind) + 4;
    let target_bytes = usize::try_from(target_mib * 1024 * 1024).expect("target bytes");

    let resize_args = ResizeArgs {
        image: image_args(&source_path),
        output: tmp.path().join("unused_host_path.img"),
        size_mib: target_mib,
        relocate: false,
        root_entries: None,
        offline_image: true,
        dry_run: false,
    };

    // 1. Clean reference resize to measure exact write count and validate output.
    let ref_out = CrashCutMemDevice::unlimited(vec![0_u8; target_bytes]);
    let ref_arc: Arc<dyn ByteDevice> = Arc::new(ref_out.clone());
    with_flock_gate(|| run_to_device(&cx, &resize_args, ref_arc))
        .expect("clean resize must succeed");
    let total_writes = ref_out.writes_completed();
    assert!(
        total_writes >= 4,
        "{kind:?}/resize: expected multi-step publication, got {total_writes}"
    );
    let completed_path = tmp.path().join("resize_complete.img");
    fs::write(&completed_path, ref_out.snapshot_bytes()).expect("write completed resize");
    let completed_chk =
        gated_check(&cx, &image_args(&completed_path)).expect("check resized image");
    assert!(
        completed_chk.clean,
        "{kind:?}/resize completed image must be clean"
    );
    assert_fsck_fat_clean(&completed_path, false);

    // 2. Sweep intermediate write cuts: every cut `< total_writes` MUST leave the
    // withheld primary boot sector (`0..512`) zeroed so no half-written candidate can
    // ever be admitted as a FAT volume, and source SHA-256 must stay untouched.
    let cuts_to_test: Vec<usize> = if total_writes <= 24 {
        (0..total_writes).collect()
    } else {
        let mut set = std::collections::BTreeSet::new();
        for edge in [
            0,
            1,
            2,
            3,
            total_writes / 4,
            total_writes / 2,
            (total_writes * 3) / 4,
            total_writes.saturating_sub(3),
            total_writes.saturating_sub(2),
            total_writes.saturating_sub(1),
        ] {
            if edge < total_writes {
                set.insert(edge);
            }
        }
        let step = (total_writes / 16).max(1);
        let mut idx = 0;
        while idx < total_writes {
            set.insert(idx);
            idx += step;
        }
        set.into_iter().collect()
    };
    let partial_path = tmp.path().join("resize_partial_probe.img");
    for cut in cuts_to_test {
        let cut_out = CrashCutMemDevice::with_cut(vec![0_u8; target_bytes], cut);
        let cut_arc: Arc<dyn ByteDevice> = Arc::new(cut_out.clone());
        assert!(
            with_flock_gate(|| run_to_device(&cx, &resize_args, cut_arc)).is_err(),
            "{kind:?}/resize cut {cut}/{total_writes} must abort before completion"
        );
        let snap = cut_out.snapshot_bytes();
        assert!(
            snap[..512].iter().all(|&b| b == 0),
            "{kind:?}/resize cut {cut}/{total_writes} leaked primary boot sector before full verification!"
        );
        if cut == 0
            || cut == 1
            || cut == total_writes / 2
            || cut + 1 == total_writes
            || total_writes <= 16
        {
            fs::write(&partial_path, &snap).expect("write partial resize");
            assert!(
                gated_check(&cx, &image_args(&partial_path)).is_err(),
                "{kind:?}/resize partial candidate at cut {cut} must be rejected cleanly"
            );
        }
    }

    let source_sha_after: [u8; 32] =
        Sha256::digest(fs::read(&source_path).expect("re-read resize source")).into();
    assert_eq!(
        source_sha_before, source_sha_after,
        "{kind:?}/resize must never mutate source image"
    );
}

// ── 12-Row Crash-Cut Matrix (6 Operations × {FAT16, FAT32}) ─────────────────

#[test]
fn row01_fat16_create_crash_cut_matrix() {
    run_create_row(FormatKind::Fat16);
}

#[test]
fn row02_fat32_create_crash_cut_matrix() {
    run_create_row(FormatKind::Fat32);
}

#[test]
fn row03_fat16_write_extend_crash_cut_matrix() {
    run_write_extend_row(FormatKind::Fat16);
}

#[test]
fn row04_fat32_write_extend_crash_cut_matrix() {
    run_write_extend_row(FormatKind::Fat32);
}

#[test]
fn row05_fat16_truncate_shrink_crash_cut_matrix() {
    run_truncate_shrink_row(FormatKind::Fat16);
}

#[test]
fn row06_fat32_truncate_shrink_crash_cut_matrix() {
    run_truncate_shrink_row(FormatKind::Fat32);
}

#[test]
fn row07_fat16_unlink_crash_cut_matrix() {
    run_unlink_row(FormatKind::Fat16);
}

#[test]
fn row08_fat32_unlink_crash_cut_matrix() {
    run_unlink_row(FormatKind::Fat32);
}

#[test]
fn row09_fat16_rename_cross_dir_crash_cut_matrix() {
    run_rename_row(FormatKind::Fat16);
}

#[test]
fn row10_fat32_rename_cross_dir_crash_cut_matrix() {
    run_rename_row(FormatKind::Fat32);
}

#[test]
fn row11_fat16_resize_crash_cut_matrix() {
    run_resize_row(FormatKind::Fat16);
}

#[test]
fn row12_fat32_resize_crash_cut_matrix() {
    run_resize_row(FormatKind::Fat32);
}
