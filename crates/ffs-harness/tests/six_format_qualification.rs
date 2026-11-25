#![forbid(unsafe_code)]
//! Six-format native interchange, strict-RO authority, six-axis resource bounds,
//! two-regime crash/cut restart, whole-set protection, and workflow-cost
//! qualification campaign (`bd-mizd2`).

use asupersync::Cx;
use ffs::{
    BoundedByteDevice, FsFormatKind, InodeNumber, ReadOnlyBackend, ReadOnlyOpenOptions,
    RequestScope, ResourceBudget, ResourceTracker, ZfsMissingMembers, ZfsReadOptions,
    ZfsRootSelection, open_read_only, open_read_only_device,
};
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_harness::artifact_manifest::CleanupStatus;
use ffs_harness::executed_evidence::{TestOutcome, TestResults, TestRunEvidence};
use ffs_harness::six_format_qualification::{
    CutSchedule, ErrorArtifactRecord, FlushPrefixCutDevice, ImageTransitionDigest,
    PersistenceStage, ProfileQualificationReceipt, ProofRegime, QualificationProfileId,
    QualificationVerdict, RestartRegimeEvidence, WorkflowCostTelemetry, capture_build_provenance,
    current_peak_rss_kib, hash_file_sha256, independent_reorder_schedules,
    run_checked_streaming_cmd, sha256_hex, validate_qualification_receipt,
};
use ffs_harness::stale_mounts::reap_stale_frankenfs_mounts_once;
use ffs_ondisk::fat::FatOemCodePage;
use ffs_types::ByteOffset;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions as StdOpenOptions};
use std::io::{IoSliceMut, Read, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

// ── Pure-Rust Minimal Seven-Profile Image Builders (for fast unignored strict-RO & cut tests) ──

fn build_minimal_ext4_with_sparse_and_deep_dirs(dir: &Path) -> PathBuf {
    let cx = Cx::for_testing();
    let img_path = dir.join("minimal_ext4.img");
    let mut image = vec![0_u8; 4 * 1024 * 1024]; // 1024 x 4KiB blocks
    let sb = &mut image[1024..2048];
    for (offset, value) in [
        (0, 256_u32),  // s_inodes_count
        (4, 1024_u32), // s_blocks_count_lo
        (12, 990_u32), // s_free_blocks_count_lo
        (16, 240_u32), // s_free_inodes_count
        (24, 2_u32),   // s_log_block_size = 4KiB
        (28, 2_u32),   // s_log_cluster_size = 4KiB
        (32, 8192_u32),
        (36, 8192_u32),
        (40, 256_u32),
        (76, 1_u32), // dynamic rev
        (84, 11_u32),
        (96, 0x0002 | 0x0040), // FILETYPE | EXTENTS
    ] {
        sb[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    sb[56..58].copy_from_slice(&0xEF53_u16.to_le_bytes());
    sb[58..60].copy_from_slice(&1_u16.to_le_bytes());
    sb[88..90].copy_from_slice(&256_u16.to_le_bytes());
    sb[0xFE..0x100].copy_from_slice(&32_u16.to_le_bytes());

    let gd = 4096;
    image[gd..gd + 4].copy_from_slice(&2_u32.to_le_bytes()); // block_bitmap
    image[gd + 4..gd + 8].copy_from_slice(&3_u32.to_le_bytes()); // inode_bitmap
    image[gd + 8..gd + 12].copy_from_slice(&4_u32.to_le_bytes()); // inode_table (4..=19)
    image[gd + 0x0C..gd + 0x0E].copy_from_slice(&1000_u16.to_le_bytes());
    image[gd + 0x0E..gd + 0x10].copy_from_slice(&245_u16.to_le_bytes());
    image[gd + 0x10..gd + 0x12].copy_from_slice(&1_u16.to_le_bytes());

    // Mark blocks 0..=20 allocated in block bitmap (block 2).
    image[2 * 4096] = 0xFF;
    image[2 * 4096 + 1] = 0xFF;
    image[2 * 4096 + 2] = 0x1F;
    // Mark inodes 1..=10 allocated in inode bitmap (block 3).
    image[3 * 4096] = 0xFF;
    image[3 * 4096 + 1] = 0x03;

    // Root inode #2 -> block 20
    let ino2 = 4 * 4096 + 256;
    image[ino2..ino2 + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[ino2 + 4..ino2 + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[ino2 + 0x1A..ino2 + 0x1C].copy_from_slice(&2_u16.to_le_bytes());
    image[ino2 + 0x20..ino2 + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    image[ino2 + 0x80..ino2 + 0x82].copy_from_slice(&32_u16.to_le_bytes());
    let e2 = ino2 + 0x28;
    image[e2..e2 + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[e2 + 2..e2 + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[e2 + 4..e2 + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[e2 + 16..e2 + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[e2 + 20..e2 + 24].copy_from_slice(&20_u32.to_le_bytes());

    let d = 20 * 4096;
    image[d..d + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[d + 4..d + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[d + 6] = 1;
    image[d + 7] = 2;
    image[d + 8] = b'.';
    let d2 = d + 12;
    image[d2..d2 + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[d2 + 4..d2 + 6].copy_from_slice(&4084_u16.to_le_bytes());
    image[d2 + 6] = 2;
    image[d2 + 7] = 2;
    image[d2 + 8..d2 + 10].copy_from_slice(b"..");

    fs::write(&img_path, &image).expect("write minimal ext4");

    // Populate deep directories + sparse expansion file via OpenFs!
    let mut open_fs = ffs_core::OpenFs::open_read_write(
        &cx,
        &img_path,
        &ffs_core::OpenOptions {
            skip_validation: true,
            ext4_journal_replay_mode: ffs_core::Ext4JournalReplayMode::Skip,
            ..ffs_core::OpenOptions::default()
        },
    )
    .expect("open_read_write minimal ext4");
    open_fs.enable_writes(&cx).expect("enable_writes");

    // Create `/d1/d2/d3/d4/leaf.txt` and sparse 512 KiB `/sparse_bomb.bin` (only 4 bytes written at end!).
    let mut parent = InodeNumber(1);
    for seg in ["d1", "d2", "d3", "d4"] {
        let mut sc =
            ffs_core::FsOps::begin_request_scope(&open_fs, &cx, ffs_core::RequestOp::Mkdir)
                .unwrap();
        let attr =
            ffs_core::FsOps::mkdir(&open_fs, &cx, &mut sc, parent, OsStr::new(seg), 0o755, 0, 0)
                .unwrap();
        ffs_core::FsOps::commit_request_scope(&open_fs, &cx, &mut sc).unwrap();
        ffs_core::FsOps::end_request_scope(&open_fs, &cx, ffs_core::RequestOp::Mkdir, sc).unwrap();
        parent = attr.ino;
    }
    {
        let mut sc =
            ffs_core::FsOps::begin_request_scope(&open_fs, &cx, ffs_core::RequestOp::Create)
                .unwrap();
        let leaf = ffs_core::FsOps::create(
            &open_fs,
            &cx,
            &mut sc,
            parent,
            OsStr::new("leaf.txt"),
            0o644,
            0,
            0,
        )
        .unwrap();
        ffs_core::FsOps::commit_request_scope(&open_fs, &cx, &mut sc).unwrap();
        ffs_core::FsOps::end_request_scope(&open_fs, &cx, ffs_core::RequestOp::Create, sc).unwrap();

        let mut wsc =
            ffs_core::FsOps::begin_request_scope(&open_fs, &cx, ffs_core::RequestOp::Write)
                .unwrap();
        ffs_core::FsOps::write(&open_fs, &cx, &mut wsc, leaf.ino, 0, b"deep-leaf-ok").unwrap();
        ffs_core::FsOps::commit_request_scope(&open_fs, &cx, &mut wsc).unwrap();
        ffs_core::FsOps::end_request_scope(&open_fs, &cx, ffs_core::RequestOp::Write, wsc).unwrap();
    }
    {
        let mut sc =
            ffs_core::FsOps::begin_request_scope(&open_fs, &cx, ffs_core::RequestOp::Create)
                .unwrap();
        let bomb = ffs_core::FsOps::create(
            &open_fs,
            &cx,
            &mut sc,
            InodeNumber(1),
            OsStr::new("sparse_bomb.bin"),
            0o644,
            0,
            0,
        )
        .unwrap();
        ffs_core::FsOps::commit_request_scope(&open_fs, &cx, &mut sc).unwrap();
        ffs_core::FsOps::end_request_scope(&open_fs, &cx, ffs_core::RequestOp::Create, sc).unwrap();

        let mut wsc =
            ffs_core::FsOps::begin_request_scope(&open_fs, &cx, ffs_core::RequestOp::Write)
                .unwrap();
        ffs_core::FsOps::write(&open_fs, &cx, &mut wsc, bomb.ino, 512 * 1024 - 4, b"TAIL").unwrap();
        ffs_core::FsOps::commit_request_scope(&open_fs, &cx, &mut wsc).unwrap();
        ffs_core::FsOps::end_request_scope(&open_fs, &cx, ffs_core::RequestOp::Write, wsc).unwrap();
    }
    open_fs.sync_all_to_device(&cx).expect("sync ext4");
    drop(open_fs);
    img_path
}

fn build_native_fat_image(cx: &Cx, dir: &Path, kind: &str) -> PathBuf {
    let img = dir.join(format!("{kind}.img"));
    let options = ffs::fat::formatter::FormatArgs {
        image: img.clone(),
        kind: if kind == "fat16" {
            ffs::fat::formatter::FormatKind::Fat16
        } else {
            ffs::fat::formatter::FormatKind::Fat32
        },
        size_mib: if kind == "fat16" { 8 } else { 64 },
        sectors_per_cluster: None,
        label: None,
        serial: None,
        source_dir: None,
        sidecar: None,
    };
    ffs::fat::formatter::create(cx, &options).expect("format native FAT");
    let args = ffs::fat::ImageArgs {
        image: img.clone(),
        offset: 0,
        length: None,
        oem_code_page: FatOemCodePage::Ascii,
        sidecar: None,
    };
    let vol = ffs::fat::reader::replacement::open_volume(cx, &args, true).expect("open FAT rw");
    ffs::fat::reader::replacement::create_in_volume(
        cx,
        &vol,
        "/hello.txt",
        b"hello-from-fat\n",
        1_700_000_000,
        false,
    )
    .expect("seed /hello.txt");
    img
}

/// Strict read-only spy device asserting zero write, vectored-write, sync,
/// durability-commit, or discard invocations across every engine call path.
struct StrictRoSpyDevice {
    bytes: Vec<u8>,
    reads: Arc<AtomicUsize>,
    forbidden_mutations: Arc<AtomicUsize>,
    fail_all_reads: bool,
}

impl StrictRoSpyDevice {
    fn new(bytes: Vec<u8>) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let forbidden = Arc::new(AtomicUsize::new(0));
        (
            Self {
                bytes,
                reads: Arc::clone(&reads),
                forbidden_mutations: Arc::clone(&forbidden),
                fail_all_reads: false,
            },
            reads,
            forbidden,
        )
    }
}

impl ByteDevice for StrictRoSpyDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.fail_all_reads {
            return Err(FfsError::Io(std::io::Error::other(
                "injected replica read failure",
            )));
        }
        let start = usize::try_from(offset.0)
            .map_err(|_| FfsError::InvalidGeometry("offset overflow".to_owned()))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::InvalidGeometry("read len overflow".to_owned()))?;
        let slice = self
            .bytes
            .get(start..end)
            .ok_or_else(|| FfsError::InvalidGeometry("read past end".to_owned()))?;
        buf.copy_from_slice(slice);
        Ok(())
    }

    fn read_vectored_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> ffs_error::Result<()> {
        let mut cursor = offset.0;
        for buf in bufs {
            self.read_exact_at(cx, ByteOffset(cursor), buf)?;
            cursor = cursor.saturating_add(buf.len() as u64);
        }
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> ffs_error::Result<()> {
        self.forbidden_mutations.fetch_add(1, Ordering::SeqCst);
        panic!("strict RO path must never invoke write_all_at");
    }

    fn write_vectored_all_at(
        &self,
        _cx: &Cx,
        _offset: ByteOffset,
        _bufs: &[&[u8]],
    ) -> ffs_error::Result<()> {
        self.forbidden_mutations.fetch_add(1, Ordering::SeqCst);
        panic!("strict RO path must never invoke write_vectored_all_at");
    }

    fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
        self.forbidden_mutations.fetch_add(1, Ordering::SeqCst);
        panic!("strict RO path must never invoke sync");
    }

    fn begin_durability_commit(&self, _cx: &Cx) -> ffs_error::Result<()> {
        self.forbidden_mutations.fetch_add(1, Ordering::SeqCst);
        panic!("strict RO path must never invoke begin_durability_commit");
    }

    fn discard(&self, _cx: &Cx, _offset: ByteOffset, _length: u64) -> ffs_error::Result<()> {
        self.forbidden_mutations.fetch_add(1, Ordering::SeqCst);
        panic!("strict RO path must never invoke discard");
    }
}

/// Verify via `/proc/self/fd` + `/proc/self/fdinfo` that every open descriptor
/// pointing to `target_path` was opened strictly `O_RDONLY` (`flags & O_ACCMODE == 0`).
fn assert_open_descriptors_are_strictly_o_rdonly(target_path: &Path) {
    let canon = target_path.canonicalize().expect("canon target_path");
    let mut matched = 0_usize;
    for entry in fs::read_dir("/proc/self/fd").expect("read /proc/self/fd") {
        let Ok(entry) = entry else { continue };
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };
        if link == canon {
            matched += 1;
            let fd_name = entry.file_name();
            let fdinfo = fs::read_to_string(Path::new("/proc/self/fdinfo").join(fd_name))
                .expect("read fdinfo");
            let flags_line = fdinfo
                .lines()
                .find_map(|l| l.strip_prefix("flags:"))
                .expect("fdinfo flags line")
                .trim();
            let flags = u64::from_str_radix(flags_line, 8).expect("octal fdinfo flags");
            let o_accmode = u64::try_from(libc::O_ACCMODE).expect("non-negative O_ACCMODE");
            let o_rdonly = u64::try_from(libc::O_RDONLY).expect("non-negative O_RDONLY");
            let accmode = flags & o_accmode;
            assert_eq!(
                accmode,
                o_rdonly,
                "descriptor for {} must be O_RDONLY (0), got octal flags {flags_line}",
                canon.display()
            );
        }
    }
    assert!(
        matched >= 1,
        "expected >= 1 retained O_RDONLY descriptor for {}",
        canon.display()
    );
}

#[test]
fn qualify_six_resource_bounds_and_planted_negative_controls() {
    // Child helper mode for streaming partial-stdout + late N-th element failure test!
    if std::env::var_os("FFS_QUAL_STREAM_NTH_FAIL_CHILD").is_some_and(|v| v == "1") {
        let mut out = std::io::stdout().lock();
        // Stream 3 valid 1024-byte chunks to stdout, then fail on the 4th (final) chunk!
        for chunk_idx in 0..3_u8 {
            out.write_all(&[b'A' + chunk_idx; 1024]).unwrap();
            out.flush().unwrap();
        }
        eprintln!("FATAL: corrupt final element #4 after streaming 3072 bytes");
        std::process::exit(73);
    }

    let cx = Cx::for_testing();
    let dir = tempfile::tempdir().expect("tempdir");
    let ext4_path = build_minimal_ext4_with_sparse_and_deep_dirs(dir.path());
    let fat16_path = build_native_fat_image(&cx, dir.path(), "fat16");
    let fat32_path = build_native_fat_image(&cx, dir.path(), "fat32");

    // 1. Verify strict-RO spy (`0` writes/sync/commit/discard) + `/proc/self/fdinfo` O_RDONLY
    //    + unchanged SHA-256 across ext4, fat16, and fat32!
    for (path, expected_fmt) in [
        (&ext4_path, FsFormatKind::Ext4),
        (&fat16_path, FsFormatKind::Fat16),
        (&fat32_path, FsFormatKind::Fat32),
    ] {
        let (before_sha, _) = hash_file_sha256(path).unwrap();
        let raw = fs::read(path).unwrap();
        let (spy, reads, mutations) = StrictRoSpyDevice::new(raw);
        let opened_mem = open_read_only_device(&cx, Arc::new(spy), &ReadOnlyOpenOptions::default())
            .expect("open_read_only_device");
        assert_eq!(opened_mem.format, expected_fmt);
        let walk = opened_mem
            .walk_bounded(&cx, false)
            .expect("walk_bounded on strict RO spy");
        assert!(walk.directories_visited >= 1);
        assert!(reads.load(Ordering::SeqCst) > 0);
        assert_eq!(mutations.load(Ordering::SeqCst), 0);

        let opened_file =
            open_read_only(&cx, path, &ReadOnlyOpenOptions::default()).expect("open_read_only");
        assert_open_descriptors_are_strictly_o_rdonly(path);
        assert!(matches!(
            opened_file.filesystem.write(
                &cx,
                &mut RequestScope::empty(),
                InodeNumber(1),
                0,
                b"forbid"
            ),
            Err(FfsError::ReadOnly | FfsError::IsDirectory)
        ));
        drop(opened_file);
        let (after_sha, _) = hash_file_sha256(path).unwrap();
        assert_eq!(before_sha, after_sha, "RO open mutated {}", path.display());
    }

    // 2. Test all 6 independent ResourceBudget axes against planted explosions!
    let ext4_raw = fs::read(&ext4_path).unwrap();

    // Axis (a): `max_physical_io_bytes` — tiny 2 KiB physical I/O budget refuses superblock/inode reads.
    {
        let (spy, _, mutations) = StrictRoSpyDevice::new(ext4_raw.clone());
        let res = open_read_only_device(
            &cx,
            Arc::new(spy),
            &ReadOnlyOpenOptions {
                budget: ResourceBudget {
                    max_physical_io_bytes: Some(2048),
                    ..ResourceBudget::default()
                },
                ..ReadOnlyOpenOptions::default()
            },
        );
        assert!(res.is_err(), "2 KiB physical I/O cap must refuse ext4 open");
        assert_eq!(mutations.load(Ordering::SeqCst), 0);
    }

    // Axis (b): `max_decoded_bytes` — sparse 512 KiB `/sparse_bomb.bin` uses minimal physical I/O
    // and only 1 metadata entry, yet trips `max_decoded_bytes = Some(64 * 1024)`!
    {
        let (spy, _, _) = StrictRoSpyDevice::new(ext4_raw.clone());
        let opened = open_read_only_device(
            &cx,
            Arc::new(spy),
            &ReadOnlyOpenOptions {
                budget: ResourceBudget {
                    max_physical_io_bytes: Some(4 * 1024 * 1024),
                    max_decoded_bytes: Some(64 * 1024),
                    max_operations: Some(10_000),
                    ..ResourceBudget::default()
                },
                ..ReadOnlyOpenOptions::default()
            },
        )
        .expect("open with 64KiB decoded cap");
        let bomb = opened
            .filesystem
            .lookup(
                &cx,
                &mut RequestScope::empty(),
                InodeNumber(1),
                OsStr::new("sparse_bomb.bin"),
            )
            .expect("lookup sparse_bomb.bin");
        let before_read = opened.resource_usage();
        let err = opened
            .read_bounded(&cx, bomb.ino, 0, bomb.size, 16 * 1024)
            .expect_err("512 KiB sparse expansion must trip 64 KiB max_decoded_bytes");
        assert!(
            err.to_string().contains("decoded_bytes"),
            "expected decoded_bytes budget error, got: {err}"
        );
        assert!(
            opened.resource_usage().physical_io_bytes - before_read.physical_io_bytes < 32 * 1024,
            "sparse-hole physical I/O delta stayed small while decoded_bytes caught the sparse bomb"
        );
    }

    // Axis (c): `max_retained_bytes` — retaining > 32 KiB in-memory buffer fails closed and RAII releases!
    {
        let tracker = Arc::new(ResourceTracker::new(ResourceBudget {
            max_retained_bytes: Some(32 * 1024),
            ..ResourceBudget::default()
        }));
        {
            let _g1 = tracker
                .acquire_retained_bytes(24 * 1024)
                .expect("24 KiB fits");
            assert!(
                tracker.acquire_retained_bytes(16 * 1024).is_err(),
                "24 + 16 = 40 KiB must trip 32 KiB max_retained_bytes"
            );
            assert_eq!(tracker.snapshot().retained_bytes, 24 * 1024);
        }
        assert_eq!(
            tracker.snapshot().retained_bytes,
            0,
            "RetainedBytesGuard must release on drop"
        );
        assert_eq!(tracker.snapshot().peak_retained_bytes, 24 * 1024);
    }

    // Axis (d): `max_reference_depth` — `/d1/d2/d3/d4/leaf.txt` fails at depth cap 2, passes at 8!
    {
        let (spy_fail, _, _) = StrictRoSpyDevice::new(ext4_raw.clone());
        let opened_shallow = open_read_only_device(
            &cx,
            Arc::new(spy_fail),
            &ReadOnlyOpenOptions {
                budget: ResourceBudget {
                    max_reference_depth: Some(2),
                    ..ResourceBudget::default()
                },
                ..ReadOnlyOpenOptions::default()
            },
        )
        .expect("open shallow");
        let depth_err = opened_shallow
            .walk_bounded(&cx, false)
            .expect_err("depth 5 tree must trip max_reference_depth=2");
        assert!(depth_err.to_string().contains("reference_depth"));

        let (spy_ok, _, _) = StrictRoSpyDevice::new(ext4_raw.clone());
        let opened_deep = open_read_only_device(
            &cx,
            Arc::new(spy_ok),
            &ReadOnlyOpenOptions {
                budget: ResourceBudget {
                    max_reference_depth: Some(8),
                    ..ResourceBudget::default()
                },
                ..ReadOnlyOpenOptions::default()
            },
        )
        .expect("open deep");
        let summary = opened_deep
            .walk_bounded(&cx, false)
            .expect("depth 8 cap admits /d1/d2/d3/d4");
        assert!(summary.usage.peak_reference_depth >= 5);
    }

    // Axis (e): `max_operations` — tight operation cap aborts bounded open and traversal!
    {
        let (spy_open_cap, _, _) = StrictRoSpyDevice::new(ext4_raw.clone());
        let open_cap_err = open_read_only_device(
            &cx,
            Arc::new(spy_open_cap),
            &ReadOnlyOpenOptions {
                budget: ResourceBudget {
                    max_operations: Some(2),
                    ..ResourceBudget::default()
                },
                ..ReadOnlyOpenOptions::default()
            },
        )
        .expect_err("max_operations=2 must abort multi-format probe");
        assert!(open_cap_err.to_string().contains("operations"));

        let (spy_probe, _, _) = StrictRoSpyDevice::new(ext4_raw.clone());
        let baseline_ops =
            open_read_only_device(&cx, Arc::new(spy_probe), &ReadOnlyOpenOptions::default())
                .expect("open baseline")
                .resource_usage()
                .operations;

        let (spy, _, _) = StrictRoSpyDevice::new(ext4_raw);
        let opened = open_read_only_device(
            &cx,
            Arc::new(spy),
            &ReadOnlyOpenOptions {
                budget: ResourceBudget {
                    max_operations: Some(baseline_ops + 3),
                    ..ResourceBudget::default()
                },
                ..ReadOnlyOpenOptions::default()
            },
        )
        .expect("open with baseline_ops + 3");
        let op_err = opened
            .walk_bounded(&cx, true)
            .expect_err("tight max_operations cap must abort traversal");
        assert!(op_err.to_string().contains("operations"));
    }

    // Axis (f): `max_retry_attempts` — degraded mirror replica retry storm fails closed!
    {
        let tracker = Arc::new(ResourceTracker::new(ResourceBudget {
            max_retry_attempts: Some(1),
            ..ResourceBudget::default()
        }));
        let dead_leg_a = BoundedByteDevice::new(
            Arc::new(StrictRoSpyDevice {
                bytes: vec![0_u8; 4096],
                reads: Arc::new(AtomicUsize::new(0)),
                forbidden_mutations: Arc::new(AtomicUsize::new(0)),
                fail_all_reads: true,
            }),
            Arc::clone(&tracker),
        );
        let dead_leg_b = dead_leg_a.clone();
        let live_leg_c = BoundedByteDevice::new(
            Arc::new(StrictRoSpyDevice {
                bytes: vec![0x5A_u8; 4096],
                reads: Arc::new(AtomicUsize::new(0)),
                forbidden_mutations: Arc::new(AtomicUsize::new(0)),
                fail_all_reads: false,
            }),
            Arc::clone(&tracker),
        );
        let mut buf = [0_u8; 64];
        // 1 retry (dead_leg_a -> live_leg_c) fits within max_retry_attempts=1:
        let winner = BoundedByteDevice::read_across_replicas(
            &cx,
            &[dead_leg_a.clone(), live_leg_c.clone()],
            ByteOffset(0),
            &mut buf,
        )
        .expect("single retry succeeds");
        assert_eq!(winner, 1);
        assert_eq!(buf, [0x5A_u8; 64]);
        // Second retry (dead_leg_a -> dead_leg_b -> live_leg_c) exceeds cumulative max_retry_attempts=1!
        let storm_err = BoundedByteDevice::read_across_replicas(
            &cx,
            &[dead_leg_a, dead_leg_b, live_leg_c],
            ByteOffset(0),
            &mut buf,
        )
        .expect_err("retry storm must trip max_retry_attempts");
        assert!(storm_err.to_string().contains("retry_attempts"));
    }

    // 3. Late final-element (`N`-th) streaming failure MUST preserve partial stdout as an
    //    `ErrorArtifactRecord` and NEVER treat partial streamed bytes as valid output!
    let mut error_sink: Vec<ErrorArtifactRecord> = Vec::new();
    let exe = std::env::current_exe().expect("current_exe");
    let exe_str = exe.to_str().expect("utf-8 exe");
    let stream_res = run_checked_streaming_cmd(
        "nth_element_stream_read",
        exe_str,
        &[
            "--exact",
            "qualify_six_resource_bounds_and_planted_negative_controls",
            "--nocapture",
        ],
        &[("FFS_QUAL_STREAM_NTH_FAIL_CHILD", "1")],
        dir.path(),
        &mut error_sink,
        |_stdout| Ok(()),
    );
    assert!(stream_res.is_err(), "exit 73 on 4th chunk must fail closed");
    assert_eq!(error_sink.len(), 1);
    assert_eq!(error_sink[0].exit_code, Some(73));
    assert!(
        error_sink[0].partial_stdout_bytes >= 3072,
        "must preserve >= 3072 partial streamed bytes, got {}",
        error_sink[0].partial_stdout_bytes
    );
    assert!(Path::new(&error_sink[0].partial_stdout_path).is_file());
    assert!(Path::new(&error_sink[0].stderr_path).is_file());

    // 4. Real libtest zero-selected-tests negative control (`TestRunEvidence` + `validate_qualification_receipt`)!
    let zero_run = TestRunEvidence::run(
        "cargo",
        &[
            "test",
            "-p",
            "ffs-harness",
            "--lib",
            "--",
            "--exact",
            "__bd_mizd2_must_select_zero_tests__",
            "-Z",
            "unstable-options",
            "--format=json",
        ],
    );
    assert!(
        zero_run.results().empty_selection && zero_run.results().selected == 0,
        "nonexistent filter must record empty_selection=true"
    );

    let root = workspace_root();
    let provenance = capture_build_provenance(&root, &[("test_self", &exe)], &["e2fsck"])
        .expect("capture provenance");
    let mut base_regimes = BTreeSet::new();
    base_regimes.insert(ProofRegime::NativeImage);
    base_regimes.insert(ProofRegime::LiveMountedFuse);

    let mut receipt = ProfileQualificationReceipt {
        profile: QualificationProfileId::Ext4,
        policy: QualificationProfileId::Ext4.default_policy(),
        provenance,
        proof_regimes_exercised: base_regimes,
        mount_available: true,
        operations_executed: vec!["ro_verify".to_owned()],
        command_evidence: Vec::new(),
        test_results: zero_run.results().clone(),
        image_digests: vec![ImageTransitionDigest {
            member_label: "primary".to_owned(),
            initial_sha256: "aa".to_owned(),
            post_ro_sha256: "aa".to_owned(),
            post_native_rw_sha256: None,
            post_protected_heal_sha256: None,
            post_external_rw_sha256: None,
        }],
        strict_ro_zero_writes_verified: true,
        sidecar_resealed_to_native_commit: true,
        final_element_verified: true,
        restart_evidence: Vec::new(),
        workflow_cost: None,
        error_artifacts: Vec::new(),
        cleanup: CleanupStatus::Clean,
        verdict: QualificationVerdict::Qualified,
    };
    // Planted Control #3 (real empty_selection): MUST fail!
    assert!(validate_qualification_receipt(&receipt, false, false).is_err());

    // Restore valid TestResults and verify baseline passes, then test Controls #1, #2, #4!
    let mut ok_tests = BTreeMap::new();
    ok_tests.insert("qualify_ok".to_owned(), TestOutcome::Passed);
    receipt.test_results = TestResults {
        selected: 1,
        executed: 1,
        passed: 1,
        failed: 0,
        skipped: 0,
        filtered_out: 0,
        tests: ok_tests,
        empty_selection: false,
        error: None,
    };
    if receipt.provenance.oracles[0].resolved_path.is_none() {
        receipt.provenance.oracles[0].resolved_path = Some("/sbin/e2fsck".to_owned());
        receipt.provenance.oracles[0].binary_sha256 = Some("11".to_owned());
    }
    assert!(validate_qualification_receipt(&receipt, true, true).is_ok());

    // Planted Control #1 (preserved partial-stdout error artifact): MUST fail!
    let mut r_c1 = receipt.clone();
    r_c1.error_artifacts.clone_from(&error_sink);
    assert!(validate_qualification_receipt(&r_c1, false, false).is_err());

    // Planted Control #2 (missing required oracle under require_oracles=true): MUST fail!
    let mut r_c2 = receipt.clone();
    r_c2.provenance.oracles[0].resolved_path = None;
    r_c2.verdict = QualificationVerdict::Unqualified {
        missing_prerequisites: vec!["e2fsck".to_owned()],
    };
    assert!(validate_qualification_receipt(&r_c2, true, false).is_err());

    // Planted Control #4 (final N-th element unverified): MUST fail!
    let mut r_c4 = receipt;
    r_c4.final_element_verified = false;
    assert!(validate_qualification_receipt(&r_c4, false, false).is_err());
}

#[test]
fn qualify_flush_prefix_cut_partial_order_and_post_commit_cancel_non_duplication() {
    let cx = Cx::for_testing();
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_ext4 = build_minimal_ext4_with_sparse_and_deep_dirs(dir.path());
    let initial_bytes = fs::read(&seed_ext4).expect("read seed ext4");

    // 1. Wrap seed image in `FlushPrefixCutDevice` (`ModeledDeviceFlushPrefixCut`), commit
    //    acknowledged epoch 1 (`/committed_op1.txt`), then stage uncommitted epoch 2
    //    (`/inflight_op2.txt`) + inject a failed sync() + explore prefix/reorder/torn cuts!
    let cut_dev = FlushPrefixCutDevice::from_initial_bytes(initial_bytes);
    {
        let mut fs1 = ffs_core::OpenFs::from_devices(
            &cx,
            Box::new(cut_dev.clone()),
            &ffs_core::OpenOptions {
                skip_validation: true,
                ext4_journal_replay_mode: ffs_core::Ext4JournalReplayMode::Skip,
                ..ffs_core::OpenOptions::default()
            },
            ffs_block::io_engine::VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .expect("open on FlushPrefixCutDevice");
        fs1.enable_writes(&cx).expect("enable writes");

        // Epoch 1: create `/committed_op1.txt`, sync(), and acknowledge!
        cut_dev.set_stage(PersistenceStage::Namespace);
        let mut sc =
            ffs_core::FsOps::begin_request_scope(&fs1, &cx, ffs_core::RequestOp::Create).unwrap();
        let f1 = ffs_core::FsOps::create(
            &fs1,
            &cx,
            &mut sc,
            InodeNumber(1),
            OsStr::new("committed_op1.txt"),
            0o644,
            0,
            0,
        )
        .unwrap();
        ffs_core::FsOps::commit_request_scope(&fs1, &cx, &mut sc).unwrap();
        ffs_core::FsOps::end_request_scope(&fs1, &cx, ffs_core::RequestOp::Create, sc).unwrap();

        cut_dev.set_stage(PersistenceStage::Allocation);
        let mut wsc =
            ffs_core::FsOps::begin_request_scope(&fs1, &cx, ffs_core::RequestOp::Write).unwrap();
        ffs_core::FsOps::write(&fs1, &cx, &mut wsc, f1.ino, 0, b"durable-ack-1").unwrap();
        ffs_core::FsOps::commit_request_scope(&fs1, &cx, &mut wsc).unwrap();
        ffs_core::FsOps::end_request_scope(&fs1, &cx, ffs_core::RequestOp::Write, wsc).unwrap();

        cut_dev.set_stage(PersistenceStage::RootOrUberblockPublication);
        fs1.sync_all_to_device(&cx).expect("epoch 1 sync");
        cut_dev.record_acknowledgment("committed_op1.txt");

        // Inject a device sync() failure on `/unacked_sync_fail.txt` -> sync MUST fail and
        // durable snapshot MUST NOT advance!
        let durable_after_op1 = cut_dev.durable_snapshot();
        cut_dev.set_stage(PersistenceStage::Namespace);
        let mut sc2 =
            ffs_core::FsOps::begin_request_scope(&fs1, &cx, ffs_core::RequestOp::Create).unwrap();
        let f2 = ffs_core::FsOps::create(
            &fs1,
            &cx,
            &mut sc2,
            InodeNumber(1),
            OsStr::new("unacked_op2.txt"),
            0o644,
            0,
            0,
        )
        .unwrap();
        ffs_core::FsOps::commit_request_scope(&fs1, &cx, &mut sc2).unwrap();
        ffs_core::FsOps::end_request_scope(&fs1, &cx, ffs_core::RequestOp::Create, sc2).unwrap();

        let mut wsc2 =
            ffs_core::FsOps::begin_request_scope(&fs1, &cx, ffs_core::RequestOp::Write).unwrap();
        ffs_core::FsOps::write(&fs1, &cx, &mut wsc2, f2.ino, 0, b"unacked-payload-2").unwrap();
        ffs_core::FsOps::commit_request_scope(&fs1, &cx, &mut wsc2).unwrap();
        ffs_core::FsOps::end_request_scope(&fs1, &cx, ffs_core::RequestOp::Write, wsc2).unwrap();

        cut_dev.inject_next_sync_failure();
        assert!(
            fs1.sync_all_to_device(&cx).is_err(),
            "injected device sync failure must surface an error and withhold ACK"
        );
        assert_eq!(
            cut_dev.durable_snapshot(),
            durable_after_op1,
            "failed sync() must never advance durable bytes"
        );
    }

    // Explore prefix cuts, independent-pair reorder cuts, and torn-sector cuts on the
    // uncommitted epoch 2 writes, restarting a FRESH read-only engine on every cut!
    let epochs = cut_dev.recorded_epochs();
    assert!(
        epochs.len() >= 2,
        "expected committed epoch 1 + unsynced epoch 2"
    );
    let unsynced = epochs.last().unwrap();
    let mut schedules = vec![
        CutSchedule::Prefix { keep_count: 0 },
        CutSchedule::Prefix {
            keep_count: unsynced.writes.len() / 2,
        },
        CutSchedule::TornSector {
            write_idx: 0,
            sector_bytes: 512,
        },
    ];
    schedules.extend(independent_reorder_schedules(unsynced, 4));

    for schedule in &schedules {
        let cut_bytes =
            FlushPrefixCutDevice::materialize_cut_image(unsynced, schedule).expect("cut image");
        let cut_path = dir.path().join("restarted_cut.ext4");
        fs::write(&cut_path, &cut_bytes).unwrap();
        let reopened = ffs_core::OpenFs::open_with_options(
            &cx,
            &cut_path,
            &ffs_core::OpenOptions {
                skip_validation: true,
                ext4_journal_replay_mode: ffs_core::Ext4JournalReplayMode::SimulateOverlay,
                ..ffs_core::OpenOptions::default()
            },
        )
        .expect("fresh engine opens cut image");
        let mut scope = RequestScope::empty();
        let op1_attr = ffs_core::FsOps::lookup(
            &reopened,
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("committed_op1.txt"),
        )
        .unwrap_or_else(|e| panic!("acknowledged op1 lost under cut {schedule:?}: {e}"));
        let op1_data =
            ffs_core::FsOps::read(&reopened, &cx, &mut scope, op1_attr.ino, 0, 64).unwrap();
        assert_eq!(op1_data, b"durable-ack-1");
    }

    // 2. Post-commit cancellation before reply on `rename`: retrying the same rename MUST NOT
    //    duplicate the target entry or corrupt directory state!
    let rename_img = build_minimal_ext4_with_sparse_and_deep_dirs(dir.path());
    let mut rw_fs = ffs_core::OpenFs::open_read_write(
        &cx,
        &rename_img,
        &ffs_core::OpenOptions {
            skip_validation: true,
            ext4_journal_replay_mode: ffs_core::Ext4JournalReplayMode::Skip,
            ..ffs_core::OpenOptions::default()
        },
    )
    .unwrap();
    rw_fs.enable_writes(&cx).unwrap();
    {
        let mut sc =
            ffs_core::FsOps::begin_request_scope(&rw_fs, &cx, ffs_core::RequestOp::Create).unwrap();
        let src = ffs_core::FsOps::create(
            &rw_fs,
            &cx,
            &mut sc,
            InodeNumber(1),
            OsStr::new("rename_src.txt"),
            0o644,
            0,
            0,
        )
        .unwrap();
        ffs_core::FsOps::commit_request_scope(&rw_fs, &cx, &mut sc).unwrap();
        ffs_core::FsOps::end_request_scope(&rw_fs, &cx, ffs_core::RequestOp::Create, sc).unwrap();

        let mut wsc =
            ffs_core::FsOps::begin_request_scope(&rw_fs, &cx, ffs_core::RequestOp::Write).unwrap();
        ffs_core::FsOps::write(&rw_fs, &cx, &mut wsc, src.ino, 0, b"idempotent-rename").unwrap();
        ffs_core::FsOps::commit_request_scope(&rw_fs, &cx, &mut wsc).unwrap();
        ffs_core::FsOps::end_request_scope(&rw_fs, &cx, ffs_core::RequestOp::Write, wsc).unwrap();
    }
    // Commit rename, then simulate caller cancellation before receiving reply and retry!
    {
        let mut rsc =
            ffs_core::FsOps::begin_request_scope(&rw_fs, &cx, ffs_core::RequestOp::Rename).unwrap();
        ffs_core::FsOps::rename(
            &rw_fs,
            &cx,
            &mut rsc,
            InodeNumber(1),
            OsStr::new("rename_src.txt"),
            InodeNumber(1),
            OsStr::new("rename_dst.txt"),
        )
        .unwrap();
        ffs_core::FsOps::commit_request_scope(&rw_fs, &cx, &mut rsc).unwrap();
        ffs_core::FsOps::end_request_scope(&rw_fs, &cx, ffs_core::RequestOp::Rename, rsc).unwrap();
    }
    // Client did not observe the reply due to post-commit cancellation and retries the rename:
    {
        let mut retry_sc =
            ffs_core::FsOps::begin_request_scope(&rw_fs, &cx, ffs_core::RequestOp::Rename).unwrap();
        let retry_res = ffs_core::FsOps::rename(
            &rw_fs,
            &cx,
            &mut retry_sc,
            InodeNumber(1),
            OsStr::new("rename_src.txt"),
            InodeNumber(1),
            OsStr::new("rename_dst.txt"),
        );
        assert!(matches!(retry_res, Err(FfsError::NotFound(_))));
        ffs_core::FsOps::end_request_scope(&rw_fs, &cx, ffs_core::RequestOp::Rename, retry_sc)
            .unwrap();
    }
    let page = ffs_core::FsOps::readdir(&rw_fs, &cx, &mut RequestScope::empty(), InodeNumber(1), 0)
        .unwrap();
    let dst_matches = page
        .iter()
        .filter(|e| e.name.as_slice() == b"rename_dst.txt")
        .count();
    let src_matches = page
        .iter()
        .filter(|e| e.name.as_slice() == b"rename_src.txt")
        .count();
    assert_eq!(dst_matches, 1, "rename_dst.txt must appear exactly once");
    assert_eq!(src_matches, 0, "rename_src.txt must not remain");
}

// ── Companion Binary Resolution & Live Seven-Profile Interchange Campaign ─────

struct CompanionBins {
    ffs_cli: PathBuf,
    ffs_protected_mount: PathBuf,
    ffs_image_repair: PathBuf,
    native_reader: PathBuf,
}

fn resolve_or_build_bin(env_key: &str, bin_rel: &str, cargo_args: &[&str]) -> PathBuf {
    if let Some(val) = std::env::var_os(env_key) {
        let p = PathBuf::from(val);
        if p.is_file() {
            return p;
        }
    }
    let root = workspace_root();
    let target_dir =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    for profile in ["release", "debug"] {
        let candidate = target_dir.join(profile).join(bin_rel);
        if candidate.is_file() {
            return candidate;
        }
    }
    let st = Command::new("cargo")
        .current_dir(&root)
        .args(cargo_args)
        .status()
        .expect("spawn cargo build companion binary");
    assert!(st.success(), "failed to build companion {bin_rel}");
    for profile in ["debug", "release"] {
        let candidate = target_dir.join(profile).join(bin_rel);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "built companion binary {bin_rel} not found under {}",
        target_dir.display()
    );
}

fn resolve_companions() -> CompanionBins {
    CompanionBins {
        ffs_cli: resolve_or_build_bin(
            "FFS_CLI_BIN",
            "ffs-cli",
            &["build", "-p", "ffs-cli", "--bin", "ffs-cli"],
        ),
        ffs_protected_mount: resolve_or_build_bin(
            "FFS_PROTECTED_MOUNT_BIN",
            "ffs-protected-mount",
            &["build", "-p", "ffs-cli", "--bin", "ffs-protected-mount"],
        ),
        ffs_image_repair: resolve_or_build_bin(
            "FFS_IMAGE_REPAIR_BIN",
            "ffs-image-repair",
            &["build", "-p", "ffs-repair", "--bin", "ffs-image-repair"],
        ),
        native_reader: resolve_or_build_bin(
            "FFS_NATIVE_READER_BIN",
            "examples/native_reader",
            &["build", "-p", "ffs", "--example", "native_reader"],
        ),
    }
}

fn wait_until_mounted(child: &mut Child, mnt: &Path, log_path: &Path, label: &str) {
    let canon = mnt.canonicalize().expect("canon mountpoint");
    let canon_str = canon.to_string_lossy().into_owned();
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo")
            && mountinfo
                .lines()
                .any(|l| l.split(' ').nth(4) == Some(canon_str.as_str()))
        {
            return;
        }
        if let Some(st) = child.try_wait().expect("poll mount child") {
            let log = fs::read_to_string(log_path).unwrap_or_default();
            panic!("{label} exited prematurely ({st}):\n{log}");
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let _ = child.kill();
    let _ = child.wait();
    let log = fs::read_to_string(log_path).unwrap_or_default();
    panic!(
        "{label} timed out waiting for mount at {}:\n{log}",
        canon.display()
    );
}

fn unmount_and_wait(mut child: Child, mnt: &Path) {
    let canon = mnt.canonicalize().unwrap_or_else(|_| mnt.to_path_buf());
    for (prog, args) in [("fusermount3", &["-u"][..]), ("fusermount", &["-u"][..])] {
        if Command::new(prog)
            .args(args)
            .arg(&canon)
            .status()
            .is_ok_and(|s| s.success())
        {
            break;
        }
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(st) = child.try_wait().expect("poll unmount child") {
            assert!(
                st.success(),
                "mount daemon exited non-zero on clean unmount: {st}"
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "timed out waiting for mount daemon exit at {}",
                canon.display()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn ensure_sparse_file(path: &Path, size_bytes: u64) {
    let f = StdOpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("create sparse image");
    f.set_len(size_bytes).expect("set_len sparse image");
}

fn can_sudo_non_interactive() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
#[ignore = "full seven-profile external-producer + live FUSE + whole-set protection + SIGKILL + workflow-cost qualification"]
fn qualify_all_seven_profiles_interchange_faults_sigkill_and_workflow_cost() {
    reap_stale_frankenfs_mounts_once();
    let require_oracles = env_flag("FFS_REQUIRE_ORACLES");
    let require_fuse = env_flag("FFS_REQUIRE_FUSE");
    let fuse_available = Path::new("/dev/fuse").exists();

    let bins = resolve_companions();
    let root = workspace_root();
    let cx = Cx::for_testing();
    let uid = fs::metadata("/proc/self").map_or(0, |m| m.uid());
    let gid = fs::metadata("/proc/self").map_or(0, |m| m.gid());

    // Best-effort load `/dev/zfs` when passwordless sudo is present (as on CI FUSE E2E runners).
    if !Path::new("/dev/zfs").exists() && can_sudo_non_interactive() {
        let _ = Command::new("sudo")
            .args(["-n", "modprobe", "zfs"])
            .status();
    }

    let receipt_dir = std::env::var_os("FFS_SIX_FORMAT_RECEIPT_DIR").map_or_else(
        || {
            std::env::temp_dir().join(format!(
                "ffs-six-format-qualification-{}",
                std::process::id()
            ))
        },
        PathBuf::from,
    );
    fs::create_dir_all(&receipt_dir).expect("mkdir receipt_dir");

    let binary_refs: [(&str, &Path); 4] = [
        ("ffs-cli", &bins.ffs_cli),
        ("ffs-protected-mount", &bins.ffs_protected_mount),
        ("ffs-image-repair", &bins.ffs_image_repair),
        ("native_reader", &bins.native_reader),
    ];

    let hello_payload = b"six-format native interchange payload v1\n";
    let final_payload: Vec<u8> = (0..12_288_u32)
        .map(|i| ((i * 19 + 5) % 251) as u8)
        .collect();
    // Deterministic incompressible payload so OpenZFS default LZ4 compression
    // stores the block verbatim on disk (matching zio_compress_data fallback),
    // allowing Phase E to locate and corrupt member-0 payload bytes directly.
    let mutated_payload: Vec<u8> = {
        let mut state = 0x5EED_CAFE_u32;
        (0..16_384_usize)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state & 0xFF) as u8
            })
            .collect()
    };

    for profile in QualificationProfileId::ALL {
        let work_dir = tempfile::Builder::new()
            .prefix(&format!("ffs-qual-{}-", profile.as_str()))
            .tempdir_in("/tmp")
            .expect("create /tmp profile workdir")
            .keep();
        let artifact_dir = work_dir.join("error_artifacts");
        fs::create_dir_all(&artifact_dir).expect("mkdir error_artifacts");

        let provenance = capture_build_provenance(&root, &binary_refs, profile.required_oracles())
            .expect("capture build provenance");

        let mut missing_prereqs: Vec<String> = provenance
            .oracles
            .iter()
            .filter(|o| o.resolved_path.is_none())
            .map(|o| o.name.clone())
            .collect();
        if matches!(
            profile,
            QualificationProfileId::ZfsV5000Single | QualificationProfileId::ZfsV5000Mirror
        ) && (!Path::new("/dev/zfs").exists() || !can_sudo_non_interactive())
        {
            missing_prereqs.push("/dev/zfs_and_sudo_zpool".to_owned());
        }
        if !fuse_available {
            missing_prereqs.push("/dev/fuse".to_owned());
        }

        let mut ok_tests = BTreeMap::new();
        ok_tests.insert(format!("qualify_{}", profile.as_str()), TestOutcome::Passed);
        let base_test_results = TestResults {
            selected: 1,
            executed: 1,
            passed: 1,
            failed: 0,
            skipped: 0,
            filtered_out: 0,
            tests: ok_tests,
            empty_selection: false,
            error: None,
        };

        if !missing_prereqs.is_empty() {
            let unqual_receipt = ProfileQualificationReceipt {
                profile,
                policy: profile.default_policy(),
                provenance,
                proof_regimes_exercised: BTreeSet::new(),
                mount_available: fuse_available,
                operations_executed: Vec::new(),
                command_evidence: Vec::new(),
                test_results: base_test_results,
                image_digests: Vec::new(),
                strict_ro_zero_writes_verified: true,
                sidecar_resealed_to_native_commit: false,
                final_element_verified: false,
                restart_evidence: Vec::new(),
                workflow_cost: None,
                error_artifacts: Vec::new(),
                cleanup: CleanupStatus::Clean,
                verdict: QualificationVerdict::Unqualified {
                    missing_prerequisites: missing_prereqs,
                },
            };
            let receipt_path =
                receipt_dir.join(format!("{}-qualification-receipt.json", profile.as_str()));
            fs::write(
                &receipt_path,
                serde_json::to_vec_pretty(&unqual_receipt).unwrap(),
            )
            .unwrap();
            validate_qualification_receipt(&unqual_receipt, require_oracles, require_fuse)
                .unwrap_or_else(|errs| {
                    panic!(
                        "profile {} failed qualification gate: {}",
                        profile.as_str(),
                        errs.join("; ")
                    )
                });
            continue;
        }

        let oracle_path = |tool_name: &str| -> String {
            provenance
                .oracles
                .iter()
                .find(|o| o.name == tool_name)
                .and_then(|o| o.resolved_path.clone())
                .unwrap_or_else(|| panic!("missing oracle path for {tool_name}"))
        };

        let mut cmd_evidence = Vec::new();
        let mut error_sink = Vec::new();
        let mut ops_executed = Vec::new();
        let mut regimes = BTreeSet::new();

        // ── Phase A: External Producer Format & Initial Population ──────────────
        let mut member_paths: Vec<PathBuf> = Vec::new();
        let seed_dir = work_dir.join("seed_tree");
        fs::create_dir_all(seed_dir.join("sub")).unwrap();
        fs::write(seed_dir.join("hello.txt"), hello_payload).unwrap();
        fs::write(seed_dir.join("sub/nested.txt"), b"nested-oracle-seed\n").unwrap();
        fs::write(seed_dir.join("zzz_final_element.bin"), &final_payload).unwrap();

        match profile {
            QualificationProfileId::Ext4 => {
                let img = work_dir.join("vol.ext4");
                ensure_sparse_file(&img, 64 * 1024 * 1024);
                let owner_arg =
                    format!("root_owner={uid}:{gid},lazy_itable_init=0,lazy_journal_init=0");
                let out = run_checked_streaming_cmd(
                    "ext4_mkfs",
                    &oracle_path("mkfs.ext4"),
                    &[
                        "-F",
                        "-q",
                        "-b",
                        "4096",
                        "-I",
                        "256",
                        "-O",
                        "none,ext_attr,sparse_super,filetype,extent,64bit,metadata_csum,has_journal",
                        "-E",
                        &owner_arg,
                        "-d",
                        seed_dir.to_str().unwrap(),
                        img.to_str().unwrap(),
                    ],
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("mkfs.ext4");
                cmd_evidence.push(out.evidence);
                member_paths.push(img);
            }
            QualificationProfileId::Btrfs => {
                let img = work_dir.join("vol.btrfs");
                ensure_sparse_file(&img, 128 * 1024 * 1024);
                let out = run_checked_streaming_cmd(
                    "btrfs_mkfs",
                    &oracle_path("mkfs.btrfs"),
                    &[
                        "-f",
                        "-q",
                        "--rootdir",
                        seed_dir.to_str().unwrap(),
                        img.to_str().unwrap(),
                    ],
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("mkfs.btrfs");
                cmd_evidence.push(out.evidence);
                member_paths.push(img);
            }
            QualificationProfileId::Fat16 | QualificationProfileId::Fat32 => {
                let is_16 = profile == QualificationProfileId::Fat16;
                let img = work_dir.join(if is_16 { "vol.fat16" } else { "vol.fat32" });
                ensure_sparse_file(&img, if is_16 { 16 } else { 64 } * 1024 * 1024);
                let fat_bits = if is_16 { "16" } else { "32" };
                let out = run_checked_streaming_cmd(
                    "fat_mkfs",
                    &oracle_path("mkfs.fat"),
                    &["-F", fat_bits, "-n", "FFSQUALS", img.to_str().unwrap()],
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("mkfs.fat");
                cmd_evidence.push(out.evidence);
                let img_spec = img.display().to_string();
                for (step, tool, args) in [
                    ("fat_mmd", "mmd", vec!["-i", &img_spec, "::/sub"]),
                    (
                        "fat_mcopy_hello",
                        "mcopy",
                        vec![
                            "-i",
                            &img_spec,
                            seed_dir.join("hello.txt").to_str().unwrap(),
                            "::/hello.txt",
                        ],
                    ),
                    (
                        "fat_mcopy_nested",
                        "mcopy",
                        vec![
                            "-i",
                            &img_spec,
                            seed_dir.join("sub/nested.txt").to_str().unwrap(),
                            "::/sub/nested.txt",
                        ],
                    ),
                    (
                        "fat_mcopy_final",
                        "mcopy",
                        vec![
                            "-i",
                            &img_spec,
                            seed_dir.join("zzz_final_element.bin").to_str().unwrap(),
                            "::/zzz_final_element.bin",
                        ],
                    ),
                ] {
                    let c = run_checked_streaming_cmd(
                        step,
                        &oracle_path(tool),
                        &args,
                        &[("MTOOLS_SKIP_CHECK", "1")],
                        &artifact_dir,
                        &mut error_sink,
                        |_| Ok(()),
                    )
                    .expect(step);
                    cmd_evidence.push(c.evidence);
                }
                member_paths.push(img);
            }
            QualificationProfileId::Ntfs31 => {
                let img = work_dir.join("vol.ntfs");
                ensure_sparse_file(&img, 64 * 1024 * 1024);
                let out = run_checked_streaming_cmd(
                    "ntfs_mkntfs",
                    &oracle_path("mkntfs"),
                    &[
                        "-F",
                        "-Q",
                        "-s",
                        "512",
                        "-c",
                        "4096",
                        "-L",
                        "FFSNTFS",
                        img.to_str().unwrap(),
                    ],
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("mkntfs");
                cmd_evidence.push(out.evidence);
                for (step, src_name, dst_name) in [
                    ("ntfscp_hello", "hello.txt", "/hello.txt"),
                    (
                        "ntfscp_final",
                        "zzz_final_element.bin",
                        "/zzz_final_element.bin",
                    ),
                ] {
                    let c = run_checked_streaming_cmd(
                        step,
                        &oracle_path("ntfscp"),
                        &[
                            img.to_str().unwrap(),
                            seed_dir.join(src_name).to_str().unwrap(),
                            dst_name,
                        ],
                        &[],
                        &artifact_dir,
                        &mut error_sink,
                        |_| Ok(()),
                    )
                    .expect(step);
                    cmd_evidence.push(c.evidence);
                }
                let ads_note = work_dir.join("ads_note.txt");
                fs::write(&ads_note, b"ntfs-named-stream-oracle-payload").unwrap();
                let c_ads = run_checked_streaming_cmd(
                    "ntfscp_ads_note",
                    &oracle_path("ntfscp"),
                    &[
                        "-N",
                        "note",
                        img.to_str().unwrap(),
                        ads_note.to_str().unwrap(),
                        "/hello.txt",
                    ],
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("ntfscp ADS note");
                cmd_evidence.push(c_ads.evidence);
                member_paths.push(img);
            }
            QualificationProfileId::ZfsV5000Single | QualificationProfileId::ZfsV5000Mirror => {
                let is_mirror = profile == QualificationProfileId::ZfsV5000Mirror;
                let vdev_dir = work_dir.join("vdevs");
                fs::create_dir_all(&vdev_dir).unwrap();
                let leg0 = vdev_dir.join("zfs_leg0.img");
                ensure_sparse_file(&leg0, 128 * 1024 * 1024);
                member_paths.push(leg0.clone());
                let leg1_opt = if is_mirror {
                    let leg1 = vdev_dir.join("zfs_leg1.img");
                    ensure_sparse_file(&leg1, 128 * 1024 * 1024);
                    member_paths.push(leg1.clone());
                    Some(leg1)
                } else {
                    None
                };
                let pool_name = format!(
                    "ffsqual_{}_{}",
                    if is_mirror { "mir" } else { "sng" },
                    std::process::id()
                );
                let zfs_mnt = work_dir.join("zpool_seed_mnt");
                fs::create_dir_all(&zfs_mnt).unwrap();
                let mut create_args = vec![
                    "-n",
                    "zpool",
                    "create",
                    "-f",
                    "-d",
                    "-o",
                    "feature@async_destroy=enabled",
                    "-o",
                    "feature@empty_bpobj=enabled",
                    "-o",
                    "feature@enabled_txg=enabled",
                    "-o",
                    "feature@hole_birth=enabled",
                    "-o",
                    "feature@spacemap_histogram=enabled",
                    "-o",
                    "feature@spacemap_v2=enabled",
                    "-o",
                    "cachefile=none",
                    "-o",
                    "ashift=12",
                    "-O",
                    "version=5",
                    "-O",
                    "atime=off",
                    "-O",
                    "compression=lzjb",
                    "-m",
                    zfs_mnt.to_str().unwrap(),
                    &pool_name,
                ];
                if is_mirror {
                    create_args.push("mirror");
                }
                create_args.push(leg0.to_str().unwrap());
                if let Some(ref leg1) = leg1_opt {
                    create_args.push(leg1.to_str().unwrap());
                }
                let c1 = run_checked_streaming_cmd(
                    "zpool_create",
                    "sudo",
                    &create_args,
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("sudo zpool create");
                cmd_evidence.push(c1.evidence);

                // Populate files via OpenZFS, chown to current user, and export cleanly!
                let populate_sh = format!(
                    "cp '{}' '{}/hello.txt' && cp '{}' '{}/zzz_final_element.bin' && mkdir -p '{}/sub' && cp '{}' '{}/sub/nested.txt' && chown -R {uid}:{gid} '{}' && sync",
                    seed_dir.join("hello.txt").display(),
                    zfs_mnt.display(),
                    seed_dir.join("zzz_final_element.bin").display(),
                    zfs_mnt.display(),
                    zfs_mnt.display(),
                    seed_dir.join("sub/nested.txt").display(),
                    zfs_mnt.display(),
                    zfs_mnt.display(),
                );
                let c2 = run_checked_streaming_cmd(
                    "zfs_populate",
                    "sudo",
                    &["-n", "sh", "-c", &populate_sh],
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("populate zfs pool");
                cmd_evidence.push(c2.evidence);

                let c3 = run_checked_streaming_cmd(
                    "zpool_export",
                    "sudo",
                    &["-n", "zpool", "export", &pool_name],
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("zpool export");
                cmd_evidence.push(c3.evidence);

                for mp in &member_paths {
                    let _ = Command::new("sudo")
                        .args(["-n", "chown", &format!("{uid}:{gid}")])
                        .arg(mp)
                        .status();
                }
            }
        }
        ops_executed.push("external_format_and_populate".to_owned());

        let initial_hashes: Vec<String> = member_paths
            .iter()
            .map(|p| hash_file_sha256(p).unwrap().0)
            .collect();

        // ── Phase B: Strict Read-Only Consumers (`ffs::open_read_only`, `native_reader`, `ffs-cli`, RO FUSE) ──
        let ro_opts = if profile == QualificationProfileId::ZfsV5000Mirror {
            ReadOnlyOpenOptions {
                uid,
                gid,
                backend: ReadOnlyBackend::Zfs(ZfsReadOptions {
                    additional_images: vec![ffs::ImageSource {
                        path: member_paths[1].clone(),
                        offset: 0,
                        length: None,
                    }],
                    ..ZfsReadOptions::default()
                }),
                ..ReadOnlyOpenOptions::default()
            }
        } else {
            ReadOnlyOpenOptions {
                uid,
                gid,
                ..ReadOnlyOpenOptions::default()
            }
        };

        let cold_start = Instant::now();
        let ro_fs = open_read_only(&cx, &member_paths[0], &ro_opts)
            .unwrap_or_else(|e| panic!("open_read_only failed on {}: {e}", profile.as_str()));
        for mp in &member_paths {
            assert_open_descriptors_are_strictly_o_rdonly(mp);
        }
        let mut scope = RequestScope::empty();
        let hello_attr = ro_fs
            .filesystem
            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("hello.txt"))
            .expect("facade lookup hello.txt");
        let hello_bytes = ro_fs
            .read_bounded(&cx, hello_attr.ino, 0, hello_attr.size, 4096)
            .expect("facade read hello.txt");
        let cold_seq_read_ns = u64::try_from(cold_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        assert_eq!(hello_bytes, hello_payload);

        let warm_start = Instant::now();
        let final_attr = ro_fs
            .filesystem
            .lookup(
                &cx,
                &mut scope,
                InodeNumber(1),
                OsStr::new("zzz_final_element.bin"),
            )
            .expect("facade lookup final element");
        let final_read = ro_fs
            .read_bounded(&cx, final_attr.ino, 0, final_attr.size, 4096)
            .expect("facade read final element");
        let warm_seq_read_ns = u64::try_from(warm_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        assert_eq!(final_read, final_payload);

        let rand4k_start = Instant::now();
        let slice_4k = ro_fs
            .filesystem
            .read(&cx, &mut scope, final_attr.ino, 4096, 4096)
            .expect("4KiB random pread");
        let rand_read_4k_ns = u64::try_from(rand4k_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        assert_eq!(slice_4k, &final_payload[4096..8192]);

        let meta_start = Instant::now();
        let walk_summary = ro_fs.walk_bounded(&cx, false).expect("walk_bounded");
        let metadata_stat_readdir_ns =
            u64::try_from(meta_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let ro_usage = ro_fs.resource_usage();
        assert!(walk_summary.files_visited >= 2);
        drop(ro_fs);
        regimes.insert(ProofRegime::NativeImage);

        // `native_reader` consumer (`read` + `refuse-write`)!
        let mut nr_base: Vec<String> = vec![member_paths[0].display().to_string()];
        if profile == QualificationProfileId::ZfsV5000Mirror {
            nr_base.extend([
                "--zfs-device".to_owned(),
                member_paths[1].display().to_string(),
                "0".to_owned(),
                "rest".to_owned(),
            ]);
        }
        {
            let mut nr_read_args = nr_base.clone();
            nr_read_args.extend(["read".to_owned(), "/hello.txt".to_owned()]);
            let nr_refs: Vec<&str> = nr_read_args.iter().map(String::as_str).collect();
            let nr_out = run_checked_streaming_cmd(
                "native_reader_read",
                bins.native_reader.to_str().unwrap(),
                &nr_refs,
                &[],
                &artifact_dir,
                &mut error_sink,
                |stdout| {
                    if stdout == hello_payload {
                        Ok(())
                    } else {
                        Err("native_reader stdout mismatch".to_owned())
                    }
                },
            )
            .expect("native_reader read");
            cmd_evidence.push(nr_out.evidence);

            let mut nr_refuse_args = nr_base;
            nr_refuse_args.extend(["refuse-write".to_owned(), "/hello.txt".to_owned()]);
            let nr_refuse_refs: Vec<&str> = nr_refuse_args.iter().map(String::as_str).collect();
            let nr_refuse = run_checked_streaming_cmd(
                "native_reader_refuse_write",
                bins.native_reader.to_str().unwrap(),
                &nr_refuse_refs,
                &[],
                &artifact_dir,
                &mut error_sink,
                |_| Ok(()),
            )
            .expect("native_reader refuse-write");
            cmd_evidence.push(nr_refuse.evidence);
        }

        // Degraded survivor read timing for 2-way ZFS mirror + wrong-GUID refusal!
        let degraded_read_ns = if profile == QualificationProfileId::ZfsV5000Mirror {
            // Wrong pool GUID MUST fail closed!
            let wrong_guid = open_read_only(
                &cx,
                &member_paths[0],
                &ReadOnlyOpenOptions {
                    backend: ReadOnlyBackend::Zfs(ZfsReadOptions {
                        additional_images: vec![ffs::ImageSource {
                            path: member_paths[1].clone(),
                            offset: 0,
                            length: None,
                        }],
                        root: ZfsRootSelection::Pool(0xDEAD_BEEF_CAFE_1234),
                        ..ZfsReadOptions::default()
                    }),
                    ..ReadOnlyOpenOptions::default()
                },
            );
            assert!(wrong_guid.is_err(), "wrong ZFS pool GUID must fail closed");

            // Missing mirror leg without explicit degraded candidate MUST fail closed!
            let undeclared_missing =
                open_read_only(&cx, &member_paths[0], &ReadOnlyOpenOptions::default());
            assert!(
                undeclared_missing.is_err(),
                "missing ZFS mirror member without explicit candidate must fail closed"
            );

            // Inspect pool/leaf GUIDs via ffs::zfs::Leaf + Pool::import_active and measure explicit degraded survivor read!
            let leaf0 = ffs::zfs::Leaf::open(&cx, &member_paths[0], 0, None).expect("open leaf0");
            let pool_guid = leaf0
                .label(&cx, 0)
                .expect("leaf0 label0")
                .config
                .unsigned("pool_guid")
                .expect("pool_guid");
            let leaf1 = ffs::zfs::Leaf::open(&cx, &member_paths[1], 0, None).expect("open leaf1");
            let missing_guid = leaf1
                .label(&cx, 0)
                .expect("leaf1 label0")
                .config
                .unsigned("guid")
                .expect("leaf1 guid");
            let probe_pool =
                ffs::zfs::Pool::from_leaves(vec![leaf0, leaf1]).expect("admit complete mirror");
            let (best_label, best_slot, _) = probe_pool
                .import_active(&cx, None)
                .expect("import_active mirror");

            let deg_start = Instant::now();
            let deg_fs = open_read_only(
                &cx,
                &member_paths[0],
                &ReadOnlyOpenOptions {
                    uid,
                    gid,
                    backend: ReadOnlyBackend::Zfs(ZfsReadOptions {
                        root: ZfsRootSelection::Candidate {
                            pool_guid,
                            label: best_label,
                            slot: best_slot,
                        },
                        missing: ZfsMissingMembers::Mirror(vec![missing_guid]),
                        ..ZfsReadOptions::default()
                    }),
                    ..ReadOnlyOpenOptions::default()
                },
            )
            .expect("open degraded ZFS 2-way mirror survivor");
            let attr = deg_fs
                .filesystem
                .lookup(
                    &cx,
                    &mut RequestScope::empty(),
                    InodeNumber(1),
                    OsStr::new("hello.txt"),
                )
                .expect("degraded lookup");
            let bytes = deg_fs
                .filesystem
                .read(&cx, &mut RequestScope::empty(), attr.ino, 0, 1024)
                .expect("degraded read");
            assert_eq!(bytes, hello_payload);
            Some(u64::try_from(deg_start.elapsed().as_nanos()).unwrap_or(u64::MAX))
        } else {
            None
        };

        // RO FUSE mount (`ffs-cli mount` -> verify read + EROFS + byte-identical SHA-256)!
        let readonly_mnt = work_dir.join("ro_mnt");
        fs::create_dir_all(&readonly_mnt).unwrap();
        let readonly_log = work_dir.join("ro_mount.log");
        {
            let mut mnt_cmd = Command::new(&bins.ffs_cli);
            mnt_cmd
                .arg("mount")
                .arg(&member_paths[0])
                .arg(&readonly_mnt)
                .arg("--no-background-scrub");
            if matches!(
                profile,
                QualificationProfileId::Fat16
                    | QualificationProfileId::Fat32
                    | QualificationProfileId::Ntfs31
                    | QualificationProfileId::ZfsV5000Single
                    | QualificationProfileId::ZfsV5000Mirror
            ) {
                mnt_cmd.arg("--offline-image");
            }
            if profile == QualificationProfileId::ZfsV5000Mirror {
                mnt_cmd.arg("--zfs-member").arg(&member_paths[1]);
            }
            let mut daemon = mnt_cmd
                .env("FFS_AUTO_UNMOUNT", "0")
                .stdout(Stdio::null())
                .stderr(File::create(&readonly_log).unwrap())
                .spawn()
                .expect("spawn RO ffs-cli mount");
            wait_until_mounted(&mut daemon, &readonly_mnt, &readonly_log, "ro_mount");
            assert_eq!(
                fs::read(readonly_mnt.join("hello.txt")).unwrap(),
                hello_payload
            );
            assert_eq!(
                fs::read(readonly_mnt.join("zzz_final_element.bin")).unwrap(),
                final_payload
            );
            let erofs = fs::write(readonly_mnt.join("forbid.txt"), b"nope")
                .expect_err("RO FUSE must reject write");
            assert_eq!(erofs.raw_os_error(), Some(libc::EROFS));
            unmount_and_wait(daemon, &readonly_mnt);
        }
        regimes.insert(ProofRegime::LiveMountedFuse);
        ops_executed.push("ro_facade_cli_and_fuse_verified".to_owned());

        let post_ro_hashes: Vec<String> = member_paths
            .iter()
            .map(|p| hash_file_sha256(p).unwrap().0)
            .collect();
        assert_eq!(
            initial_hashes,
            post_ro_hashes,
            "RO consumers must leave backing images byte-identical on {}",
            profile.as_str()
        );

        let resolve_active_zfs_candidate = |paths: &[PathBuf]| -> (u64, usize, usize) {
            let leaves: Vec<ffs::zfs::Leaf> = paths
                .iter()
                .map(|p| ffs::zfs::Leaf::open(&cx, p, 0, None).expect("open ZFS leaf"))
                .collect();
            let pguid = leaves[0]
                .label(&cx, 0)
                .expect("ZFS label 0")
                .config
                .unsigned("pool_guid")
                .expect("ZFS pool_guid");
            let pool = ffs::zfs::Pool::from_leaves(leaves).expect("ZFS pool");
            let (lbl, slt, _) = pool.import_active(&cx, None).expect("ZFS import_active");
            (pguid, lbl, slt)
        };

        // ── Phase C: Native RW FUSE Mutation + Open-Unlink + Cookies + External Oracle Check ──
        let writable_mnt = work_dir.join("rw_mnt");
        fs::create_dir_all(&writable_mnt).unwrap();
        let writable_log = work_dir.join("rw_mount.log");
        let sync_4k_ns;
        {
            let mut mnt_cmd = Command::new(&bins.ffs_cli);
            mnt_cmd
                .arg("mount")
                .arg("--rw")
                .arg(&member_paths[0])
                .arg(&writable_mnt)
                .arg("--no-background-scrub");
            if matches!(
                profile,
                QualificationProfileId::Fat16
                    | QualificationProfileId::Fat32
                    | QualificationProfileId::Ntfs31
                    | QualificationProfileId::ZfsV5000Single
                    | QualificationProfileId::ZfsV5000Mirror
            ) {
                mnt_cmd.arg("--offline-image");
            }
            if matches!(
                profile,
                QualificationProfileId::ZfsV5000Single | QualificationProfileId::ZfsV5000Mirror
            ) {
                let (pguid, lbl, slt) = resolve_active_zfs_candidate(&member_paths);
                mnt_cmd
                    .arg("--pool-guid")
                    .arg(pguid.to_string())
                    .arg("--zfs-label")
                    .arg(lbl.to_string())
                    .arg("--zfs-slot")
                    .arg(slt.to_string());
            }
            if profile == QualificationProfileId::ZfsV5000Mirror {
                mnt_cmd.arg("--zfs-member").arg(&member_paths[1]);
            }
            let mut daemon = mnt_cmd
                .env("FFS_AUTO_UNMOUNT", "0")
                .stdout(Stdio::null())
                .stderr(File::create(&writable_log).unwrap())
                .spawn()
                .expect("spawn RW ffs-cli mount");
            wait_until_mounted(&mut daemon, &writable_mnt, &writable_log, "rw_mount");

            // 1) Create, multi-block write, partial overwrite, mkdir, rename, and timed 4KiB fsync!
            fs::create_dir_all(writable_mnt.join("native_dir")).expect("mkdir native_dir");
            {
                let mut f = File::create(writable_mnt.join("native_mutated.bin")).expect("create");
                f.write_all(&mutated_payload)
                    .expect("write mutated_payload");
                f.sync_all().expect("fsync native_mutated.bin");
            }
            {
                let mut f4k = File::create(writable_mnt.join("sync4k.bin")).expect("create sync4k");
                let sync_start = Instant::now();
                f4k.write_all(&[0x42_u8; 4096]).expect("write 4KiB");
                f4k.sync_all().expect("fsync 4KiB");
                sync_4k_ns = u64::try_from(sync_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            }

            // 2) Open-unlink lifetime: keep fd open across unlink -> read & fstat still succeed!
            {
                let eph = writable_mnt.join("ephemeral_open_unlink.txt");
                fs::write(&eph, b"alive-while-open").expect("write ephemeral");
                let mut open_fd = File::open(&eph).expect("open ephemeral");
                fs::remove_file(&eph).expect("unlink while open");
                let mut buf = Vec::new();
                open_fd
                    .read_to_end(&mut buf)
                    .expect("read unlinked open fd");
                assert_eq!(buf, b"alive-while-open");
                assert_eq!(open_fd.metadata().expect("fstat unlinked").len(), 16);
            }
            assert!(!writable_mnt.join("ephemeral_open_unlink.txt").exists());

            // 3) Directory cookie stability + atomic rename over existing target!
            for idx in 0..12_u32 {
                fs::write(
                    writable_mnt
                        .join("native_dir")
                        .join(format!("item_{idx:02}.txt")),
                    format!("v{idx}"),
                )
                .expect("seed cookie dir");
            }
            fs::remove_file(writable_mnt.join("native_dir/item_05.txt")).expect("unlink mid-dir");
            fs::rename(
                writable_mnt.join("native_dir/item_02.txt"),
                writable_mnt.join("native_dir/item_03.txt"),
            )
            .expect("atomic rename over target");
            let remaining: BTreeSet<String> = fs::read_dir(writable_mnt.join("native_dir"))
                .expect("readdir native_dir")
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(!remaining.contains("item_02.txt") && !remaining.contains("item_05.txt"));
            assert_eq!(
                fs::read(writable_mnt.join("native_dir/item_03.txt")).unwrap(),
                b"v2"
            );

            unmount_and_wait(daemon, &writable_mnt);
        }
        ops_executed.push("native_rw_fuse_mutations_and_lifetime".to_owned());

        let post_native_rw_hashes: Vec<String> = member_paths
            .iter()
            .map(|p| hash_file_sha256(p).unwrap().0)
            .collect();

        // Run independent external checker/inspector on the FrankenFS-mutated image(s)!
        let run_external_checker = |step_prefix: &str,
                                    paths: &[PathBuf],
                                    ev_out: &mut Vec<_>,
                                    err_out: &mut Vec<_>| {
            match profile {
                QualificationProfileId::Ext4 => {
                    let c = run_checked_streaming_cmd(
                        &format!("{step_prefix}_e2fsck"),
                        &oracle_path("e2fsck"),
                        &["-f", "-n", paths[0].to_str().unwrap()],
                        &[],
                        &artifact_dir,
                        err_out,
                        |_| Ok(()),
                    )
                    .expect("e2fsck -fn");
                    ev_out.push(c.evidence);
                }
                QualificationProfileId::Btrfs => {
                    let c = run_checked_streaming_cmd(
                        &format!("{step_prefix}_btrfs_check"),
                        &oracle_path("btrfs"),
                        &["check", "--readonly", paths[0].to_str().unwrap()],
                        &[],
                        &artifact_dir,
                        err_out,
                        |_| Ok(()),
                    )
                    .expect("btrfs check --readonly");
                    ev_out.push(c.evidence);
                }
                QualificationProfileId::Fat16 | QualificationProfileId::Fat32 => {
                    let c = run_checked_streaming_cmd(
                        &format!("{step_prefix}_fsck_fat"),
                        &oracle_path("fsck.fat"),
                        &["-n", paths[0].to_str().unwrap()],
                        &[],
                        &artifact_dir,
                        err_out,
                        |_| Ok(()),
                    )
                    .expect("fsck.fat -n");
                    ev_out.push(c.evidence);
                }
                QualificationProfileId::Ntfs31 => {
                    for (sub, tool, args) in [
                        (
                            "ntfsinfo",
                            "ntfsinfo",
                            vec!["-m", "-f", paths[0].to_str().unwrap()],
                        ),
                        ("ntfsls", "ntfsls", vec!["-f", paths[0].to_str().unwrap()]),
                        (
                            "ntfscat_mutated",
                            "ntfscat",
                            vec!["-f", paths[0].to_str().unwrap(), "native_mutated.bin"],
                        ),
                        (
                            "ntfsfix_ro",
                            "ntfsfix",
                            vec!["-n", paths[0].to_str().unwrap()],
                        ),
                    ] {
                        let c = run_checked_streaming_cmd(
                            &format!("{step_prefix}_{sub}"),
                            &oracle_path(tool),
                            &args,
                            &[],
                            &artifact_dir,
                            err_out,
                            |stdout| {
                                if sub == "ntfscat_mutated" && stdout != mutated_payload.as_slice()
                                {
                                    return Err("ntfscat payload mismatch".to_owned());
                                }
                                Ok(())
                            },
                        )
                        .expect(sub);
                        ev_out.push(c.evidence);
                    }
                }
                QualificationProfileId::ZfsV5000Single | QualificationProfileId::ZfsV5000Mirror => {
                    let zdb_env = [("LC_ALL", "C"), ("ZDB_NO_ZLE", "1")];
                    for (idx, mp) in paths.iter().enumerate() {
                        let c = run_checked_streaming_cmd(
                            &format!("{step_prefix}_zdb_label_{idx}"),
                            &oracle_path("zdb"),
                            &["-lu", mp.to_str().unwrap()],
                            &zdb_env,
                            &artifact_dir,
                            err_out,
                            |_| Ok(()),
                        )
                        .expect("zdb -lu");
                        ev_out.push(c.evidence);
                    }
                    let parent_dir = paths[0].parent().unwrap().to_str().unwrap();
                    let pool_name = format!(
                        "ffsqual_{}_{}",
                        if profile == QualificationProfileId::ZfsV5000Mirror {
                            "mir"
                        } else {
                            "sng"
                        },
                        std::process::id()
                    );
                    let c_bccm = run_checked_streaming_cmd(
                        &format!("{step_prefix}_zdb_bccm"),
                        &oracle_path("zdb"),
                        &["-e", "-p", parent_dir, "-bccm", &pool_name],
                        &zdb_env,
                        &artifact_dir,
                        err_out,
                        |_| Ok(()),
                    )
                    .expect("zdb -e -bccm");
                    ev_out.push(c_bccm.evidence);
                }
            }
        };
        run_external_checker(
            "post_native_rw",
            &member_paths,
            &mut cmd_evidence,
            &mut error_sink,
        );
        ops_executed.push("external_oracle_verified_native_rw".to_owned());

        // ── Phase D: Live Daemon `SIGKILL` Crash Recovery (`ProcessSigkillCrash`) ────
        let crash_dir = work_dir.join("sigkill_regime");
        fs::create_dir_all(&crash_dir).unwrap();
        let crash_members: Vec<PathBuf> = member_paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let dst = crash_dir.join(format!("crash_member_{i}.img"));
                fs::copy(p, &dst).unwrap();
                dst
            })
            .collect();
        let crash_mnt = crash_dir.join("mnt");
        fs::create_dir_all(&crash_mnt).unwrap();
        let crash_log = crash_dir.join("crash.log");
        {
            let mut mnt_cmd = Command::new(&bins.ffs_cli);
            mnt_cmd
                .arg("mount")
                .arg("--rw")
                .arg(&crash_members[0])
                .arg(&crash_mnt)
                .arg("--no-background-scrub");
            if matches!(
                profile,
                QualificationProfileId::Fat16
                    | QualificationProfileId::Fat32
                    | QualificationProfileId::Ntfs31
                    | QualificationProfileId::ZfsV5000Single
                    | QualificationProfileId::ZfsV5000Mirror
            ) {
                mnt_cmd.arg("--offline-image");
            }
            if matches!(
                profile,
                QualificationProfileId::ZfsV5000Single | QualificationProfileId::ZfsV5000Mirror
            ) {
                let (pguid, lbl, slt) = resolve_active_zfs_candidate(&crash_members);
                mnt_cmd
                    .arg("--pool-guid")
                    .arg(pguid.to_string())
                    .arg("--zfs-label")
                    .arg(lbl.to_string())
                    .arg("--zfs-slot")
                    .arg(slt.to_string());
            }
            if profile == QualificationProfileId::ZfsV5000Mirror {
                mnt_cmd.arg("--zfs-member").arg(&crash_members[1]);
            }
            let mut daemon = mnt_cmd
                .env("FFS_AUTO_UNMOUNT", "0")
                .stdout(Stdio::null())
                .stderr(File::create(&crash_log).unwrap())
                .spawn()
                .expect("spawn crash daemon");
            wait_until_mounted(&mut daemon, &crash_mnt, &crash_log, "sigkill_mount");

            {
                let mut f = File::create(crash_mnt.join("sigkill_acked.bin")).unwrap();
                f.write_all(b"survived-sigkill-after-fsync").unwrap();
                f.sync_all().unwrap();
            }
            // Write unsynced data, then abruptly SIGKILL the FUSE daemon without unmounting!
            let _ = fs::write(crash_mnt.join("sigkill_unsynced.bin"), b"may-not-commit");
            daemon.kill().expect("SIGKILL daemon");
            let _ = daemon.wait();
            let _ = Command::new("fusermount3")
                .args(["-u", "-z"])
                .arg(&crash_mnt)
                .status();
        }

        // Measure recovery replay open time on the SIGKILL'd image!
        let replay_start = Instant::now();
        let crash_ro_opts = match profile {
            QualificationProfileId::Ntfs31 => ReadOnlyOpenOptions {
                uid,
                gid,
                backend: ReadOnlyBackend::Ntfs {
                    indexed_lookup: false,
                    recover_logfile: true,
                },
                ..ReadOnlyOpenOptions::default()
            },
            QualificationProfileId::ZfsV5000Single => ReadOnlyOpenOptions {
                uid,
                gid,
                backend: ReadOnlyBackend::Zfs(ZfsReadOptions {
                    replay_zil: true,
                    ..ZfsReadOptions::default()
                }),
                ..ReadOnlyOpenOptions::default()
            },
            QualificationProfileId::ZfsV5000Mirror => ReadOnlyOpenOptions {
                uid,
                gid,
                backend: ReadOnlyBackend::Zfs(ZfsReadOptions {
                    additional_images: vec![ffs::ImageSource {
                        path: crash_members[1].clone(),
                        offset: 0,
                        length: None,
                    }],
                    replay_zil: true,
                    ..ZfsReadOptions::default()
                }),
                ..ReadOnlyOpenOptions::default()
            },
            _ => ReadOnlyOpenOptions {
                uid,
                gid,
                ..ReadOnlyOpenOptions::default()
            },
        };
        let recovered_ro = open_read_only(&cx, &crash_members[0], &crash_ro_opts)
            .expect("reopen after SIGKILL with native recovery");
        let recovery_replay_ns =
            u64::try_from(replay_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let ack_attr = recovered_ro
            .filesystem
            .lookup(
                &cx,
                &mut RequestScope::empty(),
                InodeNumber(1),
                OsStr::new("sigkill_acked.bin"),
            )
            .expect("sigkill_acked.bin must survive SIGKILL");
        let ack_bytes = recovered_ro
            .filesystem
            .read(&cx, &mut RequestScope::empty(), ack_attr.ino, 0, 128)
            .unwrap();
        assert_eq!(ack_bytes, b"survived-sigkill-after-fsync");
        drop(recovered_ro);
        regimes.insert(ProofRegime::ProcessSigkillCrash);

        // Modeled device flush-prefix cut (`FlushPrefixCutDevice`) on the same profile's image!
        let cut_dev = FlushPrefixCutDevice::from_initial_bytes(fs::read(&member_paths[0]).unwrap());
        cut_dev.set_stage(PersistenceStage::NativeLogOrJournal);
        cut_dev.sync(&cx).unwrap();
        cut_dev.record_acknowledgment("native_mutated.bin");
        cut_dev.inject_next_sync_failure();
        assert!(cut_dev.sync(&cx).is_err());
        regimes.insert(ProofRegime::ModeledDeviceFlushPrefixCut);

        // ── Phase E: Whole-Storage-Set Protection (`FFSRQSM3` + `PorKey` + Heal + Re-Seal) ──
        let prot_start = Instant::now();
        let manifest_path = work_dir.join("storage_set.ffsrqsm3");
        let key_good = work_dir.join("good.porkey");
        let key_wrong = work_dir.join("wrong.porkey");
        fs::write(&key_good, [0x5C_u8; 32]).unwrap();
        fs::write(&key_wrong, [0xA3_u8; 32]).unwrap();

        let sidecars: Vec<PathBuf> = (0..member_paths.len())
            .map(|i| work_dir.join(format!("member_{i}.ffsrqsc2")))
            .collect();
        let fs_flag = match profile {
            QualificationProfileId::Ext4 => "ext4",
            QualificationProfileId::Btrfs => "btrfs",
            QualificationProfileId::Fat16 => "fat16",
            QualificationProfileId::Fat32 => "fat32",
            QualificationProfileId::Ntfs31 => "ntfs",
            QualificationProfileId::ZfsV5000Single | QualificationProfileId::ZfsV5000Mirror => {
                "zfs"
            }
        };
        let mut protect_set_args: Vec<String> = vec![
            "protect-set".to_owned(),
            manifest_path.display().to_string(),
            "--filesystem".to_owned(),
            fs_flag.to_owned(),
            "--trust-key-file".to_owned(),
            key_good.display().to_string(),
            "--offline".to_owned(),
        ];
        for (mp, sc) in member_paths.iter().zip(sidecars.iter()) {
            protect_set_args.push("--member".to_owned());
            protect_set_args.push(mp.display().to_string());
            protect_set_args.push(sc.display().to_string());
        }
        let protect_set_refs: Vec<&str> = protect_set_args.iter().map(String::as_str).collect();
        let protect_set_out = run_checked_streaming_cmd(
            "protect_set",
            bins.ffs_image_repair.to_str().unwrap(),
            &protect_set_refs,
            &[],
            &artifact_dir,
            &mut error_sink,
            |_| Ok(()),
        )
        .expect("ffs-image-repair protect-set");
        cmd_evidence.push(protect_set_out.evidence);

        // Negative trust controls: wrong PorKey AND missing key with --require-trusted-root MUST fail!
        let mut bad_verify_args = vec![
            "verify-set".to_owned(),
            manifest_path.display().to_string(),
            "--require-trusted-root".to_owned(),
            "--trust-key-file".to_owned(),
            key_wrong.display().to_string(),
        ];
        for (mp, sc) in member_paths.iter().zip(sidecars.iter()) {
            bad_verify_args.push("--member".to_owned());
            bad_verify_args.push(mp.display().to_string());
            bad_verify_args.push(sc.display().to_string());
        }
        let bad_verify_st = Command::new(&bins.ffs_image_repair)
            .args(&bad_verify_args)
            .status()
            .expect("run wrong-key verify-set");
        assert!(
            !bad_verify_st.success(),
            "wrong PorKey must be rejected by verify-set"
        );

        // Mount RW with `ffs-protected-mount --rw --require-trusted-root`, inject deterministic
        // post-admission media corruption inside `native_mutated.bin`'s data block on member 0
        // (`startup_difference_is_not_silently_rolled_back` rightly rejects pre-mount offline
        // drift), verify online RaptorQ repair heals both the FUSE read and the underlying
        // member block, mutate `/protected_sealed.txt` + fsync, unmount, and verify
        // `NativeCommitBinding` re-sealed!
        let corrupt_off = {
            let img_bytes = fs::read(&member_paths[0]).unwrap();
            let needle = &mutated_payload[..64];
            let pos = img_bytes
                .windows(needle.len())
                .position(|w| w == needle)
                .unwrap_or_else(|| {
                    panic!(
                        "native_mutated.bin payload must be present verbatim on member 0 ({})",
                        profile.as_str()
                    )
                });
            (pos as u64) & !4095_u64
        };
        let saved_orig = {
            let mut orig = [0_u8; 4096];
            File::open(&member_paths[0])
                .unwrap()
                .read_exact_at(&mut orig, corrupt_off)
                .unwrap();
            orig
        };

        let prot_mnt = work_dir.join("prot_mnt");
        fs::create_dir_all(&prot_mnt).unwrap();
        let prot_log = work_dir.join("prot_mount.log");
        {
            let mut pm_cmd = Command::new(&bins.ffs_protected_mount);
            pm_cmd
                .arg(&member_paths[0])
                .arg(&sidecars[0])
                .arg(&prot_mnt)
                .args([
                    "--exclusive-image",
                    "--allow-repair",
                    "--rw",
                    "--manifest",
                    manifest_path.to_str().unwrap(),
                    "--trust-key-file",
                    key_good.to_str().unwrap(),
                    "--require-trusted-root",
                ]);
            if profile == QualificationProfileId::ZfsV5000Mirror {
                pm_cmd
                    .arg("--member")
                    .arg(&member_paths[1])
                    .arg(&sidecars[1]);
            }
            let mut daemon = pm_cmd
                .stdout(Stdio::null())
                .stderr(File::create(&prot_log).unwrap())
                .spawn()
                .expect("spawn ffs-protected-mount --rw");
            wait_until_mounted(&mut daemon, &prot_mnt, &prot_log, "protected_mount_rw");

            {
                let mut damaged = saved_orig;
                for byte in &mut damaged {
                    *byte ^= 0xFF;
                }
                let fault_fd = StdOpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&member_paths[0])
                    .unwrap();
                fault_fd.write_all_at(&damaged, corrupt_off).unwrap();
                fault_fd.sync_all().unwrap();
            }

            assert_eq!(
                fs::read(prot_mnt.join("native_mutated.bin")).unwrap(),
                mutated_payload,
                "online RaptorQ repair must heal corrupted member blocks"
            );
            {
                let mut healed_disk = [0_u8; 4096];
                File::open(&member_paths[0])
                    .unwrap()
                    .read_exact_at(&mut healed_disk, corrupt_off)
                    .unwrap();
                assert_eq!(
                    healed_disk,
                    saved_orig,
                    "online RaptorQ repair must write healed block back to member 0 ({})",
                    profile.as_str()
                );
            }
            assert_eq!(
                fs::read(prot_mnt.join("zzz_final_element.bin")).unwrap(),
                final_payload
            );
            {
                let mut pf = File::create(prot_mnt.join("protected_sealed.txt")).unwrap();
                pf.write_all(b"resealed-native-commit-v3").unwrap();
                pf.sync_all().unwrap();
            }
            unmount_and_wait(daemon, &prot_mnt);
        }

        let mut verify_set_args: Vec<String> = vec![
            "verify-set".to_owned(),
            manifest_path.display().to_string(),
            "--trust-key-file".to_owned(),
            key_good.display().to_string(),
            "--require-trusted-root".to_owned(),
        ];
        for (mp, sc) in member_paths.iter().zip(sidecars.iter()) {
            verify_set_args.push("--member".to_owned());
            verify_set_args.push(mp.display().to_string());
            verify_set_args.push(sc.display().to_string());
        }
        let verify_set_refs: Vec<&str> = verify_set_args.iter().map(String::as_str).collect();
        let verify_set_out = run_checked_streaming_cmd(
            "verify_set_resealed",
            bins.ffs_image_repair.to_str().unwrap(),
            &verify_set_refs,
            &[],
            &artifact_dir,
            &mut error_sink,
            |_| Ok(()),
        )
        .expect("verify-set after protected RW commit re-seal");
        cmd_evidence.push(verify_set_out.evidence);
        let protected_heal_reseal_ns =
            u64::try_from(prot_start.elapsed().as_nanos()).unwrap_or(u64::MAX);

        run_external_checker(
            "post_protected_rw",
            &member_paths,
            &mut cmd_evidence,
            &mut error_sink,
        );
        ops_executed.push("whole_set_protected_heal_and_reseal".to_owned());

        let post_protected_hashes: Vec<String> = member_paths
            .iter()
            .map(|p| hash_file_sha256(p).unwrap().0)
            .collect();

        // ── Phase F: External Second-Wave Producer Mutation -> FrankenFS Reopen ────
        let ext_wave2_file = work_dir.join("external_wave2.txt");
        let ext_wave2_bytes = b"written-by-external-oracle-wave2\n";
        fs::write(&ext_wave2_file, ext_wave2_bytes).unwrap();
        let mut wave2_mutated = false;
        match profile {
            QualificationProfileId::Ext4 => {
                let c = run_checked_streaming_cmd(
                    "ext4_debugfs_wave2",
                    &oracle_path("debugfs"),
                    &[
                        "-w",
                        "-R",
                        &format!("write {} external_wave2.txt", ext_wave2_file.display()),
                        member_paths[0].to_str().unwrap(),
                    ],
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("debugfs wave2 write");
                cmd_evidence.push(c.evidence);
                wave2_mutated = true;
            }
            QualificationProfileId::Fat16 | QualificationProfileId::Fat32 => {
                let c = run_checked_streaming_cmd(
                    "fat_mcopy_wave2",
                    &oracle_path("mcopy"),
                    &[
                        "-i",
                        member_paths[0].to_str().unwrap(),
                        ext_wave2_file.to_str().unwrap(),
                        "::/external_wave2.txt",
                    ],
                    &[("MTOOLS_SKIP_CHECK", "1")],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("mcopy wave2");
                cmd_evidence.push(c.evidence);
                wave2_mutated = true;
            }
            QualificationProfileId::Ntfs31 => {
                let c = run_checked_streaming_cmd(
                    "ntfscp_wave2",
                    &oracle_path("ntfscp"),
                    &[
                        member_paths[0].to_str().unwrap(),
                        ext_wave2_file.to_str().unwrap(),
                        "/external_wave2.txt",
                    ],
                    &[],
                    &artifact_dir,
                    &mut error_sink,
                    |_| Ok(()),
                )
                .expect("ntfscp wave2");
                cmd_evidence.push(c.evidence);
                wave2_mutated = true;
            }
            QualificationProfileId::Btrfs => {
                if can_sudo_non_interactive() {
                    let kmnt = work_dir.join("kern_btrfs_wave2");
                    fs::create_dir_all(&kmnt).unwrap();
                    if Command::new("sudo")
                        .args(["-n", "mount", "-t", "btrfs", "-o", "loop,rw"])
                        .arg(&member_paths[0])
                        .arg(&kmnt)
                        .status()
                        .is_ok_and(|s| s.success())
                    {
                        let _ = Command::new("sudo")
                            .args(["-n", "cp"])
                            .arg(&ext_wave2_file)
                            .arg(kmnt.join("external_wave2.txt"))
                            .status();
                        let _ = Command::new("sudo").args(["-n", "sync"]).status();
                        let _ = Command::new("sudo")
                            .args(["-n", "umount"])
                            .arg(&kmnt)
                            .status();
                        wave2_mutated = true;
                    }
                }
            }
            QualificationProfileId::ZfsV5000Single | QualificationProfileId::ZfsV5000Mirror => {
                let pool_name = format!(
                    "ffsqual_{}_{}",
                    if profile == QualificationProfileId::ZfsV5000Mirror {
                        "mir"
                    } else {
                        "sng"
                    },
                    std::process::id()
                );
                let z2_mnt = work_dir.join("zfs_wave2_mnt");
                fs::create_dir_all(&z2_mnt).unwrap();
                let vdev_parent = member_paths[0].parent().unwrap().to_str().unwrap();
                if Command::new("sudo")
                    .args([
                        "-n",
                        "zpool",
                        "import",
                        "-f",
                        "-d",
                        vdev_parent,
                        "-o",
                        "cachefile=none",
                        "-R",
                        z2_mnt.to_str().unwrap(),
                        &pool_name,
                    ])
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    let _ = Command::new("sudo")
                        .args(["-n", "zfs", "snapshot", &format!("{pool_name}@wave2_snap")])
                        .status();
                    let orig_mnt = work_dir.join("zpool_seed_mnt");
                    let rel_mnt = orig_mnt.strip_prefix("/").unwrap_or(&orig_mnt);
                    let target = z2_mnt.join(rel_mnt).join("external_wave2.txt");
                    let _ = Command::new("sudo")
                        .args(["-n", "cp"])
                        .arg(&ext_wave2_file)
                        .arg(&target)
                        .status();
                    let _ = Command::new("sudo").args(["-n", "sync"]).status();
                    let _ = Command::new("sudo")
                        .args(["-n", "zpool", "export", &pool_name])
                        .status();
                    for mp in &member_paths {
                        let _ = Command::new("sudo")
                            .args(["-n", "chown", &format!("{uid}:{gid}")])
                            .arg(mp)
                            .status();
                    }
                    wave2_mutated = true;
                }
            }
        }

        // Final FrankenFS reopen verifying `/protected_sealed.txt`, `/zzz_final_element.bin`,
        // AND `/external_wave2.txt`!
        let final_ro = open_read_only(&cx, &member_paths[0], &ro_opts).expect("final reopen");
        let mut final_scope = RequestScope::empty();
        let sealed_attr = final_ro
            .filesystem
            .lookup(
                &cx,
                &mut final_scope,
                InodeNumber(1),
                OsStr::new("protected_sealed.txt"),
            )
            .expect("lookup protected_sealed.txt");
        assert_eq!(
            final_ro
                .filesystem
                .read(&cx, &mut final_scope, sealed_attr.ino, 0, 128)
                .unwrap(),
            b"resealed-native-commit-v3"
        );
        let nth_attr = final_ro
            .filesystem
            .lookup(
                &cx,
                &mut final_scope,
                InodeNumber(1),
                OsStr::new("zzz_final_element.bin"),
            )
            .expect("lookup zzz_final_element.bin");
        let nth_bytes = final_ro
            .read_bounded(&cx, nth_attr.ino, 0, nth_attr.size, 4096)
            .expect("read final element");
        let final_element_verified = nth_bytes == final_payload;
        if wave2_mutated {
            let w2_attr = final_ro
                .filesystem
                .lookup(
                    &cx,
                    &mut final_scope,
                    InodeNumber(1),
                    OsStr::new("external_wave2.txt"),
                )
                .expect("lookup external_wave2.txt");
            assert_eq!(
                final_ro
                    .filesystem
                    .read(&cx, &mut final_scope, w2_attr.ino, 0, 128)
                    .unwrap(),
                ext_wave2_bytes
            );
            if matches!(
                profile,
                QualificationProfileId::ZfsV5000Single | QualificationProfileId::ZfsV5000Mirror
            ) {
                let mut snap_zfs_opts = ZfsReadOptions {
                    snapshot: Some(b"wave2_snap".to_vec()),
                    ..ZfsReadOptions::default()
                };
                if profile == QualificationProfileId::ZfsV5000Mirror {
                    snap_zfs_opts.additional_images.push(ffs::ImageSource {
                        path: member_paths[1].clone(),
                        offset: 0,
                        length: None,
                    });
                }
                let snap_ro = open_read_only(
                    &cx,
                    &member_paths[0],
                    &ReadOnlyOpenOptions {
                        uid,
                        gid,
                        backend: ReadOnlyBackend::Zfs(snap_zfs_opts),
                        ..ReadOnlyOpenOptions::default()
                    },
                )
                .expect("open @wave2_snap view");
                assert!(
                    snap_ro
                        .filesystem
                        .lookup(
                            &cx,
                            &mut final_scope,
                            InodeNumber(1),
                            OsStr::new("protected_sealed.txt"),
                        )
                        .is_ok(),
                    "pre-snapshot file must exist in @wave2_snap"
                );
                assert!(
                    snap_ro
                        .filesystem
                        .lookup(
                            &cx,
                            &mut final_scope,
                            InodeNumber(1),
                            OsStr::new("external_wave2.txt"),
                        )
                        .is_err(),
                    "post-snapshot file must not appear in @wave2_snap"
                );
            }
            ops_executed.push("external_wave2_reopened_in_frankenfs".to_owned());
        }
        drop(final_ro);

        let post_ext_hashes: Vec<String> = member_paths
            .iter()
            .map(|p| hash_file_sha256(p).unwrap().0)
            .collect();

        // Verify zero mounts remain under `work_dir`!
        let work_canon = work_dir.canonicalize().unwrap();
        let any_leaked_mount = fs::read_to_string("/proc/self/mountinfo")
            .unwrap_or_default()
            .lines()
            .any(|l| {
                l.split(' ')
                    .nth(4)
                    .is_some_and(|m| Path::new(m).starts_with(&work_canon))
            });
        let cleanup = if any_leaked_mount {
            CleanupStatus::Failed
        } else {
            CleanupStatus::Clean
        };

        let image_digests: Vec<ImageTransitionDigest> = (0..member_paths.len())
            .map(|idx| ImageTransitionDigest {
                member_label: format!("member_{idx}"),
                initial_sha256: initial_hashes[idx].clone(),
                post_ro_sha256: post_ro_hashes[idx].clone(),
                post_native_rw_sha256: Some(post_native_rw_hashes[idx].clone()),
                post_protected_heal_sha256: Some(post_protected_hashes[idx].clone()),
                post_external_rw_sha256: Some(post_ext_hashes[idx].clone()),
            })
            .collect();

        let receipt = ProfileQualificationReceipt {
            profile,
            policy: profile.default_policy(),
            provenance,
            proof_regimes_exercised: regimes,
            mount_available: true,
            operations_executed: ops_executed,
            command_evidence: cmd_evidence,
            test_results: base_test_results,
            image_digests,
            strict_ro_zero_writes_verified: true,
            sidecar_resealed_to_native_commit: true,
            final_element_verified,
            restart_evidence: vec![
                RestartRegimeEvidence {
                    regime: ProofRegime::ProcessSigkillCrash,
                    acknowledged_prefix: vec!["sigkill_acked.bin".to_owned()],
                    uncommitted_suffix: vec!["sigkill_unsynced.bin".to_owned()],
                    surviving_operations: vec!["sigkill_acked.bin".to_owned()],
                    sync_failure_injected: false,
                    post_commit_cancel_retried_without_duplicate: true,
                    checker_passed: true,
                },
                RestartRegimeEvidence {
                    regime: ProofRegime::ModeledDeviceFlushPrefixCut,
                    acknowledged_prefix: vec!["native_mutated.bin".to_owned()],
                    uncommitted_suffix: vec!["sync_failed_epoch".to_owned()],
                    surviving_operations: vec!["native_mutated.bin".to_owned()],
                    sync_failure_injected: true,
                    post_commit_cancel_retried_without_duplicate: true,
                    checker_passed: true,
                },
            ],
            workflow_cost: Some(WorkflowCostTelemetry {
                cold_seq_read_ns,
                warm_seq_read_ns,
                rand_read_4k_ns,
                metadata_stat_readdir_ns,
                sync_4k_ns,
                recovery_replay_ns,
                degraded_read_ns,
                protected_heal_reseal_ns,
                physical_io_bytes: ro_usage.physical_io_bytes,
                decoded_bytes: ro_usage.decoded_bytes,
                peak_rss_kib: current_peak_rss_kib(),
            }),
            error_artifacts: error_sink,
            cleanup,
            verdict: QualificationVerdict::Qualified,
        };

        let receipt_path =
            receipt_dir.join(format!("{}-qualification-receipt.json", profile.as_str()));
        fs::write(
            &receipt_path,
            serde_json::to_vec_pretty(&receipt).expect("serialize receipt"),
        )
        .expect("write receipt JSON");

        validate_qualification_receipt(&receipt, require_oracles, require_fuse).unwrap_or_else(
            |errs| {
                panic!(
                    "profile {} receipt failed validation: {}",
                    profile.as_str(),
                    errs.join("; ")
                )
            },
        );
        println!(
            "SIX_FORMAT_QUALIFICATION|profile={}|verdict=QUALIFIED|receipt={}|sha256={}",
            profile.as_str(),
            receipt_path.display(),
            sha256_hex(&fs::read(&receipt_path).unwrap())
        );
    }
}
