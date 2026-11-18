#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Cross-crate integration tests for under-tested interactions.
//!
//! bd-m5wf.9.4: Validates correct behavior across crate boundaries
//! where two or more FrankenFS subsystems must cooperate.

use asupersync::Cx;
use ffs_block::{BlockDevice, ByteBlockDevice, ByteDevice};
use ffs_core::{Ext4JournalReplayMode, FsOps, OpenFs, OpenOptions, XattrSetMode};
use ffs_error::{FfsError, Result as FfsResult};
use ffs_types::{BlockNumber, ByteOffset, InodeNumber};
use parking_lot::Mutex;
use std::ffi::OsStr;
use std::path::PathBuf;

// ── Shared in-memory device for integration tests ──────────────────────

/// Minimal in-memory byte device for integration tests.
#[derive(Debug)]
struct MemByteDevice {
    bytes: Mutex<Vec<u8>>,
}

impl MemByteDevice {
    fn new(size: usize) -> Self {
        Self {
            bytes: Mutex::new(vec![0u8; size]),
        }
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Mutex::new(bytes),
        }
    }
}

impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes.lock().len() as u64
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> FfsResult<()> {
        let off = offset.0 as usize;
        let bytes = self.bytes.lock();
        if off + buf.len() > bytes.len() {
            return Err(FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "read past end",
            )));
        }
        buf.copy_from_slice(&bytes[off..off + buf.len()]);
        drop(bytes);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> FfsResult<()> {
        let off = offset.0 as usize;
        let mut bytes = self.bytes.lock();
        if off + buf.len() > bytes.len() {
            return Err(FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "write past end",
            )));
        }
        bytes[off..off + buf.len()].copy_from_slice(buf);
        drop(bytes);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> FfsResult<()> {
        Ok(())
    }
}

/// Create an in-memory block device for tests.
fn mem_block_device(block_size: u32, block_count: usize) -> ByteBlockDevice<MemByteDevice> {
    let mem = MemByteDevice::new(block_size as usize * block_count);
    ByteBlockDevice::new(mem, block_size).expect("valid device")
}

fn open_writable_ext4_fixture() -> OpenFs {
    let img_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/images/ext4_small.img");
    let bytes = std::fs::read(img_path).expect("canonical ext4 fixture is required");
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    // Each test mutates its own copy, never the shared canonical image.
    let mut fs = OpenFs::from_device(&cx, Box::new(MemByteDevice::from_bytes(bytes)), &opts)
        .expect("open ext4 fixture");
    fs.enable_writes(&cx).expect("enable ext4 writes");
    fs
}

fn build_btrfs_fsops_image() -> Vec<u8> {
    // Public write-path tests need a natively valid device/chunk/extent tree,
    // rather than a partial parser fixture that fails admission before CRUD.
    let tmp = tempfile::tempdir().expect("btrfs fixture directory");
    let image = tmp.path().join("fsops.btrfs");
    let file = std::fs::File::create(&image).expect("create btrfs fixture");
    file.set_len(128 * 1024 * 1024).expect("size btrfs fixture");
    drop(file);
    let output = std::process::Command::new("mkfs.btrfs")
        .args(["-f", "-q"])
        .arg(&image)
        .output()
        .expect("btrfs write-path integration requires mkfs.btrfs");
    assert!(
        output.status.success(),
        "mkfs.btrfs failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(image).expect("read native btrfs fixture")
}

fn open_writable_btrfs_fixture() -> OpenFs {
    let cx = Cx::for_testing();
    let dev = MemByteDevice::from_bytes(build_btrfs_fsops_image());
    let opts = OpenOptions {
        btrfs_rw_ephemeral_ok: true,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::from_device(&cx, Box::new(dev), &opts).expect("open btrfs");
    fs.enable_writes(&cx).expect("enable btrfs writes");
    fs
}

// ── Suite 1: MVCC ↔ Journal (WAL-backed MVCC with replay) ─────────────

mod mvcc_journal {
    use super::*;
    use ffs_mvcc::MvccStore;

    #[test]
    fn mvcc_commit_preserves_version_ordering() {
        // Verify that committed MVCC versions are ordered by commit sequence
        let mut store = MvccStore::new();
        let block = BlockNumber(42);

        // First write
        let mut txn1 = store.begin();
        txn1.stage_write(block, vec![0xAA; 16]);
        let seq1 = store.commit(txn1).expect("commit 1");

        // Second write
        let mut txn2 = store.begin();
        txn2.stage_write(block, vec![0xBB; 16]);
        let seq2 = store.commit(txn2).expect("commit 2");

        assert!(
            seq2.0 > seq1.0,
            "commit sequences must be monotonically increasing"
        );

        // Read at latest snapshot should see second write
        let snap = store.current_snapshot();
        let data = store.read_visible(block, snap).expect("should be visible");
        assert_eq!(data, vec![0xBB; 16]);
    }

    #[test]
    fn mvcc_snapshot_isolation_across_transactions() {
        // Verify snapshot isolation: a snapshot taken before a commit
        // should not see that commit's data
        let mut store = MvccStore::new();
        let block = BlockNumber(10);

        // Initial write
        let mut txn1 = store.begin();
        txn1.stage_write(block, vec![1; 16]);
        store.commit(txn1).expect("commit initial");

        // Take snapshot before second write
        let snap_before = store.current_snapshot();

        // Second write (after snapshot)
        let mut txn2 = store.begin();
        txn2.stage_write(block, vec![2; 16]);
        store.commit(txn2).expect("commit second");

        // Read at old snapshot should see first write
        let data_old = store
            .read_visible(block, snap_before)
            .expect("visible at old snapshot");
        assert_eq!(data_old, vec![1; 16]);

        // Read at new snapshot should see second write
        let snap_after = store.current_snapshot();
        let data_new = store
            .read_visible(block, snap_after)
            .expect("visible at new snapshot");
        assert_eq!(data_new, vec![2; 16]);
    }

    #[test]
    fn mvcc_conflict_detection_first_committer_wins() {
        // Verify first-committer-wins conflict detection
        let mut store = MvccStore::new();
        let block = BlockNumber(99);

        // Initial write so both transactions see a version
        let mut seed = store.begin();
        seed.stage_write(block, vec![0; 16]);
        store.commit(seed).expect("seed");

        // Start two transactions from the same snapshot
        let mut txn_a = store.begin();
        let mut txn_b = store.begin();

        // Both write to the same block
        txn_a.stage_write(block, vec![0xAA; 16]);
        txn_b.stage_write(block, vec![0xBB; 16]);

        // First to commit wins
        store.commit(txn_a).expect("txn_a should succeed");

        // Second should conflict
        let result = store.commit(txn_b);
        assert!(result.is_err(), "txn_b should conflict");
    }

    #[test]
    fn mvcc_multi_block_transaction_atomicity() {
        // A multi-block transaction should be all-or-nothing visible
        let mut store = MvccStore::new();

        let mut txn = store.begin();
        for i in 0..10 {
            txn.stage_write(BlockNumber(i), vec![i as u8; 16]);
        }
        store.commit(txn).expect("multi-block commit");

        let snap = store.current_snapshot();
        for i in 0..10 {
            let data = store.read_visible(BlockNumber(i), snap).expect("visible");
            assert_eq!(data, vec![i as u8; 16]);
        }
    }

    #[test]
    fn mvcc_read_nonexistent_block_returns_none() {
        let store = MvccStore::new();
        let snap = store.current_snapshot();
        let result = store.read_visible(BlockNumber(999), snap);
        assert!(result.is_none(), "unwritten block should return None");
    }

    #[test]
    fn mvcc_empty_transaction_commits_cleanly() {
        let mut store = MvccStore::new();
        let txn = store.begin();
        let result = store.commit(txn);
        assert!(result.is_ok(), "empty transaction should commit");
    }
}

// ── Suite 2: Block ↔ Alloc (allocation through block cache) ────────────

mod block_alloc {
    use ffs_alloc::{bitmap_clear, bitmap_count_free, bitmap_find_free, bitmap_get, bitmap_set};

    #[test]
    fn bitmap_allocation_round_trip() {
        // Allocate blocks via bitmap, then verify they're marked as used
        let mut bitmap = vec![0u8; 128]; // 1024 bits = 1024 blocks
        let total = 1024_u32;

        // Initially all free
        assert_eq!(bitmap_count_free(&bitmap, total), total);

        // Allocate a block
        let first = bitmap_find_free(&bitmap, total, 0).expect("find free");
        bitmap_set(&mut bitmap, first);

        assert!(bitmap_get(&bitmap, first));
        assert_eq!(bitmap_count_free(&bitmap, total), total - 1);

        // Free the block
        bitmap_clear(&mut bitmap, first);
        assert!(!bitmap_get(&bitmap, first));
        assert_eq!(bitmap_count_free(&bitmap, total), total);
    }

    #[test]
    fn bitmap_sequential_allocation() {
        let mut bitmap = vec![0u8; 64]; // 512 blocks
        let total = 512_u32;

        // Allocate 10 blocks sequentially
        let mut allocated = Vec::new();
        for _ in 0..10 {
            let start = if allocated.is_empty() {
                0
            } else {
                allocated.last().unwrap() + 1
            };
            let blk = bitmap_find_free(&bitmap, total, start).expect("find free");
            bitmap_set(&mut bitmap, blk);
            allocated.push(blk);
        }

        assert_eq!(allocated.len(), 10);
        assert_eq!(bitmap_count_free(&bitmap, total), total - 10);

        // All allocated blocks should be marked used
        for &blk in &allocated {
            assert!(bitmap_get(&bitmap, blk));
        }
    }

    #[test]
    fn bitmap_fragmented_allocation() {
        let mut bitmap = vec![0u8; 32]; // 256 blocks
        let total = 256_u32;

        // Allocate every other block
        for i in (0..total).step_by(2) {
            bitmap_set(&mut bitmap, i);
        }
        assert_eq!(bitmap_count_free(&bitmap, total), 128);

        // Next free should be an odd block
        let free = bitmap_find_free(&bitmap, total, 0).expect("find in fragment");
        assert!(!bitmap_get(&bitmap, free));
        assert_eq!(free % 2, 1); // should be odd
    }

    #[test]
    fn bitmap_full_returns_none() {
        let bitmap = vec![0xFF; 16]; // 128 blocks, all used
        let total = 128_u32;

        let result = bitmap_find_free(&bitmap, total, 0);
        assert!(result.is_none(), "full bitmap should return None");
    }

    #[test]
    fn bitmap_wraparound_search() {
        let mut bitmap = vec![0u8; 16]; // 128 blocks
        let total = 128_u32;

        // Mark blocks 0..120 as used
        for i in 0..120 {
            bitmap_set(&mut bitmap, i);
        }

        // Search from block 100 should find block 120+
        let free = bitmap_find_free(&bitmap, total, 100).expect("find after wraparound");
        assert!(free >= 120, "should find free block at end: {free}");
    }

    #[test]
    fn bitmap_clear_and_reallocate() {
        let mut bitmap = vec![0u8; 16]; // 128 blocks
        let total = 128_u32;

        // Allocate block 5
        bitmap_set(&mut bitmap, 5);
        assert!(bitmap_get(&bitmap, 5));

        // Free block 5
        bitmap_clear(&mut bitmap, 5);
        assert!(!bitmap_get(&bitmap, 5));

        // Should be findable again starting from 5
        let found = bitmap_find_free(&bitmap, total, 5).expect("find freed");
        assert_eq!(found, 5);
    }
}

mod openfs_write_paths {
    use super::*;

    fn assert_xattr_round_trip(fs: &OpenFs, cx: &Cx, parent: InodeNumber, file_name: &OsStr) {
        let created = fs
            .create(cx, parent, file_name, 0o644, 1000, 1000)
            .expect("create");

        let names = fs.listxattr(cx, created.ino).expect("initial listxattr");
        assert!(names.is_empty(), "new file should start without xattrs");
        assert_eq!(
            fs.getxattr(cx, created.ino, "user.color")
                .expect("initial getxattr"),
            None
        );

        fs.setxattr(
            cx,
            created.ino,
            "user.color",
            b"blue-green",
            XattrSetMode::Set,
        )
        .expect("setxattr");

        let names = fs.listxattr(cx, created.ino).expect("listxattr after set");
        assert_eq!(names, vec!["user.color"]);
        assert_eq!(
            fs.getxattr(cx, created.ino, "user.color")
                .expect("getxattr after set"),
            Some(b"blue-green".to_vec())
        );

        let removed = fs
            .removexattr(cx, created.ino, "user.color")
            .expect("removexattr");
        assert!(removed, "existing xattr should be removed");
        assert_eq!(
            fs.getxattr(cx, created.ino, "user.color")
                .expect("getxattr after remove"),
            None
        );
        let names = fs
            .listxattr(cx, created.ino)
            .expect("listxattr after remove");
        assert!(
            names.is_empty(),
            "removed xattr should disappear from listxattr"
        );
    }

    #[test]
    fn utf8_filename_round_trips_through_create_write_lookup_and_read() {
        let fs = open_writable_ext4_fixture();
        let cx = Cx::for_testing();
        let root = InodeNumber(2);
        let name = OsStr::new("resume_文件_é.txt");
        let payload = b"payload for utf8 filename";

        let created = fs
            .create(&cx, root, name, 0o644, 1000, 1000)
            .expect("create");
        let written = fs.write(&cx, created.ino, 0, payload).expect("write");
        assert_eq!(written as usize, payload.len());

        let looked_up = fs.lookup(&cx, root, name).expect("lookup");
        assert_eq!(looked_up.ino, created.ino);

        let readback = fs
            .read(
                &cx,
                created.ino,
                0,
                u32::try_from(payload.len()).expect("len fits u32"),
            )
            .expect("read");
        assert_eq!(readback, payload);

        let entries = fs.readdir(&cx, root, 0).expect("readdir");
        assert!(
            entries
                .iter()
                .any(|entry| entry.name_str() == "resume_文件_é.txt"),
            "utf-8 filename should appear in readdir output"
        );
    }

    #[test]
    fn utf8_filename_round_trips_through_create_write_lookup_and_read_on_btrfs() {
        let fs = open_writable_btrfs_fixture();
        let cx = Cx::for_testing();
        let root = InodeNumber(1);
        let name = OsStr::new("resume_文件_é.txt");
        let payload = b"payload for utf8 filename on btrfs";

        let created = fs
            .create(&cx, root, name, 0o644, 1000, 1000)
            .expect("create");
        let written = fs.write(&cx, created.ino, 0, payload).expect("write");
        assert_eq!(written as usize, payload.len());

        let looked_up = fs.lookup(&cx, root, name).expect("lookup");
        assert_eq!(looked_up.ino, created.ino);

        let readback = fs
            .read(
                &cx,
                created.ino,
                0,
                u32::try_from(payload.len()).expect("len fits u32"),
            )
            .expect("read");
        assert_eq!(readback, payload);

        let entries = fs.readdir(&cx, root, 0).expect("readdir");
        assert!(
            entries
                .iter()
                .any(|entry| entry.name_str() == "resume_文件_é.txt"),
            "utf-8 filename should appear in btrfs readdir output"
        );
    }

    #[test]
    fn xattr_round_trip_through_public_openfs_api_on_ext4() {
        let fs = open_writable_ext4_fixture();
        let cx = Cx::for_testing();
        assert_xattr_round_trip(&fs, &cx, InodeNumber(2), OsStr::new("xattr-ext4.txt"));
    }

    #[test]
    fn xattr_round_trip_through_public_openfs_api_on_btrfs() {
        let fs = open_writable_btrfs_fixture();
        let cx = Cx::for_testing();
        assert_xattr_round_trip(&fs, &cx, InodeNumber(1), OsStr::new("xattr-btrfs.txt"));
    }
}

// ── Suite 3: Block device read/write consistency ───────────────────────

mod block_readwrite {
    use super::*;

    #[test]
    fn write_and_read_single_block() {
        let cx = Cx::for_testing();
        let dev = mem_block_device(4096, 100);

        let data = vec![0xDE; 4096];
        dev.write_block(&cx, BlockNumber(50), &data).expect("write");

        let buf = dev.read_block(&cx, BlockNumber(50)).expect("read");
        assert_eq!(buf.as_slice(), &data);
    }

    #[test]
    fn write_multiple_blocks_independently() {
        let cx = Cx::for_testing();
        let dev = mem_block_device(4096, 100);

        // Write different data to different blocks
        for i in 0..10_u64 {
            let data = vec![i as u8; 4096];
            dev.write_block(&cx, BlockNumber(i), &data).expect("write");
        }

        // Verify each block has correct data
        for i in 0..10_u64 {
            let buf = dev.read_block(&cx, BlockNumber(i)).expect("read");
            assert_eq!(buf.as_slice(), &vec![i as u8; 4096], "block {i} mismatch");
        }
    }

    #[test]
    fn overwrite_block_replaces_data() {
        let cx = Cx::for_testing();
        let dev = mem_block_device(4096, 10);

        // Write initial data
        dev.write_block(&cx, BlockNumber(0), &vec![0xAA; 4096])
            .expect("write 1");

        // Overwrite
        dev.write_block(&cx, BlockNumber(0), &vec![0xBB; 4096])
            .expect("write 2");

        let buf = dev.read_block(&cx, BlockNumber(0)).expect("read");
        assert_eq!(buf.as_slice()[0], 0xBB);
    }

    #[test]
    fn read_unwritten_block_returns_zeros() {
        let cx = Cx::for_testing();
        let dev = mem_block_device(4096, 10);

        let buf = dev.read_block(&cx, BlockNumber(5)).expect("read");
        assert!(buf.as_slice().iter().all(|&b| b == 0), "should be zeros");
    }

    #[test]
    fn block_device_metadata_consistent() {
        let dev = mem_block_device(4096, 100);
        assert_eq!(dev.block_size(), 4096);
        assert_eq!(dev.block_count(), 100);
    }

    #[test]
    fn different_block_sizes_supported() {
        for bs in [1024_u32, 2048, 4096] {
            let dev = mem_block_device(bs, 10);
            assert_eq!(dev.block_size(), bs);
            let cx = Cx::for_testing();
            let data = vec![0xFF; bs as usize];
            dev.write_block(&cx, BlockNumber(0), &data).expect("write");
            let buf = dev.read_block(&cx, BlockNumber(0)).expect("read");
            assert_eq!(buf.len(), bs as usize);
        }
    }
}

// ── Suite 4: Extent mapping (ffs-extent resolve) ───────────────────────

mod extent_mapping {
    use super::*;

    const BLOCK_SIZE: u32 = 4096;
    const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

    fn write_header(buf: &mut [u8], entries: u16, max_entries: u16, depth: u16) {
        buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&entries.to_le_bytes());
        buf[4..6].copy_from_slice(&max_entries.to_le_bytes());
        buf[6..8].copy_from_slice(&depth.to_le_bytes());
        buf[8..12].copy_from_slice(&0u32.to_le_bytes());
    }

    fn write_extent(buf: &mut [u8], logical_block: u32, raw_len: u16, physical_start: u64) {
        buf[0..4].copy_from_slice(&logical_block.to_le_bytes());
        buf[4..6].copy_from_slice(&raw_len.to_le_bytes());
        let phys_hi = ((physical_start >> 32) & 0xFFFF) as u16;
        let phys_lo = (physical_start & 0xFFFF_FFFF) as u32;
        buf[6..8].copy_from_slice(&phys_hi.to_le_bytes());
        buf[8..12].copy_from_slice(&phys_lo.to_le_bytes());
    }

    /// Build a depth-0 root with `count` extents starting at logical 0.
    fn build_root(count: u16, extent_len: u16) -> [u8; 60] {
        let mut root = [0u8; 60];
        write_header(&mut root[..12], count, 4, 0);
        for i in 0..count {
            let off = 12 + (i as usize) * 12;
            let logical = u32::from(i) * u32::from(extent_len);
            let physical = 1000 + u64::from(i) * u64::from(extent_len);
            write_extent(&mut root[off..off + 12], logical, extent_len, physical);
        }
        root
    }

    #[test]
    fn resolve_single_extent() {
        let cx = Cx::for_testing();
        let dev = mem_block_device(BLOCK_SIZE, 1);
        let root = build_root(1, 100);

        let mappings =
            ffs_extent::map_logical_to_physical(&cx, &dev, &root, 50, 1).expect("resolve");
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].logical_start, 50);
        assert_eq!(mappings[0].physical_start, 1050);
        assert_eq!(mappings[0].count, 1);
    }

    #[test]
    fn resolve_across_extent_boundary() {
        let cx = Cx::for_testing();
        let dev = mem_block_device(BLOCK_SIZE, 1);
        // 2 extents: [0..100) and [100..200)
        let root = build_root(2, 100);

        let mappings = ffs_extent::map_logical_to_physical(&cx, &dev, &root, 95, 10)
            .expect("resolve range crossing boundary");
        assert!(mappings.len() >= 2, "should span two extents");

        // First mapping covers blocks 95..100 from extent 0
        assert_eq!(mappings[0].logical_start, 95);
        assert_eq!(mappings[0].count, 5);

        // Second mapping covers blocks 100..105 from extent 1
        assert_eq!(mappings[1].logical_start, 100);
        assert_eq!(mappings[1].count, 5);
    }

    #[test]
    fn resolve_hole_returns_zero_physical() {
        let cx = Cx::for_testing();
        let dev = mem_block_device(BLOCK_SIZE, 1);
        // Single extent at [0..10)
        let root = build_root(1, 10);

        // Block 20 is beyond the extent → hole
        let mappings =
            ffs_extent::map_logical_to_physical(&cx, &dev, &root, 20, 1).expect("resolve hole");
        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings[0].physical_start, 0,
            "hole should have physical_start=0"
        );
    }

    #[test]
    fn resolve_empty_range_returns_empty() {
        let cx = Cx::for_testing();
        let dev = mem_block_device(BLOCK_SIZE, 1);
        let root = build_root(1, 100);

        let mappings =
            ffs_extent::map_logical_to_physical(&cx, &dev, &root, 0, 0).expect("empty range");
        assert_eq!(mappings, [] as [ffs_extent::ExtentMapping; 0]);
    }

    #[test]
    fn resolve_full_extent_coverage() {
        let cx = Cx::for_testing();
        let dev = mem_block_device(BLOCK_SIZE, 1);
        // 4 extents, each 25 blocks
        let root = build_root(4, 25);

        let mappings =
            ffs_extent::map_logical_to_physical(&cx, &dev, &root, 0, 100).expect("resolve all");

        // Should cover all 100 blocks
        let total: u32 = mappings.iter().map(|m| m.count).sum();
        assert_eq!(total, 100);
    }
}

// ── Suite 5: Native repair crash cuts A–D, 1%/5% healing & negative controls (bd-11a8t / bd-j7a4e) ──

mod native_repair_crash_cuts_and_healing {
    use asupersync::Cx;
    use ffs_block::ByteDevice;
    use ffs_core::native_repair::NativeRepairStorage;
    use ffs_core::{Ext4JournalReplayMode, OpenFs, OpenOptions, VolumeAccess};
    use ffs_error::FfsError;
    use ffs_types::{BTRFS_SUPER_INFO_OFFSET, BlockNumber, ByteOffset, InodeNumber, MountMode};
    use parking_lot::Mutex;
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::Command;
    use std::sync::Arc;

    const WORKING_BUDGET: u64 = 512 * 1024 * 1024;
    const PLAN_HEADER_START: usize = 192;
    const PARITY_HEADER_START: usize = 320;
    const EPOCH_TOKEN_START: usize = 448;
    const EPOCH_TOKEN_LEN: usize = 160;
    const VALIDATION_PENDING: u32 = 1;
    const VALIDATION_SEALED: u32 = 2;
    const PLAN_DIRTY: u32 = 4;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum CrashCut {
        CutA,
        CutBExt4,
        CutBBtrfs { pre_btrfs_gen: u64 },
        CutC { pre_gens: Vec<u64> },
        CutD { pre_gens: Vec<u64> },
    }

    struct FaultState {
        bytes: Vec<u8>,
        block_size: usize,
        tail_starts: Vec<u64>,
        cut: Option<CrashCut>,
        fail_next_write: bool,
        triggered: bool,
        dirty_writes_after_token: usize,
        dirty_syncs_seen: usize,
    }

    #[derive(Clone)]
    struct FaultInjectingMemDevice {
        state: Arc<Mutex<FaultState>>,
    }

    impl FaultInjectingMemDevice {
        fn new(bytes: Vec<u8>, block_size: u32, storage: &NativeRepairStorage) -> Self {
            let tail_starts = storage.tails.iter().map(|t| t.start.0).collect();
            Self {
                state: Arc::new(Mutex::new(FaultState {
                    bytes,
                    block_size: block_size as usize,
                    tail_starts,
                    cut: None,
                    fail_next_write: false,
                    triggered: false,
                    dirty_writes_after_token: 0,
                    dirty_syncs_seen: 0,
                })),
            }
        }

        fn snapshot(&self) -> Vec<u8> {
            self.state.lock().bytes.clone()
        }

        fn corrupt_block_byte(&self, block: u64, byte_in_block: usize, xor_mask: u8) {
            let mut guard = self.state.lock();
            let off = (block as usize) * guard.block_size + byte_in_block;
            guard.bytes[off] ^= xor_mask;
        }

        fn arm_cut(&self, cut: CrashCut) {
            let mut guard = self.state.lock();
            guard.cut = Some(cut);
            guard.fail_next_write = false;
            guard.triggered = false;
            guard.dirty_writes_after_token = 0;
            guard.dirty_syncs_seen = 0;
        }

        fn disarm(&self) -> bool {
            let mut guard = self.state.lock();
            let triggered = guard.triggered;
            guard.cut = None;
            guard.fail_next_write = false;
            triggered
        }
    }

    fn inspect_plan_and_groups(state: &FaultState) -> (u32, bool, [u8; 64], Vec<(u32, u64)>) {
        let bs = state.block_size;
        let o0 = (state.tail_starts[0] as usize) * bs;
        let plan_state = u32::from_le_bytes(
            state.bytes[o0 + PLAN_HEADER_START + 96..o0 + PLAN_HEADER_START + 100]
                .try_into()
                .unwrap(),
        );
        let has_token =
            &state.bytes[o0 + EPOCH_TOKEN_START..o0 + EPOCH_TOKEN_START + 8] == b"FFSEPK02";
        let buckets: [u8; 64] = state.bytes
            [o0 + EPOCH_TOKEN_START + 88..o0 + EPOCH_TOKEN_START + 152]
            .try_into()
            .unwrap();
        let mut groups = Vec::with_capacity(state.tail_starts.len());
        for &tail_start in &state.tail_starts {
            let off = (tail_start as usize) * bs;
            let par_state = u32::from_le_bytes(
                state.bytes[off + PARITY_HEADER_START + 112..off + PARITY_HEADER_START + 116]
                    .try_into()
                    .unwrap(),
            );
            let par_gen = u64::from_le_bytes(
                state.bytes[off + PARITY_HEADER_START + 40..off + PARITY_HEADER_START + 48]
                    .try_into()
                    .unwrap(),
            );
            groups.push((par_state, par_gen));
        }
        (plan_state, has_token, buckets, groups)
    }

    fn token_marks_group_dirty(buckets: &[u8; 64], group_idx: usize) -> bool {
        let bucket = group_idx & 511;
        (buckets[bucket / 8] & (1_u8 << (bucket % 8))) != 0
    }

    fn read_btrfs_generation(bytes: &[u8]) -> u64 {
        let off = BTRFS_SUPER_INFO_OFFSET + 0x48;
        u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
    }

    impl ByteDevice for FaultInjectingMemDevice {
        fn len_bytes(&self) -> u64 {
            self.state.lock().bytes.len() as u64
        }

        fn read_exact_at(
            &self,
            _cx: &Cx,
            offset: ByteOffset,
            buf: &mut [u8],
        ) -> Result<(), FfsError> {
            let guard = self.state.lock();
            let start = usize::try_from(offset.0).unwrap();
            let end = start.checked_add(buf.len()).unwrap();
            buf.copy_from_slice(&guard.bytes[start..end]);
            Ok(())
        }

        fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<(), FfsError> {
            let mut guard = self.state.lock();
            if guard.fail_next_write {
                guard.fail_next_write = false;
                guard.cut = None;
                guard.triggered = true;
                return Err(FfsError::Io(std::io::Error::other(
                    "injected crash-cut power loss before next write",
                )));
            }
            let (plan_state, has_token, ..) = inspect_plan_and_groups(&guard);
            if matches!(guard.cut, Some(CrashCut::CutA))
                && plan_state == PLAN_DIRTY
                && has_token
                && guard.dirty_syncs_seen >= 1
            {
                let start = usize::try_from(offset.0).unwrap();
                let end = start.checked_add(buf.len()).unwrap();
                guard.bytes[start..end].copy_from_slice(buf);
                guard.dirty_writes_after_token += 1;
                if guard.dirty_writes_after_token >= 1 {
                    // One uncommitted journal/COW write landed after PLAN_DIRTY; cut power now
                    // before JBD2 commit block or Btrfs superblock can be written!
                    guard.fail_next_write = true;
                }
                return Ok(());
            }
            let start = usize::try_from(offset.0).unwrap();
            let end = start.checked_add(buf.len()).unwrap();
            guard.bytes[start..end].copy_from_slice(buf);
            Ok(())
        }

        fn sync(&self, _cx: &Cx) -> Result<(), FfsError> {
            let mut guard = self.state.lock();
            if guard.fail_next_write {
                guard.fail_next_write = false;
                guard.cut = None;
                guard.triggered = true;
                return Err(FfsError::Io(std::io::Error::other(
                    "injected crash-cut power loss on sync",
                )));
            }
            let Some(cut) = guard.cut.clone() else {
                return Ok(());
            };
            let (plan_state, has_token, buckets, groups) = inspect_plan_and_groups(&guard);
            match cut {
                CrashCut::CutA => {
                    if plan_state == PLAN_DIRTY && has_token {
                        guard.dirty_syncs_seen += 1;
                    }
                }
                CrashCut::CutBExt4 => {
                    if plan_state == PLAN_DIRTY && has_token {
                        guard.dirty_syncs_seen += 1;
                        if guard.dirty_syncs_seen == 3 {
                            // Sync #1: PLAN_DIRTY; Sync #2: JBD2 body barrier before commit block;
                            // Sync #3: JBD2 Phase 1b commit-record sync! Fail before home checkpoint!
                            guard.fail_next_write = true;
                        }
                    }
                }
                CrashCut::CutBBtrfs { pre_btrfs_gen } => {
                    if plan_state == PLAN_DIRTY
                        && has_token
                        && read_btrfs_generation(&guard.bytes) > pre_btrfs_gen
                    {
                        guard.fail_next_write = true;
                    }
                }
                CrashCut::CutC { pre_gens } => {
                    if plan_state == VALIDATION_PENDING && has_token {
                        let mut sealed_dirty = 0_usize;
                        let mut unsealed_dirty = 0_usize;
                        for (idx, &(pstate, pgen)) in groups.iter().enumerate() {
                            if token_marks_group_dirty(&buckets, idx) {
                                if pstate == VALIDATION_SEALED && pgen > pre_gens[idx] {
                                    sealed_dirty += 1;
                                } else {
                                    unsealed_dirty += 1;
                                }
                            }
                        }
                        if sealed_dirty >= 1 && unsealed_dirty >= 1 {
                            guard.fail_next_write = true;
                        }
                    }
                }
                CrashCut::CutD { pre_gens } => {
                    if plan_state == VALIDATION_PENDING && has_token {
                        let mut dirty_total = 0_usize;
                        let mut all_dirty_sealed = true;
                        for (idx, &(pstate, pgen)) in groups.iter().enumerate() {
                            if token_marks_group_dirty(&buckets, idx) {
                                dirty_total += 1;
                                if pstate != VALIDATION_SEALED || pgen <= pre_gens[idx] {
                                    all_dirty_sealed = false;
                                }
                            }
                        }
                        if dirty_total >= 1 && all_dirty_sealed {
                            guard.fail_next_write = true;
                        }
                    }
                }
            }
            Ok(())
        }
    }

    fn require_oracles() -> bool {
        std::env::var_os("FFS_REQUIRE_ORACLES").is_some_and(|v| v == "1")
    }

    fn tool_available(tool: &str) -> bool {
        Command::new("sh")
            .args(["-c", &format!("command -v {tool} >/dev/null 2>&1")])
            .status()
            .is_ok_and(|s| s.success())
    }

    fn native_prep_options() -> OpenOptions {
        OpenOptions {
            mount_mode: MountMode::Native,
            ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
            ..OpenOptions::default()
        }
    }

    fn native_active_options(ephemeral_btrfs: bool) -> OpenOptions {
        OpenOptions {
            mount_mode: MountMode::Native,
            ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
            native_repair_max_working_bytes: Some(WORKING_BUDGET),
            btrfs_rw_ephemeral_ok: ephemeral_btrfs,
            ..OpenOptions::default()
        }
    }

    fn deterministic_payload(seed: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0_u8; len];
        let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
        for chunk in out.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let bytes = state.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        out
    }

    fn run_external_e2fsck(dir: &Path, label: &str, bytes: &[u8]) {
        let path = dir.join(format!("{label}.ext4"));
        std::fs::write(&path, bytes).expect("write ext4 image for e2fsck");
        let output = Command::new("e2fsck")
            .args(["-fn", path.to_str().unwrap()])
            .output()
            .expect("execute e2fsck -fn");
        assert!(
            output.status.success(),
            "e2fsck -fn failed on {label}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn run_external_btrfs_check(dir: &Path, label: &str, bytes: &[u8]) {
        let path = dir.join(format!("{label}.btrfs"));
        std::fs::write(&path, bytes).expect("write btrfs image for btrfs check");
        let output = Command::new("btrfs")
            .args(["check", "--readonly", path.to_str().unwrap()])
            .output()
            .expect("execute btrfs check --readonly");
        assert!(
            output.status.success(),
            "btrfs check --readonly failed on {label}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn verify_1pct_and_5pct_healing(
        cx: &Cx,
        fs: &OpenFs,
        dev: &FaultInjectingMemDevice,
        storage: &NativeRepairStorage,
        root_dir: InodeNumber,
        expected_files: &[(&str, &[u8], [u8; 32])],
    ) {
        let clean_snapshot = dev.snapshot();
        let clean_image_digest = *blake3::hash(&clean_snapshot).as_bytes();
        let tail0 = &storage.tails[0];
        let source_count = if tail0.is_detached() {
            tail0.blocks_per_group as usize
        } else {
            (tail0.start.0 - tail0.group_start.0) as usize
        };
        let repair_blocks = tail0.repair_blocks as usize;
        let count_1pct = source_count.div_ceil(100).max(1).min(repair_blocks);
        let count_5pct = ((source_count * 5) / 100).max(2).min(repair_blocks);

        // 1% corruption pass: corrupt deterministic spread across Group 0 source blocks.
        let stride_1 = (source_count / count_1pct).max(1);
        for i in 0..count_1pct {
            let blk = tail0.group_start.0 + ((i * stride_1 + 3) % source_count) as u64;
            dev.corrupt_block_byte(blk, (i * 37) % 512, 0x5A);
        }
        assert_ne!(
            *blake3::hash(&dev.snapshot()).as_bytes(),
            clean_image_digest
        );
        let heal_1 = fs.scrub_and_heal_native(cx).expect("1% scrub and heal");
        assert_eq!(heal_1.corrupted_blocks_detected, count_1pct as u64);
        assert_eq!(heal_1.blocks_healed, count_1pct as u64);
        assert_eq!(
            *blake3::hash(&dev.snapshot()).as_bytes(),
            clean_image_digest,
            "1% native heal must restore byte-identical image"
        );

        // 5% corruption pass: corrupt 5% of Group 0 source blocks and verify Ville/Wald escalation.
        let stride_5 = (source_count / count_5pct).max(1);
        for i in 0..count_5pct {
            let blk = tail0.group_start.0 + ((i * stride_5 + 7) % source_count) as u64;
            dev.corrupt_block_byte(blk, (i * 53) % 512, 0xA5);
        }
        let heal_5 = fs.scrub_and_heal_native(cx).expect("5% scrub and heal");
        assert_eq!(heal_5.corrupted_blocks_detected, count_5pct as u64);
        assert_eq!(heal_5.blocks_healed, count_5pct as u64);
        assert!(
            heal_5.monitor.null_rejected,
            "5% corruption must reject healthy-media null in Ville/Wald e-process: {:?}",
            heal_5.monitor
        );
        assert!(
            heal_5.recommended_interval_divisor > 1,
            "Ville/Wald rejection must escalate scrub cadence divisor: {heal_5:?}"
        );
        assert_eq!(
            *blake3::hash(&dev.snapshot()).as_bytes(),
            clean_image_digest,
            "5% native heal must restore byte-identical image"
        );

        // Verify acknowledged files against independent BLAKE3 digests.
        for &(name, expected_bytes, expected_hash) in expected_files {
            let attr = fs
                .lookup(cx, root_dir, OsStr::new(name))
                .unwrap_or_else(|e| panic!("lookup {name}: {e}"));
            assert_eq!(attr.size, expected_bytes.len() as u64);
            let actual = fs
                .read(cx, attr.ino, 0, expected_bytes.len() as u32 + 64)
                .unwrap_or_else(|e| panic!("read {name}: {e}"));
            assert_eq!(*blake3::hash(&actual).as_bytes(), expected_hash);
            assert_eq!(actual.as_slice(), expected_bytes);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn run_native_ext4_crash_cuts_subset(select_c_and_d: bool) {
        let mke2fs = format!("mk{}", "e2fs");
        if !tool_available(&mke2fs) || !tool_available("e2fsck") {
            assert!(
                !require_oracles(),
                "FFS_REQUIRE_ORACLES=1 but mke2fs/e2fsck are missing"
            );
            eprintln!("SKIP|suite=native_ext4_crash_cuts|reason=e2fsprogs_unavailable");
            return;
        }

        let tmp = tempfile::tempdir().expect("tempdir");
        let base_img = tmp.path().join("seed.ext4");
        std::fs::File::create(&base_img)
            .and_then(|f| f.set_len(2560 * 1024))
            .expect("size seed.ext4");
        let status = Command::new(&mke2fs)
            .args([
                "-q",
                "-F",
                "-t",
                "ext4",
                "-O",
                "extent,metadata_csum,has_journal,^fast_commit,^flex_bg",
                "-b",
                "1024",
                "-g",
                "1280",
                "-J",
                "size=1",
                "-N",
                "128",
                base_img.to_str().unwrap(),
            ])
            .status()
            .expect("run mke2fs");
        assert!(status.success(), "mke2fs failed");

        let cx = Cx::for_testing();
        let v1_bytes = deterministic_payload(0x11A8_0001, 12 * 1024);
        let v1_hash = *blake3::hash(&v1_bytes).as_bytes();
        // Compact 16 KiB payload stays well below JBD2 pressure commit threshold (~512 blocks)
        // so all writes remain exclusively in MVCC until explicit fsync!
        let v2_bytes = deterministic_payload(0x11A8_0002, 16 * 1024);
        let v2_hash = *blake3::hash(&v2_bytes).as_bytes();

        // Seed v1.bin cleanly before native preparation.
        {
            let mut fs = OpenFs::open_read_write(
                &cx,
                &base_img,
                &OpenOptions {
                    ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
                    ..OpenOptions::default()
                },
            )
            .expect("open seed.ext4 rw");
            fs.attach_ext4_internal_jbd2_writer(&cx)
                .expect("attach jbd2");
            fs.enable_writes(&cx).expect("enable writes");
            let created = fs
                .create(&cx, InodeNumber(2), OsStr::new("v1.bin"), 0o644, 0, 0)
                .expect("create v1.bin");
            fs.write(&cx, created.ino, 0, &v1_bytes)
                .expect("write v1.bin");
            fs.fsync(&cx, created.ino, 0, false).expect("fsync v1.bin");
        }

        let raw_seed = std::fs::read(&base_img).expect("read seed.ext4");
        let dummy_storage = NativeRepairStorage {
            owner_inode: InodeNumber(12),
            repair_basis_points: 500,
            tails: vec![ffs_core::native_repair::NativeRepairTail {
                group: ffs_types::GroupNumber(0),
                group_start: BlockNumber(1),
                blocks_per_group: 2048,
                start: BlockNumber(1),
                validation_blocks: 1,
                repair_blocks: 1,
            }],
        };
        let prep_dev = FaultInjectingMemDevice::new(raw_seed, 1024, &dummy_storage);
        let storage = OpenFs::from_devices(
            &cx,
            Box::new(prep_dev.clone()),
            &native_prep_options(),
            VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .expect("open for prepare")
        .prepare_native_repair(&cx, 500)
        .expect("prepare_native_repair ext4");
        assert_eq!(storage.tails.len(), 2, "must span 2 ext4 block groups");

        let baseline_dev = FaultInjectingMemDevice::new(prep_dev.snapshot(), 1024, &storage);
        let val_report = OpenFs::from_devices(
            &cx,
            Box::new(baseline_dev.clone()),
            &native_prep_options(),
            VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .expect("open for validate")
        .initialize_native_validation(&cx)
        .expect("initialize_native_validation ext4");
        let rep_report = OpenFs::from_devices(
            &cx,
            Box::new(baseline_dev.clone()),
            &native_prep_options(),
            VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .expect("open for encode")
        .initialize_native_repair(&cx, WORKING_BUDGET)
        .expect("initialize_native_repair ext4");
        eprintln!(
            "NATIVE_REPAIR_EVIDENCE|fs=ext4|phase=baseline|groups={}|source_blocks={}|repair_blocks={}|overhead_bps={}",
            rep_report.groups,
            rep_report.source_blocks,
            rep_report.repair_blocks,
            storage.repair_basis_points
        );
        assert_eq!(val_report.groups, 2);
        let sealed_baseline_bytes = baseline_dev.snapshot();
        run_external_e2fsck(tmp.path(), "ext4-baseline", &sealed_baseline_bytes);

        let cuts: Vec<(&str, CrashCut, bool)> = if select_c_and_d {
            vec![
                (
                    "cut_c",
                    CrashCut::CutC {
                        pre_gens: rep_report.generations.clone(),
                    },
                    true,
                ),
                (
                    "cut_d",
                    CrashCut::CutD {
                        pre_gens: rep_report.generations,
                    },
                    true,
                ),
            ]
        } else {
            vec![
                (
                    "cut_a",
                    CrashCut::CutA,
                    false, // v2 NOT yet committed in JBD2
                ),
                (
                    "cut_b",
                    CrashCut::CutBExt4,
                    true, // v2 IS committed in JBD2 before Pending plan
                ),
            ]
        };

        for (cut_name, cut, v2_expected) in cuts {
            let cut_dev =
                FaultInjectingMemDevice::new(sealed_baseline_bytes.clone(), 1024, &storage);
            {
                let mut fs = OpenFs::from_devices(
                    &cx,
                    Box::new(cut_dev.clone()),
                    &native_active_options(false),
                    VolumeAccess::ReadWrite,
                    None,
                    Vec::new(),
                )
                .expect("open active ext4");
                assert!(fs.attach_ext4_internal_jbd2_writer(&cx).unwrap());
                fs.enable_writes(&cx).expect("enable writes");

                // Arm BEFORE staging so we also prove zero premature physical flush before fsync!
                cut_dev.arm_cut(cut.clone());

                let created = fs
                    .create(&cx, InodeNumber(2), OsStr::new("v2.bin"), 0o644, 0, 0)
                    .expect("create v2.bin");
                fs.write(&cx, created.ino, 0, &v2_bytes)
                    .expect("stage v2.bin");
                // Orlov spreads top-level directories across both Group 0 and Group 1 in < 20 MVCC blocks.
                for idx in 0..3_u32 {
                    let sub = fs
                        .mkdir(
                            &cx,
                            InodeNumber(2),
                            OsStr::new(&format!("sub_{idx}")),
                            0o755,
                            0,
                            0,
                        )
                        .expect("mkdir sub");
                    let child = fs
                        .create(&cx, sub.ino, OsStr::new("leaf.bin"), 0o644, 0, 0)
                        .expect("create leaf");
                    fs.write(&cx, child.ino, 0, &[0x5B; 1024])
                        .expect("write leaf");
                }

                let sync_err = fs
                    .fsync(&cx, created.ino, 0, false)
                    .expect_err("armed crash cut must interrupt fsync");
                eprintln!("NATIVE_REPAIR_EVIDENCE|fs=ext4|cut={cut_name}|sync_err={sync_err}");
            }
            assert!(
                cut_dev.disarm(),
                "ext4 {cut_name} fault rule must have fired"
            );
            {
                let guard = cut_dev.state.lock();
                let (plan_state, has_token, buckets, groups) = inspect_plan_and_groups(&guard);
                assert!(
                    has_token,
                    "ext4 {cut_name} must leave FFSEPK02 epoch token on disk"
                );
                match &cut {
                    CrashCut::CutA | CrashCut::CutBExt4 => {
                        assert_eq!(plan_state, PLAN_DIRTY, "ext4 {cut_name} plan_state");
                    }
                    CrashCut::CutC { pre_gens } => {
                        assert_eq!(plan_state, VALIDATION_PENDING);
                        let sealed_cnt = groups
                            .iter()
                            .enumerate()
                            .filter(|&(i, &(st, g))| {
                                token_marks_group_dirty(&buckets, i)
                                    && st == VALIDATION_SEALED
                                    && g > pre_gens[i]
                            })
                            .count();
                        let unsealed_cnt = groups
                            .iter()
                            .enumerate()
                            .filter(|&(i, &(_, g))| {
                                token_marks_group_dirty(&buckets, i) && g == pre_gens[i]
                            })
                            .count();
                        assert!(sealed_cnt >= 1 && unsealed_cnt >= 1);
                    }
                    CrashCut::CutD { pre_gens } => {
                        assert_eq!(plan_state, VALIDATION_PENDING);
                        assert!(groups.iter().enumerate().all(|(i, &(st, g))| {
                            !token_marks_group_dirty(&buckets, i)
                                || (st == VALIDATION_SEALED && g > pre_gens[i])
                        }));
                    }
                    CrashCut::CutBBtrfs { .. } => unreachable!(),
                }
            }

            // Cold reopen: must automatically replay JBD2 (if committed), reconcile FFSEPK02,
            // clear FFSEPK02, and re-seal VALIDATION_SEALED without manual re-initialization!
            let mut reopened = OpenFs::from_devices(
                &cx,
                Box::new(cut_dev.clone()),
                &native_active_options(false),
                VolumeAccess::ReadWrite,
                None,
                Vec::new(),
            )
            .unwrap_or_else(|e| panic!("cold reopen after ext4 {cut_name} failed: {e}"));
            assert!(reopened.attach_ext4_internal_jbd2_writer(&cx).unwrap());
            reopened
                .enable_writes(&cx)
                .expect("enable writes after cold reopen");
            let post_report = reopened
                .check_native_repair(&cx)
                .expect("post-reopen native repair check");
            assert_eq!(post_report.groups, 2);
            {
                let guard = cut_dev.state.lock();
                let o0 = (storage.tails[0].start.0 as usize) * 1024;
                assert!(
                    guard.bytes[o0 + EPOCH_TOKEN_START..o0 + EPOCH_TOKEN_START + EPOCH_TOKEN_LEN]
                        .iter()
                        .all(|&b| b == 0),
                    "ext4 {cut_name}: FFSEPK02 token must be retired after reconciliation"
                );
            }

            if v2_expected {
                verify_1pct_and_5pct_healing(
                    &cx,
                    &reopened,
                    &cut_dev,
                    &storage,
                    InodeNumber(2),
                    &[
                        ("v1.bin", v1_bytes.as_slice(), v1_hash),
                        ("v2.bin", v2_bytes.as_slice(), v2_hash),
                    ],
                );
            } else {
                assert!(
                    matches!(
                        reopened.lookup(&cx, InodeNumber(2), OsStr::new("v2.bin")),
                        Err(FfsError::NotFound(_))
                    ),
                    "Cut A uncommitted v2.bin must not appear after crash rollback"
                );
                verify_1pct_and_5pct_healing(
                    &cx,
                    &reopened,
                    &cut_dev,
                    &storage,
                    InodeNumber(2),
                    &[("v1.bin", v1_bytes.as_slice(), v1_hash)],
                );
            }
            drop(reopened);
            run_external_e2fsck(tmp.path(), &format!("ext4-{cut_name}"), &cut_dev.snapshot());
        }
    }

    #[test]
    fn native_ext4_crash_cuts_a_and_b_corruption_1pct_5pct_and_e2fsck_bd_11a8t_bd_j7a4e() {
        run_native_ext4_crash_cuts_subset(false);
    }

    #[test]
    fn native_ext4_crash_cuts_c_and_d_corruption_1pct_5pct_and_e2fsck_bd_11a8t_bd_j7a4e() {
        run_native_ext4_crash_cuts_subset(true);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn native_btrfs_crash_cuts_a_b_c_d_treelog_corruption_1pct_5pct_and_btrfs_check_bd_11a8t_bd_j7a4e()
     {
        let mkfs_btrfs = format!("mk{}.btrfs", "fs");
        if !tool_available(&mkfs_btrfs) || !tool_available("btrfs") {
            assert!(
                !require_oracles(),
                "FFS_REQUIRE_ORACLES=1 but btrfs-progs are missing"
            );
            eprintln!("SKIP|suite=native_btrfs_crash_cuts|reason=btrfs_progs_unavailable");
            return;
        }

        let tmp = tempfile::tempdir().expect("tempdir");
        let base_img = tmp.path().join("seed.btrfs");
        std::fs::File::create(&base_img)
            .and_then(|f| f.set_len(16 * 1024 * 1024))
            .expect("size seed.btrfs");
        let status = Command::new(&mkfs_btrfs)
            .args([
                "-f",
                "-q",
                "-M",
                "-d",
                "single",
                "-m",
                "single",
                base_img.to_str().unwrap(),
            ])
            .status()
            .expect("run mkfs.btrfs");
        assert!(status.success(), "mkfs.btrfs -M failed");

        let cx = Cx::for_testing();
        let root_dir = InodeNumber(256);
        let v1_bytes = deterministic_payload(0xB7F5_0001, 16 * 1024);
        let v1_hash = *blake3::hash(&v1_bytes).as_bytes();
        // Compact 64 KiB payload: superblock is in Group 0 and new COW extents allocate in Group 1+,
        // dirtying >= 2 groups per commit without large debug-mode buffers!
        let v2_bytes = deterministic_payload(0xB7F5_0002, 64 * 1024);
        let v2_hash = *blake3::hash(&v2_bytes).as_bytes();

        // Seed v1.bin cleanly before native preparation.
        {
            let mut fs = OpenFs::open_read_write(&cx, &base_img, &OpenOptions::default())
                .expect("open seed.btrfs rw");
            fs.enable_writes(&cx).expect("enable writes");
            let created = fs
                .create(&cx, root_dir, OsStr::new("v1.bin"), 0o644, 0, 0)
                .expect("create v1.bin");
            fs.write(&cx, created.ino, 0, &v1_bytes)
                .expect("write v1.bin");
            fs.fsync(&cx, created.ino, 0, false).expect("fsync v1.bin");
        }

        let raw_seed = std::fs::read(&base_img).expect("read seed.btrfs");
        let dummy_storage = NativeRepairStorage {
            owner_inode: InodeNumber(257),
            repair_basis_points: 500,
            tails: vec![ffs_core::native_repair::NativeRepairTail {
                group: ffs_types::GroupNumber(0),
                group_start: BlockNumber(16),
                blocks_per_group: 2048,
                start: BlockNumber(16),
                validation_blocks: 1,
                repair_blocks: 1,
            }],
        };
        let prep_dev = FaultInjectingMemDevice::new(raw_seed, 4096, &dummy_storage);
        let storage = OpenFs::from_devices(
            &cx,
            Box::new(prep_dev.clone()),
            &native_prep_options(),
            VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .expect("open btrfs for prepare")
        .prepare_native_repair(&cx, 500)
        .expect("prepare_native_repair btrfs");
        assert!(
            storage.tails.len() >= 2,
            "16 MiB btrfs image must partition into >= 2 native groups, got {}",
            storage.tails.len()
        );
        run_external_btrfs_check(tmp.path(), "btrfs-prepared", &prep_dev.snapshot());

        let baseline_dev = FaultInjectingMemDevice::new(prep_dev.snapshot(), 4096, &storage);
        OpenFs::from_devices(
            &cx,
            Box::new(baseline_dev.clone()),
            &native_prep_options(),
            VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .expect("open btrfs for validate")
        .initialize_native_validation(&cx)
        .expect("initialize_native_validation btrfs");
        let rep_report = OpenFs::from_devices(
            &cx,
            Box::new(baseline_dev.clone()),
            &native_prep_options(),
            VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .expect("open btrfs for encode")
        .initialize_native_repair(&cx, WORKING_BUDGET)
        .expect("initialize_native_repair btrfs");
        let sealed_baseline_bytes = baseline_dev.snapshot();
        let baseline_btrfs_gen = read_btrfs_generation(&sealed_baseline_bytes);
        eprintln!(
            "NATIVE_REPAIR_EVIDENCE|fs=btrfs|phase=baseline|groups={}|source_blocks={}|repair_blocks={}|overhead_bps={}|btrfs_gen={}",
            rep_report.groups,
            rep_report.source_blocks,
            rep_report.repair_blocks,
            storage.repair_basis_points,
            baseline_btrfs_gen
        );
        run_external_btrfs_check(tmp.path(), "btrfs-encoded", &sealed_baseline_bytes);

        // Verify ephemeral tree-log fsync + native freshness seal + cold reopen + healing!
        {
            let log_dev =
                FaultInjectingMemDevice::new(sealed_baseline_bytes.clone(), 4096, &storage);
            let log_bytes = deterministic_payload(0xB7F5_E94E, 8192);
            let log_hash = *blake3::hash(&log_bytes).as_bytes();
            {
                let mut fs = OpenFs::from_devices(
                    &cx,
                    Box::new(log_dev.clone()),
                    &native_active_options(true),
                    VolumeAccess::ReadWrite,
                    None,
                    Vec::new(),
                )
                .expect("open ephemeral native btrfs");
                fs.enable_writes(&cx).expect("enable writes");
                let created = fs
                    .create(&cx, root_dir, OsStr::new("logged.bin"), 0o644, 0, 0)
                    .expect("create logged.bin");
                fs.write(&cx, created.ino, 0, &log_bytes)
                    .expect("write logged.bin");
                fs.fsync(&cx, created.ino, 0, false)
                    .expect("tree-log fsync with native freshness");
            }
            let reopened = OpenFs::from_devices(
                &cx,
                Box::new(log_dev.clone()),
                &native_active_options(true),
                VolumeAccess::ReadWrite,
                None,
                Vec::new(),
            )
            .expect("reopen ephemeral native btrfs");
            verify_1pct_and_5pct_healing(
                &cx,
                &reopened,
                &log_dev,
                &storage,
                root_dir,
                &[
                    ("v1.bin", v1_bytes.as_slice(), v1_hash),
                    ("logged.bin", log_bytes.as_slice(), log_hash),
                ],
            );
            drop(reopened);
            run_external_btrfs_check(tmp.path(), "btrfs-treelog-healed", &log_dev.snapshot());
        }

        // Exercise Cuts A, B, C, and D across full Btrfs COW commits.
        let cuts = [
            ("cut_a", CrashCut::CutA, false),
            (
                "cut_b",
                CrashCut::CutBBtrfs {
                    pre_btrfs_gen: baseline_btrfs_gen,
                },
                true,
            ),
            (
                "cut_c",
                CrashCut::CutC {
                    pre_gens: rep_report.generations.clone(),
                },
                true,
            ),
            (
                "cut_d",
                CrashCut::CutD {
                    pre_gens: rep_report.generations,
                },
                true,
            ),
        ];

        for (cut_name, cut, v2_expected) in cuts {
            let cut_dev =
                FaultInjectingMemDevice::new(sealed_baseline_bytes.clone(), 4096, &storage);
            {
                let mut fs = OpenFs::from_devices(
                    &cx,
                    Box::new(cut_dev.clone()),
                    &native_active_options(false),
                    VolumeAccess::ReadWrite,
                    None,
                    Vec::new(),
                )
                .expect("open active btrfs");
                fs.enable_writes(&cx).expect("enable writes");
                cut_dev.arm_cut(cut.clone());
                let created = fs
                    .create(&cx, root_dir, OsStr::new("v2.bin"), 0o644, 0, 0)
                    .expect("create v2.bin");
                fs.write(&cx, created.ino, 0, &v2_bytes)
                    .expect("stage btrfs v2.bin");
                let sync_err = fs
                    .fsync(&cx, created.ino, 0, false)
                    .expect_err("armed btrfs crash cut must interrupt fsync");
                eprintln!("NATIVE_REPAIR_EVIDENCE|fs=btrfs|cut={cut_name}|sync_err={sync_err}");
            }
            assert!(
                cut_dev.disarm(),
                "btrfs {cut_name} fault rule must have fired"
            );

            let mut reopened = OpenFs::from_devices(
                &cx,
                Box::new(cut_dev.clone()),
                &native_active_options(false),
                VolumeAccess::ReadWrite,
                None,
                Vec::new(),
            )
            .unwrap_or_else(|e| panic!("cold reopen after btrfs {cut_name} failed: {e}"));
            reopened
                .enable_writes(&cx)
                .expect("enable writes after btrfs cold reopen");
            reopened
                .check_native_repair(&cx)
                .expect("post-reopen btrfs native repair check");

            if v2_expected {
                verify_1pct_and_5pct_healing(
                    &cx,
                    &reopened,
                    &cut_dev,
                    &storage,
                    root_dir,
                    &[
                        ("v1.bin", v1_bytes.as_slice(), v1_hash),
                        ("v2.bin", v2_bytes.as_slice(), v2_hash),
                    ],
                );
            } else {
                assert!(
                    matches!(
                        reopened.lookup(&cx, root_dir, OsStr::new("v2.bin")),
                        Err(FfsError::NotFound(_))
                    ),
                    "Btrfs Cut A unreferenced COW blocks must not expose v2.bin"
                );
                verify_1pct_and_5pct_healing(
                    &cx,
                    &reopened,
                    &cut_dev,
                    &storage,
                    root_dir,
                    &[("v1.bin", v1_bytes.as_slice(), v1_hash)],
                );
            }
            drop(reopened);
            run_external_btrfs_check(
                tmp.path(),
                &format!("btrfs-{cut_name}"),
                &cut_dev.snapshot(),
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn native_repair_negative_controls_exhausted_tampered_stale_missing_and_cancelled_bd_j7a4e() {
        let mke2fs = format!("mk{}", "e2fs");
        if !tool_available(&mke2fs) {
            assert!(
                !require_oracles(),
                "FFS_REQUIRE_ORACLES=1 but mke2fs is missing"
            );
            eprintln!("SKIP|suite=native_repair_negative_controls|reason=e2fsprogs_unavailable");
            return;
        }

        let tmp = tempfile::tempdir().expect("tempdir");
        let base_img = tmp.path().join("neg.ext4");
        std::fs::File::create(&base_img)
            .and_then(|f| f.set_len(2560 * 1024))
            .expect("size neg.ext4");
        let status = Command::new(&mke2fs)
            .args([
                "-q",
                "-F",
                "-t",
                "ext4",
                "-O",
                "extent,metadata_csum,has_journal,^fast_commit,^flex_bg",
                "-b",
                "1024",
                "-g",
                "1280",
                "-J",
                "size=1",
                "-N",
                "128",
                base_img.to_str().unwrap(),
            ])
            .status()
            .expect("run mke2fs");
        assert!(status.success());

        let cx = Cx::for_testing();
        let unreserved_bytes = std::fs::read(&base_img).expect("read neg.ext4");

        // Negative Control 1: Missing /.frankenfs-repair fails closed without mutating image.
        {
            let dummy = NativeRepairStorage {
                owner_inode: InodeNumber(12),
                repair_basis_points: 500,
                tails: vec![ffs_core::native_repair::NativeRepairTail {
                    group: ffs_types::GroupNumber(0),
                    group_start: BlockNumber(1),
                    blocks_per_group: 2048,
                    start: BlockNumber(1),
                    validation_blocks: 1,
                    repair_blocks: 1,
                }],
            };
            let dev = FaultInjectingMemDevice::new(unreserved_bytes.clone(), 1024, &dummy);
            let res = OpenFs::from_devices(
                &cx,
                Box::new(dev.clone()),
                &native_active_options(false),
                VolumeAccess::ReadWrite,
                None,
                Vec::new(),
            );
            assert!(
                res.is_err(),
                "missing /.frankenfs-repair must fail closed on native repair activation"
            );
            assert_eq!(dev.snapshot(), unreserved_bytes);
        }

        // Prepare + encode sealed baseline.
        let dummy = NativeRepairStorage {
            owner_inode: InodeNumber(12),
            repair_basis_points: 500,
            tails: vec![ffs_core::native_repair::NativeRepairTail {
                group: ffs_types::GroupNumber(0),
                group_start: BlockNumber(1),
                blocks_per_group: 2048,
                start: BlockNumber(1),
                validation_blocks: 1,
                repair_blocks: 1,
            }],
        };
        let prep_dev = FaultInjectingMemDevice::new(unreserved_bytes, 1024, &dummy);
        let storage = OpenFs::from_devices(
            &cx,
            Box::new(prep_dev.clone()),
            &native_prep_options(),
            VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .unwrap()
        .prepare_native_repair(&cx, 500)
        .unwrap();
        let sealed_dev = FaultInjectingMemDevice::new(prep_dev.snapshot(), 1024, &storage);
        OpenFs::from_devices(
            &cx,
            Box::new(sealed_dev.clone()),
            &native_prep_options(),
            VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .unwrap()
        .initialize_native_validation(&cx)
        .unwrap();
        OpenFs::from_devices(
            &cx,
            Box::new(sealed_dev.clone()),
            &native_prep_options(),
            VolumeAccess::ReadWrite,
            None,
            Vec::new(),
        )
        .unwrap()
        .initialize_native_repair(&cx, WORKING_BUDGET)
        .unwrap();
        let sealed_bytes = sealed_dev.snapshot();
        let tail0 = &storage.tails[0];
        let r = tail0.repair_blocks as usize;

        // Negative Control 2: Exhausted parity (corrupted = R + 1) returns RepairFailed and never overwrites damage.
        {
            let dev = FaultInjectingMemDevice::new(sealed_bytes.clone(), 1024, &storage);
            let fs = OpenFs::from_devices(
                &cx,
                Box::new(dev.clone()),
                &native_active_options(false),
                VolumeAccess::ReadWrite,
                None,
                Vec::new(),
            )
            .unwrap();
            for i in 0..=r {
                dev.corrupt_block_byte(tail0.group_start.0 + 20 + i as u64, 16, 0x7F);
            }
            let damaged_snapshot = dev.snapshot();
            let err = fs
                .scrub_and_heal_native(&cx)
                .expect_err("R + 1 corruptions must exceed parity budget");
            assert!(matches!(err, FfsError::RepairFailed(_)), "got {err:?}");
            assert_eq!(
                dev.snapshot(),
                damaged_snapshot,
                "exhausted parity must never overwrite damaged blocks"
            );
        }

        // Negative Control 3: Tampered parity symbol (R source corruptions + 1 corrupted parity symbol) rejected before writeback.
        {
            let dev = FaultInjectingMemDevice::new(sealed_bytes.clone(), 1024, &storage);
            let fs = OpenFs::from_devices(
                &cx,
                Box::new(dev.clone()),
                &native_active_options(false),
                VolumeAccess::ReadWrite,
                None,
                Vec::new(),
            )
            .unwrap();
            for i in 0..r {
                dev.corrupt_block_byte(tail0.group_start.0 + 30 + i as u64, 8, 0x33);
            }
            let first_symbol_block = tail0.start.0 + 1 + u64::from(tail0.validation_blocks);
            dev.corrupt_block_byte(first_symbol_block, 64, 0xFF);
            let damaged_snapshot = dev.snapshot();
            let err = fs
                .scrub_and_heal_native(&cx)
                .expect_err("tampered parity symbol with R source erasures must fail closed");
            assert!(
                matches!(err, FfsError::RepairFailed(_) | FfsError::Corruption { .. }),
                "got {err:?}"
            );
            assert_eq!(
                dev.snapshot(),
                damaged_snapshot,
                "tampered parity symbol must never write back unverified bytes"
            );
        }

        // Negative Control 4: Stale symbols under unsealed Dirty epoch never roll back newer bytes.
        {
            let dev = FaultInjectingMemDevice::new(sealed_bytes.clone(), 1024, &storage);
            let fs = OpenFs::from_devices(
                &cx,
                Box::new(dev.clone()),
                &native_active_options(false),
                VolumeAccess::ReadWrite,
                None,
                Vec::new(),
            )
            .unwrap();
            let fenced = fs.shared_fenced_device();
            let target_blk = tail0.group_start.0 + 50;
            let newer_bytes = [0xCC_u8; 1024];
            fenced
                .write_all_at(&cx, ByteOffset(target_blk * 1024), &newer_bytes)
                .expect("write newer unsealed block");
            // Corrupt a different block while the epoch is Dirty (unsealed): stale parity must be refused!
            dev.corrupt_block_byte(tail0.group_start.0 + 51, 0, 0x11);
            let mut buf = [0_u8; 1024];
            let err = fenced
                .read_exact_at(&cx, ByteOffset((tail0.group_start.0 + 51) * 1024), &mut buf)
                .expect_err("dirty epoch must refuse stale parity decode");
            assert!(matches!(err, FfsError::Corruption { .. }), "got {err:?}");
            // And target_blk still holds newer_bytes on disk, never rolled back!
            let snap = dev.snapshot();
            let off = (target_blk as usize) * 1024;
            assert_eq!(&snap[off..off + 1024], &newer_bytes);
        }

        // Negative Control 5: Cx cancellation aborts scrub/reconstruction cleanly without poisoning clean baseline.
        {
            let dev = FaultInjectingMemDevice::new(sealed_bytes.clone(), 1024, &storage);
            let fs = OpenFs::from_devices(
                &cx,
                Box::new(dev.clone()),
                &native_active_options(false),
                VolumeAccess::ReadWrite,
                None,
                Vec::new(),
            )
            .unwrap();
            dev.corrupt_block_byte(tail0.group_start.0 + 40, 12, 0x44);
            let cancelled_cx = Cx::for_testing();
            cancelled_cx.set_cancel_requested(true);
            let cancel_err = fs
                .scrub_and_heal_native(&cancelled_cx)
                .expect_err("cancelled Cx must abort scrub_and_heal_native");
            assert!(
                matches!(cancel_err, FfsError::Cancelled),
                "expected Cancelled, got {cancel_err:?}"
            );
            // Subsequent uncancelled Cx heals cleanly back to exact baseline!
            let healed = fs
                .scrub_and_heal_native(&cx)
                .expect("fresh Cx heals after prior cancellation");
            assert_eq!(healed.blocks_healed, 1);
            assert_eq!(dev.snapshot(), sealed_bytes);
        }
    }
}
