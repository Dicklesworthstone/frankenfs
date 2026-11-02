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
