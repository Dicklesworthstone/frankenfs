#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_core::{OpenFs, OpenOptions};
use ffs_error::{FfsError, Result};
use ffs_types::{ByteOffset, EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_OFFSET};
use std::sync::{Arc, Mutex};

const BLOCK_SIZE: usize = 4096;
const IMAGE_SIZE: usize = 256 * 1024;
const TARGET_BLOCK: usize = 15;
const TARGET_PREFIX_LEN: usize = 16;
const JOURNAL_INODE: u32 = 8;
const JOURNAL_START_BLOCK: usize = 20;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_BLOCKTYPE_DESCRIPTOR: u32 = 1;
const JBD2_BLOCKTYPE_COMMIT: u32 = 2;
const JBD2_BLOCKTYPE_REVOKE: u32 = 5;
const JBD2_LAST_TAG: u32 = 0x0000_0008;

#[derive(Clone, Copy, Debug)]
enum JournalScenario {
    Committed,
    Uncommitted,
    Revoked,
}

#[derive(Clone, Debug)]
struct MemByteDevice {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl MemByteDevice {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(bytes)),
        }
    }

    fn read_block_prefix(&self, block: usize, prefix_len: usize) -> Vec<u8> {
        let start = block
            .checked_mul(BLOCK_SIZE)
            .expect("block offset should not overflow");
        let end = start
            .checked_add(prefix_len)
            .expect("prefix end should not overflow");
        let bytes = self.bytes.lock().expect("mem device lock");
        bytes[start..end].to_vec()
    }
}

impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        let bytes = self.bytes.lock().expect("mem device lock");
        u64::try_from(bytes.len()).expect("device length should fit in u64")
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset does not fit usize".to_owned()))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("read range overflow".to_owned()))?;
        let bytes = self
            .bytes
            .lock()
            .map_err(|_| FfsError::Format("mem device lock poisoned".to_owned()))?;
        if end > bytes.len() {
            return Err(FfsError::Format(format!(
                "read out of bounds: offset={} len={} device_len={}",
                offset.0,
                buf.len(),
                bytes.len()
            )));
        }
        buf.copy_from_slice(&bytes[start..end]);
        drop(bytes);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let start = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("offset does not fit usize".to_owned()))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("write range overflow".to_owned()))?;
        let mut bytes = self
            .bytes
            .lock()
            .map_err(|_| FfsError::Format("mem device lock poisoned".to_owned()))?;
        if end > bytes.len() {
            return Err(FfsError::Format(format!(
                "write out of bounds: offset={} len={} device_len={}",
                offset.0,
                buf.len(),
                bytes.len()
            )));
        }
        bytes[start..end].copy_from_slice(buf);
        drop(bytes);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

#[test]
fn ext4_journal_recovery_replays_committed_transaction() {
    let image = build_ext4_image_with_journal(JournalScenario::Committed);
    let dev = MemByteDevice::new(image);
    let inspector = dev.clone();
    let cx = Cx::for_testing();

    let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default())
        .expect("open ext4 with committed journal");
    let replay = fs
        .ext4_journal_replay()
        .expect("replay outcome should be present");

    eprintln!(
        "committed replay stats: scanned={} descriptors={} commits={} revokes={} replayed={} skipped_revoked={} incomplete={}",
        replay.stats.scanned_blocks,
        replay.stats.descriptor_blocks,
        replay.stats.commit_blocks,
        replay.stats.revoke_blocks,
        replay.stats.replayed_blocks,
        replay.stats.skipped_revoked_blocks,
        replay.stats.incomplete_transactions
    );

    assert_eq!(replay.committed_sequences, vec![1]);
    assert_eq!(replay.stats.replayed_blocks, 1);
    assert_eq!(replay.stats.skipped_revoked_blocks, 0);
    assert_eq!(replay.stats.incomplete_transactions, 0);
    assert_eq!(
        inspector.read_block_prefix(TARGET_BLOCK, TARGET_PREFIX_LEN),
        b"JBD2-REPLAY-TEST"
    );
}

#[test]
fn ext4_journal_recovery_ignores_uncommitted_transaction() {
    let image = build_ext4_image_with_journal(JournalScenario::Uncommitted);
    let dev = MemByteDevice::new(image);
    let inspector = dev.clone();
    let cx = Cx::for_testing();

    let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default())
        .expect("open ext4 with uncommitted journal");
    let replay = fs
        .ext4_journal_replay()
        .expect("replay outcome should be present");

    eprintln!(
        "uncommitted replay stats: scanned={} descriptors={} commits={} revokes={} replayed={} skipped_revoked={} incomplete={}",
        replay.stats.scanned_blocks,
        replay.stats.descriptor_blocks,
        replay.stats.commit_blocks,
        replay.stats.revoke_blocks,
        replay.stats.replayed_blocks,
        replay.stats.skipped_revoked_blocks,
        replay.stats.incomplete_transactions
    );

    assert!(replay.committed_sequences.is_empty());
    assert_eq!(replay.stats.replayed_blocks, 0);
    assert_eq!(replay.stats.commit_blocks, 0);
    assert_eq!(replay.stats.incomplete_transactions, 1);
    assert_eq!(
        inspector.read_block_prefix(TARGET_BLOCK, TARGET_PREFIX_LEN),
        b"BLOCK15-ORIGINAL"
    );
}

#[test]
fn ext4_journal_recovery_honors_revoke_before_commit() {
    let image = build_ext4_image_with_journal(JournalScenario::Revoked);
    let dev = MemByteDevice::new(image);
    let inspector = dev.clone();
    let cx = Cx::for_testing();

    let fs = OpenFs::from_device(&cx, Box::new(dev), &OpenOptions::default())
        .expect("open ext4 with revoked transaction");
    let replay = fs
        .ext4_journal_replay()
        .expect("replay outcome should be present");

    eprintln!(
        "revoked replay stats: scanned={} descriptors={} commits={} revokes={} replayed={} skipped_revoked={} incomplete={}",
        replay.stats.scanned_blocks,
        replay.stats.descriptor_blocks,
        replay.stats.commit_blocks,
        replay.stats.revoke_blocks,
        replay.stats.replayed_blocks,
        replay.stats.skipped_revoked_blocks,
        replay.stats.incomplete_transactions
    );

    assert_eq!(replay.committed_sequences, vec![1]);
    assert_eq!(replay.stats.commit_blocks, 1);
    assert_eq!(replay.stats.revoke_blocks, 1);
    assert_eq!(replay.stats.replayed_blocks, 0);
    assert_eq!(replay.stats.skipped_revoked_blocks, 1);
    assert_eq!(replay.stats.incomplete_transactions, 0);
    assert_eq!(
        inspector.read_block_prefix(TARGET_BLOCK, TARGET_PREFIX_LEN),
        b"BLOCK15-ORIGINAL"
    );
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_image_with_journal(scenario: JournalScenario) -> Vec<u8> {
    let mut image = build_ext4_image_with_extents();
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    // Enable HAS_JOURNAL and point to internal journal inode #8.
    let compat = u32::from_le_bytes([
        image[sb_off + 0x5C],
        image[sb_off + 0x5D],
        image[sb_off + 0x5E],
        image[sb_off + 0x5F],
    ]);
    image[sb_off + 0x5C..sb_off + 0x60].copy_from_slice(&(compat | 0x0004).to_le_bytes());
    image[sb_off + 0xE0..sb_off + 0xE4].copy_from_slice(&JOURNAL_INODE.to_le_bytes());

    let journal_len_blocks: u16 = match scenario {
        JournalScenario::Revoked => 4,
        JournalScenario::Committed | JournalScenario::Uncommitted => 3,
    };

    // Inode #8 (index 7) -> journal extent [block 20..].
    let ino8_off = 4 * BLOCK_SIZE + 7 * 256;
    image[ino8_off..ino8_off + 2].copy_from_slice(&0o100_600_u16.to_le_bytes());
    image[ino8_off + 4..ino8_off + 8]
        .copy_from_slice(&(u32::from(journal_len_blocks) * 4096).to_le_bytes());
    image[ino8_off + 0x1A..ino8_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino8_off + 0x20..ino8_off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    image[ino8_off + 0x80..ino8_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let e = ino8_off + 0x28;
    image[e..e + 2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // extent magic
    image[e + 2..e + 4].copy_from_slice(&1_u16.to_le_bytes()); // entries
    image[e + 4..e + 6].copy_from_slice(&4_u16.to_le_bytes()); // max
    image[e + 6..e + 8].copy_from_slice(&0_u16.to_le_bytes()); // depth=0
    image[e + 12..e + 16].copy_from_slice(&0_u32.to_le_bytes()); // logical 0
    image[e + 16..e + 18].copy_from_slice(&journal_len_blocks.to_le_bytes());
    image[e + 18..e + 20].copy_from_slice(&0_u16.to_le_bytes()); // start_hi
    image[e + 20..e + 24].copy_from_slice(
        &u32::try_from(JOURNAL_START_BLOCK)
            .expect("journal start block should fit u32")
            .to_le_bytes(),
    );

    // Baseline payload in target block so tests can prove whether replay wrote.
    let target_off = TARGET_BLOCK * BLOCK_SIZE;
    image[target_off..target_off + TARGET_PREFIX_LEN].copy_from_slice(b"BLOCK15-ORIGINAL");

    // Journal block +0: descriptor with one tag targeting block 15.
    let j_desc = JOURNAL_START_BLOCK * BLOCK_SIZE;
    write_jbd2_header(
        &mut image[j_desc..j_desc + BLOCK_SIZE],
        JBD2_BLOCKTYPE_DESCRIPTOR,
        1,
    );
    image[j_desc + 12..j_desc + 16].copy_from_slice(
        &u32::try_from(TARGET_BLOCK)
            .expect("target block should fit u32")
            .to_be_bytes(),
    );
    image[j_desc + 16..j_desc + 20].copy_from_slice(&JBD2_LAST_TAG.to_be_bytes());

    // Journal block +1: staged payload for target block 15.
    let j_data = (JOURNAL_START_BLOCK + 1) * BLOCK_SIZE;
    image[j_data..j_data + TARGET_PREFIX_LEN].copy_from_slice(b"JBD2-REPLAY-TEST");

    match scenario {
        JournalScenario::Committed => {
            let j_commit = (JOURNAL_START_BLOCK + 2) * BLOCK_SIZE;
            write_jbd2_header(
                &mut image[j_commit..j_commit + BLOCK_SIZE],
                JBD2_BLOCKTYPE_COMMIT,
                1,
            );
        }
        JournalScenario::Uncommitted => {
            // Leave trailing blocks zeroed; replay must treat transaction as incomplete.
        }
        JournalScenario::Revoked => {
            let j_revoke = (JOURNAL_START_BLOCK + 2) * BLOCK_SIZE;
            write_jbd2_header(
                &mut image[j_revoke..j_revoke + BLOCK_SIZE],
                JBD2_BLOCKTYPE_REVOKE,
                1,
            );
            image[j_revoke + 12..j_revoke + 16].copy_from_slice(
                &u32::try_from(TARGET_BLOCK)
                    .expect("target block should fit u32")
                    .to_be_bytes(),
            );

            let j_commit = (JOURNAL_START_BLOCK + 3) * BLOCK_SIZE;
            write_jbd2_header(
                &mut image[j_commit..j_commit + BLOCK_SIZE],
                JBD2_BLOCKTYPE_COMMIT,
                1,
            );
        }
    }

    image
}

fn write_jbd2_header(block: &mut [u8], block_type: u32, sequence: u32) {
    block[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    block[4..8].copy_from_slice(&block_type.to_be_bytes());
    block[8..12].copy_from_slice(&sequence.to_be_bytes());
}

/// Build an ext4 image with file inodes that have extent trees.
///
/// This matches the unit-test scaffold used in `ffs-core`, giving a compact
/// deterministic image that `OpenFs` can open in-memory.
#[allow(clippy::cast_possible_truncation)]
fn build_ext4_image_with_extents() -> Vec<u8> {
    let block_size: u32 = u32::try_from(BLOCK_SIZE).expect("block size should fit u32");
    let image_size: u32 = u32::try_from(IMAGE_SIZE).expect("image size should fit u32");
    let mut image = vec![0_u8; IMAGE_SIZE];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    // Superblock.
    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log=2 -> 4K
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes()); // inodes_count
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes()); // first_data_block
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes()); // rev_level
    let incompat: u32 = 0x0002 | 0x0040; // FILETYPE | EXTENTS
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat.to_le_bytes());
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino

    // Group descriptor at block 1.
    let gd_off = BLOCK_SIZE;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes()); // block_bitmap
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes()); // inode_bitmap
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes()); // inode_table

    // Inode #11 (index 10): regular file with leaf extent to block 10.
    let ino11_off = 4 * BLOCK_SIZE + 10 * 256;
    image[ino11_off..ino11_off + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[ino11_off + 4..ino11_off + 8].copy_from_slice(&14_u32.to_le_bytes());
    image[ino11_off + 0x1A..ino11_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino11_off + 0x20..ino11_off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    image[ino11_off + 0x80..ino11_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let extent11 = ino11_off + 0x28;
    image[extent11..extent11 + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[extent11 + 2..extent11 + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[extent11 + 4..extent11 + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[extent11 + 6..extent11 + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[extent11 + 12..extent11 + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[extent11 + 16..extent11 + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[extent11 + 18..extent11 + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[extent11 + 20..extent11 + 24].copy_from_slice(&10_u32.to_le_bytes());

    // Inode #12 (index 11): regular file with index extent via block 11.
    let ino12_off = 4 * BLOCK_SIZE + 11 * 256;
    image[ino12_off..ino12_off + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[ino12_off + 4..ino12_off + 8].copy_from_slice(&14_u32.to_le_bytes());
    image[ino12_off + 0x1A..ino12_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino12_off + 0x20..ino12_off + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    image[ino12_off + 0x80..ino12_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let extent12 = ino12_off + 0x28;
    image[extent12..extent12 + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[extent12 + 2..extent12 + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[extent12 + 4..extent12 + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[extent12 + 6..extent12 + 8].copy_from_slice(&1_u16.to_le_bytes()); // depth=1
    image[extent12 + 12..extent12 + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[extent12 + 16..extent12 + 20].copy_from_slice(&11_u32.to_le_bytes());
    image[extent12 + 20..extent12 + 22].copy_from_slice(&0_u16.to_le_bytes());

    // Extent leaf block for inode #12.
    let leaf = 11 * BLOCK_SIZE;
    image[leaf..leaf + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[leaf + 2..leaf + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[leaf + 4..leaf + 6].copy_from_slice(&340_u16.to_le_bytes());
    image[leaf + 6..leaf + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[leaf + 12..leaf + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[leaf + 16..leaf + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[leaf + 18..leaf + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[leaf + 20..leaf + 24].copy_from_slice(&12_u32.to_le_bytes());

    image
}
