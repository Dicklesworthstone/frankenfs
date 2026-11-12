#![no_main]

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_journal::{
    replay_jbd2, replay_jbd2_segments, Jbd2Superblock, Jbd2Writer, JournalRegion, JournalSegment,
    ReplayOutcome,
};
use ffs_types::BlockNumber;
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

const BLOCK_SIZE: usize = 512;
const MIN_BLOCK_COUNT: u64 = 4_096;
const MAX_JOURNAL_BYTES: usize = 128 * BLOCK_SIZE;
const STRUCTURED_REGION_BLOCKS: u64 = 32;
const STRUCTURED_TARGET_BASE: u64 = 512;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }
}

#[derive(Debug)]
struct MemBlockDevice {
    blocks: RwLock<BTreeMap<BlockNumber, Vec<u8>>>,
    block_size: u32,
    block_count: u64,
}

impl MemBlockDevice {
    fn empty(block_count: u64) -> Self {
        Self {
            blocks: RwLock::new(BTreeMap::new()),
            block_size: u32::try_from(BLOCK_SIZE).expect("block size fits u32"),
            block_count,
        }
    }

    fn from_journal_blocks(journal_blocks: &[Vec<u8>]) -> Self {
        let block_count =
            MIN_BLOCK_COUNT.max(u64::try_from(journal_blocks.len()).unwrap_or(u64::MAX));
        let device = Self::empty(block_count);
        for (index, block) in journal_blocks.iter().enumerate() {
            device.raw_write(
                BlockNumber(u64::try_from(index).expect("block index fits u64")),
                block.clone(),
            );
        }
        device
    }

    fn raw_write(&self, block: BlockNumber, data: Vec<u8>) {
        self.blocks
            .write()
            .expect("lock poisoned")
            .insert(block, data);
    }

    fn snapshot(&self) -> BTreeMap<u64, Vec<u8>> {
        self.blocks
            .read()
            .expect("lock poisoned")
            .iter()
            .map(|(block, bytes)| (block.0, bytes.clone()))
            .collect()
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        if block.0 >= self.block_count {
            return Err(FfsError::Format(format!(
                "block out of range: {} >= {}",
                block.0, self.block_count
            )));
        }
        let data = self
            .blocks
            .read()
            .expect("lock poisoned")
            .get(&block)
            .cloned()
            .unwrap_or_else(|| vec![0_u8; BLOCK_SIZE]);
        Ok(BlockBuf::new(data))
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        if block.0 >= self.block_count {
            return Err(FfsError::Format(format!(
                "block out of range: {} >= {}",
                block.0, self.block_count
            )));
        }
        if data.len() != BLOCK_SIZE {
            return Err(FfsError::Format(format!(
                "size mismatch: got {} expected {}",
                data.len(),
                BLOCK_SIZE
            )));
        }
        self.blocks
            .write()
            .expect("lock poisoned")
            .insert(block, data.to_vec());
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn journal_blocks(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(BLOCK_SIZE)
        .map(|chunk| {
            let mut block = vec![0_u8; BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect()
}

fn region_for(block_count: usize) -> JournalRegion {
    JournalRegion {
        start: BlockNumber(0),
        blocks: u64::try_from(block_count).unwrap_or(u64::MAX),
    }
}

fn equivalent_segments(total_blocks: u64, selector: u8) -> Vec<JournalSegment> {
    if total_blocks == 0 {
        return Vec::new();
    }
    if total_blocks == 1 {
        return vec![JournalSegment {
            start: BlockNumber(0),
            blocks: 1,
        }];
    }
    let split = 1 + (u64::from(selector) % (total_blocks - 1));
    vec![
        JournalSegment {
            start: BlockNumber(0),
            blocks: split,
        },
        JournalSegment {
            start: BlockNumber(split),
            blocks: total_blocks - split,
        },
    ]
}

fn next_payload(cursor: &mut ByteCursor<'_>, marker: u8) -> Vec<u8> {
    let len = 1 + (usize::from(cursor.next_u8()) % BLOCK_SIZE);
    let mut payload: Vec<_> = (0..len).map(|_| cursor.next_u8()).collect();
    payload[0] = marker;
    payload
}

fn padded_payload(payload: &[u8]) -> Vec<u8> {
    let mut padded = vec![0_u8; BLOCK_SIZE];
    padded[..payload.len()].copy_from_slice(payload);
    padded
}

fn structured_targets(cursor: &mut ByteCursor<'_>) -> (BlockNumber, BlockNumber) {
    let first = STRUCTURED_TARGET_BASE + u64::from(cursor.next_u8());
    (BlockNumber(first), BlockNumber(first.saturating_add(1)))
}

fn structured_journal_blocks(
    data: &[u8],
) -> (Vec<Vec<u8>>, Vec<u32>, BlockNumber, Vec<u8>, BlockNumber) {
    let mut cursor = ByteCursor::new(data);
    let start_seq = cursor.next_u32();
    let (target_a, target_b) = structured_targets(&mut cursor);
    let first_payload_a = next_payload(&mut cursor, 0xA1);
    let first_payload_b = next_payload(&mut cursor, 0xB2);
    let second_payload_a = next_payload(&mut cursor, 0xC3);

    let cx = Cx::for_testing();
    let region = JournalRegion {
        start: BlockNumber(0),
        blocks: STRUCTURED_REGION_BLOCKS,
    };
    let dev = MemBlockDevice::empty(MIN_BLOCK_COUNT);
    let mut writer = Jbd2Writer::new(region, start_seq);

    let mut first_txn = writer.begin_transaction();
    first_txn.add_write(target_a, first_payload_a);
    first_txn.add_write(target_b, first_payload_b);
    first_txn.add_revoke(target_b);
    let first_seq = writer.next_seq();
    let first_commit = writer.commit_transaction(&cx, &dev, &first_txn);
    assert!(
        first_commit.is_ok(),
        "structured first JBD2 transaction commit must succeed"
    );

    let mut second_txn = writer.begin_transaction();
    second_txn.add_write(target_a, second_payload_a.clone());
    let second_seq = writer.next_seq();
    let second_commit = writer.commit_transaction(&cx, &dev, &second_txn);
    assert!(
        second_commit.is_ok(),
        "structured second JBD2 transaction commit must succeed"
    );

    let journal_len = usize::try_from(writer.head()).unwrap_or(usize::MAX);
    let snapshot = dev.snapshot();
    let journal = (0..journal_len)
        .map(|index| {
            snapshot
                .get(&(u64::try_from(index).unwrap_or(u64::MAX)))
                .cloned()
                .unwrap_or_else(|| vec![0_u8; BLOCK_SIZE])
        })
        .collect();

    (
        journal,
        vec![first_seq, second_seq],
        target_a,
        padded_payload(&second_payload_a),
        target_b,
    )
}

fn assert_superblock_invariants(block: &[u8]) {
    let first = Jbd2Superblock::parse(block);
    let second = Jbd2Superblock::parse(block);
    assert_eq!(
        first, second,
        "JBD2 superblock parsing should be deterministic"
    );
    if let Some(superblock) = first {
        let segment = superblock.external_journal_segment();
        let expected_start = if superblock.first_log_block > 0 {
            u64::from(superblock.first_log_block)
        } else {
            1
        };
        assert_eq!(
            segment.start,
            BlockNumber(expected_start),
            "external journal segment start should follow first_log_block semantics"
        );
        assert_eq!(
            segment.blocks,
            u64::from(superblock.max_len).saturating_sub(expected_start),
            "external journal segment length should be max_len minus the superblock block"
        );
    }
}

fn assert_replay_invariants(outcome: &ReplayOutcome) {
    let unique_sequences: BTreeSet<_> = outcome.committed_sequences.iter().copied().collect();
    assert_eq!(
        unique_sequences.len(),
        outcome.committed_sequences.len(),
        "committed sequence list must not contain duplicates"
    );
    assert!(
        outcome.stats.descriptor_blocks <= outcome.stats.scanned_blocks,
        "descriptor block count cannot exceed scanned block count"
    );
    assert!(
        outcome.stats.commit_blocks <= outcome.stats.scanned_blocks,
        "commit block count cannot exceed scanned block count"
    );
    assert!(
        outcome.stats.revoke_blocks <= outcome.stats.scanned_blocks,
        "revoke block count cannot exceed scanned block count"
    );
    assert!(
        outcome.stats.replayed_blocks <= outcome.stats.descriptor_tags,
        "replayed blocks must come from descriptor tags"
    );
    assert!(
        outcome.stats.skipped_revoked_blocks <= outcome.stats.revoke_entries,
        "skipped revoked blocks cannot exceed revoke entry count"
    );
    assert!(
        outcome.stats.orphaned_commit_blocks <= outcome.stats.commit_blocks,
        "orphaned commit count cannot exceed commit block count"
    );
    assert!(
        u64::try_from(outcome.committed_sequences.len()).unwrap_or(u64::MAX)
            <= outcome.stats.commit_blocks,
        "every committed sequence must correspond to a commit block"
    );
    assert!(
        outcome
            .stats
            .replayed_blocks
            .saturating_add(outcome.stats.skipped_revoked_blocks)
            <= outcome.stats.descriptor_tags,
        "replayed and revoked writes together cannot exceed descriptor tags"
    );
}

fn assert_results_match(
    left: &std::result::Result<ReplayOutcome, FfsError>,
    right: &std::result::Result<ReplayOutcome, FfsError>,
    context: &str,
) {
    match (left, right) {
        (Ok(left), Ok(right)) => {
            assert_eq!(
                left, right,
                "{context} should produce identical replay outcomes"
            );
            assert_replay_invariants(left);
        }
        (Err(left), Err(right)) => {
            assert_eq!(
                left.to_string(),
                right.to_string(),
                "{context} should deterministically reject the same malformed journal"
            );
        }
        (left, right) => {
            let left_kind = if left.is_ok() { "Ok" } else { "Err" };
            let right_kind = if right.is_ok() { "Ok" } else { "Err" };
            assert_eq!(
                left_kind, right_kind,
                "{context} should deterministically agree on replay success or rejection"
            );
        }
    }
}

fn assert_structured_writer_replay(data: &[u8]) {
    let (journal, expected_sequences, target_a, expected_a, target_b) =
        structured_journal_blocks(data);
    let region = region_for(journal.len());
    let cx = Cx::for_testing();

    let direct = MemBlockDevice::from_journal_blocks(&journal);
    let direct_result = replay_jbd2(&cx, &direct, region);
    assert!(
        direct_result.is_ok(),
        "structured JBD2 replay must accept the writer-produced journal"
    );
    let outcome = match &direct_result {
        Ok(outcome) => outcome,
        Err(_) => return,
    };

    assert_eq!(outcome.committed_sequences, expected_sequences);
    assert_eq!(outcome.stats.descriptor_blocks, 2);
    assert_eq!(outcome.stats.descriptor_tags, 3);
    assert_eq!(outcome.stats.revoke_blocks, 1);
    assert_eq!(outcome.stats.revoke_entries, 1);
    assert_eq!(outcome.stats.commit_blocks, 2);
    assert_eq!(outcome.stats.replayed_blocks, 1);
    assert_eq!(outcome.stats.skipped_revoked_blocks, 1);
    assert_eq!(outcome.stats.incomplete_transactions, 0);
    assert_eq!(outcome.stats.orphaned_commit_blocks, 0);
    assert_replay_invariants(outcome);

    let target_a_result = direct.read_block(&cx, target_a);
    assert!(
        target_a_result.is_ok(),
        "structured JBD2 replay target A read must succeed"
    );
    let target_a_block = match target_a_result {
        Ok(block) => block,
        Err(_) => return,
    };
    assert_eq!(target_a_block.as_slice(), expected_a.as_slice());

    let target_b_result = direct.read_block(&cx, target_b);
    assert!(
        target_b_result.is_ok(),
        "structured JBD2 replay target B read must succeed"
    );
    let target_b_block = match target_b_result {
        Ok(block) => block,
        Err(_) => return,
    };
    assert!(
        target_b_block.as_slice().iter().all(|byte| *byte == 0),
        "revoked structured JBD2 write target must remain zeroed"
    );

    let segmented = MemBlockDevice::from_journal_blocks(&journal);
    let segments = equivalent_segments(region.blocks, data.first().copied().unwrap_or(0));
    let segmented_result = replay_jbd2_segments(&cx, &segmented, &segments);
    assert_results_match(
        &direct_result,
        &segmented_result,
        "structured replay_jbd2_segments",
    );
    assert_eq!(
        direct.snapshot(),
        segmented.snapshot(),
        "structured segment replay should match direct replay device mutations"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_JOURNAL_BYTES {
        return;
    }

    assert_structured_writer_replay(data);

    let journal = journal_blocks(data);
    let region = region_for(journal.len());
    let cx = Cx::for_testing();

    if let Some(first_block) = journal.first() {
        assert_superblock_invariants(first_block);
    }

    let direct_left = MemBlockDevice::from_journal_blocks(&journal);
    let direct_right = MemBlockDevice::from_journal_blocks(&journal);
    let direct_first = replay_jbd2(&cx, &direct_left, region);
    let direct_second = replay_jbd2(&cx, &direct_right, region);
    assert_results_match(&direct_first, &direct_second, "replay_jbd2");
    assert_eq!(
        direct_left.snapshot(),
        direct_right.snapshot(),
        "replay_jbd2 should apply the same device mutations on repeated runs"
    );

    if region.blocks > 0 {
        let segmented = MemBlockDevice::from_journal_blocks(&journal);
        let segments = equivalent_segments(region.blocks, data.first().copied().unwrap_or(0));
        let segmented_result = replay_jbd2_segments(&cx, &segmented, &segments);
        assert_results_match(&direct_first, &segmented_result, "replay_jbd2_segments");
        assert_eq!(
            direct_left.snapshot(),
            segmented.snapshot(),
            "segment-based replay should produce the same final device image as region-based replay"
        );
    }
});
