#![no_main]

use ffs_error::FfsError;
use ffs_journal::{replay_fast_commit, FcDelRange, FcDentry, FcExtentRange, FcOperation};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;
const MAX_NAME_LEN: usize = 255;

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

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }
}

fn build_fc_tag(tag_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut tag = Vec::with_capacity(4 + payload.len());
    tag.extend_from_slice(&tag_type.to_le_bytes());
    let payload_len = u16::try_from(payload.len()).expect("fuzz payload length fits u16");
    tag.extend_from_slice(&payload_len.to_le_bytes());
    tag.extend_from_slice(payload);
    tag
}

fn build_dentry_payload(cursor: &mut ByteCursor<'_>, boundary: bool) -> (Vec<u8>, FcDentry) {
    let parent_ino = cursor.next_u32();
    let ino = cursor.next_u32();
    let name_len = if boundary {
        MAX_NAME_LEN
    } else {
        1 + usize::from(cursor.next_u8()) % MAX_NAME_LEN
    };
    let name: Vec<_> = (0..name_len).map(|_| cursor.next_u8()).collect();
    let mut payload = Vec::with_capacity(8 + name.len());
    payload.extend_from_slice(&parent_ino.to_le_bytes());
    payload.extend_from_slice(&ino.to_le_bytes());
    payload.extend_from_slice(&name);
    (
        payload,
        FcDentry {
            parent_ino,
            ino,
            name,
        },
    )
}

fn build_extent_payload(cursor: &mut ByteCursor<'_>, boundary: bool) -> (Vec<u8>, FcExtentRange) {
    let ino = cursor.next_u32();
    let logical_block = cursor.next_u32();
    let ee_len = if boundary {
        u16::MAX
    } else {
        cursor.next_u16().max(1)
    };
    let high = if boundary {
        u16::MAX
    } else {
        cursor.next_u16()
    };
    let low = cursor.next_u32();
    let unwritten = ee_len > 32768;
    let range = FcExtentRange {
        ino,
        logical_block,
        len: u32::from(if unwritten { ee_len - 32768 } else { ee_len }),
        physical_block: (u64::from(high) << 32) | u64::from(low),
        unwritten,
    };
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(&range.ino.to_le_bytes());
    payload.extend_from_slice(&range.logical_block.to_le_bytes());
    payload.extend_from_slice(&ee_len.to_le_bytes());
    payload.extend_from_slice(&high.to_le_bytes());
    payload.extend_from_slice(&low.to_le_bytes());
    (payload, range)
}

fn build_del_range_payload(cursor: &mut ByteCursor<'_>) -> (Vec<u8>, FcDelRange) {
    let range = FcDelRange {
        ino: cursor.next_u32(),
        logical_block: cursor.next_u32(),
        len: cursor.next_u32(),
    };
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&range.ino.to_le_bytes());
    payload.extend_from_slice(&range.logical_block.to_le_bytes());
    payload.extend_from_slice(&range.len.to_le_bytes());
    (payload, range)
}

fn build_structured_commit(
    data: &[u8],
    operation_selector: u8,
    inode_size: u16,
    boundary: bool,
) -> (Vec<u8>, FcOperation, u32) {
    let mut cursor = ByteCursor::new(data);
    let tid = cursor.next_u32();
    let mut stream = Vec::new();
    let mut head_payload = vec![0; 4];
    head_payload.extend_from_slice(&tid.to_le_bytes());
    stream.extend(build_fc_tag(9, &head_payload));

    let expected = match operation_selector {
        0 => {
            let ino = cursor.next_u32();
            let body_len = if boundary {
                usize::from(inode_size)
            } else {
                128
            };
            let body: Vec<_> = (0..body_len).map(|_| cursor.next_u8()).collect();
            let mut payload = ino.to_le_bytes().to_vec();
            payload.extend_from_slice(&body);
            stream.extend(build_fc_tag(6, &payload));
            FcOperation::InodeUpdate(ino, body)
        }
        1 => {
            let (payload, range) = build_extent_payload(&mut cursor, boundary);
            stream.extend(build_fc_tag(1, &payload));
            FcOperation::AddRange(range)
        }
        2 => {
            let (payload, range) = build_del_range_payload(&mut cursor);
            stream.extend(build_fc_tag(2, &payload));
            FcOperation::DelRange(range)
        }
        3 => {
            let (payload, dentry) = build_dentry_payload(&mut cursor, boundary);
            stream.extend(build_fc_tag(3, &payload));
            FcOperation::Create(dentry)
        }
        4 => {
            let (payload, dentry) = build_dentry_payload(&mut cursor, boundary);
            stream.extend(build_fc_tag(4, &payload));
            FcOperation::Link(dentry)
        }
        _ => {
            let (payload, dentry) = build_dentry_payload(&mut cursor, boundary);
            stream.extend(build_fc_tag(5, &payload));
            FcOperation::Unlink(dentry)
        }
    };

    let mut tail = Vec::with_capacity(8);
    tail.extend_from_slice(&tid.to_le_bytes());
    tail.extend_from_slice(&cursor.next_u32().to_le_bytes());
    stream.extend(build_fc_tag(8, &tail));

    (stream, expected, tid)
}

fn assert_clean_structured_commit(
    stream: &[u8],
    expected: &FcOperation,
    tid: u32,
    inode_size: u16,
) {
    let result =
        replay_fast_commit(stream, inode_size).expect("structured fast-commit stream replays");
    assert_eq!(result.transactions_found, 1);
    assert_eq!(result.last_tid, tid);
    assert_eq!(result.blocks_scanned, 1);
    assert_eq!(result.incomplete_transactions, 0);
    assert!(!result.fallback_required);
    assert_eq!(result.operations.as_slice(), std::slice::from_ref(expected));
}

fn assert_structured_padding_oracles(
    stream: &[u8],
    expected: &FcOperation,
    tid: u32,
    inode_size: u16,
) {
    let mut zero_padded = stream.to_vec();
    zero_padded.extend_from_slice(&[0_u8; 32]);
    assert_clean_structured_commit(&zero_padded, expected, tid, inode_size);

    // Insert an actual PAD TLV after the 12-byte HEAD record. Its contents
    // must not change the operation or commit metadata.
    let mut tag_padded = stream[..12].to_vec();
    tag_padded.extend(build_fc_tag(7, &[0xA5; 17]));
    tag_padded.extend_from_slice(&stream[12..]);
    assert_clean_structured_commit(&tag_padded, expected, tid, inode_size);

    // TAIL has an eight-byte minimum, unlike the fixed-size HEAD. Extra
    // bytes inside its declared payload are valid block-filling padding.
    let tail_start = stream.len() - 12;
    for padding_len in [1, 32, 255] {
        let mut tail_payload = stream[tail_start + 4..].to_vec();
        tail_payload.resize(8 + padding_len, 0xA5);
        let mut padded_tail = stream[..tail_start].to_vec();
        padded_tail.extend(build_fc_tag(8, &tail_payload));
        assert_clean_structured_commit(&padded_tail, expected, tid, inode_size);
    }

    let mut nonzero_tail = stream.to_vec();
    nonzero_tail.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
    let result = replay_fast_commit(&nonzero_tail, inode_size)
        .expect("nonzero tail returns fallback result");
    assert_eq!(result.transactions_found, 1);
    assert_eq!(result.last_tid, tid);
    assert_eq!(result.incomplete_transactions, 0);
    assert!(result.fallback_required);
    assert_eq!(result.operations.as_slice(), std::slice::from_ref(expected));
}

fn assert_malformed_tlv_lengths(inode_size: u16) {
    // Complete known records with bad lengths are corruption, not a successful
    // transaction or the recoverable fallback reserved for truncated input.
    for (tag, lengths) in [
        (9, vec![7, 9]),
        (8, vec![0, 7]),
        (1, vec![15, 17]),
        (2, vec![11, 13]),
        (3, vec![8, 264]),
        (4, vec![8, 264]),
        (5, vec![8, 264]),
        (6, vec![4, 131, usize::from(inode_size) + 5]),
    ] {
        for len in lengths {
            let mut stream = build_fc_tag(9, &[0; 8]);
            stream.extend(build_fc_tag(tag, &vec![0; len]));
            stream.extend(build_fc_tag(8, &[0; 8]));
            assert!(
                matches!(
                    replay_fast_commit(&stream, inode_size),
                    Err(FfsError::Corruption { .. })
                ),
                "complete tag {tag} with payload length {len} must be corruption"
            );
        }
    }
}

fn assert_truncated_transaction_requires_fallback(stream: &[u8], inode_size: u16) {
    // Remove part of TAIL's declared payload while leaving the complete HEAD
    // and operation. No operation may escape the uncommitted transaction.
    let truncated = &stream[..stream.len() - 1];
    let result = replay_fast_commit(truncated, inode_size).expect("truncation returns fallback");
    assert!(result.operations.is_empty());
    assert_eq!(result.transactions_found, 0);
    assert_eq!(result.incomplete_transactions, 1);
    assert!(result.fallback_required);
}

fn assert_arbitrary_replay_determinism(data: &[u8], inode_size: u16) {
    let first = replay_fast_commit(data, inode_size);
    let second = replay_fast_commit(data, inode_size);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "fast-commit replay changed success/error classification for identical input"
    );

    match (first, second) {
        (Ok(first), Ok(second)) => {
            assert_eq!(
                first, second,
                "fast-commit replay should be deterministic for successful parses"
            );

            assert!(
                first.transactions_found <= first.blocks_scanned,
                "committed transactions cannot exceed scanned HEAD blocks"
            );
            assert!(
                first.transactions_found + first.incomplete_transactions <= first.blocks_scanned,
                "each scanned HEAD can contribute at most one committed or discarded transaction"
            );
            assert!(
                first.operations.is_empty() || first.transactions_found > 0,
                "replayed operations require at least one committed transaction"
            );

            if first.transactions_found == 0 {
                assert_eq!(
                    first.last_tid, 0,
                    "without a committed transaction there must be no replayed tid"
                );
                assert!(
                    first.operations.is_empty(),
                    "operations should only be committed after a valid TAIL tag"
                );
            }

            if !first.fallback_required {
                assert_eq!(
                    first.incomplete_transactions, 0,
                    "clean replay should not discard incomplete transactions"
                );
            }
        }
        (Err(first), Err(second)) => {
            assert_eq!(
                first.to_string(),
                second.to_string(),
                "fast-commit replay should deterministically reject the same malformed input"
            );
        }
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => {}
    };
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Even empty smoke input exercises all six operations and both supported
    // inode-size boundaries. This is parser evidence, not kernel CRC/TID or
    // crash-recovery certification.
    for inode_size in [128, 256] {
        for selector in 0..6 {
            for boundary in [false, true] {
                let (stream, expected, tid) =
                    build_structured_commit(data, selector, inode_size, boundary);
                assert_clean_structured_commit(&stream, &expected, tid, inode_size);
                assert_structured_padding_oracles(&stream, &expected, tid, inode_size);
                assert_truncated_transaction_requires_fallback(&stream, inode_size);
            }
        }
        assert_malformed_tlv_lengths(inode_size);
        assert_arbitrary_replay_determinism(data, inode_size);
        // ee_len=32768 is written, while 32769 is unwritten length one.
        // Keep both sides of this non-bitmask boundary in every smoke run.
        for encoded_len in [32768_u16, 32769] {
            let mut extent_seed = [0xFF; 20];
            extent_seed[12..14].copy_from_slice(&encoded_len.to_le_bytes());
            let (stream, expected, tid) =
                build_structured_commit(&extent_seed, 1, inode_size, false);
            assert_clean_structured_commit(&stream, &expected, tid, inode_size);
        }
    }
});
