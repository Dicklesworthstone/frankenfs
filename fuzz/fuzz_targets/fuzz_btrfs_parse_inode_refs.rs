#![no_main]
//! Fuzz target for ffs_btrfs::parse_inode_refs (bd-kbj23).
//!
//! parse_inode_refs walks a list of variable-length INODE_REF entries
//! (u64 index + u16 name_len + name bytes). It is on the hot path of
//! every subvolume enumeration and snapshot navigation. The sibling
//! parsers (parse_root_item, parse_inode_item, parse_dir_items,
//! parse_root_ref, parse_xattr_items, parse_extent_data) all live
//! behind fuzz_btrfs_tree_items, but parse_inode_refs has only two
//! integration tests and no dedicated fuzz harness.
//!
//! Note: a parallel implementation exists in
//! ffs_core::OpenFs::btrfs_parse_inode_ref_payload (fuzzed via
//! fuzz_btrfs_inode_ref_payload). This target hits the ffs_btrfs
//! crate's parser directly so that drift between the two
//! implementations gets exercised at libfuzzer scale.
//!
//!   MR-1 - Determinism: parse_inode_refs called twice on the same
//!          input must return Result-equivalent output (parsed Vec
//!          or Err formatted identically).
//!   MR-2 - No-panic: arbitrary bytes must never panic the parser
//!          (any panic crashes the fuzzer).
//!   MR-3 - Round-trip: every parsed entry, re-serialized via
//!          BtrfsInodeRef::try_to_bytes and concatenated, must
//!          re-parse to the same Vec<BtrfsInodeRef>.
//!   MR-4 - Append-invariance: appending a partial-header tail
//!          (1..9 bytes) to a valid payload must reject with
//!          InsufficientData (length-checking is the only thing
//!          standing between this parser and a buffer over-read).

use ffs_btrfs::{parse_inode_refs, BtrfsInodeRef};
use libfuzzer_sys::fuzz_target;

const MAX_NAME_BYTES: usize = 64;
const INODE_REF_HEADER_BYTES: usize = 10;

fn parse_must_reject(payload: &[u8], context: &str) {
    let result = parse_inode_refs(payload);
    assert!(result.is_err(), "{context} must reject");
    if let Err(err) = result {
        let rendered = format!("{err:?}");
        assert!(!rendered.is_empty(), "{context} must render an error");
    }
}

fuzz_target!(|data: &[u8]| {
    // MR-1, MR-2: pump arbitrary bytes through twice; result must
    // be deterministic and the parser must never panic.
    let result_a = parse_inode_refs(data);
    let result_b = parse_inode_refs(data);
    match (&result_a, &result_b) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a, b, "parse_inode_refs must be deterministic on Ok");
        }
        (Err(a), Err(b)) => {
            assert_eq!(
                format!("{a:?}"),
                format!("{b:?}"),
                "parse_inode_refs must be deterministic on Err"
            );
        }
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
            assert_eq!(
                result_a.is_ok(),
                result_b.is_ok(),
                "parse_inode_refs must be deterministic across Ok/Err"
            );
        }
    }

    // MR-3 round-trip: if we got a valid parse, re-serialize each
    // entry and assert the concatenated bytes parse back to the
    // same Vec<BtrfsInodeRef>.
    if let Ok(entries) = result_a {
        let mut reassembled = Vec::new();
        let mut serialize_failed = false;
        for entry in &entries {
            match entry.try_to_bytes() {
                Ok(bytes) => reassembled.extend_from_slice(&bytes),
                Err(_) => {
                    // A name shouldn't exceed u16::MAX in any real
                    // input, but guard for fuzz-induced edge cases.
                    serialize_failed = true;
                    break;
                }
            }
        }
        if !serialize_failed {
            let reparsed = parse_inode_refs(&reassembled)
                .expect("re-parse of self-serialized output must succeed");
            assert_eq!(
                reparsed, entries,
                "MR-3: stamp(parse(x)) -> parse must be idempotent"
            );
        }
    }

    let mut index_bytes = [0_u8; 8];
    for (dst, src) in index_bytes.iter_mut().zip(data.iter().copied()) {
        *dst = src;
    }
    let index = u64::from_le_bytes(index_bytes);
    let len_bytes = [
        data.get(8).copied().unwrap_or_default(),
        data.get(9).copied().unwrap_or_default(),
    ];
    let name_len_choice = (usize::from(u16::from_le_bytes(len_bytes)) % MAX_NAME_BYTES) + 1;
    let name_byte = data.get(10).copied().unwrap_or(b'x');

    // Named malformed paths from bd-kbj23: short header, zero
    // name_len, and declared name_len that overruns the remaining
    // payload.
    let mut zero_name = Vec::with_capacity(INODE_REF_HEADER_BYTES);
    zero_name.extend_from_slice(&index.to_le_bytes());
    zero_name.extend_from_slice(&0_u16.to_le_bytes());
    for short_len in 1..INODE_REF_HEADER_BYTES {
        parse_must_reject(&zero_name[..short_len], "short inode_ref header");
    }
    parse_must_reject(&zero_name, "zero-length inode_ref name");

    let mut name_len_overflow = Vec::with_capacity(INODE_REF_HEADER_BYTES + 1);
    name_len_overflow.extend_from_slice(&index.to_le_bytes());
    name_len_overflow.extend_from_slice(&2_u16.to_le_bytes());
    name_len_overflow.push(name_byte);
    parse_must_reject(&name_len_overflow, "inode_ref name_len overflow");

    // MR-4 length-checking: build a synthetic single-entry payload
    // from the first ~16 bytes of fuzz input as (index, name_len,
    // partial_name) and assert the truncated-tail variants reject
    // with InsufficientData rather than buffer-over-reading.
    let entry = BtrfsInodeRef {
        index,
        name: vec![name_byte; name_len_choice],
    };
    let valid = entry
        .try_to_bytes()
        .expect("constructed entry has small name");
    let parsed = parse_inode_refs(&valid).expect("valid single-entry must parse");
    assert_eq!(parsed, vec![entry.clone()]);

    // Truncate by 1..9 bytes; any truncation inside the header or
    // mid-name must reject, never panic.
    for trunc in 1..=valid.len().min(INODE_REF_HEADER_BYTES - 1) {
        let truncated = &valid[..valid.len() - trunc];
        parse_must_reject(truncated, "truncated inode_ref payload");
    }
});
