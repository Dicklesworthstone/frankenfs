#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B for JBD2 crash-recovery decode paths (guards commit `05ce88c5` and
//! the revoke event fusion path).
//!
//! `replay_jbd2_inner` used to decode every descriptor block's tag region TWICE
//! — `strict_descriptor_tag_count_with_format` (validate + count) immediately
//! followed by `parse_descriptor_tags_with_format` (build the `Vec`) — an
//! identical O(tags) scan run back-to-back over the same buffer. The single
//! strict pass (`parse_descriptor_tags_strict_with_format`) validates AND builds
//! the tags at once. This benches the old two-pass vs the new one-pass on a
//! descriptor with 32 tags (via the `bench_descriptor_decode` shim).
//!
//! The revoke row compares the legacy replay shape (strict revoke parse into a
//! temporary `Vec<BlockNumber>`, then append `TxnBodyEvent::Revoke`) with the
//! fused scanner that appends events while decoding the fixed-width revoke
//! payload.
//!
//! Run per-crate:
//!   CARGO_TARGET_DIR=/data/projects/frankenfs/.rch-targets/blackthrush-dig5 \
//!   rch exec -- cargo bench --profile release-perf -p ffs-journal --bench descriptor_decode

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_journal::wal_buffer::{WalEntry, WalEntryType};
use ffs_types::{BlockNumber, CommitSeq, TxnId};
use std::hint::black_box;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const BLOCKTYPE_DESCRIPTOR: u32 = 1;
const BLOCKTYPE_REVOKE: u32 = 5;
const HEADER_SIZE: usize = 12;
const REVOKE_HEADER_SIZE: usize = 16;
const FLAGS_OFFSET_V1_V2: usize = 6;
const FLAG_SAME_UUID: u16 = 0x0002;
const FLAG_LAST: u16 = 0x0008;
const N_TAGS: usize = 32;
const N_REVOKES: usize = 1020;

fn partition_allocating(entries: Vec<WalEntry>, epoch: u64) -> (Vec<WalEntry>, Vec<WalEntry>) {
    entries.into_iter().partition(|entry| entry.epoch <= epoch)
}

fn partition_extract_future(
    mut entries: Vec<WalEntry>,
    epoch: u64,
) -> (Vec<WalEntry>, Vec<WalEntry>) {
    let remaining = entries
        .extract_if(.., |entry| entry.epoch > epoch)
        .collect();
    (entries, remaining)
}

fn sort_stable_by_epoch(mut entries: Vec<WalEntry>) -> Vec<WalEntry> {
    entries.sort_by_key(|entry| entry.epoch);
    entries
}

fn sort_unstable_by_epoch(mut entries: Vec<WalEntry>) -> Vec<WalEntry> {
    entries.sort_unstable_by_key(|entry| entry.epoch);
    entries
}

fn group_commit_entries(unsorted: bool) -> Vec<WalEntry> {
    (0_u64..1024)
        .map(|index| {
            let rank = if unsorted {
                index.wrapping_mul(73) % 1024
            } else {
                index
            };
            let epoch = if rank < 896 { 1 } else { 2 };
            WalEntry {
                epoch,
                txn_id: TxnId(index + 1),
                commit_seq: CommitSeq(index + 11),
                entry_type: WalEntryType::Write {
                    block: BlockNumber(index + 101),
                    data: vec![index as u8; 32],
                },
                crc32c: index as u32 ^ 0xA5A5_5A5A,
            }
        })
        .collect()
}

/// Build a Legacy JBD2 descriptor block with `n` SAME_UUID tags (8-byte
/// records), the last one LAST-terminated — the shape replay decodes.
fn build_descriptor(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    b[4..8].copy_from_slice(&BLOCKTYPE_DESCRIPTOR.to_be_bytes());
    b[8..12].copy_from_slice(&7u32.to_be_bytes()); // sequence
    for i in 0..n {
        let off = HEADER_SIZE + i * 8;
        b[off..off + 4].copy_from_slice(&((i as u32) + 1).to_be_bytes()); // blocknr
        let mut fl = FLAG_SAME_UUID;
        if i == n - 1 {
            fl |= FLAG_LAST;
        }
        b[off + FLAGS_OFFSET_V1_V2..off + FLAGS_OFFSET_V1_V2 + 2]
            .copy_from_slice(&fl.to_be_bytes());
    }
    b
}

/// Build a 4 KiB 32-bit JBD2 revoke block with a dense payload. The entry count
/// matches `(4096 - 16) / 4`, which is the full block shape replay validates.
fn build_revoke(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    b[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    b[4..8].copy_from_slice(&BLOCKTYPE_REVOKE.to_be_bytes());
    b[8..12].copy_from_slice(&7u32.to_be_bytes());

    let r_count = REVOKE_HEADER_SIZE + n * 4;
    b[12..16].copy_from_slice(&(r_count as u32).to_be_bytes());

    for i in 0..n {
        let off = REVOKE_HEADER_SIZE + i * 4;
        let block = (i as u32).wrapping_mul(17).wrapping_add(11);
        b[off..off + 4].copy_from_slice(&block.to_be_bytes());
    }

    b
}

// One flat scenario list: each parity assertion sits directly beside the
// bench it guards, so splitting this would separate a claim from its proof.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario list, asserts beside their benches"
)]
fn bench(c: &mut Criterion) {
    let group_commit = group_commit_entries(false);
    let unsorted_group_commit = group_commit_entries(true);
    assert_eq!(
        partition_extract_future(group_commit.clone(), 1),
        partition_allocating(group_commit.clone(), 1),
        "in-place partition must preserve sorted output order"
    );
    assert_eq!(
        partition_extract_future(unsorted_group_commit.clone(), 1),
        partition_allocating(unsorted_group_commit, 1),
        "in-place partition must preserve both unsorted output orders"
    );

    {
        let mut g = c.benchmark_group("group_commit_partition_1024");
        for control in ["allocating_partition_a", "allocating_partition_b"] {
            g.bench_function(control, |b| {
                b.iter_batched(
                    || group_commit.clone(),
                    |entries| black_box(partition_allocating(entries, 1)),
                    BatchSize::SmallInput,
                );
            });
        }
        g.bench_function("extract_future_in_place", |b| {
            b.iter_batched(
                || group_commit.clone(),
                |entries| black_box(partition_extract_future(entries, 1)),
                BatchSize::SmallInput,
            );
        });
        g.finish();
    }

    let epoch_sort_entries = group_commit_entries(true);
    let stable_epoch_sort = sort_stable_by_epoch(epoch_sort_entries.clone());
    let unstable_epoch_sort = sort_unstable_by_epoch(epoch_sort_entries.clone());
    assert!(
        stable_epoch_sort
            .windows(2)
            .all(|pair| pair[0].epoch <= pair[1].epoch),
        "stable control must order entries by epoch"
    );
    assert!(
        unstable_epoch_sort
            .windows(2)
            .all(|pair| pair[0].epoch <= pair[1].epoch),
        "unstable candidate must order entries by epoch"
    );
    let mut stable_canonical = stable_epoch_sort;
    let mut unstable_canonical = unstable_epoch_sort;
    stable_canonical.sort_unstable_by_key(|entry| entry.txn_id.0);
    unstable_canonical.sort_unstable_by_key(|entry| entry.txn_id.0);
    assert_eq!(
        unstable_canonical, stable_canonical,
        "epoch sorting must preserve every complete WAL entry"
    );

    {
        let mut g = c.benchmark_group("wal_epoch_sort_1024");
        for control in ["stable_sort_a", "stable_sort_b"] {
            g.bench_function(control, |b| {
                b.iter_batched(
                    || epoch_sort_entries.clone(),
                    |entries| black_box(sort_stable_by_epoch(entries)),
                    BatchSize::SmallInput,
                );
            });
        }
        g.bench_function("unstable_sort_candidate", |b| {
            b.iter_batched(
                || epoch_sort_entries.clone(),
                |entries| black_box(sort_unstable_by_epoch(entries)),
                BatchSize::SmallInput,
            );
        });
        g.finish();
    }

    let block = build_descriptor(N_TAGS);
    // format=0 (Legacy), is_64bit=false, has_tail=false.
    let two = ffs_journal::bench_descriptor_decode(&block, false, false, 0, false);
    let one = ffs_journal::bench_descriptor_decode(&block, false, false, 0, true);
    assert_eq!(two, N_TAGS, "two-pass must decode all {N_TAGS} tags");
    assert_eq!(one, two, "one-pass must match two-pass count");

    {
        let mut g = c.benchmark_group("jbd2_descriptor_decode_32tags");
        g.bench_function("two_pass_count_then_parse", |b| {
            b.iter(|| {
                black_box(ffs_journal::bench_descriptor_decode(
                    black_box(&block),
                    false,
                    false,
                    0,
                    false,
                ))
            });
        });
        g.bench_function("one_pass_strict_parse", |b| {
            b.iter(|| {
                black_box(ffs_journal::bench_descriptor_decode(
                    black_box(&block),
                    false,
                    false,
                    0,
                    true,
                ))
            });
        });
        g.finish();
    }

    let revoke = build_revoke(N_REVOKES);
    let legacy = ffs_journal::bench_revoke_decode(&revoke, false, false, false);
    let fused = ffs_journal::bench_revoke_decode(&revoke, false, false, true);
    assert_ne!(legacy, 0, "legacy revoke decode must consume entries");
    assert_eq!(fused, legacy, "fused revoke decode must match legacy");

    {
        let mut g = c.benchmark_group("jbd2_revoke_decode_1020entries");
        g.bench_function("legacy_vec_then_events", |b| {
            b.iter(|| {
                black_box(ffs_journal::bench_revoke_decode(
                    black_box(&revoke),
                    false,
                    false,
                    false,
                ))
            });
        });
        g.bench_function("fused_decode_events", |b| {
            b.iter(|| {
                black_box(ffs_journal::bench_revoke_decode(
                    black_box(&revoke),
                    false,
                    false,
                    true,
                ))
            });
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
