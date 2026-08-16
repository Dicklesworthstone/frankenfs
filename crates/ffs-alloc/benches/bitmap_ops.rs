//! Benchmark: succinct bitmap vs plain linear scan.
//!
//! Compares O(1) rank / O(log n) select via `SuccinctBitmap` against
//! the plain `bitmap_count_free` / `bitmap_find_free` O(n) helpers.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_alloc::succinct::SuccinctBitmap;
use ffs_alloc::{
    GroupStats, bitmap_count_free, bitmap_find_contiguous, bitmap_find_free,
    bitmap_largest_free_run,
};
use ffs_block::BlockBuf;
use ffs_types::{BlockNumber, GroupNumber};
use std::hint::black_box;
use std::sync::OnceLock;

/// Build a realistic ext4-like bitmap: 4096 bytes (32768 bits),
/// ~5% free blocks scattered in clusters.
fn make_bitmap() -> Vec<u8> {
    let mut bm = vec![0xFF_u8; 4096];
    // Free a cluster every ~650 blocks (≈5% free).
    let mut pos = 100_usize;
    while pos + 32 < 32768 {
        for i in pos..pos + 32 {
            bm[i / 8] &= !(1 << (i % 8));
        }
        pos += 650;
    }
    bm
}

/// Build an almost-full bitmap where a valid 32-block allocation exists only
/// near the end. This stresses contiguous-run search without changing the
/// ext4-scale 4 KiB bitmap shape.
fn make_late_free_cluster_bitmap() -> Vec<u8> {
    let mut bm = vec![0xFF_u8; 4096];
    for i in 32000..32032 {
        bm[i / 8] &= !(1 << (i % 8));
    }
    bm
}

/// Build a fragmented bitmap dominated by mixed bytes, where byte-level run
/// summaries should beat per-bit inspection.
fn make_fragmented_bitmap() -> Vec<u8> {
    let pattern = [0b1110_0001, 0b1000_1111, 0b1111_1000, 0b1100_0011];
    pattern.into_iter().cycle().take(4096).collect()
}

fn copy_bitmap_for_mutation_old(buf: &BlockBuf) -> Vec<u8> {
    buf.as_slice().to_vec()
}

fn move_bitmap_for_mutation(buf: BlockBuf) -> Vec<u8> {
    buf.into_inner()
}

fn bench_bitmap_owned_move(c: &mut Criterion) {
    let bm = make_fragmented_bitmap();
    debug_assert_eq!(
        copy_bitmap_for_mutation_old(&BlockBuf::new(bm.clone())),
        move_bitmap_for_mutation(BlockBuf::new(bm.clone())),
        "copy and move paths must expose identical mutable bitmap bytes"
    );

    let mut group = c.benchmark_group("bitmap_owned_move_ab");
    group.bench_function("old_copy_to_vec_4k", |b| {
        b.iter_batched(
            || BlockBuf::new(bm.clone()),
            |buf| black_box(copy_bitmap_for_mutation_old(black_box(&buf))),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("move_into_inner_4k", |b| {
        b.iter_batched(
            || BlockBuf::new(bm.clone()),
            |buf| black_box(move_bitmap_for_mutation(black_box(buf))),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn count_free_unrolled_chunks32(bitmap: &[u8], count: u32) -> u32 {
    let requested_full_bytes = (count / 8) as usize;
    let full_bytes = requested_full_bytes.min(bitmap.len());
    let remainder = count % 8;
    let mut free = 0_u32;

    let (blocks, blocks_rest) = bitmap[..full_bytes].as_chunks::<32>();
    for block in blocks {
        free += (!u64::from_le_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]))
        .count_ones();
        free += (!u64::from_le_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]))
        .count_ones();
        free += (!u64::from_le_bytes([
            block[16], block[17], block[18], block[19], block[20], block[21], block[22], block[23],
        ]))
        .count_ones();
        free += (!u64::from_le_bytes([
            block[24], block[25], block[26], block[27], block[28], block[29], block[30], block[31],
        ]))
        .count_ones();
    }

    let (chunks, chunks_rest) = blocks_rest.as_chunks::<8>();
    for chunk in chunks {
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        free += (!word).count_ones();
    }
    for &byte in chunks_rest {
        free += byte.count_zeros();
    }

    if remainder > 0 && requested_full_bytes < bitmap.len() {
        let byte = bitmap[requested_full_bytes];
        let mask = u8::MAX >> (8 - remainder);
        free += ((!byte) & mask).count_ones();
    }

    free
}

fn bench_count_free(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);

    let mut group = c.benchmark_group("count_free");

    group.bench_function("plain_O(n)", |b| {
        b.iter(|| black_box(bitmap_count_free(black_box(&bm), 32768)));
    });

    group.bench_function("succinct_O(1)", |b| {
        b.iter(|| black_box(sb.count_zeros()));
    });

    group.finish();
}

fn bench_count_free_unroll_vs_chunks8(c: &mut Criterion) {
    let bm = make_bitmap();
    let count = 32768;
    debug_assert_eq!(
        count_free_unrolled_chunks32(&bm, count),
        bitmap_count_free(&bm, count),
        "8-byte and 32-byte popcount paths must agree"
    );

    let mut group = c.benchmark_group("count_free_ab");
    group.bench_function("old_unrolled_chunks32", |b| {
        b.iter(|| {
            black_box(count_free_unrolled_chunks32(
                black_box(&bm),
                black_box(count),
            ))
        });
    });
    group.bench_function("restored_chunks8", |b| {
        b.iter(|| black_box(bitmap_count_free(black_box(&bm), black_box(count))));
    });
    group.finish();
}

fn bench_find_free(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);

    let mut group = c.benchmark_group("find_free");

    group.bench_function("plain_O(n)", |b| {
        b.iter(|| black_box(bitmap_find_free(black_box(&bm), 32768, black_box(16000))));
    });

    group.bench_function("succinct_O(log_n)", |b| {
        b.iter(|| black_box(sb.find_free(black_box(16000))));
    });

    group.finish();
}

fn succinct_find_free_rank_select(sb: &SuccinctBitmap, start: u32) -> Option<u32> {
    if sb.count_zeros() == 0 {
        return None;
    }

    let zeros_before = sb.rank0(start);
    let total_zeros = sb.count_zeros();
    if zeros_before < total_zeros {
        let pos = sb.select0(zeros_before)?;
        if pos >= start {
            return Some(pos);
        }
    }

    sb.select0(0)
}

fn bench_succinct_find_free_direct_vs_rank_select(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);
    let start = 16000;
    debug_assert_eq!(
        succinct_find_free_rank_select(&sb, start),
        sb.find_free(start),
        "rank/select and direct-word find_free must agree"
    );

    let mut group = c.benchmark_group("succinct_find_free_ab");
    group.bench_function("old_rank_select", |b| {
        b.iter(|| {
            black_box(succinct_find_free_rank_select(
                black_box(&sb),
                black_box(start),
            ))
        });
    });
    group.bench_function("direct_word_scan", |b| {
        b.iter(|| black_box(sb.find_free(black_box(start))));
    });
    group.finish();
}

fn bench_find_contiguous(c: &mut Criterion) {
    let bm = make_bitmap();

    let mut group = c.benchmark_group("find_contiguous");

    group.bench_function("plain_32_O(n)", |b| {
        b.iter(|| {
            black_box(bitmap_find_contiguous(
                black_box(&bm),
                32768,
                black_box(32),
                black_box(16000),
            ))
        });
    });

    group.finish();
}

fn succinct_find_contiguous_bit_scan(bitmap: &[u8], count: u32, n: u32) -> Option<u32> {
    if n == 0 {
        return Some(0);
    }

    let mut run_start = 0_u32;
    let mut run_len = 0_u32;
    for pos in 0..count {
        let byte = bitmap[(pos / 8) as usize];
        if (byte >> (pos % 8)) & 1 == 1 {
            run_start = pos + 1;
            run_len = 0;
        } else {
            run_len += 1;
            if run_len >= n {
                return Some(run_start);
            }
        }
    }
    None
}

fn bench_succinct_find_contiguous_word_vs_bit(c: &mut Criterion) {
    let bm = make_late_free_cluster_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);
    let n = 32;
    debug_assert_eq!(
        succinct_find_contiguous_bit_scan(&bm, 32768, n),
        sb.find_contiguous(n),
        "old bit scan and new broadword succinct scans must agree"
    );

    let mut group = c.benchmark_group("succinct_find_contiguous_ab");
    group.bench_function("old_bit_scan", |b| {
        b.iter(|| {
            black_box(succinct_find_contiguous_bit_scan(
                black_box(&bm),
                32768,
                black_box(n),
            ))
        });
    });
    group.bench_function("broadword_zero_run", |b| {
        b.iter(|| black_box(sb.find_contiguous(black_box(n))));
    });
    group.finish();
}

fn bench_largest_free_run(c: &mut Criterion) {
    let bm = make_fragmented_bitmap();

    let mut group = c.benchmark_group("largest_free_run");

    group.bench_function("fragmented_mixed_bytes", |b| {
        b.iter(|| black_box(bitmap_largest_free_run(black_box(&bm), 32768)));
    });

    group.finish();
}

const OLD_ZERO_RUN_FIELD_MASK: u16 = 0x1F;
const OLD_ZERO_RUN_SUFFIX_SHIFT: u16 = 5;
const OLD_ZERO_RUN_BEST_SHIFT: u16 = 10;
static OLD_HALFWORD_ZERO_RUNS: [u16; 65_536] = build_old_halfword_zero_runs();

#[expect(
    clippy::large_stack_arrays,
    reason = "const-evaluated static table initializer; no runtime stack allocation"
)]
const fn build_old_halfword_zero_runs() -> [u16; 65_536] {
    let mut runs = [0_u16; 65_536];
    let mut halfword = 0_u16;
    loop {
        runs[halfword as usize] = old_halfword_zero_run_summary(halfword);
        if halfword == u16::MAX {
            break;
        }
        halfword += 1;
    }
    runs
}

const fn old_halfword_zero_run_summary(halfword: u16) -> u16 {
    let mut prefix = 0_u16;
    while prefix < 16 && ((halfword >> prefix) & 1) == 0 {
        prefix += 1;
    }

    let mut suffix = 0_u16;
    while suffix < 16 && ((halfword >> (15 - suffix)) & 1) == 0 {
        suffix += 1;
    }

    let mut best = 0_u16;
    let mut run = 0_u16;
    let mut bit = 0_u16;
    while bit < 16 {
        if ((halfword >> bit) & 1) == 0 {
            run += 1;
            if run > best {
                best = run;
            }
        } else {
            run = 0;
        }
        bit += 1;
    }

    prefix | (suffix << OLD_ZERO_RUN_SUFFIX_SHIFT) | (best << OLD_ZERO_RUN_BEST_SHIFT)
}

fn largest_free_run_halfword_table_scan(bitmap: &[u8], count: u32) -> u32 {
    if count == 0 {
        return 0;
    }
    let full_bytes = (count / 8) as usize;
    let remainder = count % 8;

    let mut best = 0_u32;
    let mut run = 0_u32;

    let available_full_bytes = full_bytes.min(bitmap.len());
    let word_bytes = available_full_bytes - (available_full_bytes % 8);

    for chunk in bitmap[..word_bytes].as_chunks::<8>().0 {
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        apply_old_word_zero_run(word, &mut run, &mut best);
    }

    for &byte in &bitmap[word_bytes..available_full_bytes] {
        apply_old_byte_zero_run(byte, &mut run, &mut best);
    }

    if full_bytes > available_full_bytes {
        run = 0;
    }

    if remainder > 0
        && let Some(&byte) = bitmap.get(full_bytes)
    {
        let mask = u8::MAX >> (8 - remainder);
        apply_old_byte_zero_run(byte | !mask, &mut run, &mut best);
    }

    best
}

fn apply_old_word_zero_run(word: u64, run: &mut u32, best: &mut u32) {
    if word == 0 {
        *run = run.saturating_add(64);
        *best = (*best).max(*run);
        return;
    }
    if word == u64::MAX {
        *run = 0;
        return;
    }

    for shift in [0_u32, 16, 32, 48] {
        let halfword = ((word >> shift) & 0xFFFF) as u16;
        apply_old_halfword_zero_run(OLD_HALFWORD_ZERO_RUNS[usize::from(halfword)], run, best);
    }
}

fn apply_old_halfword_zero_run(summary: u16, run: &mut u32, best: &mut u32) {
    let prefix = u32::from(summary & OLD_ZERO_RUN_FIELD_MASK);
    if prefix == 16 {
        *run = run.saturating_add(16);
        *best = (*best).max(*run);
        return;
    }

    if prefix > 0 {
        *best = (*best).max(run.saturating_add(prefix));
    }
    *best = (*best).max(u32::from(
        (summary >> OLD_ZERO_RUN_BEST_SHIFT) & OLD_ZERO_RUN_FIELD_MASK,
    ));
    *run = u32::from((summary >> OLD_ZERO_RUN_SUFFIX_SHIFT) & OLD_ZERO_RUN_FIELD_MASK);
}

fn apply_old_byte_zero_run(byte: u8, run: &mut u32, best: &mut u32) {
    apply_old_halfword_zero_run(OLD_HALFWORD_ZERO_RUNS[usize::from(byte)], run, best);
}

fn bench_largest_free_run_word_vs_halfword(c: &mut Criterion) {
    let bm = make_fragmented_bitmap();
    debug_assert_eq!(
        largest_free_run_halfword_table_scan(&bm, 32768),
        bitmap_largest_free_run(&bm, 32768),
        "old halfword-table and new word-run scans must agree"
    );

    let mut group = c.benchmark_group("largest_free_run_ab");
    group.bench_function("old_halfword_table", |b| {
        b.iter(|| black_box(largest_free_run_halfword_table_scan(black_box(&bm), 32768)));
    });
    group.bench_function("word_run_detector", |b| {
        b.iter(|| black_box(bitmap_largest_free_run(black_box(&bm), 32768)));
    });
    group.finish();
}

fn largest_free_run_bitmap_scan_groups(bitmaps: &[Vec<u8>]) -> u64 {
    bitmaps
        .iter()
        .map(|bitmap| u64::from(bitmap_largest_free_run(bitmap, 32768)))
        .max()
        .unwrap_or(0)
}

fn largest_free_run_pruned_bitmap_scan_groups(bitmaps: &[Vec<u8>], free_blocks: &[u32]) -> u64 {
    let mut best = 0_u64;
    for (bitmap, &free_blocks) in bitmaps.iter().zip(free_blocks) {
        if u64::from(free_blocks) <= best {
            continue;
        }
        best = best.max(u64::from(bitmap_largest_free_run(bitmap, 32768)));
    }
    best
}

fn largest_free_run_cached_groups(groups: &[GroupStats]) -> u64 {
    groups
        .iter()
        .filter_map(GroupStats::cached_block_largest_free_run)
        .map(u64::from)
        .max()
        .unwrap_or(0)
}

fn bench_largest_free_run_cache_vs_bitmap_scan(c: &mut Criterion) {
    let bitmaps: Vec<Vec<u8>> = (0..128).map(|_| make_fragmented_bitmap()).collect();
    let groups: Vec<GroupStats> = bitmaps
        .iter()
        .enumerate()
        .map(|(idx, bitmap)| GroupStats {
            group: GroupNumber(
                u32::try_from(idx).expect("benchmark group count is bounded by u32"),
            ),
            free_blocks: bitmap_count_free(bitmap, 32768),
            block_largest_free_run: Some(bitmap_largest_free_run(bitmap, 32768)),
            free_inodes: 0,
            inode_search_start: 0,
            used_dirs: 0,
            block_bitmap_block: BlockNumber(
                u64::try_from(idx).expect("benchmark group count is bounded by u64"),
            ),
            inode_bitmap_block: BlockNumber(0),
            inode_table_block: BlockNumber(0),
            flags: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
            reserved_cache: OnceLock::new(),
            reserved_confirmed: OnceLock::new(),
        })
        .collect();

    debug_assert_eq!(
        largest_free_run_bitmap_scan_groups(&bitmaps),
        largest_free_run_cached_groups(&groups),
        "cached group summaries must match rescanning all group bitmaps"
    );

    let mut group = c.benchmark_group("largest_free_run_cached_ab");
    group.bench_function("bitmap_scan_128_groups", |b| {
        b.iter(|| black_box(largest_free_run_bitmap_scan_groups(black_box(&bitmaps))));
    });
    group.bench_function("cached_group_stats_128_groups", |b| {
        b.iter(|| black_box(largest_free_run_cached_groups(black_box(&groups))));
    });
    group.finish();
}

fn bench_largest_free_run_free_count_prune(c: &mut Criterion) {
    let mut bitmaps: Vec<Vec<u8>> = Vec::with_capacity(128);
    bitmaps.push(vec![0_u8; 4096]);
    bitmaps.extend((1..128).map(|_| make_fragmented_bitmap()));
    let free_blocks: Vec<u32> = bitmaps
        .iter()
        .map(|bitmap| bitmap_count_free(bitmap, 32768))
        .collect();

    debug_assert_eq!(
        largest_free_run_bitmap_scan_groups(&bitmaps),
        largest_free_run_pruned_bitmap_scan_groups(&bitmaps, &free_blocks),
        "free-block-count pruning must preserve the maximum free run"
    );

    let mut group = c.benchmark_group("largest_free_run_free_count_prune_ab");
    group.bench_function("bitmap_scan_128_groups", |b| {
        b.iter(|| black_box(largest_free_run_bitmap_scan_groups(black_box(&bitmaps))));
    });
    group.bench_function("free_count_pruned_128_groups", |b| {
        b.iter(|| {
            black_box(largest_free_run_pruned_bitmap_scan_groups(
                black_box(&bitmaps),
                black_box(&free_blocks),
            ))
        });
    });
    group.finish();
}

fn bench_rank(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);

    c.bench_function("succinct_rank0", |b| {
        b.iter(|| black_box(sb.rank0(black_box(20000))));
    });
}

fn bench_select(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);
    let target = sb.count_zeros() / 2; // select the middle free block

    c.bench_function("succinct_select0", |b| {
        b.iter(|| black_box(sb.select0(black_box(target))));
    });

    let target = sb.count_ones() / 2; // select the middle allocated block
    c.bench_function("succinct_select1", |b| {
        b.iter(|| black_box(sb.select1(black_box(target))));
    });
}

fn raw_get_bit(bitmap: &[u8], pos: u32) -> bool {
    let byte_idx = (pos / 8) as usize;
    let bit_idx = pos % 8;
    (bitmap[byte_idx] >> bit_idx) & 1 == 1
}

fn raw_read_word(bitmap: &[u8], word_idx: u32) -> u64 {
    let byte_start = (word_idx * 8) as usize;
    let mut word = 0_u64;
    for (i, &byte) in bitmap[byte_start..bitmap.len().min(byte_start + 8)]
        .iter()
        .enumerate()
    {
        word |= u64::from(byte) << (i * 8);
    }
    word
}

fn raw_select_nth_set_bit(mut word: u64, mut n: u32) -> u32 {
    loop {
        let bit = word.trailing_zeros();
        if n == 0 {
            return bit;
        }
        word &= word - 1;
        n -= 1;
    }
}

fn select0_in_block_bit_scan(
    bitmap: &[u8],
    block_idx: u32,
    len: u32,
    mut remaining: u32,
) -> Option<u32> {
    let bit_base = block_idx * 256;
    let bits_in_block = 256.min(len - bit_base);

    for bit in 0..bits_in_block {
        let pos = bit_base + bit;
        if !raw_get_bit(bitmap, pos) {
            if remaining == 0 {
                return Some(pos);
            }
            remaining -= 1;
        }
    }

    None
}

fn select0_in_block_broadword(
    bitmap: &[u8],
    block_idx: u32,
    len: u32,
    mut remaining: u32,
) -> Option<u32> {
    let mut word_base = block_idx * 256;
    let block_end = word_base.saturating_add(256).min(len);

    while word_base < block_end {
        let bits_in_word = (block_end - word_base).min(64);
        let mut zero_mask = !raw_read_word(bitmap, word_base / 64);
        if bits_in_word < 64 {
            zero_mask &= (1_u64 << bits_in_word) - 1;
        }

        let zeros_in_word = zero_mask.count_ones();
        if remaining < zeros_in_word {
            return Some(word_base + raw_select_nth_set_bit(zero_mask, remaining));
        }
        remaining -= zeros_in_word;
        word_base += 64;
    }

    None
}

fn select1_in_block_bit_scan(
    bitmap: &[u8],
    block_idx: u32,
    len: u32,
    mut remaining: u32,
) -> Option<u32> {
    let bit_base = block_idx * 256;
    let bits_in_block = 256.min(len - bit_base);

    for bit in 0..bits_in_block {
        let pos = bit_base + bit;
        if raw_get_bit(bitmap, pos) {
            if remaining == 0 {
                return Some(pos);
            }
            remaining -= 1;
        }
    }

    None
}

fn select1_in_block_broadword(
    bitmap: &[u8],
    block_idx: u32,
    len: u32,
    mut remaining: u32,
) -> Option<u32> {
    let mut word_base = block_idx * 256;
    let block_end = word_base.saturating_add(256).min(len);

    while word_base < block_end {
        let bits_in_word = (block_end - word_base).min(64);
        let mut one_mask = raw_read_word(bitmap, word_base / 64);
        if bits_in_word < 64 {
            one_mask &= (1_u64 << bits_in_word) - 1;
        }

        let ones_in_word = one_mask.count_ones();
        if remaining < ones_in_word {
            return Some(word_base + raw_select_nth_set_bit(one_mask, remaining));
        }
        remaining -= ones_in_word;
        word_base += 64;
    }

    None
}

/// A/B only the one changed lever: the final in-block select0 scan.
fn bench_select0_in_block_bit_scan_vs_broadword(c: &mut Criterion) {
    let mut bm = vec![0xFF_u8; 64]; // 512 bits, two succinct 256-bit blocks.
    for pos in [256_u32, 257, 258, 300, 301, 302, 303, 304] {
        bm[(pos / 8) as usize] &= !(1 << (pos % 8));
    }
    let len = 305;
    let block_idx = 1;
    let target_in_block = 7;
    debug_assert_eq!(
        select0_in_block_bit_scan(&bm, block_idx, len, target_in_block),
        select0_in_block_broadword(&bm, block_idx, len, target_in_block)
    );

    let mut group = c.benchmark_group("select0_in_block");
    group.bench_function("old_bit_scan", |b| {
        b.iter(|| {
            black_box(select0_in_block_bit_scan(
                black_box(&bm),
                block_idx,
                len,
                black_box(target_in_block),
            ))
        });
    });
    group.bench_function("new_broadword", |b| {
        b.iter(|| {
            black_box(select0_in_block_broadword(
                black_box(&bm),
                block_idx,
                len,
                black_box(target_in_block),
            ))
        });
    });
    group.finish();
}

/// A/B the symmetric select1 in-block scan before moving production select1
/// onto the same broadword primitive select0 already uses.
fn bench_select1_in_block_bit_scan_vs_broadword(c: &mut Criterion) {
    let mut bm = vec![0_u8; 64]; // 512 bits, two succinct 256-bit blocks.
    for pos in [256_u32, 257, 258, 300, 301, 302, 303, 304] {
        bm[(pos / 8) as usize] |= 1 << (pos % 8);
    }
    let len = 305;
    let block_idx = 1;
    let target_in_block = 7;
    debug_assert_eq!(
        select1_in_block_bit_scan(&bm, block_idx, len, target_in_block),
        select1_in_block_broadword(&bm, block_idx, len, target_in_block)
    );

    let mut group = c.benchmark_group("select1_in_block");
    group.bench_function("old_bit_scan", |b| {
        b.iter(|| {
            black_box(select1_in_block_bit_scan(
                black_box(&bm),
                block_idx,
                len,
                black_box(target_in_block),
            ))
        });
    });
    group.bench_function("new_broadword", |b| {
        b.iter(|| {
            black_box(select1_in_block_broadword(
                black_box(&bm),
                block_idx,
                len,
                black_box(target_in_block),
            ))
        });
    });
    group.finish();
}

fn bench_build(c: &mut Criterion) {
    let bm = make_bitmap();

    c.bench_function("succinct_build", |b| {
        b.iter(|| black_box(SuccinctBitmap::build(black_box(&bm), 32768)));
    });
}

/// Pre-optimization byte-at-a-time find-free scan (the shape `bitmap_find_free`
/// had before the word-at-a-time fast path). Kept here only to A/B the lever in
/// one binary on one CPU (so the ratio is valid despite rch worker variance).
fn find_free_byte_scan(bitmap: &[u8], count: u32, start: u32) -> Option<u32> {
    fn range(bitmap: &[u8], mut idx: u32, end: u32) -> Option<u32> {
        while idx < end && !idx.is_multiple_of(8) {
            let &byte = bitmap.get((idx / 8) as usize)?;
            if (byte >> (idx % 8)) & 1 == 0 {
                return Some(idx);
            }
            idx += 1;
        }
        while end.saturating_sub(idx) >= 8 {
            let &byte = bitmap.get((idx / 8) as usize)?;
            if byte != 0xFF {
                return Some(idx + (!byte).trailing_zeros());
            }
            idx += 8;
        }
        while idx < end {
            let &byte = bitmap.get((idx / 8) as usize)?;
            if (byte >> (idx % 8)) & 1 == 0 {
                return Some(idx);
            }
            idx += 1;
        }
        None
    }
    let start = start.min(count);
    range(bitmap, start, count).or_else(|| range(bitmap, 0, start))
}

/// Pre-optimization contiguous free-run scan. Kept only for same-binary A/B
/// proof of the word-at-a-time production path.
fn find_contiguous_byte_scan(bitmap: &[u8], count: u32, n: u32, start: u32) -> Option<u32> {
    fn range(bitmap: &[u8], count: u32, n: u32, start: u32) -> Option<u32> {
        let mut run_start = start;
        let mut run_len = 0_u32;
        let mut idx = start;

        while idx < count {
            if idx.is_multiple_of(8) && (idx + 8) <= count {
                let byte_idx = (idx / 8) as usize;
                match bitmap.get(byte_idx).copied() {
                    None | Some(0xFF) => {
                        idx += 8;
                        run_start = idx;
                        run_len = 0;
                        continue;
                    }
                    Some(0x00) => {
                        if run_len == 0 {
                            run_start = idx;
                        }
                        run_len = run_len.saturating_add(8);
                        if run_len >= n {
                            return Some(run_start);
                        }
                        idx += 8;
                        continue;
                    }
                    Some(byte) => {
                        let base = idx;
                        for bit in 0..8 {
                            let pos = base + bit;
                            if (byte >> bit) & 1 == 1 {
                                run_start = pos + 1;
                                run_len = 0;
                            } else {
                                run_len += 1;
                                if run_len >= n {
                                    return Some(run_start);
                                }
                            }
                        }
                        idx += 8;
                        continue;
                    }
                }
            }

            if raw_get_bit(bitmap, idx) {
                idx += 1;
                run_start = idx;
                run_len = 0;
            } else {
                run_len += 1;
                if run_len >= n {
                    return Some(run_start);
                }
                idx += 1;
            }
        }
        None
    }

    if n == 0 {
        return Some(0);
    }
    if n > count {
        return None;
    }
    range(bitmap, count, n, start).or_else(|| {
        let pass2_end = start.saturating_add(n).saturating_sub(1).min(count);
        range(bitmap, pass2_end, n, 0)
    })
}

/// A/B the word-at-a-time lever against the old byte scan over a fully
/// allocated (all-0xFF) 4 KiB block bitmap — the worst case that forces a full
/// scan to the end (returns None). Both run in this one binary on one CPU.
fn bench_find_free_full_scan_word_vs_byte(c: &mut Criterion) {
    let bm = vec![0xFF_u8; 4096]; // 32768 bits, no free bit → full scan
    debug_assert_eq!(
        find_free_byte_scan(&bm, 32768, 0),
        bitmap_find_free(&bm, 32768, 0),
        "byte and word scans must agree"
    );

    let mut group = c.benchmark_group("find_free_full_scan");
    group.bench_function("byte_at_a_time", |b| {
        b.iter(|| black_box(find_free_byte_scan(black_box(&bm), 32768, 0)));
    });
    group.bench_function("word_at_a_time", |b| {
        b.iter(|| black_box(bitmap_find_free(black_box(&bm), 32768, 0)));
    });
    group.finish();
}

/// A/B contiguous free-run search on the same ext4-like bitmap used by the
/// production benchmark. This isolates the 64-bit skip path from rch worker
/// variance.
fn bench_find_contiguous_word_vs_byte(c: &mut Criterion) {
    let bm = make_bitmap();
    let count = 32768;
    let n = 32;
    let start = 16000;
    debug_assert_eq!(
        find_contiguous_byte_scan(&bm, count, n, start),
        bitmap_find_contiguous(&bm, count, n, start),
        "byte and word contiguous scans must agree"
    );

    let mut group = c.benchmark_group("find_contiguous_ab");
    group.bench_function("old_byte_scan", |b| {
        b.iter(|| {
            black_box(find_contiguous_byte_scan(
                black_box(&bm),
                count,
                black_box(n),
                black_box(start),
            ))
        });
    });
    group.bench_function("word_at_a_time", |b| {
        b.iter(|| {
            black_box(bitmap_find_contiguous(
                black_box(&bm),
                count,
                black_box(n),
                black_box(start),
            ))
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_bitmap_owned_move,
    bench_count_free,
    bench_count_free_unroll_vs_chunks8,
    bench_find_free,
    bench_succinct_find_free_direct_vs_rank_select,
    bench_find_contiguous,
    bench_succinct_find_contiguous_word_vs_bit,
    bench_largest_free_run,
    bench_largest_free_run_word_vs_halfword,
    bench_largest_free_run_cache_vs_bitmap_scan,
    bench_largest_free_run_free_count_prune,
    bench_rank,
    bench_select,
    bench_select0_in_block_bit_scan_vs_broadword,
    bench_select1_in_block_bit_scan_vs_broadword,
    bench_build,
    bench_find_free_full_scan_word_vs_byte,
    bench_find_contiguous_word_vs_byte,
);
criterion_main!(benches);
