#![forbid(unsafe_code)]

//! Per-crate A/Bs for indirect-truncate scans: the empty-block check and the
//! cutoff-prefix selector used before visiting pointers in an indirect block.
//!
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc \
//!   rch exec -- cargo bench --profile release-perf -p ffs-inode --bench indirect_zero_scan

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn byte_all_zero(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}

fn unrolled4_all_zero(data: &[u8]) -> bool {
    // Mirrors the production `indirect_block_all_zero` conversion: same split,
    // same order, `.all()` still short-circuits at the first non-zero lane, so the
    // arm this bench measures stays the arm production runs (bd-3ao0l).
    let (blocks, blocks_rest) = data.as_chunks::<32>();
    for block in blocks {
        let w0 = u64::from_ne_bytes(block[0..8].try_into().unwrap());
        let w1 = u64::from_ne_bytes(block[8..16].try_into().unwrap());
        let w2 = u64::from_ne_bytes(block[16..24].try_into().unwrap());
        let w3 = u64::from_ne_bytes(block[24..32].try_into().unwrap());
        if (w0 | w1 | w2 | w3) != 0 {
            return false;
        }
    }
    let (lanes, rest) = blocks_rest.as_chunks::<8>();
    lanes.iter().all(|c| u64::from_ne_bytes(*c) == 0) && rest.iter().all(|&b| b == 0)
}

#[inline(never)]
fn linear_cutoff_scan(pointers: &[u32], base: u64, cutoff: u64, entry_span: u64) -> (u64, u64) {
    let ppb = pointers.len() as u64;
    let mut visited = 0u64;
    let mut digest = 0u64;
    for i in 0..ppb {
        let child_base = base.saturating_add(i.saturating_mul(entry_span));
        if child_base.saturating_add(entry_span) <= cutoff {
            continue;
        }
        let pointer = pointers[usize::try_from(i).expect("pointer index fits usize")];
        if pointer == 0 {
            continue;
        }
        visited += 1;
        digest = digest
            .wrapping_mul(0x9e37_79b1_85eb_ca87)
            .wrapping_add(i.rotate_left(17) ^ u64::from(pointer));
    }
    (visited, digest)
}

#[inline(never)]
fn bounded_cutoff_scan(pointers: &[u32], base: u64, cutoff: u64, entry_span: u64) -> (u64, u64) {
    let ppb = pointers.len() as u64;
    let first_entry = if entry_span == 0 {
        if base <= cutoff { ppb } else { 0 }
    } else if cutoff == u64::MAX {
        ppb
    } else {
        (cutoff.saturating_sub(base) / entry_span).min(ppb)
    };
    let mut visited = 0u64;
    let mut digest = 0u64;
    for i in first_entry..ppb {
        let child_base = base.saturating_add(i.saturating_mul(entry_span));
        if child_base.saturating_add(entry_span) <= cutoff {
            continue;
        }
        let pointer = pointers[usize::try_from(i).expect("pointer index fits usize")];
        if pointer == 0 {
            continue;
        }
        visited += 1;
        digest = digest
            .wrapping_mul(0x9e37_79b1_85eb_ca87)
            .wrapping_add(i.rotate_left(17) ^ u64::from(pointer));
    }
    (visited, digest)
}

#[inline(never)]
fn bounded_leaf_scan(pointers: &[u32], base: u64, cutoff: u64) -> (u64, u64) {
    let ppb = pointers.len() as u64;
    let first_entry = if cutoff == u64::MAX {
        ppb
    } else {
        cutoff.saturating_sub(base).min(ppb)
    };
    let mut visited = 0u64;
    let mut digest = 0u64;
    for i in first_entry..ppb {
        let pointer = pointers[usize::try_from(i).expect("pointer index fits usize")];
        if pointer == 0 {
            continue;
        }
        visited += 1;
        digest = digest
            .wrapping_mul(0x9e37_79b1_85eb_ca87)
            .wrapping_add(i.rotate_left(17) ^ u64::from(pointer));
    }
    (visited, digest)
}

/// One indirect block's worth of pointers, every 11th a hole, shared by both
/// truncate benches below so the two groups measure the same fixture.
fn fixture_pointers() -> Vec<u32> {
    (0..1024)
        .map(|i| if i % 11 == 0 { 0 } else { i + 1 })
        .collect()
}

const FIXTURE_BASE: u64 = 12;
const FIXTURE_CUTOFF: u64 = FIXTURE_BASE + 900;

fn bench_all_zero(c: &mut Criterion) {
    let zero = vec![0u8; 4096];
    let mut early = vec![0u8; 4096];
    early[0] = 1;
    for (name, block) in [("empty", &zero), ("nonempty_early", &early)] {
        assert_eq!(byte_all_zero(block), unrolled4_all_zero(block));
        let mut g = c.benchmark_group(format!("indirect_all_zero_{name}"));
        g.bench_function("byte", |b| {
            b.iter(|| black_box(byte_all_zero(black_box(block))));
        });
        g.bench_function("unrolled4", |b| {
            b.iter(|| black_box(unrolled4_all_zero(black_box(block))));
        });
        g.finish();
    }
}

fn bench_truncate_prefix(c: &mut Criterion) {
    let pointers = fixture_pointers();
    let base = FIXTURE_BASE;
    let cutoff = FIXTURE_CUTOFF;
    let entry_span = 1u64;
    for &(case_base, case_cutoff, case_span) in &[
        (base, base - 1, 1),
        (base, base, 1),
        (base, base + 1, 1),
        (base, cutoff, 1),
        (base, base + pointers.len() as u64, 1),
        (base, u64::MAX, 1),
        (u64::MAX - 3, u64::MAX - 2, 2),
        (base, base - 1, 0),
        (base, base, 0),
    ] {
        assert_eq!(
            linear_cutoff_scan(&pointers, case_base, case_cutoff, case_span),
            bounded_cutoff_scan(&pointers, case_base, case_cutoff, case_span)
        );
    }

    let mut g = c.benchmark_group("indirect_truncate_prefix_ab");
    g.bench_function("linear_a", |b| {
        b.iter(|| {
            black_box(linear_cutoff_scan(
                black_box(&pointers),
                black_box(base),
                black_box(cutoff),
                black_box(entry_span),
            ))
        });
    });
    g.bench_function("linear_b", |b| {
        b.iter(|| {
            black_box(linear_cutoff_scan(
                black_box(&pointers),
                black_box(base),
                black_box(cutoff),
                black_box(entry_span),
            ))
        });
    });
    g.bench_function("bounded", |b| {
        b.iter(|| {
            black_box(bounded_cutoff_scan(
                black_box(&pointers),
                black_box(base),
                black_box(cutoff),
                black_box(entry_span),
            ))
        });
    });
    g.finish();
}

fn bench_leaf_guard(c: &mut Criterion) {
    let pointers = fixture_pointers();
    let base = FIXTURE_BASE;
    let cutoff = FIXTURE_CUTOFF;
    for &(case_base, case_cutoff) in &[
        (base, base - 1),
        (base, base),
        (base, base + 1),
        (base, cutoff),
        (base, base + pointers.len() as u64),
        (base, u64::MAX),
        (u64::MAX - 3, u64::MAX - 2),
        (u64::MAX - 3, u64::MAX - 1),
        (u64::MAX, u64::MAX - 1),
    ] {
        assert_eq!(
            bounded_cutoff_scan(&pointers, case_base, case_cutoff, 1),
            bounded_leaf_scan(&pointers, case_base, case_cutoff),
            "leaf guard elision diverged at base={case_base}, cutoff={case_cutoff}"
        );
    }

    let mut g = c.benchmark_group("indirect_truncate_leaf_guard_ab");
    g.bench_function("bounded_guard_a", |b| {
        b.iter(|| {
            black_box(bounded_cutoff_scan(
                black_box(&pointers),
                black_box(base),
                black_box(cutoff),
                black_box(1),
            ))
        });
    });
    g.bench_function("bounded_guard_b", |b| {
        b.iter(|| {
            black_box(bounded_cutoff_scan(
                black_box(&pointers),
                black_box(base),
                black_box(cutoff),
                black_box(1),
            ))
        });
    });
    g.bench_function("leaf_guard_elided", |b| {
        b.iter(|| {
            black_box(bounded_leaf_scan(
                black_box(&pointers),
                black_box(base),
                black_box(cutoff),
            ))
        });
    });
    g.finish();
}

fn bench(c: &mut Criterion) {
    bench_all_zero(c);
    bench_truncate_prefix(c);
    bench_leaf_guard(c);
}

criterion_group!(benches, bench);
criterion_main!(benches);
