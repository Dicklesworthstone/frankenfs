#![forbid(unsafe_code)]

//! A/B benchmark for the JBD2 data-block padding buffer prep in the per-commit
//! journal write path (`Jbd2Writer::commit_transaction`).
//!
//! Each journaled block write builds a `bs`-sized buffer. The old code did
//! `vec![0u8; bs]` (a full-block zero-init) then `copy_from_slice(payload)`; for
//! the common full-block payload the zero-init is entirely overwritten. The new
//! code copies the payload directly (`payload[..bs].to_vec()`) for full blocks
//! and only zero-pads short payloads. This measures whether skipping the
//! redundant zero-init is a real saving. Both produce byte-identical buffers.

use criterion::{Criterion, criterion_group, criterion_main};
use std::borrow::Cow;
use std::hint::black_box;

const BS: usize = 4096;
const JBD2_MAGIC: u32 = 0xC03B_3998;
/// One descriptor group's worth of data blocks, so per-iteration harness
/// overhead is amortized across a realistic commit chunk.
const BLOCKS: usize = 256;

/// Old strategy: zero-init the block, then copy the payload over it.
fn prep_zero_init(payload: &[u8]) -> Vec<u8> {
    let mut padded = vec![0_u8; BS];
    let copy_len = payload.len().min(BS);
    padded[..copy_len].copy_from_slice(&payload[..copy_len]);
    padded
}

/// New strategy: full-block payloads copy directly (no zero-init); short
/// payloads still zero-pad to the block size.
fn prep_skip_zero_init(payload: &[u8]) -> Vec<u8> {
    let copy_len = payload.len().min(BS);
    if copy_len == BS {
        payload[..BS].to_vec()
    } else {
        let mut p = vec![0_u8; BS];
        p[..copy_len].copy_from_slice(&payload[..copy_len]);
        p
    }
}

/// Frozen production shape after zero-fill elision: every full payload still
/// becomes a temporary owned block before `write_block(&[u8])` consumes it.
fn prep_owned_payload(payload: &[u8]) -> Cow<'_, [u8]> {
    let copy_len = payload.len().min(BS);
    let escaped = payload.len() >= 4 && payload[0..4] == JBD2_MAGIC.to_be_bytes();
    let mut padded = if copy_len == BS {
        payload[..BS].to_vec()
    } else {
        let mut p = vec![0_u8; BS];
        p[..copy_len].copy_from_slice(&payload[..copy_len]);
        p
    };
    if escaped {
        padded[0..4].copy_from_slice(&[0_u8; 4]);
    }
    Cow::Owned(padded)
}

/// Candidate production shape: borrow an exact full block unless JBD2 escape
/// mutation or short-payload zero padding requires ownership.
fn prep_borrow_exact_payload(payload: &[u8]) -> Cow<'_, [u8]> {
    let copy_len = payload.len().min(BS);
    let escaped = payload.len() >= 4 && payload[0..4] == JBD2_MAGIC.to_be_bytes();
    if copy_len == BS && !escaped {
        Cow::Borrowed(&payload[..BS])
    } else {
        let mut padded = if copy_len == BS {
            payload[..BS].to_vec()
        } else {
            let mut p = vec![0_u8; BS];
            p[..copy_len].copy_from_slice(&payload[..copy_len]);
            p
        };
        if escaped {
            padded[0..4].copy_from_slice(&[0_u8; 4]);
        }
        Cow::Owned(padded)
    }
}

fn prep_payload_chunk(payload: &[u8], prep: for<'a> fn(&'a [u8]) -> Cow<'a, [u8]>) -> u64 {
    let mut acc = 0_u64;
    for _ in 0..BLOCKS {
        let padded = prep(black_box(payload));
        acc = acc
            .wrapping_add(u64::from(padded[0]))
            .wrapping_add(u64::from(padded[BS - 1]));
        black_box(padded);
    }
    acc
}

fn prep_chunk<F: Fn(&[u8]) -> Vec<u8>>(payload: &[u8], prep: F) -> u64 {
    let mut acc = 0_u64;
    for _ in 0..BLOCKS {
        let padded = prep(black_box(payload));
        // Touch first + last byte so the buffer build cannot be elided.
        acc = acc
            .wrapping_add(u64::from(padded[0]))
            .wrapping_add(u64::from(padded[BS - 1]));
    }
    acc
}

fn bench_jbd2_data_block_prep(c: &mut Criterion) {
    let full = vec![0xAB_u8; BS];
    let short = vec![0xCD_u8; 100];

    // Byte-identity: both strategies produce the same buffer for full and short
    // payloads (the padded tail zeros are what the short arm preserves).
    assert_eq!(
        prep_zero_init(&full),
        prep_skip_zero_init(&full),
        "full-block prep diverged"
    );
    assert_eq!(
        prep_zero_init(&short),
        prep_skip_zero_init(&short),
        "short-payload prep diverged"
    );

    let mut group = c.benchmark_group("jbd2_data_block_prep_256x4096");
    group.bench_function("zero_init_then_copy_a", |b| {
        b.iter(|| black_box(prep_chunk(black_box(&full), prep_zero_init)));
    });
    group.bench_function("zero_init_then_copy_b", |b| {
        b.iter(|| black_box(prep_chunk(black_box(&full), prep_zero_init)));
    });
    group.bench_function("skip_zero_init", |b| {
        b.iter(|| black_box(prep_chunk(black_box(&full), prep_skip_zero_init)));
    });
    group.finish();

    let mut escaped = full.clone();
    escaped[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    for payload in [&full[..], &short[..], &escaped[..]] {
        assert_eq!(
            prep_owned_payload(payload).as_ref(),
            prep_borrow_exact_payload(payload).as_ref(),
            "payload preparation bytes diverged"
        );
    }
    let borrowed = prep_borrow_exact_payload(&full);
    assert!(matches!(borrowed, Cow::Borrowed(_)));
    assert_eq!(borrowed.as_ptr(), full.as_ptr());
    assert!(matches!(prep_borrow_exact_payload(&short), Cow::Owned(_)));
    assert!(matches!(prep_borrow_exact_payload(&escaped), Cow::Owned(_)));

    let mut group = c.benchmark_group("jbd2_full_block_payload_ownership_256x4096");
    group.sample_size(10);
    group.bench_function("owned_copy_a", |b| {
        b.iter(|| black_box(prep_payload_chunk(black_box(&full), prep_owned_payload)));
    });
    group.bench_function("owned_copy_b", |b| {
        b.iter(|| black_box(prep_payload_chunk(black_box(&full), prep_owned_payload)));
    });
    group.bench_function("borrow_exact_full_block", |b| {
        b.iter(|| {
            black_box(prep_payload_chunk(
                black_box(&full),
                prep_borrow_exact_payload,
            ))
        });
    });
    group.finish();
}

// ── legacy tag data-checksum elision ───────────────────────────────────────
//
// `stamp_jbd2_tag_data_checksum` used to compute a full data-block CRC up front
// and then discard it for the `Legacy` tag format (legacy tags carry no data
// checksum). The lever moves the CRC into the checksummed arms so legacy
// journals skip it. This measures the per-block CRC that legacy writes no longer
// pay. `checksum_jbd2_data_block` mirrors the private production helper exactly.

fn checksum_jbd2_data_block(block: &[u8], sequence: u32, seed: u32) -> u32 {
    let sequence = sequence.to_be_bytes();
    let checksum = crc32c::crc32c_append(!seed, &sequence);
    !crc32c::crc32c_append(checksum, block)
}

/// Old legacy path: compute the data-block CRC, then discard it. `black_box` on
/// the result models production, where the value was assigned before the match
/// and so computed unconditionally (a pure call the optimizer cannot elide).
fn legacy_stamp_old(data: &[u8], seq: u32, seed: u32) -> u64 {
    let mut acc = 0_u64;
    for _ in 0..BLOCKS {
        let checksum = checksum_jbd2_data_block(black_box(data), seq, seed);
        acc = acc.wrapping_add(u64::from(black_box(checksum)));
    }
    acc
}

/// New legacy path: no data-block CRC at all.
fn legacy_stamp_new(data: &[u8], _seq: u32, _seed: u32) -> u64 {
    let mut acc = 0_u64;
    for i in 0..BLOCKS {
        // Touch the data pointer so both arms observe the same input, without
        // hashing it.
        acc = acc
            .wrapping_add(i as u64)
            .wrapping_add(u64::from(black_box(data)[0]));
    }
    acc
}

fn bench_jbd2_legacy_tag_stamp(c: &mut Criterion) {
    let data = vec![0x5A_u8; BS];
    let seq = 0x0123_4567_u32;
    let seed = 0x89AB_CDEF_u32;

    let mut group = c.benchmark_group("jbd2_legacy_tag_stamp_256x4096");
    group.bench_function("compute_and_discard_crc_a", |b| {
        b.iter(|| black_box(legacy_stamp_old(black_box(&data), seq, seed)));
    });
    group.bench_function("compute_and_discard_crc_b", |b| {
        b.iter(|| black_box(legacy_stamp_old(black_box(&data), seq, seed)));
    });
    group.bench_function("skip_crc", |b| {
        b.iter(|| black_box(legacy_stamp_new(black_box(&data), seq, seed)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_jbd2_data_block_prep,
    bench_jbd2_legacy_tag_stamp
);
criterion_main!(benches);
