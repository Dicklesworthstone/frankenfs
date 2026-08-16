#![forbid(unsafe_code)]

//! Same-process A/B for the btrfs scrub `BtrfsTreeBlockValidator` fsid pre-check.
//!
//! `validate` runs on EVERY block of the device. The old form calls
//! `BtrfsHeader::parse_from_block` (copies csum[32]+fsid[16]+chunk_tree_uuid[16]
//! = 64 bytes + reads ~8 integer fields) and only then rejects on fsid mismatch.
//! On a data-heavy image the `ZeroCheckValidator` ahead of it early-exits at the
//! first non-zero byte, so this header parse is the dominant per-block cost — yet
//! ~every block is non-metadata and gets rejected. The new form does a 16-byte
//! fsid compare (block[0x20..0x30] vs this fs's fsid) BEFORE the parse and skips
//! it for every non-matching block. Behaviour-identical (parse also rejects on
//! fsid mismatch). This benches the two on a realistic data-heavy block set
//! (non-zero bytes, fsid never matching → the common non-metadata case).
//!
//! RESULT (2026-07-04, BlackThrush): WIN — LANDED. release-perf / opt-3, rch:
//!   old_parse_always  611.6 ns  vs  new_fsid_precheck  402.0 ns  = ~1.52x
//! for a 256-block batch of data-heavy (non-metadata) blocks. Behaviour-identical
//! (the equivalence assert below passed over all 256 varied blocks; ffs-repair
//! btrfs_tree validator tests + full suite green). The 16-byte fsid pre-check
//! skips the ~64-byte header copy + field parse for every non-metadata block.
//! Real scrub impact scales with the DATA-HEAVY fraction of the image (where the
//! preceding ZeroCheck early-exits at the first non-zero byte, leaving this
//! header parse as the dominant per-block cost); ~neutral on mostly-zero images
//! (ZeroCheck's full-block scan dominates there). Run per-crate:
//!   rch exec -- cargo bench --profile release-perf -p ffs-repair --bench scrub_fsid_precheck

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::BtrfsHeader;
use std::hint::black_box;

const BLOCK: usize = 16_384; // btrfs nodesize
const N: usize = 256; // blocks per iter (one read batch worth)
const FSID: [u8; 16] = [0x11; 16]; // this filesystem's fsid

/// A data-heavy block: non-zero bytes, fsid region (0x20..0x30) NOT matching FSID.
// Deliberate truncation: this synthesises a byte pattern, so only the low 8
// bits are wanted.
#[expect(clippy::cast_possible_truncation, reason = "synthetic byte pattern")]
fn make_block(seed: usize) -> Vec<u8> {
    let mut b = vec![0u8; BLOCK];
    for (i, x) in b.iter_mut().enumerate() {
        *x = ((i.wrapping_mul(31).wrapping_add(seed).wrapping_add(7)) | 1) as u8; // never 0
    }
    // ensure fsid region differs from FSID (0x11 repeated)
    for x in &mut b[0x20..0x30] {
        *x = 0x22;
    }
    b
}

/// OLD: parse the full header, then reject on fsid mismatch.
fn old_validate(slice: &[u8]) -> bool {
    // true == metadata candidate
    BtrfsHeader::parse_from_block(slice).is_ok_and(|header| header.fsid == FSID)
}

/// NEW: 16-byte fsid pre-check, only parse on match.
fn new_validate(slice: &[u8]) -> bool {
    if slice.get(0x20..0x30) != Some(&FSID[..]) {
        return false;
    }
    matches!(BtrfsHeader::parse_from_block(slice), Ok(h) if h.fsid == FSID)
}

fn bench(c: &mut Criterion) {
    let blocks: Vec<Vec<u8>> = (0..N).map(make_block).collect();

    // Equivalence: both reject every non-metadata block.
    for b in &blocks {
        assert_eq!(old_validate(b), new_validate(b), "verdicts must match");
        assert!(!new_validate(b));
    }

    let mut g = c.benchmark_group("scrub_btrfs_treeblock_validate_256");
    g.bench_function("old_parse_always", |bch| {
        bch.iter(|| {
            let mut acc = 0u64;
            for b in &blocks {
                acc += u64::from(old_validate(black_box(b)));
            }
            black_box(acc);
        });
    });
    g.bench_function("new_fsid_precheck", |bch| {
        bch.iter(|| {
            let mut acc = 0u64;
            for b in &blocks {
                acc += u64::from(new_validate(black_box(b)));
            }
            black_box(acc);
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
