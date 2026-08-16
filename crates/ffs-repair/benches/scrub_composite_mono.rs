#![forbid(unsafe_code)]

//! Same-process A/B for monomorphising the btrfs scrub validator.
//!
//! `CompositeValidator::validate` runs on EVERY scanned block and loops
//! `Vec<Box<dyn BlockValidator>>` = 3 vtable-indirect calls (`ZeroCheck`,
//! `BtrfsSuperblock`, `BtrfsTreeBlock`) + a `Vec::new()` + the merge match, per
//! block. After the fsid pre-check (e8932055) and the division hoist (9f790529)
//! made each validator cheap, that dynamic-dispatch overhead is a large share of
//! the remaining per-block validation — LLVM cannot inline/hoist across the
//! `dyn` calls. This benches the real `CompositeValidator` (dynamic) against a
//! hand-inlined monomorphic equivalent doing the same three checks, on a
//! data-heavy block set (non-zero, fsid never matching, not the superblock — the
//! common non-metadata case that reaches a Clean verdict).
//!
//! Run per-crate:
//!   rch exec -- cargo bench --profile release-perf -p ffs-repair --bench scrub_composite_mono

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::BlockBuf;
use ffs_repair::scrub::{
    BlockValidator, BlockVerdict, BtrfsScrubValidator, BtrfsSuperblockValidator,
    BtrfsTreeBlockValidator, CompositeValidator, ZeroCheckValidator,
};
use ffs_types::BlockNumber;
use std::hint::black_box;

const BLOCK: usize = 16_384; // btrfs nodesize
const N: usize = 256;
const BLOCK_SIZE: u32 = 16_384;
const SUPER_INFO_OFFSET: u64 = 64 * 1024;
const FSID: [u8; 16] = [0x11; 16];
const CSUM_CRC32C: u16 = 0;
/// Filesystem size: too small to span any superblock mirror, so only the primary
/// is a validator target (the bench only touches data blocks 100.. anyway).
const TOTAL_BYTES: u64 = 1 << 20;

// The `as u8` below is a deliberate truncation: this synthesises a byte
// pattern, so only the low 8 bits are wanted. Same form the gf256 tables in
// lrc.rs use for the same reason.
#[expect(clippy::cast_possible_truncation, reason = "synthetic byte pattern")]
fn make_block(seed: usize) -> Vec<u8> {
    let mut b = vec![0u8; BLOCK];
    for (i, x) in b.iter_mut().enumerate() {
        *x = ((i.wrapping_mul(31).wrapping_add(seed).wrapping_add(7)) | 1) as u8; // never 0
    }
    for x in &mut b[0x20..0x30] {
        *x = 0x22; // fsid region != FSID
    }
    b
}

/// Word-wise all-zeros test (mirrors production `is_all_zero`).
fn is_all_zero(data: &[u8]) -> bool {
    let (chunks, remainder) = data.as_chunks::<8>();
    chunks.iter().all(|c| u64::from_ne_bytes(*c) == 0) && remainder.iter().all(|&b| b == 0)
}

/// Monomorphic inline of the 3-validator btrfs composite for the common
/// (non-metadata, non-superblock, non-zero) block → Clean. Precomputed block
/// numbers, no dyn dispatch, no per-block Vec.
fn mono_validate(block: u64, data: &[u8], sb_block: u64) -> u8 {
    // ZeroCheck (stage 1)
    if is_all_zero(data) {
        return 2; // Corrupt(UnexpectedZeroes)
    }
    // BtrfsSuperblock (stage 2): Skip unless target
    // BtrfsTreeBlock (stage 3): Skip if superblock block, else fsid pre-check
    if block != sb_block && data.get(0x20..0x30) != Some(&FSID[..]) {
        // both metadata validators Skip; ZeroCheck was Clean → checked, no issues
        return 1; // Clean
    }
    // (would descend into a real superblock/tree-block validation — not the
    // data-block common case this bench targets)
    1
}

/// Capturable-in-production variant: a concrete monomorphic validator that
/// takes `&BlockBuf` (calls `as_slice` ONCE, unlike the 3 dyn validators which
/// each Arc-deref) and returns a real `BlockVerdict`, inlining the same three
/// checks. This is what a production `BtrfsScrubValidator` concrete type would
/// do — no `Vec<Box<dyn>>`, no per-validator vtable call, no per-block merge Vec.
struct BtrfsMonoValidator {
    sb_block: u64,
    fsid: [u8; 16],
}
impl BtrfsMonoValidator {
    fn validate(&self, block: u64, buf: &BlockBuf) -> BlockVerdict {
        let data = buf.as_slice();
        // ZeroCheck (stage 1)
        if is_all_zero(data) {
            return BlockVerdict::Corrupt(vec![(
                ffs_repair::scrub::CorruptionKind::UnexpectedZeroes,
                ffs_repair::scrub::Severity::Warning,
                "block is entirely zeroed".to_owned(),
            )]);
        }
        // Superblock (stage 2): Skip unless target. TreeBlock (stage 3): Skip
        // unless this is not the superblock block and the fsid matches.
        if block != self.sb_block && data.get(0x20..0x30) != Some(&self.fsid[..]) {
            // both metadata validators Skip; ZeroCheck was Clean and checked
            // -> composite verdict Clean.
            return BlockVerdict::Clean;
        }
        // (real path would descend into superblock/tree-block validation)
        BlockVerdict::Clean
    }
}

fn verdict_code(v: &BlockVerdict) -> u8 {
    match v {
        BlockVerdict::Skip => 0,
        BlockVerdict::Clean => 1,
        BlockVerdict::Corrupt(_) => 2,
    }
}

fn bench(c: &mut Criterion) {
    let raw: Vec<Vec<u8>> = (0..N).map(make_block).collect();
    let bufs: Vec<BlockBuf> = raw.iter().map(|b| BlockBuf::new(b.clone())).collect();
    let sb_block = SUPER_INFO_OFFSET / u64::from(BLOCK_SIZE);
    let mono_bb = BtrfsMonoValidator {
        sb_block,
        fsid: FSID,
    };
    // The ACTUAL production type this bench justifies.
    let prod = BtrfsScrubValidator::new(BLOCK_SIZE, FSID, CSUM_CRC32C, TOTAL_BYTES);

    let composite = CompositeValidator::new(vec![
        Box::new(ZeroCheckValidator),
        Box::new(BtrfsSuperblockValidator::new(BLOCK_SIZE, TOTAL_BYTES)),
        Box::new(BtrfsTreeBlockValidator::new(BLOCK_SIZE, FSID, CSUM_CRC32C)),
    ]);

    // Equivalence: the two paths agree on every data block (block numbers 100..).
    for (i, buf) in bufs.iter().enumerate() {
        let b = 100 + i as u64;
        let c = verdict_code(&composite.validate(BlockNumber(b), buf));
        let m = mono_validate(b, &raw[i], sb_block);
        let mb = verdict_code(&mono_bb.validate(b, buf));
        let pv = verdict_code(&prod.validate(BlockNumber(b), buf));
        assert_eq!(c, m, "verdicts must match at block {b}");
        assert_eq!(c, mb, "mono_bb verdict must match at block {b}");
        assert_eq!(
            c, pv,
            "BtrfsScrubValidator verdict must match composite at block {b}"
        );
        assert_eq!(c, 1, "data block should be Clean");
    }

    let mut g = c.benchmark_group("scrub_btrfs_composite_validate_256");
    g.bench_function("composite_dyn", |bch| {
        bch.iter(|| {
            let mut acc = 0u64;
            for (i, buf) in bufs.iter().enumerate() {
                let b = 100 + i as u64;
                acc += u64::from(verdict_code(
                    &composite.validate(black_box(BlockNumber(b)), black_box(buf)),
                ));
            }
            black_box(acc);
        });
    });
    g.bench_function("monomorphic_inline", |bch| {
        bch.iter(|| {
            let mut acc = 0u64;
            for (i, r) in raw.iter().enumerate() {
                let b = 100 + i as u64;
                acc += u64::from(mono_validate(
                    black_box(b),
                    black_box(r),
                    black_box(sb_block),
                ));
            }
            black_box(acc);
        });
    });
    g.bench_function("btrfs_scrub_validator", |bch| {
        bch.iter(|| {
            let mut acc = 0u64;
            for (i, buf) in bufs.iter().enumerate() {
                let b = 100 + i as u64;
                acc += u64::from(verdict_code(
                    &prod.validate(black_box(BlockNumber(b)), black_box(buf)),
                ));
            }
            black_box(acc);
        });
    });
    g.bench_function("monomorphic_blockbuf", |bch| {
        bch.iter(|| {
            let mut acc = 0u64;
            for (i, buf) in bufs.iter().enumerate() {
                let b = 100 + i as u64;
                acc += u64::from(verdict_code(
                    &mono_bb.validate(black_box(b), black_box(buf)),
                ));
            }
            black_box(acc);
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
