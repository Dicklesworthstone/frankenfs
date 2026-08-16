#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Scrub and RaptorQ codec benchmarks for ffs-repair.
//!
//! Measures:
//! - Scrub latency over clean vs. corrupted block ranges.
//! - RaptorQ encode/decode throughput for 16-block repair groups.

use asupersync::Cx;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice, ByteBlockDevice, ByteDevice};
use ffs_error::Result;
use ffs_repair::autopilot::{RefreshLossModel, WorkloadProfile};
use ffs_repair::codec::{decode_group, decode_group_with_owned_repair_symbols, encode_group};
use ffs_repair::lrc::{LrcConfig, encode_global};
use ffs_repair::scrub::{BlockValidator, BlockVerdict, Scrubber, ZeroCheckValidator};
use ffs_types::{BlockNumber, ByteOffset, GroupNumber};
use parking_lot::Mutex;
use std::hint::black_box;

const BLOCK_SIZE: u32 = 4096;
const SCRUB_BLOCK_COUNT: u64 = 256;
const RAPTORQ_SOURCE_BLOCKS: u32 = 16;
const RAPTORQ_REPAIR_COUNT: u32 = 4;
const LRC_DATA_BLOCKS: u32 = 64;
const LRC_LOCAL_GROUP_SIZE: u32 = 8;
const LRC_GLOBAL_PARITY_COUNT: u32 = 8;

// ── In-memory ByteDevice ──────────────────────────────────────────────────

#[derive(Debug)]
struct MemByteDevice {
    bytes: Mutex<Vec<u8>>,
}

impl MemByteDevice {
    fn new(size: usize) -> Self {
        Self {
            bytes: Mutex::new(vec![0u8; size]),
        }
    }
}

impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes.lock().len() as u64
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let off = offset.0 as usize;
        let guard = self.bytes.lock();
        buf.copy_from_slice(&guard[off..off + buf.len()]);
        drop(guard);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let off = offset.0 as usize;
        let mut guard = self.bytes.lock();
        guard[off..off + buf.len()].copy_from_slice(buf);
        drop(guard);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn make_device(block_count: usize) -> ByteBlockDevice<MemByteDevice> {
    let mem = MemByteDevice::new(BLOCK_SIZE as usize * block_count);
    ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device")
}

/// Fill device blocks with deterministic non-zero data.
fn fill_device(cx: &Cx, device: &impl BlockDevice, count: u64) {
    for i in 0..count {
        let mut data = vec![0u8; BLOCK_SIZE as usize];
        // Fill with block-number-derived pattern so blocks are distinct.
        let seed = (i as u32).to_le_bytes();
        for chunk in data.chunks_mut(4) {
            chunk.copy_from_slice(&seed);
        }
        device
            .write_block(cx, BlockNumber(i), &data)
            .expect("write");
    }
}

// ── Scrub benchmarks ──────────────────────────────────────────────────────

/// Validator that marks specific blocks as corrupt (for benchmarking the
/// corruption detection path).
struct CorruptEveryNthValidator {
    every_n: u64,
}

impl BlockValidator for CorruptEveryNthValidator {
    fn validate(&self, block: BlockNumber, _data: &BlockBuf) -> BlockVerdict {
        if block.0.is_multiple_of(self.every_n) && block.0 > 0 {
            BlockVerdict::Corrupt(vec![(
                ffs_repair::scrub::CorruptionKind::ChecksumMismatch,
                ffs_repair::scrub::Severity::Error,
                format!("synthetic corruption at block {}", block.0),
            )])
        } else {
            BlockVerdict::Clean
        }
    }
}

fn bench_scrub(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let device = make_device(SCRUB_BLOCK_COUNT as usize);
    fill_device(&cx, &device, SCRUB_BLOCK_COUNT);

    // Scrub 256 clean blocks (zero-check validator on non-zero data = all clean).
    let clean_validator = ZeroCheckValidator;
    c.bench_function("scrub_clean_256blocks", |b| {
        b.iter(|| {
            let scrubber = Scrubber::new(&device, &clean_validator);
            let report = scrubber
                .scrub_range(&cx, BlockNumber(0), SCRUB_BLOCK_COUNT)
                .expect("scrub");
            assert_eq!(report.blocks_scanned, SCRUB_BLOCK_COUNT);
        });
    });

    // Scrub 256 blocks with ~10% corruption (every 10th block).
    let corrupt_validator = CorruptEveryNthValidator { every_n: 10 };
    c.bench_function("scrub_corrupted_256blocks", |b| {
        b.iter(|| {
            let scrubber = Scrubber::new(&device, &corrupt_validator);
            let report = scrubber
                .scrub_range(&cx, BlockNumber(0), SCRUB_BLOCK_COUNT)
                .expect("scrub");
            assert!(report.blocks_corrupt > 0);
        });
    });
}

// ── RaptorQ codec benchmarks ──────────────────────────────────────────────

fn bench_raptorq_codec(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let device = make_device(RAPTORQ_SOURCE_BLOCKS as usize);
    fill_device(&cx, &device, u64::from(RAPTORQ_SOURCE_BLOCKS));

    let fs_uuid: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let group = GroupNumber(0);

    // Encode benchmark.
    c.bench_function("raptorq_encode_group_16blocks", |b| {
        b.iter(|| {
            let encoded = encode_group(
                &cx,
                &device,
                &fs_uuid,
                group,
                BlockNumber(0),
                RAPTORQ_SOURCE_BLOCKS,
                RAPTORQ_REPAIR_COUNT,
            )
            .expect("encode");
            assert_eq!(encoded.repair_symbols.len(), RAPTORQ_REPAIR_COUNT as usize);
        });
    });

    // Pre-encode for decode benchmark.
    let encoded = encode_group(
        &cx,
        &device,
        &fs_uuid,
        group,
        BlockNumber(0),
        RAPTORQ_SOURCE_BLOCKS,
        RAPTORQ_REPAIR_COUNT,
    )
    .expect("encode for decode");

    let repair_symbols: Vec<(u32, Vec<u8>)> = encoded
        .repair_symbols
        .iter()
        .map(|s| (s.esi, s.data.clone()))
        .collect();

    // Corrupt indices: blocks 0 and 1 (2 blocks to recover).
    let corrupt_indices = [0_u32, 1];

    // Decode benchmark.
    c.bench_function("raptorq_decode_group_16blocks", |b| {
        b.iter(|| {
            let outcome = decode_group(
                &cx,
                &device,
                &fs_uuid,
                group,
                BlockNumber(0),
                RAPTORQ_SOURCE_BLOCKS,
                &corrupt_indices,
                &repair_symbols,
            )
            .expect("decode");
            assert!(outcome.complete);
        });
    });

    c.bench_function("raptorq_decode_group_owned_symbols_16blocks", |b| {
        b.iter_batched(
            || repair_symbols.clone(),
            |symbols| {
                let outcome = decode_group_with_owned_repair_symbols(
                    &cx,
                    &device,
                    &fs_uuid,
                    group,
                    BlockNumber(0),
                    RAPTORQ_SOURCE_BLOCKS,
                    &corrupt_indices,
                    symbols,
                )
                .expect("decode");
                assert!(outcome.complete);
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("raptorq_decode_group_no_corruption_16blocks", |b| {
        b.iter(|| {
            let outcome = decode_group(
                &cx,
                &device,
                &fs_uuid,
                group,
                BlockNumber(0),
                RAPTORQ_SOURCE_BLOCKS,
                &[],
                &repair_symbols,
            )
            .expect("decode");
            assert!(outcome.complete);
            assert!(outcome.recovered.is_empty());
        });
    });
}

// ── LRC global parity benchmarks ───────────────────────────────────────────

fn make_lrc_data(block_count: u32, block_size: usize) -> Vec<Vec<u8>> {
    (0..block_count)
        .map(|block| {
            (0..block_size)
                .map(|byte| {
                    u8::try_from((u64::from(block) * 131 + byte as u64 * 17 + 29) % 251)
                        .expect("pattern byte fits")
                })
                .collect()
        })
        .collect()
}

fn bench_lrc_codec(c: &mut Criterion) {
    let config = LrcConfig::new(
        LRC_DATA_BLOCKS,
        LRC_LOCAL_GROUP_SIZE,
        LRC_GLOBAL_PARITY_COUNT,
    );
    let data = make_lrc_data(LRC_DATA_BLOCKS, BLOCK_SIZE as usize);

    c.bench_function("lrc_encode_global_64blocks_8parity", |b| {
        b.iter(|| {
            let global = encode_global(&config, &data);
            assert_eq!(global.len(), LRC_GLOBAL_PARITY_COUNT as usize);
        });
    });
}

// ── Refresh policy/staleness benchmarks ───────────────────────────────────

fn bench_refresh_policy_staleness(c: &mut Criterion) {
    let model = RefreshLossModel::default();
    let profiles = WorkloadProfile::ALL;

    c.bench_function("repair_symbol_refresh_staleness_latency", |b| {
        b.iter(|| {
            let mut combined_loss = 0.0;
            for profile in profiles {
                let comparison = model.compare_policies(30.0, 500, profile);
                combined_loss += comparison.loss_age_only;
                combined_loss += comparison.loss_block_count;
                combined_loss += comparison.loss_hybrid;
                black_box(comparison.best_policy);
            }
            black_box(combined_loss);
        });
    });
}

// ── A/B: scrub buffer preparation (bd-xmh5g.7) ──────────────────────────────
//
// Same-binary A/B isolating the buffer-prep cost the lever changed. The scrub
// loop reads SCRUB_READ_BATCH_BLOCKS (64) blocks per batched preadv; an 8 MiB
// scrub is 32 batches. `old_zero_per_batch` allocates + zeroes 64 fresh
// BlockBufs every batch (the previous behaviour: BlockBuf::new(Vec::new()) per
// batch, then read_contiguous_blocks zeroed each). `new_reuse_pool` allocates
// the pool once and skips re-zeroing already-sized buffers — preadv overwrites
// every byte, so the zero is pure waste. `simulate_read_fill` stands in for the
// preadv overwrite so both arms touch every byte identically.
const PREP_BATCH: usize = 64;
const PREP_BATCHES: usize = 32;

fn simulate_read_fill(bufs: &mut [BlockBuf]) {
    for buf in &mut *bufs {
        let slice = buf.make_mut();
        let n = slice.len();
        slice[0] = black_box(0xAB);
        slice[n / 2] = black_box(0xCD);
        slice[n - 1] = black_box(0xEF);
    }
}

fn bench_scrub_buffer_prep(c: &mut Criterion) {
    let block = BLOCK_SIZE as usize;
    let mut group = c.benchmark_group("scrub_buffer_prep");

    group.bench_function("old_zero_per_batch", |b| {
        b.iter(|| {
            for _ in 0..PREP_BATCHES {
                let mut bufs: Vec<BlockBuf> =
                    (0..PREP_BATCH).map(|_| BlockBuf::zeroed(block)).collect();
                simulate_read_fill(&mut bufs);
                black_box(&bufs);
            }
        });
    });

    group.bench_function("new_reuse_pool", |b| {
        b.iter(|| {
            let mut bufs: Vec<BlockBuf> = Vec::new();
            for _ in 0..PREP_BATCHES {
                if bufs.len() < PREP_BATCH {
                    bufs.resize_with(PREP_BATCH, || BlockBuf::new(Vec::new()));
                }
                for buf in &mut bufs {
                    if buf.len() != block {
                        *buf = BlockBuf::zeroed(block);
                    }
                }
                simulate_read_fill(&mut bufs[..PREP_BATCH]);
                black_box(&bufs);
            }
        });
    });

    group.finish();
}

criterion_group!(
    repair_benches,
    bench_scrub,
    bench_scrub_buffer_prep,
    bench_raptorq_codec,
    bench_lrc_codec,
    bench_refresh_policy_staleness
);
criterion_main!(repair_benches);
