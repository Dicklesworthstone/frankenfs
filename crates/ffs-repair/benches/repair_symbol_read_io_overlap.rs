#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the repair-symbol block reads in
//! `RepairGroupStorage::read_symbols_for_desc` / `read_raw_symbols` (bd-w52e5).
//!
//! Both functions read `desc.repair_block_count` repair-symbol blocks with a
//! serial loop before the decoder runs, so a recovery serializes that many
//! device-read access latencies up front. The block reads are independent; only
//! the parse afterward is sequential (ESI threading / empty-tail check). The
//! lever reads all blocks across the rayon pool (`read_blocks_parallel`) and
//! then parses serially in block order, so a blocking read parks its worker and
//! the access latencies overlap up to the pool size (bd-307e4/bd-g5v1s family),
//! while parse order / error order stay byte-identical.
//!
//! This bench isolates the read+parse split on a `LatencyBlockDevice` (a fixed
//! per-read latency park plus a cheap memcpy from a pre-built store, the
//! production cost shape), using the raw-symbol parse (first `symbol_size` bytes,
//! zero-skip) as the representative parse. Both arms produce the identical
//! symbol batch in order (asserted), so this measures only the read overlap.

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const BS: usize = 4096; // block size (bytes)
const SYMBOL_SIZE: usize = 1024; // raw symbol size
/// Per-block read access latency. Models a real-disk / SSD-queue round trip.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

fn block_bytes(blk: u64) -> Vec<u8> {
    // Non-zero so the zero-skip never fires (every block yields a symbol).
    (0..BS).map(|i| prng(blk << 20 ^ i as u64) | 1).collect()
}

/// Latency-injecting in-memory device (blocks pre-built once).
struct LatencyBlockDevice {
    blocks: Vec<BlockBuf>,
    read_latency: Duration,
}

impl LatencyBlockDevice {
    fn new(block_count: u64, read_latency: Duration) -> Self {
        let blocks = (0..block_count)
            .map(|blk| BlockBuf::new(block_bytes(blk)))
            .collect();
        Self {
            blocks,
            read_latency,
        }
    }

    fn block(&self, block: BlockNumber) -> Result<BlockBuf> {
        let idx = usize::try_from(block.0)
            .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
        self.blocks
            .get(idx)
            .map(BlockBuf::clone_ref)
            .ok_or_else(|| FfsError::Format(format!("bench block out of range: {}", block.0)))
    }
}

impl BlockDevice for LatencyBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        std::thread::sleep(self.read_latency);
        self.block(block)
    }

    fn supports_contiguous_reads(&self) -> bool {
        false
    }

    fn read_contiguous_blocks(
        &self,
        _cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        std::thread::sleep(self.read_latency);
        for (i, buf) in bufs.iter_mut().enumerate() {
            *buf = self.block(BlockNumber(start.0 + i as u64))?;
        }
        Ok(())
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn block_size(&self) -> u32 {
        BS as u32
    }

    fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

type SymbolBatch = Vec<(u32, Vec<u8>)>;

fn symbol_slice(bytes: &[u8]) -> Result<&[u8]> {
    bytes
        .get(..SYMBOL_SIZE)
        .ok_or_else(|| FfsError::RepairFailed("raw symbol slice out of bounds".into()))
}

fn all_zero_unrolled4(data: &[u8]) -> bool {
    let (chunks, rem) = data.as_chunks::<32>();
    for block in chunks {
        let w0 = u64::from_ne_bytes(block[0..8].try_into().unwrap());
        let w1 = u64::from_ne_bytes(block[8..16].try_into().unwrap());
        let w2 = u64::from_ne_bytes(block[16..24].try_into().unwrap());
        let w3 = u64::from_ne_bytes(block[24..32].try_into().unwrap());
        if (w0 | w1 | w2 | w3) != 0 {
            return false;
        }
    }
    let (tail, tail_rem) = rem.as_chunks::<8>();
    tail.iter().all(|chunk| u64::from_ne_bytes(*chunk) == 0)
        && tail_rem.iter().all(|&byte| byte == 0)
}

/// Representative raw-symbol parse: first `SYMBOL_SIZE` bytes, skip all-zero.
fn parse_symbol(block_index: u32, bytes: &[u8]) -> Result<Option<(u32, Vec<u8>)>> {
    let symbol = symbol_slice(bytes)?.to_vec();
    if symbol.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    Ok(Some((block_index, symbol)))
}

/// NEW raw-symbol parse shape: skip the allocation/copy for all-zero symbols.
fn parse_symbol_zero_then_copy(block_index: u32, bytes: &[u8]) -> Result<Option<(u32, Vec<u8>)>> {
    let symbol = symbol_slice(bytes)?;
    if all_zero_unrolled4(symbol) {
        return Ok(None);
    }
    Ok(Some((block_index, symbol.to_vec())))
}

/// OLD: serial read loop, parse inline — N read latencies back to back.
fn read_serial(cx: &Cx, device: &dyn BlockDevice, blocks: &[BlockNumber]) -> Result<SymbolBatch> {
    let mut out = Vec::new();
    for (i, &block) in blocks.iter().enumerate() {
        let bytes = device.read_block(cx, block)?;
        if let Some(sym) = parse_symbol(i as u32, bytes.as_slice())? {
            out.push(sym);
        }
    }
    Ok(out)
}

/// NEW: parallel reads, then serial parse in block order.
fn read_parallel(cx: &Cx, device: &dyn BlockDevice, blocks: &[BlockNumber]) -> Result<SymbolBatch> {
    let reads: Vec<Result<BlockBuf>> = blocks
        .par_iter()
        .map(|&block| device.read_block(cx, block))
        .collect();
    let mut out = Vec::new();
    for (i, read) in reads.into_iter().enumerate() {
        let bytes = read?;
        if let Some(sym) = parse_symbol(i as u32, bytes.as_slice())? {
            out.push(sym);
        }
    }
    Ok(out)
}

// The criterion group's lifetime is deliberate: it spans every input size
// before finish(). Tightening it would reshape the measured region.
#[expect(
    clippy::significant_drop_tightening,
    reason = "criterion group scope is intentional"
)]
fn bench_symbol_read(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("repair_symbol_read_io_overlap");
    for &n in &[16_usize, 64, 256] {
        let device = LatencyBlockDevice::new(n as u64, READ_LATENCY);
        let blocks: Vec<BlockNumber> = (0..n as u64).map(BlockNumber).collect();

        // Isomorphism: parallel reads + serial parse == serial loop, same order.
        assert_eq!(
            read_serial(&cx, &device, &blocks).expect("serial read"),
            read_parallel(&cx, &device, &blocks).expect("parallel read"),
            "parallel symbol read diverged from serial (n={n})"
        );

        group.bench_with_input(BenchmarkId::new("serial", n), &n, |b, _| {
            b.iter(|| black_box(read_serial(&cx, &device, black_box(&blocks))));
        });
        group.bench_with_input(BenchmarkId::new("parallel_rayon", n), &n, |b, _| {
            b.iter(|| black_box(read_parallel(&cx, &device, black_box(&blocks))));
        });
    }
    group.finish();

    let zero = vec![0u8; BS];
    let mut nonzero_early = vec![0u8; BS];
    nonzero_early[0] = 1;
    let mut nonzero_late = vec![0u8; BS];
    nonzero_late[SYMBOL_SIZE - 1] = 1;

    for (name, block) in [
        ("zero", &zero),
        ("nonzero_early", &nonzero_early),
        ("nonzero_late", &nonzero_late),
    ] {
        assert_eq!(
            parse_symbol(7, block).expect("old parse"),
            parse_symbol_zero_then_copy(7, block).expect("new parse"),
            "raw symbol zero-skip changed parse result for {name}"
        );
        let mut group = c.benchmark_group(format!("raw_symbol_zero_skip_{name}"));
        group.bench_function("copy_then_zero", |b| {
            b.iter(|| black_box(parse_symbol(7, black_box(block))));
        });
        group.bench_function("zero_then_copy", |b| {
            b.iter(|| black_box(parse_symbol_zero_then_copy(7, black_box(block))));
        });
        group.finish();
    }
}

criterion_group!(benches, bench_symbol_read);
criterion_main!(benches);
