#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the non-contiguous run reads in ext4
//! `read_ext4_indirect` (bd-r9c10, I/O-overlap sibling of the extent-path
//! bd-yg6tk).
//!
//! `read_ext4_indirect` is the legacy indirect-mapped read path. It already
//! coalesces a contiguous-physical run of full blocks into one vectored op
//! (bd-bov9c), but a fragmented legacy file with N non-contiguous runs issued
//! those N run reads back-to-back, so on real storage (each ranged read pays an
//! access latency) the N latencies serialized. The lever plans the read into
//! ordered segments serially (the indirect-block resolution stays serial — it's
//! a dependent, cached chain), then reads each segment's bytes in a rayon
//! `par_iter` and assembles them into the output buffer in byte order.
//!
//! This bench isolates that fan-out. The in-memory device is a zero-latency
//! memcpy and cannot show the win; a `LatencyBlockDevice` parks the worker for a
//! fixed per-read latency before delegating to a pre-built store. Both arms read
//! identical bytes into an identical buffer (asserted), so this measures only the
//! latency overlap.

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const RUN_BLOCKS: usize = 8; // blocks per contiguous run
const BS: usize = 4096; // ext4 block size
const RUN_BYTES: usize = RUN_BLOCKS * BS;
const LARGE_RUN_BLOCKS: usize = 8192; // 32 MiB: matches the residual ext4 gap row.
const LARGE_CHUNK_BLOCKS: &[usize] = &[16, 32, 64, 128, 256, 512];
/// Per-read access latency. Models a real-disk / SSD-queue round trip.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Latency-injecting in-memory device (blocks pre-built once).
struct LatencyBlockDevice {
    blocks: Vec<BlockBuf>,
    read_latency: Duration,
}

impl LatencyBlockDevice {
    fn new(block_count: u64, read_latency: Duration) -> Self {
        let blocks = (0..block_count)
            .map(|blk| BlockBuf::new((0..BS).map(|i| prng(blk << 20 ^ i as u64)).collect()))
            .collect();
        Self {
            blocks,
            read_latency,
        }
    }
}

impl BlockDevice for LatencyBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        std::thread::sleep(self.read_latency);
        let idx = usize::try_from(block.0)
            .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
        self.blocks
            .get(idx)
            .map(BlockBuf::clone_ref)
            .ok_or_else(|| FfsError::Format(format!("bench block out of range: {}", block.0)))
    }

    fn supports_contiguous_reads(&self) -> bool {
        true
    }

    fn read_contiguous_blocks(
        &self,
        _cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        std::thread::sleep(self.read_latency);
        for (i, buf) in bufs.iter_mut().enumerate() {
            let idx = usize::try_from(start.0 + i as u64)
                .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
            *buf = self
                .blocks
                .get(idx)
                .map(BlockBuf::clone_ref)
                .ok_or_else(|| FfsError::Format("bench block out of range".into()))?;
        }
        Ok(())
    }

    fn read_contiguous_into(&self, _cx: &Cx, start: BlockNumber, dst: &mut [u8]) -> Result<()> {
        if !dst.len().is_multiple_of(BS) {
            return Err(FfsError::Format(
                "bench read_contiguous_into requires block-aligned dst".into(),
            ));
        }
        std::thread::sleep(self.read_latency);
        for (i, chunk) in dst.chunks_mut(BS).enumerate() {
            let idx = usize::try_from(start.0 + i as u64)
                .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
            chunk.copy_from_slice(
                self.blocks
                    .get(idx)
                    .ok_or_else(|| FfsError::Format("bench block out of range".into()))?
                    .as_slice(),
            );
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

/// Read one contiguous run of `RUN_BLOCKS` blocks starting at `phys0`.
fn read_run(cx: &Cx, dev: &LatencyBlockDevice, phys0: u64) -> Result<Vec<u8>> {
    let mut bufs = vec![BlockBuf::new(Vec::new()); RUN_BLOCKS];
    dev.read_contiguous_blocks(cx, BlockNumber(phys0), &mut bufs)?;
    let mut out = Vec::with_capacity(RUN_BYTES);
    for b in &bufs {
        out.extend_from_slice(b.as_slice());
    }
    Ok(out)
}

/// Read one contiguous run directly into the caller's output window.
fn read_run_into(cx: &Cx, dev: &LatencyBlockDevice, phys0: u64, dst: &mut [u8]) -> Result<()> {
    dev.read_contiguous_into(cx, BlockNumber(phys0), dst)
}

/// OLD: read each run serially into the output in byte order.
fn read_serial(cx: &Cx, dev: &LatencyBlockDevice, run_starts: &[u64]) -> Result<Vec<u8>> {
    let mut buf = vec![0_u8; run_starts.len() * RUN_BYTES];
    for (i, &phys0) in run_starts.iter().enumerate() {
        let data = read_run(cx, dev, phys0)?;
        buf[i * RUN_BYTES..(i + 1) * RUN_BYTES].copy_from_slice(&data);
    }
    Ok(buf)
}

/// NEW: read runs in parallel into owned buffers, assemble in byte order.
fn read_parallel(cx: &Cx, dev: &LatencyBlockDevice, run_starts: &[u64]) -> Result<Vec<u8>> {
    let reads: Vec<Result<Vec<u8>>> = run_starts
        .par_iter()
        .map(|&phys0| read_run(cx, dev, phys0))
        .collect();
    let mut buf = vec![0_u8; run_starts.len() * RUN_BYTES];
    for (i, read) in reads.into_iter().enumerate() {
        let data = read?;
        buf[i * RUN_BYTES..(i + 1) * RUN_BYTES].copy_from_slice(&data);
    }
    Ok(buf)
}

/// CANDIDATE: read runs in parallel directly into disjoint output windows.
fn read_parallel_in_place(
    cx: &Cx,
    dev: &LatencyBlockDevice,
    run_starts: &[u64],
) -> Result<Vec<u8>> {
    let mut buf = vec![0_u8; run_starts.len() * RUN_BYTES];
    let mut jobs = Vec::with_capacity(run_starts.len());
    {
        let mut rest = buf.as_mut_slice();
        for &phys0 in run_starts {
            let (dst, after_dst) = rest.split_at_mut(RUN_BYTES);
            rest = after_dst;
            jobs.push((phys0, dst));
        }
    }
    let reads: Vec<Result<()>> = jobs
        .into_par_iter()
        .map(|(phys0, dst)| read_run_into(cx, dev, phys0, dst))
        .collect();
    for read in reads {
        read?;
    }
    Ok(buf)
}

/// OLD large-run shape: one huge coalesced run, then serial assembly copy.
fn read_large_run_single(cx: &Cx, dev: &LatencyBlockDevice, blocks: usize) -> Result<Vec<u8>> {
    let span = blocks * BS;
    let mut tmp = vec![0_u8; span];
    dev.read_contiguous_into(cx, BlockNumber(0), &mut tmp)?;
    let mut buf = vec![0_u8; span];
    buf.copy_from_slice(&tmp);
    Ok(buf)
}

/// NEW large-run shape: split one coalesced run into ordered owned chunks.
fn read_large_run_chunked(
    cx: &Cx,
    dev: &LatencyBlockDevice,
    blocks: usize,
    chunk_blocks: usize,
) -> Result<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut block_off = 0_usize;
    while block_off < blocks {
        let take_blocks = (blocks - block_off).min(chunk_blocks);
        chunks.push((block_off, take_blocks, block_off * BS));
        block_off += take_blocks;
    }

    let reads: Vec<Result<Vec<u8>>> = chunks
        .par_iter()
        .map(|&(block_off, take_blocks, _)| {
            let mut tmp = vec![0_u8; take_blocks * BS];
            dev.read_contiguous_into(cx, BlockNumber(block_off as u64), &mut tmp)?;
            Ok(tmp)
        })
        .collect();

    let mut buf = vec![0_u8; blocks * BS];
    for ((_, _, buf_off), read) in chunks.iter().zip(reads) {
        let data = read?;
        buf[*buf_off..*buf_off + data.len()].copy_from_slice(&data);
    }
    Ok(buf)
}

/// CANDIDATE large-run shape: split one run, fill ordered output chunks in place.
fn read_large_run_chunked_in_place(
    cx: &Cx,
    dev: &LatencyBlockDevice,
    blocks: usize,
    chunk_blocks: usize,
) -> Result<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut block_off = 0_usize;
    while block_off < blocks {
        let take_blocks = (blocks - block_off).min(chunk_blocks);
        chunks.push((block_off, take_blocks));
        block_off += take_blocks;
    }

    let mut buf = vec![0_u8; blocks * BS];
    let mut jobs = Vec::with_capacity(chunks.len());
    {
        let mut rest = buf.as_mut_slice();
        for &(block_off, take_blocks) in &chunks {
            let bytes = take_blocks * BS;
            let (dst, after_dst) = rest.split_at_mut(bytes);
            rest = after_dst;
            jobs.push((block_off, dst));
        }
    }

    let reads: Vec<Result<()>> = jobs
        .into_par_iter()
        .map(|(block_off, dst)| dev.read_contiguous_into(cx, BlockNumber(block_off as u64), dst))
        .collect();
    for read in reads {
        read?;
    }
    Ok(buf)
}

fn bench_indirect(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("ext4_indirect_read_overlap");
    for &runs in &[16_usize, 64, 256] {
        // Non-contiguous runs: a gap between each run so they cannot coalesce.
        let total_blocks = (runs as u64) * (RUN_BLOCKS as u64) * 2 + RUN_BLOCKS as u64;
        let dev = LatencyBlockDevice::new(total_blocks, READ_LATENCY);
        let run_starts: Vec<u64> = (0..runs as u64)
            .map(|r| r * (RUN_BLOCKS as u64) * 2)
            .collect();

        assert_eq!(
            read_serial(&cx, &dev, &run_starts).expect("serial"),
            read_parallel(&cx, &dev, &run_starts).expect("parallel"),
            "parallel indirect read diverged from serial (runs={runs})"
        );
        assert_eq!(
            read_serial(&cx, &dev, &run_starts).expect("serial"),
            read_parallel_in_place(&cx, &dev, &run_starts).expect("parallel in-place"),
            "in-place indirect read diverged from serial (runs={runs})"
        );

        group.bench_with_input(BenchmarkId::new("serial", runs), &runs, |b, _| {
            b.iter(|| black_box(read_serial(&cx, &dev, black_box(&run_starts))));
        });
        group.bench_with_input(BenchmarkId::new("parallel_rayon", runs), &runs, |b, _| {
            b.iter(|| black_box(read_parallel(&cx, &dev, black_box(&run_starts))));
        });
        group.bench_with_input(
            BenchmarkId::new("parallel_in_place", runs),
            &runs,
            |b, _| {
                b.iter(|| black_box(read_parallel_in_place(&cx, &dev, black_box(&run_starts))));
            },
        );
    }

    let dev = LatencyBlockDevice::new(LARGE_RUN_BLOCKS as u64, READ_LATENCY);
    let single_large =
        read_large_run_single(&cx, &dev, LARGE_RUN_BLOCKS).expect("large-run single");
    for &chunk_blocks in LARGE_CHUNK_BLOCKS {
        assert_eq!(
            single_large,
            read_large_run_chunked(&cx, &dev, LARGE_RUN_BLOCKS, chunk_blocks)
                .expect("large-run chunked"),
            "chunked large-run indirect read diverged from one-run read (chunk_blocks={chunk_blocks})",
        );
        assert_eq!(
            single_large,
            read_large_run_chunked_in_place(&cx, &dev, LARGE_RUN_BLOCKS, chunk_blocks)
                .expect("large-run chunked in-place"),
            "in-place chunked large-run indirect read diverged from one-run read (chunk_blocks={chunk_blocks})",
        );
    }
    group.bench_with_input(
        BenchmarkId::new("large_run_single", LARGE_RUN_BLOCKS),
        &LARGE_RUN_BLOCKS,
        |b, &blocks| {
            b.iter(|| black_box(read_large_run_single(&cx, &dev, black_box(blocks))));
        },
    );
    for &chunk_blocks in LARGE_CHUNK_BLOCKS {
        group.bench_with_input(
            BenchmarkId::new(
                format!("large_run_chunked_{chunk_blocks}blocks"),
                LARGE_RUN_BLOCKS,
            ),
            &LARGE_RUN_BLOCKS,
            |b, &blocks| {
                b.iter(|| {
                    black_box(read_large_run_chunked(
                        &cx,
                        &dev,
                        black_box(blocks),
                        black_box(chunk_blocks),
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new(
                format!("large_run_chunked_in_place_{chunk_blocks}blocks"),
                LARGE_RUN_BLOCKS,
            ),
            &LARGE_RUN_BLOCKS,
            |b, &blocks| {
                b.iter(|| {
                    black_box(read_large_run_chunked_in_place(
                        &cx,
                        &dev,
                        black_box(blocks),
                        black_box(chunk_blocks),
                    ))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_indirect);
criterion_main!(benches);
