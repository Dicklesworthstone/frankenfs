#![forbid(unsafe_code)]

//! Throughput benchmark for 128 MiB (`32,768 × 4 KiB`) RFC 6330 §4.3
//! block-interleaved striped RaptorQ group encoding and sparse `GF(256)`
//! single-block delta parity refresh.

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ffs_block::{BlockDevice, ByteBlockDevice, ByteDevice};
use ffs_error::{FfsError, Result};
use ffs_repair::codec::{
    BlockDelta, StripedGroupConfig, encode_group_striped, update_striped_group_delta,
};
use ffs_types::{BlockNumber, ByteOffset, GroupNumber};
use std::hint::black_box;
use std::time::Duration;

const BLOCK_SIZE: u32 = 4096;
const GROUP_BLOCKS_128_MIB: u32 = 32_768;
const FS_UUID: [u8; 16] = *b"ffs-128m-rqbench";

struct ContiguousImageByteDevice {
    bytes: Vec<u8>,
}

impl ContiguousImageByteDevice {
    fn new(block_count: u32) -> Self {
        let total_bytes = (block_count as usize) * (BLOCK_SIZE as usize);
        let mut bytes = vec![0_u8; total_bytes];
        for (blk, block_arr) in bytes
            .as_chunks_mut::<{ BLOCK_SIZE as usize }>()
            .0
            .iter_mut()
            .enumerate()
        {
            let seed = (blk as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            for (chunk_idx, chunk) in block_arr.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                let word = seed ^ (chunk_idx as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                *chunk = word.to_le_bytes();
            }
        }
        Self { bytes }
    }
}

impl ByteDevice for ContiguousImageByteDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        true
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset.0)
            .map_err(|_| FfsError::Format("byte offset overflow".to_owned()))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| FfsError::Format("byte range overflow".to_owned()))?;
        let slice = self
            .bytes
            .get(start..end)
            .ok_or_else(|| FfsError::Format("byte range out of bounds".to_owned()))?;
        buf.copy_from_slice(slice);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _buf: &[u8]) -> Result<()> {
        Err(FfsError::UnsupportedFeature(
            "read-only bench image".to_owned(),
        ))
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn bench_raptorq_128mib_group(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let device = ByteBlockDevice::new(
        ContiguousImageByteDevice::new(GROUP_BLOCKS_128_MIB),
        BLOCK_SIZE,
    )
    .expect("128 MiB ByteBlockDevice");
    let config = StripedGroupConfig {
        max_stripe_blocks: 64,
        repair_blocks_per_stripe: 4,
    };

    let mut group = c.benchmark_group("raptorq_128mib_group");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));
    group.throughput(Throughput::Bytes(
        u64::from(GROUP_BLOCKS_128_MIB) * u64::from(BLOCK_SIZE),
    ));

    group.bench_with_input(
        BenchmarkId::new("encode_full_128mib_striped", "32768x4k_r4_per_64"),
        &GROUP_BLOCKS_128_MIB,
        |b, &block_count| {
            b.iter(|| {
                let encoded = encode_group_striped(
                    &cx,
                    black_box(&device),
                    &FS_UUID,
                    GroupNumber(0),
                    BlockNumber(0),
                    block_count,
                    config,
                )
                .expect("striped 128 MiB encode");
                black_box(encoded.total_repair_symbols())
            });
        },
    );

    let mut encoded = encode_group_striped(
        &cx,
        &device,
        &FS_UUID,
        GroupNumber(0),
        BlockNumber(0),
        GROUP_BLOCKS_128_MIB,
        config,
    )
    .expect("initial 128 MiB encode");
    let old_block = device
        .read_block(&cx, BlockNumber(1337))
        .expect("read 1337")
        .into_inner();
    let new_block: Vec<u8> = old_block.iter().map(|&byte| byte ^ 0x5A).collect();

    group.throughput(Throughput::Bytes(u64::from(BLOCK_SIZE)));
    group.bench_function("delta_update_single_4k_block_in_128mib", |b| {
        let mut toggle = false;
        b.iter(|| {
            let delta = if toggle {
                BlockDelta {
                    source_index: 1337,
                    old_block: &new_block,
                    new_block: &old_block,
                }
            } else {
                BlockDelta {
                    source_index: 1337,
                    old_block: &old_block,
                    new_block: &new_block,
                }
            };
            toggle = !toggle;
            update_striped_group_delta(black_box(&mut encoded), black_box(&[delta]))
                .expect("delta refresh");
        });
    });

    group.finish();
}

criterion_group!(benches, bench_raptorq_128mib_group);
criterion_main!(benches);
