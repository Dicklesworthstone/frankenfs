#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for parallelizing the RaptorQ encode GF combine (bd-blr6r).
//!
//! `encode_group` builds R repair symbols, each an independent GF256 linear
//! combination of K source symbols into a fresh block. The old loop ran the R
//! combines serially; the new code runs them in parallel across cores (rayon).
//! This bench isolates that GF combine: build K random source blocks + R random
//! coefficient rows, then compute the R repair blocks serially vs. via
//! `into_par_iter`. Both produce the identical repair blocks (asserted).

use asupersync::raptorq::gf256::{Gf256, gf256_addmul_slice};
use criterion::{Criterion, criterion_group, criterion_main};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;

const K: usize = 64; // source symbols per group
const R: usize = 16; // repair symbols (parallelized across)
const BLOCK: usize = 4096; // symbol size (bytes)

#[cfg(feature = "bench-instrumentation")]
mod source_read_batch {
    use asupersync::Cx;
    use criterion::Criterion;
    use ffs_block::{BlockBuf, BlockDevice, ByteBlockDevice, FileByteDevice};
    use ffs_error::{FfsError, Result};
    use ffs_repair::codec::{EncodedGroup, encode_group, encode_group_batched_read_candidate};
    use ffs_types::{BlockNumber, GroupNumber};
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::hint::black_box;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    const SOURCE_BLOCKS: u32 = 16;
    const REPAIR_SYMBOLS: u32 = 1;
    const READ_LATENCY: Duration = Duration::from_micros(250);
    const ROUNDS: usize = 31;
    const BOOTSTRAP_RESAMPLES: usize = 10_000;
    const BOOTSTRAP_SEED: u64 = 0xF5A1_4A22_2026_0726;
    const FS_UUID: [u8; 16] = *b"ffs-encode-ab-v1";
    const GROUP: GroupNumber = GroupNumber(7);

    struct PairedStats {
        p50_a_ns: f64,
        p50_b_ns: f64,
        ratio_p50: f64,
        ratio_ci: (f64, f64),
        checksum: u64,
    }

    struct LatencyBlockDevice {
        blocks: Vec<BlockBuf>,
        read_latency: Duration,
        fail_blocks: Vec<u64>,
        logical_reads: AtomicU64,
        io_calls: AtomicU64,
        active_reads: AtomicU64,
        max_active_reads: AtomicU64,
    }

    impl LatencyBlockDevice {
        fn new(block_count: u64, read_latency: Duration, fail_blocks: Vec<u64>) -> Self {
            let blocks = (0..block_count)
                .map(|block| {
                    let data = (0..super::BLOCK)
                        .map(|offset| {
                            super::prng((block << 32) ^ u64::try_from(offset).unwrap_or(0))
                        })
                        .collect();
                    BlockBuf::new(data)
                })
                .collect();
            Self {
                blocks,
                read_latency,
                fail_blocks,
                logical_reads: AtomicU64::new(0),
                io_calls: AtomicU64::new(0),
                active_reads: AtomicU64::new(0),
                max_active_reads: AtomicU64::new(0),
            }
        }

        fn logical_reads(&self) -> u64 {
            self.logical_reads.load(Ordering::Relaxed)
        }

        fn io_calls(&self) -> u64 {
            self.io_calls.load(Ordering::Relaxed)
        }

        fn max_active_reads(&self) -> u64 {
            self.max_active_reads.load(Ordering::Relaxed)
        }

        fn block_result(&self, block: BlockNumber) -> Result<BlockBuf> {
            if self.fail_blocks.contains(&block.0) {
                Err(FfsError::Io(std::io::Error::other(format!(
                    "injected source read failure at block {}",
                    block.0
                ))))
            } else {
                usize::try_from(block.0)
                    .map_err(|_| FfsError::Format("bench block index overflow".to_owned()))
                    .and_then(|index| {
                        self.blocks
                            .get(index)
                            .map(BlockBuf::clone_ref)
                            .ok_or_else(|| {
                                FfsError::Format(format!("bench block out of range: {}", block.0))
                            })
                    })
            }
        }
    }

    impl BlockDevice for LatencyBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            self.logical_reads.fetch_add(1, Ordering::Relaxed);
            self.io_calls.fetch_add(1, Ordering::Relaxed);
            let active = self.active_reads.fetch_add(1, Ordering::Relaxed) + 1;
            self.max_active_reads.fetch_max(active, Ordering::Relaxed);
            std::thread::sleep(self.read_latency);

            let result = self.block_result(block);

            self.active_reads.fetch_sub(1, Ordering::Relaxed);
            result
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
            self.logical_reads.fetch_add(
                u64::try_from(bufs.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            self.io_calls.fetch_add(1, Ordering::Relaxed);
            let active = self.active_reads.fetch_add(1, Ordering::Relaxed) + 1;
            self.max_active_reads.fetch_max(active, Ordering::Relaxed);
            std::thread::sleep(self.read_latency);

            let result = (|| {
                for (index, buf) in bufs.iter_mut().enumerate() {
                    let offset = u64::try_from(index)
                        .map_err(|_| FfsError::Format("bench block index overflow".to_owned()))?;
                    let block = BlockNumber(start.0.checked_add(offset).ok_or_else(|| {
                        FfsError::Format("bench block range overflow".to_owned())
                    })?);
                    *buf = self.block_result(block)?;
                }
                Ok(())
            })();

            self.active_reads.fetch_sub(1, Ordering::Relaxed);
            result
        }

        fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
            Err(FfsError::ReadOnly)
        }

        fn block_size(&self) -> u32 {
            u32::try_from(super::BLOCK).expect("block size fits u32")
        }

        fn block_count(&self) -> u64 {
            u64::try_from(self.blocks.len()).expect("block count fits u64")
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    fn self_identity() -> String {
        let Ok(path) = std::env::current_exe() else {
            return "unavailable".to_owned();
        };
        let Ok(bytes) = std::fs::read(&path) else {
            return "unavailable".to_owned();
        };
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let mut encoded = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(encoded, "{byte:02x}");
        }
        format!("{} ({} bytes) {}", encoded, bytes.len(), path.display())
    }

    fn print_codegen_isa() {
        #[cfg(target_arch = "x86_64")]
        println!(
            "codegen_isa,target_arch=x86_64,compile_sse2={},compile_sse4_2={},compile_avx2={},compile_fma={},runtime_sse4_2={},runtime_avx2={},runtime_fma={}",
            cfg!(target_feature = "sse2"),
            cfg!(target_feature = "sse4.2"),
            cfg!(target_feature = "avx2"),
            cfg!(target_feature = "fma"),
            std::arch::is_x86_feature_detected!("sse4.2"),
            std::arch::is_x86_feature_detected!("avx2"),
            std::arch::is_x86_feature_detected!("fma"),
        );

        #[cfg(not(target_arch = "x86_64"))]
        println!("codegen_isa,target_arch={}", std::env::consts::ARCH);
    }

    fn assert_encoded_equal(expected: &EncodedGroup, actual: &EncodedGroup) {
        assert_eq!(expected.group, actual.group);
        assert_eq!(expected.source_block_count, actual.source_block_count);
        assert_eq!(expected.symbol_size, actual.symbol_size);
        assert_eq!(expected.seed, actual.seed);
        assert_eq!(expected.repair_symbols.len(), actual.repair_symbols.len());
        for (expected, actual) in expected.repair_symbols.iter().zip(&actual.repair_symbols) {
            assert_eq!(expected.esi, actual.esi);
            assert_eq!(expected.data, actual.data);
            assert_eq!(expected.is_source, actual.is_source);
            assert_eq!(expected.degree, actual.degree);
        }
    }

    fn encoded_digest(encoded: &EncodedGroup) -> u64 {
        let mut digest = u64::from(encoded.group.0)
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::from(encoded.source_block_count))
            .wrapping_add(u64::from(encoded.symbol_size))
            .wrapping_add(encoded.seed);
        for symbol in &encoded.repair_symbols {
            digest = digest
                .rotate_left(7)
                .wrapping_add(u64::from(symbol.esi))
                .wrapping_add(u64::try_from(symbol.degree).unwrap_or(u64::MAX))
                .wrapping_add(u64::from(symbol.is_source));
            for &byte in &symbol.data {
                digest = digest.rotate_left(3) ^ u64::from(byte);
            }
        }
        digest
    }

    fn run_serial(device: &dyn BlockDevice, cx: &Cx) -> u64 {
        let encoded = encode_group(
            cx,
            device,
            &FS_UUID,
            GROUP,
            BlockNumber(0),
            SOURCE_BLOCKS,
            REPAIR_SYMBOLS,
        )
        .expect("serial-control encode succeeds");
        encoded_digest(&encoded)
    }

    fn run_batched(device: &dyn BlockDevice, cx: &Cx) -> u64 {
        let encoded = encode_group_batched_read_candidate(
            cx,
            device,
            &FS_UUID,
            GROUP,
            BlockNumber(0),
            SOURCE_BLOCKS,
            REPAIR_SYMBOLS,
        )
        .expect("batched-read encode succeeds");
        encoded_digest(&encoded)
    }

    fn current_exe_block_device() -> (ByteBlockDevice<FileByteDevice>, u32) {
        let path = std::env::current_exe().expect("current executable path");
        let len = std::fs::metadata(&path)
            .expect("current executable metadata")
            .len();
        let max_block_size = (len / u64::from(SOURCE_BLOCKS)).min(4096);
        let block_size = (1..=max_block_size)
            .rev()
            .find(|candidate| len % candidate == 0)
            .and_then(|candidate| u32::try_from(candidate).ok())
            .expect("executing ELF has a usable exact block size");
        let byte_device = FileByteDevice::open(path).expect("open executing ELF as byte device");
        (
            ByteBlockDevice::new(byte_device, block_size)
                .expect("executing ELF length is block aligned"),
            block_size,
        )
    }

    fn median(values: &[f64]) -> f64 {
        let mut sorted = values.to_vec();
        sorted.sort_unstable_by(f64::total_cmp);
        sorted[sorted.len() / 2]
    }

    fn bootstrap_median_ci(values: &[f64], seed: u64) -> (f64, f64) {
        let mut state = seed;
        let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
        let mut resample = Vec::with_capacity(values.len());

        for _ in 0..BOOTSTRAP_RESAMPLES {
            resample.clear();
            for _ in 0..values.len() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                resample.push(values[(state as usize) % values.len()]);
            }
            medians.push(median(&resample));
        }

        medians.sort_unstable_by(f64::total_cmp);
        let low = BOOTSTRAP_RESAMPLES * 25 / 1_000;
        let high = BOOTSTRAP_RESAMPLES * 975 / 1_000;
        (medians[low], medians[high.min(medians.len() - 1)])
    }

    fn paired(run_a: &impl Fn() -> u64, run_b: &impl Fn() -> u64) -> PairedStats {
        let mut times_a = Vec::with_capacity(ROUNDS);
        let mut times_b = Vec::with_capacity(ROUNDS);
        let mut ratios = Vec::with_capacity(ROUNDS);
        let mut checksum = 0_u64;

        for round in 0..ROUNDS {
            let time = |run: &dyn Fn() -> u64| {
                let started = Instant::now();
                let observed = black_box(run());
                (
                    u64::try_from(started.elapsed().as_nanos())
                        .unwrap_or(u64::MAX)
                        .max(1),
                    observed,
                )
            };
            let ((elapsed_a, checksum_a), (elapsed_b, checksum_b)) = if round % 2 == 0 {
                (time(run_a), time(run_b))
            } else {
                let b = time(run_b);
                let a = time(run_a);
                (a, b)
            };
            times_a.push(elapsed_a as f64);
            times_b.push(elapsed_b as f64);
            ratios.push(elapsed_a as f64 / elapsed_b.max(1) as f64);
            checksum ^= checksum_a.rotate_left((round % u64::BITS as usize) as u32);
            checksum ^= checksum_b.rotate_right((round % u64::BITS as usize) as u32);
        }

        PairedStats {
            p50_a_ns: median(&times_a),
            p50_b_ns: median(&times_b),
            ratio_p50: median(&ratios),
            ratio_ci: bootstrap_median_ci(&ratios, BOOTSTRAP_SEED),
            checksum,
        }
    }

    fn print_stats(label: &str, stats: &PairedStats) {
        println!(
            "{label},rounds={ROUNDS},p50_a_ns={:.0},p50_b_ns={:.0},ratio_p50={:.6},ratio_ci95=[{:.6},{:.6}],checksum={:016x}",
            stats.p50_a_ns,
            stats.p50_b_ns,
            stats.ratio_p50,
            stats.ratio_ci.0,
            stats.ratio_ci.1,
            stats.checksum,
        );
    }

    fn print_gate(label: &str, null: &PairedStats, real: &PairedStats) -> &'static str {
        let null_half_width = (null.ratio_ci.0 - 1.0)
            .abs()
            .max((null.ratio_ci.1 - 1.0).abs());
        let required_lower_bound = 1.0 + 2.0 * null_half_width;
        let decisive_win = real.ratio_ci.0 > required_lower_bound;
        let decisive_loss = real.ratio_ci.1 < required_lower_bound.recip();
        let verdict = if decisive_win {
            "decidable_win"
        } else if decisive_loss {
            "decidable_loss"
        } else {
            "unresolved"
        };
        println!(
            "repair_encode_source_read_gate,shape={label},median_ci_gate={verdict},real_ratio_ci95=[{:.6},{:.6}],null_half_width={null_half_width:.6},required_2x_margin_lower_bound={required_lower_bound:.6},cv_is_not_a_gate=true",
            real.ratio_ci.0, real.ratio_ci.1
        );
        verdict
    }

    fn run_contract() {
        println!("bench_elf_sha256={}", self_identity());
        print_codegen_isa();

        let cx = Cx::for_testing();
        let serial_device =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), READ_LATENCY, Vec::new());
        let batched_device =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), READ_LATENCY, Vec::new());
        let serial = encode_group(
            &cx,
            &serial_device,
            &FS_UUID,
            GROUP,
            BlockNumber(0),
            SOURCE_BLOCKS,
            REPAIR_SYMBOLS,
        )
        .expect("serial-control parity encode");
        let batched = encode_group_batched_read_candidate(
            &cx,
            &batched_device,
            &FS_UUID,
            GROUP,
            BlockNumber(0),
            SOURCE_BLOCKS,
            REPAIR_SYMBOLS,
        )
        .expect("batched-read parity encode");
        assert_encoded_equal(&serial, &batched);
        assert_eq!(serial_device.logical_reads(), u64::from(SOURCE_BLOCKS));
        assert_eq!(serial_device.io_calls(), u64::from(SOURCE_BLOCKS));
        assert_eq!(serial_device.max_active_reads(), 1);
        assert_eq!(batched_device.logical_reads(), u64::from(SOURCE_BLOCKS));
        assert_eq!(batched_device.io_calls(), 1);
        assert_eq!(batched_device.max_active_reads(), 1);

        let serial_fail =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), Duration::ZERO, vec![3, 7]);
        let batched_fail =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), Duration::ZERO, vec![3, 7]);
        let serial_error = encode_group(
            &cx,
            &serial_fail,
            &FS_UUID,
            GROUP,
            BlockNumber(0),
            SOURCE_BLOCKS,
            REPAIR_SYMBOLS,
        )
        .expect_err("serial control must surface injected read error")
        .to_string();
        let batched_error = encode_group_batched_read_candidate(
            &cx,
            &batched_fail,
            &FS_UUID,
            GROUP,
            BlockNumber(0),
            SOURCE_BLOCKS,
            REPAIR_SYMBOLS,
        )
        .expect_err("batched path must surface injected read error")
        .to_string();
        assert_eq!(serial_error, batched_error);

        println!(
            "behavior_parity=exact,source_blocks={SOURCE_BLOCKS},repair_symbols={REPAIR_SYMBOLS},serial_logical_reads={},batched_logical_reads={},serial_io_calls={},batched_io_calls={},first_error={serial_error:?}",
            serial_device.logical_reads(),
            batched_device.logical_reads(),
            serial_device.io_calls(),
            batched_device.io_calls(),
        );
        println!(
            "bench_config=rounds={ROUNDS},bootstrap_resamples={BOOTSTRAP_RESAMPLES},bootstrap_seed={BOOTSTRAP_SEED:016x},read_latency_ns={}",
            READ_LATENCY.as_nanos()
        );

        let null_a = LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), READ_LATENCY, Vec::new());
        let null_b = LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), READ_LATENCY, Vec::new());
        let real_serial =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), READ_LATENCY, Vec::new());
        let real_batched =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), READ_LATENCY, Vec::new());

        black_box(run_serial(&null_a, &cx));
        black_box(run_batched(&real_batched, &cx));
        let null = paired(&|| run_serial(&null_a, &cx), &|| run_serial(&null_b, &cx));
        let real = paired(&|| run_serial(&real_serial, &cx), &|| {
            run_batched(&real_batched, &cx)
        });
        print_stats("latency_null_serial_serial", &null);
        print_stats("latency_real_serial_batched", &real);
        assert_eq!(print_gate("latency_250us", &null, &real), "decidable_win");

        let zero_null_a =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), Duration::ZERO, Vec::new());
        let zero_null_b =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), Duration::ZERO, Vec::new());
        let zero_serial =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), Duration::ZERO, Vec::new());
        let zero_batched =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), Duration::ZERO, Vec::new());
        let zero_null = paired(&|| run_serial(&zero_null_a, &cx), &|| {
            run_serial(&zero_null_b, &cx)
        });
        let zero_real = paired(&|| run_serial(&zero_serial, &cx), &|| {
            run_batched(&zero_batched, &cx)
        });
        print_stats("zero_latency_null_serial_serial", &zero_null);
        print_stats("zero_latency_real_serial_batched", &zero_real);
        assert_ne!(
            print_gate("zero_latency", &zero_null, &zero_real),
            "decidable_loss",
            "batched source reads decisively regress the zero-latency control"
        );

        let (file_null_a, file_block_size) = current_exe_block_device();
        let (file_null_b, _) = current_exe_block_device();
        let (file_serial, _) = current_exe_block_device();
        let (file_batched, _) = current_exe_block_device();
        assert_eq!(
            run_serial(&file_serial, &cx),
            run_batched(&file_batched, &cx),
            "file-backed serial/batched encoded digest mismatch"
        );
        black_box(run_batched(&file_batched, &cx));
        let file_null = paired(&|| run_serial(&file_null_a, &cx), &|| {
            run_serial(&file_null_b, &cx)
        });
        let file_real = paired(&|| run_serial(&file_serial, &cx), &|| {
            run_batched(&file_batched, &cx)
        });
        println!(
            "file_backed_config=source=current_exe,block_size={file_block_size},source_blocks={SOURCE_BLOCKS},page_cache=warm"
        );
        print_stats("file_backed_null_serial_serial", &file_null);
        print_stats("file_backed_real_serial_batched", &file_real);
        assert_eq!(
            print_gate("file_backed_warm", &file_null, &file_real),
            "decidable_win",
            "file-backed batched source reads did not clear the null floor"
        );
    }

    pub(super) fn bench(c: &mut Criterion) {
        run_contract();

        let cx = Cx::for_testing();
        let serial_device =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), READ_LATENCY, Vec::new());
        let batched_device =
            LatencyBlockDevice::new(u64::from(SOURCE_BLOCKS), READ_LATENCY, Vec::new());
        let mut group = c.benchmark_group("repair_encode_source_read_batch_16");
        group.bench_function("serial_production", |b| {
            b.iter(|| black_box(run_serial(black_box(&serial_device), &cx)));
        });
        group.bench_function("batched_candidate", |b| {
            b.iter(|| black_box(run_batched(black_box(&batched_device), &cx)));
        });
        group.finish();
    }
}

/// Deterministic pseudo-random byte (no Math.random in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

fn build_sources() -> Vec<Vec<u8>> {
    (0..K)
        .map(|s| {
            (0..BLOCK)
                .map(|b| prng((s as u64) << 20 ^ b as u64))
                .collect()
        })
        .collect()
}

/// R coefficient rows, each K non-trivial GF256 coefficients.
fn build_coeffs() -> Vec<Vec<u8>> {
    (0..R)
        .map(|r| {
            (0..K)
                .map(|s| prng(0x00C0_FFEE ^ (r as u64) << 16 ^ s as u64) | 1)
                .collect()
        })
        .collect()
}

fn combine_one(coeffs: &[u8], sources: &[Vec<u8>]) -> Vec<u8> {
    let mut data = vec![0_u8; BLOCK];
    for (&c, src) in coeffs.iter().zip(sources) {
        let coeff = Gf256::new(c);
        if coeff.is_zero() {
            continue;
        }
        gf256_addmul_slice(&mut data, src, coeff);
    }
    data
}

fn encode_serial(coeff_rows: &[Vec<u8>], sources: &[Vec<u8>]) -> Vec<Vec<u8>> {
    coeff_rows
        .iter()
        .map(|row| combine_one(row, sources))
        .collect()
}

fn encode_parallel(coeff_rows: &[Vec<u8>], sources: &[Vec<u8>]) -> Vec<Vec<u8>> {
    (0..coeff_rows.len())
        .into_par_iter()
        .map(|r| combine_one(&coeff_rows[r], sources))
        .collect()
}

fn bench_encode(c: &mut Criterion) {
    let sources = build_sources();
    let coeff_rows = build_coeffs();

    // Isomorphism: parallel produces the identical repair blocks, same order.
    assert_eq!(
        encode_serial(&coeff_rows, &sources),
        encode_parallel(&coeff_rows, &sources),
        "parallel encode diverged from serial"
    );

    let mut group = c.benchmark_group("raptorq_encode_combine_k64_r16_4k");
    group.bench_function("serial", |b| {
        b.iter(|| black_box(encode_serial(black_box(&coeff_rows), black_box(&sources))));
    });
    group.bench_function("parallel_rayon", |b| {
        b.iter(|| black_box(encode_parallel(black_box(&coeff_rows), black_box(&sources))));
    });
    group.finish();
}

// ── Local-parity XOR combine (encode_local) ────────────────────────────────

const GROUPS: usize = 16; // local groups
const GROUP_SIZE: usize = 4; // data blocks per local group

fn xor_one(group: &[Vec<u8>]) -> Vec<u8> {
    let mut parity = vec![0_u8; BLOCK];
    for block in group {
        for (p, &b) in parity.iter_mut().zip(block) {
            *p ^= b;
        }
    }
    parity
}

fn local_serial(groups: &[Vec<Vec<u8>>]) -> Vec<Vec<u8>> {
    groups.iter().map(|g| xor_one(g)).collect()
}

fn local_parallel(groups: &[Vec<Vec<u8>>]) -> Vec<Vec<u8>> {
    (0..groups.len())
        .into_par_iter()
        .map(|g| xor_one(&groups[g]))
        .collect()
}

fn bench_local(c: &mut Criterion) {
    let groups: Vec<Vec<Vec<u8>>> = (0..GROUPS)
        .map(|g| {
            (0..GROUP_SIZE)
                .map(|i| {
                    (0..BLOCK)
                        .map(|b| prng((g as u64) << 24 ^ (i as u64) << 12 ^ b as u64))
                        .collect()
                })
                .collect()
        })
        .collect();

    assert_eq!(local_serial(&groups), local_parallel(&groups));

    let mut group = c.benchmark_group("lrc_local_xor_g16_gs4_4k");
    group.bench_function("serial", |b| {
        b.iter(|| black_box(local_serial(black_box(&groups))));
    });
    group.bench_function("parallel_rayon", |b| {
        b.iter(|| black_box(local_parallel(black_box(&groups))));
    });
    group.finish();
}

fn bench_source_read_batch(c: &mut Criterion) {
    #[cfg(feature = "bench-instrumentation")]
    source_read_batch::bench(c);
    #[cfg(not(feature = "bench-instrumentation"))]
    let _ = c;
}

criterion_group!(benches, bench_encode, bench_local, bench_source_read_batch);
criterion_main!(benches);
