# FrankenFS `PLAN_TO_PORT` §9.5 End-to-End Performance Baselines — 20261119

## Scope

Records live runtime verification of all seven `PLAN_TO_PORT_FRANKENFS_TO_RUST.md` §9.5
throughput, latency, cache-hit, RaptorQ self-healing, and idle-CPU targets against a real
Linux FUSE mount (`ffs-cli mount`), direct `OpenFs` engine calls, `ffs-repair` codec routines,
and the `ffs-tui` runtime (`bd-wire-prod-ssi-slot-merge-and-port-perf-gates-vkibu`, `bd-rchk5`).

Harness test: `crates/ffs-cli/tests/cli_e2e.rs::measure_and_verify_section_9_5_performance_baselines_vkibu`

## Command & Provenance

```bash
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
CARGO_PROFILE_RELEASE_PANIC=unwind \
CARGO_PROFILE_RELEASE_LTO=thin \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  cargo test --release -p ffs-cli --test cli_e2e \
    measure_and_verify_section_9_5_performance_baselines_vkibu -- --ignored --exact --nocapture
```

| Field | Value |
|---|---|
| Source commit | `b4b5270491b9d8ce898b7b842635da1fc0a60075` |
| GitHub Actions run / job | `44450271352` / `135312202623` (`FUSE E2E`, Step 17 `PLAN_TO_PORT section 9.5 performance baselines`) |
| Runner OS / Arch | GitHub-hosted `ubuntu-latest` (`x86_64-unknown-linux-gnu`, `/dev/fuse` live userspace mount) |
| Profile | `release` (`opt-level = 3`, `lto = "thin"`, `codegen-units = 16`, `#![forbid(unsafe_code)]`) |
| Structured receipt | `SECTION_9_5_BASELINES\|{"seq_read_mb_s":12116.621795799147,"mounted_rand4k_cached_iops":4817771.917493548,"engine_rand4k_cached_iops":2251357.4137396626,"extent_cache_hit_ratio":0.9538950715421304,"total_cache_hit_ratio":0.9612195222575188,"getattr_p50_us":26.533,"getattr_p95_us":43.196,"getattr_p99_us":52.262,"raptorq_encode_128mib_p50_ms":65.046174,"raptorq_decode_single_4k_p50_ms":0.08012999999999999,"raptorq_decode_single_4k_p99_ms":0.211811,"tui_idle_cpu_pct":0.0}` |

## Measured Results vs `PLAN_TO_PORT` §9.5 Targets

| §9.5 Metric | Measured Value | Target | Status |
|---|---:|---:|---|
| Sequential read throughput (mounted FUSE, 64 MiB file) | `12,116.62 MB/s` | `>= 200 MB/s` | PASS (`60.6x` target) |
| Random 4 KiB read IOPS — mounted FUSE (cached) | `4,817,771.92 IOPS` | `>= 50,000 IOPS` | PASS (`96.4x` target) |
| Random 4 KiB read IOPS — direct `OpenFs::read` (`ShardedExtentReadCache` + `S3Fifo`) | `2,251,357.41 IOPS` | `>= 50,000 IOPS` | PASS (`45.0x` target) |
| Cache hit ratio (`ShardedExtentReadCache` / combined block+extent cache, Zipfian working set) | `95.39%` (`96.12%` total) | `>= 90.0%` | PASS (`+5.39 pp` / `+6.12 pp`) |
| Mounted `getattr` (`stat`) latency (p50 / p95 / p99) | `26.53 us` / `43.20 us` / `52.26 us` | `p99 < 100 us` | PASS (`1.91x` headroom) |
| RaptorQ 128 MiB (`32,768 × 4 KiB`) striped group encode (p50) | `65.05 ms` | `< 100 ms` | PASS (`1.54x` headroom) |
| RaptorQ single 4 KiB block corruption decode (p50 / p99) | `0.080 ms` / `0.212 ms` | `< 10 ms` | PASS (`47.2x` p99 headroom) |
| Idle TUI CPU overhead (`ffs-tui` over 2 s quiescent window) | `0.00%` | `< 1.0%` | PASS |
