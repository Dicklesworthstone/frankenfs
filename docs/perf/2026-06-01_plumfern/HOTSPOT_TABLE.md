# Ranked Hotspot Table — `2026-06-01_plumfern`

> Measurement-only pass (PlumFern, cc). Hand-off to `extreme-software-optimization`.
> Score = Impact × Confidence / Effort (filled per-bead). Each row cites an artifact.

## Environment (see `fingerprint.json`)
AMD Ryzen Threadripper PRO 5975WX (64T, governor=powersave), 215 GiB RAM,
kernel 6.17.0-29, rustc 1.98.0-nightly, build `release-perf` +
`-C force-frame-pointers=yes`, git `12c36788`, `perf_event_paranoid=1`.

## Baseline numbers (this host, current HEAD)
| Scenario | p50 | p95 | p99 | User | System | Peak RSS |
|----------|-----|-----|-----|------|--------|----------|
| `fsck -f --json` (8 MiB img) | 16.0 ms | 18.3 ms | 18.9 ms | ~4.3 ms | ~10.9 ms | ~14 MB |
| `info --groups --mvcc --journal --json` | 2.19 ms | 2.48 ms | 2.54 ms | 0.5 ms | 1.8 ms | ~5.9 MB |
| `inspect --json` | 2.17 ms | 2.56 ms | 2.66 ms | 0.2 ms | 1.9 ms | ~5.2 MB |

`info`/`inspect` are below hyperfine's ~5 ms reliability floor (process-spawn
dominated); `fsck -f` is the only single-shot CLI scenario that clears it.
Artifacts: `baseline_macro.json`, `baseline_fsck.json`.

## Ranked hotspots

| Rank | Location | Metric | Value | Category | Evidence |
|------|----------|--------|-------|----------|----------|
| 1 | Offline read path — one `pread64` per 4 KiB block (`ffs-block` `ByteDevice`/`BlockDevice` read → `ffs-core` fsck/scrub group walk) | syscalls / scan | **2048 preads** for 8 MiB; **58.45%** of syscall time; **scales linearly with FS size** | I/O | `strace_fsck_syscalls.txt`, `strace_fsck_read_sizes.txt` |
| 2 | Read-buffer movement `__memmove_avx_unaligned_erms` / `__memset_avx2_unaligned_erms` (per-block buffer alloc+zero+copy) | cumulative (file-read stack) | **13.5% (CLI) / 22.8% (FUSE)** stack; ~2.7% + ~1.8% self | CPU/alloc | `docs/reports/PROFILE_ANALYSIS.md` (same-CPU flamegraphs) |
| 3 | `ffs_types::ensure_slice` + `read_le_*` + `Result<&[u8],ParseError>::branch` (parser primitive density) | self | ~1.9% + ~1.1% + ~1.4% | CPU | `docs/reports/PROFILE_ANALYSIS.md` |
| 4 | `Cx::checkpoint` (asupersync request-scope checkpoint on the hot read loop) | self | ~1.8–2.0% | CPU | `docs/reports/PROFILE_ANALYSIS.md` |
| 5 | Subsystem-level: ARC/S3-FIFO cache scan, RaptorQ scrub, WAL commit families (criterion) | per-op p50 | see `docs/planning/PROFILING-SUMMARY.md` / `benchmarks/baselines/latest.json` | mixed | established baselines (peer gauntlet refreshing) |

**Headline:** the read path's cost is dominated by **structure, not a hot
function** — it reads and copies one 4 KiB block per syscall. Rank 1 (syscall
batching / vectored reads / read-ahead) is the single highest-leverage target;
ranks 2–4 are the CPU symptoms that the same per-block structure produces and
will shrink as a side effect of fixing rank 1.

## Confirmation status
- Rank 1: **fresh** (this host, current HEAD) via strace — strongest evidence,
  independent of any CPU profiler.
- Ranks 2–4: CPU self-symbols sourced from the prior 2026-05-10 flamegraph on the
  **same CPU** and same code path (`docs/reports/PROFILE_ANALYSIS.md`). A fresh
  symbolicated capture was **blocked by host profiler misconfig** (`perf` header
  corruption from a broken `perf_event_mlock_kb`; `samply` headless capture is
  unsymbolicated) — see `perf_read_path_selfsymbols.txt`.
- Fresh `samply` of `profile-read-path --mode direct-read` (10120 samples) shows
  the tight in-process block-read loop is **concentrated** (63.8% of leaf samples
  in a single routine), reinforcing rank 1 (the read primitive dominates this
  mode) — `samply_direct_read_top_unsymbolized.txt`.

## Hand-off
Top targets filed as perf-tagged beads (see commit). Optimizer must prove
behavior unchanged against `conformance/golden/ext4_8mb_reference.json` and
re-measure `fsck -f` p95 + syscall count (`strace -c`) after each lever.
