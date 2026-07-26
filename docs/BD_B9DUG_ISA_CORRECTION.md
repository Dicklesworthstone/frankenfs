# bd-b9dug — the benchmarked binary is not the shipped binary

**Lane L (ledger/low-burn), 2026-07-25. No worker was used to produce this document.**

Every published frankenfs performance ratio was measured on a binary that is **not**
the one `scripts/build-perf.sh` produces. This document states the delta exactly,
re-states the affected claims by class, and fixes the admissibility rule so the
mismatch cannot be published silently again.

---

## 1. The delta, exactly

| | benchmarked (`cargo bench --profile release-perf`) | shipped (`scripts/build-perf.sh`) |
|---|---|---|
| Cargo profile | `release-perf` | `release-perf` (same) |
| `opt-level` | 3 | 3 |
| `lto` | `"fat"` | `"fat"` |
| `codegen-units` | 1 (inherited) | 1 (inherited) |
| `panic` | `abort` (inherited) | `abort` (inherited) |
| **`target-cpu`** | **none — x86-64 baseline (SSE2)** | **`x86-64-v3` (AVX2 / BMI2 / FMA)** |
| **PGO** | **none** | **`-C profile-generate` → train → `-C profile-use`** |

The two differences are exactly the two things a Cargo profile **cannot** express:
`target-cpu` is a `RUSTFLAGS` setting, and PGO is a two-stage build. So
`[profile.release-perf]` in `Cargo.toml` is not wrong — it is simply *incomplete* as a
description of what ships, and nothing in the bench path ever said so.

### Direct in-binary witness

The `ffs-mvcc` bench harness now prints its own codegen configuration. From the
2026-07-25 runs on `vmi1227854`:

```
codegen_isa,target_arch=x86_64,compile_sse2=true,compile_sse4_2=false,
            compile_avx2=false,runtime_sse4_2=true,runtime_avx2=true
```

`compile_avx2=false` with `runtime_avx2=true`: the binary was compiled for a CPU far
weaker than the one it ran on. This is not inference — the executing binary reported it.

### Size of the effect, from evidence already in the repo

`scripts/build-perf.sh`'s header records `perf stat` measurements (2026-07-03,
`docs/NEGATIVE_EVIDENCE.md`), both behaviour-preserving (`create-bench` → `e2fsck`
clean) and stacking:

| lever | create | lookup |
|---|---:|---:|
| `target-cpu=x86-64-v3` | ~8.5% fewer instructions | ~3% |
| PGO, on top | ~10% fewer instructions | ~24% |
| **compounded** | **~17.6% fewer instructions** | **~26.3%** |

⚠ **These are instruction counts, not wall clock.** The script says so explicitly:
*"wall-clock was too noisy to see them."* This repo's own ledger carries the matching
lesson — *"instructions alone (7–13%) with flat cycles = neutral"* (the scrub
word→SIMD REJECT). So the **direction** of the correction is established and the
**instruction magnitude** is measured, but the **wall-clock magnitude is unknown**.
Do not convert 17.6% fewer instructions into 17.6% faster.

---

## 2. Re-stating the affected claims

Every published ratio falls into one of three classes, and the correction differs by class.

### Class A — "FrankenFS beats the kernel by N×" (wins)

Examples: allocator range-overlap **3110×**, journal replay **2024×**, extent
coalescing **120×**, incremental crc32c **24.7×**, rmdir dir-emptiness, htree lookup.

The FrankenFS arm ran on the weaker binary; the kernel arm is unaffected. The shipped
binary is faster than the benchmarked one, therefore **these wins are UNDERSTATED** —
the shipped advantage is at least what was published. **No claim needs to be withdrawn.**
They should be quoted as *"≥ N× (measured on a baseline-ISA build; the shipped
`build-perf.sh` binary retires ~18% fewer create instructions)"*.

### Class B — "FrankenFS is N× slower than the kernel" (losses)

Examples: parallel metadata writes **8.3× slower at 8 threads**, multi-file parallel
read **~2.9× slower**, mounted small-file create storm **4.599×**.

Same direction, opposite consequence: the shipped binary is faster, so **these losses
are OVERSTATED** — the real gap is smaller than published. This is the class that
matters, because these numbers drive lever selection. An 8.3× gap that is really, say,
7× changes nothing strategically, but it does mean **no loss in this class should be
called "structural" or "irreducible" on the strength of a baseline-ISA measurement.**
Campaign §3b names exactly this failure — constant factors from a downgraded ISA being
ledgered as irreducible walls.

### Class C — internal A/B (candidate vs control, one binary)

Examples: the 2026-07-25 wait-free publication gate **1.70–2.11× at 8 threads**, and
essentially every KEEP/REJECT row in `docs/progress/perf-negative-results.md`.

Both arms come from the same ELF, so **the ISA cancels and the ratio stands as
measured.** What does *not* automatically transfer is the magnitude on the shipped
binary: a lever whose benefit is compute-shaped can shrink under v3+PGO (the baseline it
improves gets faster), while a lever whose benefit is contention-shaped can **grow** (the
compute term shrinks, so the serialization term becomes a larger share of the whole).

Applying that to this session's own result: the wait-free publication gate is
contention-shaped — it removes a global mutex, and the two arms differ only in
synchronization. Its 1.70× is **not** at risk from the ISA gap, and if anything the
shipped binary should show a **larger** ratio. That is a prediction, not a measurement,
and it is recorded here as such.

### Not affected

`e2fsck` results, byte-identity proofs, correctness gates, conformance counts. ISA
changes codegen, not behaviour; `build-perf.sh` states its builds are
behaviour-preserving and `e2fsck`-clean.

---

## 3. The correction

> **UPDATE 2026-07-25 — the fleet ISA constraint has been lifted.** The orchestrator
> surveyed `/proc/cpuinfo` on all 12 rch workers: `ovh-b` (Xeon E3-1245 V2, Ivy Bridge
> 2012) was the **only** one without `avx2`+`fma`; all 11 others have both, and `hz2`
> has `avx512f`. Rust had to target the fleet's lowest common denominator, so that one
> 8-core box was pinning every franken benchmark binary to SSE2. `ovh-b` is now out of
> the `rust` tag — **73 rust slots across 11 AVX2+FMA workers.** The `ovh-b` SIGILL
> argument below is therefore **obsolete**, and §3.3 is upgraded from "how to reproduce
> production if you want to" to **"this is how benchmarks should be built from now on."**
> The *product* argument is untouched — see immediately below.

**Still true, and unaffected by the fleet change: do not make `target-cpu=x86-64-v3` the
default for the SHIPPED product build.** `build-perf.sh` explains why it is opt-in — v3
requires a 2015+ CPU and removes the runtime scalar fallback FrankenFS deliberately
keeps for older hardware. That is a portability decision about users' machines, not
about our workers, so lifting the fleet constraint does not touch it.

What *has* changed is the **benchmark** configuration. There is no longer any reason to
measure at x86-64 baseline: doing so measures a binary nobody ships, on hardware that
could have run the real one. Benchmarks should now be built with
`RUSTFLAGS="-C target-cpu=x86-64-v3"`.

**And make the mismatch unpublishable either way:**

1. **Every bench binary self-reports its codegen ISA**, as `ffs-mvcc/benches/wal_throughput.rs`
   now does via `print_codegen_isa()`. One `cfg!(target_feature = ...)` line per binary.
2. **Admissibility rule (new):** a performance ratio may not be published from a bench
   run whose output lacks a `codegen_isa` line. A ratio whose `compile_avx2` differs
   from the shipped configuration must carry the class-A/B/C qualifier above.
3. **Reproducing production for a measurement** — no config change required, just the
   documented invocation:
   ```
   RUSTFLAGS="-C target-cpu=x86-64-v3" cargo bench --profile release-perf …   # v3, no PGO
   scripts/build-perf.sh                                                       # v3 + PGO (ships)
   ```
   Any such run **must be pinned to an AVX2-capable worker** (`ovh-b` excluded) and must
   report `codegen_isa` to prove the flag reached the compiler — same source and same
   worker with a *different* ELF sha means codegen actually changed.
4. **Do not gate on instruction count for an ISA A/B.** An ISA change retires more work
   per instruction, so fewer instructions is the mechanism, not a neutral proxy. Gate on
   wall/cycles (campaign §2.6).

---

## 4. What this does not resolve — corrected

An earlier revision of this document said the wall-clock size of the gap was "still
unmeasured". **That was wrong, and the correction matters.**
`docs/NEGATIVE_EVIDENCE.md:128` (bd-b9dug, 2026-07-11) already ran an **interleaved,
drift-cancelled** A/B of a production-ISA `create-bench` against the default build:

> v3 is **1.18–1.40× faster** in absolute throughput at every thread count
> (t1 74k→93k, t8 46k→54k), so the benchmark binary **UNDERSTATES production** and the
> "8.3×@8t" gap is inflated.

Two things follow, and they are exactly the re-statement in §2 arrived at independently
a fortnight earlier — which is corroboration, not coincidence:

- It confirms **Class B**: the published parallel-metadata-write loss is inflated.
- It confirms the **Class C** reasoning about contention-shaped levers. The same row
  reports the *scaling shape* is unchanged (v3 `t8/t1` = **0.58×** vs opt-z **0.62×**,
  both negative) and concludes *"the contention is real + ISA-independent."* That is
  direct evidence for the prediction in §2 that the wait-free publication gate's
  1.70–2.11× is not at risk from the ISA gap.

**What genuinely remains open is narrower than "the wall-clock gap".** That A/B compared
`v3 + opt-3 + fat-LTO` against **the default `release` profile, which is `opt-level="z"`**
— so it measures `opt-z → opt-3` *plus* fat-LTO *plus* the ISA, conflated. The
benchmark profile `release-perf` **already has opt-3 and fat LTO**. So the ISA-only
delta from `release-perf` to production is **strictly smaller than 1.18–1.40×**, and
that residual is what is unmeasured.

Retry predicate for the residual: on an AVX2-capable pinned worker, build
`--profile release-perf` with and without `-C target-cpu=x86-64-v3` from identical
source, confirm the ELF shas differ (proving the flag reached the compiler), and gate on
wall/cycles — never on instruction count. With `ovh-b` out of the `rust` tag this is now
schedulable on any of 11 workers; it was not before.
